package splittunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type step struct {
	code       uint32
	input      []byte
	outputSize int
	reply      []byte
	err        error
}

type scriptedTransport struct {
	mu     sync.Mutex
	steps  []step
	closed int
}

func (s *scriptedTransport) ioctl(_ context.Context, code uint32, input, output []byte) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.steps) == 0 {
		return 0, fmt.Errorf("unexpected IOCTL %#x", code)
	}
	want := s.steps[0]
	s.steps = s.steps[1:]
	if code != want.code || !bytes.Equal(input, want.input) || len(output) != want.outputSize {
		return 0, fmt.Errorf("IOCTL got (%#x,%x,%d), want (%#x,%x,%d)",
			code, input, len(output), want.code, want.input, want.outputSize)
	}
	copy(output, want.reply)
	return uint32(len(want.reply)), want.err
}

func (s *scriptedTransport) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed++
	return nil
}

func stateReply(state State) []byte {
	b := make([]byte, 8)
	le.PutUint64(b, uint64(state))
	return b
}

func closeController(t *testing.T, c *Controller) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Errorf("close controller: %v", err)
	}
}

func TestInitializeUsesV13AndNeverImplicitlyResets(t *testing.T) {
	a, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	b, _ := ParseGUID("ffeeddcc-bbaa-9988-7766-554433221100")
	d := &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateStarted)},
		{code: ioctlInitialize, input: unhex(t, loadFixture(t).Sublayers)},
	}}
	c := newController(d)
	if err := c.Initialize(context.Background(), Sublayers{a, b}); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil || d.closed != 1 || len(d.steps) != 0 {
		t.Fatalf("close did not only close once: %v; %+v", err, d)
	}
	d = &scriptedTransport{steps: []step{{code: ioctlGetState, outputSize: 8, reply: stateReply(StateEngaged)}}}
	c = newController(d)
	defer closeController(t, c)
	if err := c.Initialize(context.Background(), Sublayers{a, b}); !errors.Is(err, ErrState) {
		t.Fatalf("expected a state error without automatic reset: %v", err)
	}
}

func TestEmptyExclusionsUseClearIOCTL(t *testing.T) {
	d := &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateEngaged)},
		{code: ioctlClearConfiguration},
	}}
	c := newController(d)
	defer closeController(t, c)
	if err := c.SetExcludedDevicePaths(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(d.steps) != 0 {
		t.Fatal("clear was not sent")
	}
}

func TestConfigurationUsesSizeProbe(t *testing.T) {
	fixture := unhex(t, loadFixture(t).Configuration)
	size := stateReply(State(len(fixture)))
	d := &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateReady)},
		{code: ioctlGetConfiguration, outputSize: 8, reply: size},
		{code: ioctlGetConfiguration, outputSize: len(fixture), reply: fixture},
	}}
	c := newController(d)
	defer closeController(t, c)
	paths, err := c.ExcludedDevicePaths(context.Background())
	if err != nil || len(paths) != 2 || paths[1] != fixturePaths()[1] || len(d.steps) != 0 {
		t.Fatalf("configuration: %v, %v", paths, err)
	}
}

func TestControllerOperationsUseExpectedWireMessages(t *testing.T) {
	addresses := Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.64.0.2"),
		InternetIPv4: netip.MustParseAddr("192.0.2.2"),
		TunnelIPv6:   netip.MustParseAddr("fd00::2"),
		InternetIPv6: netip.MustParseAddr("2001:db8::2"),
	}
	encodedAddresses, err := encodeAddresses(addresses)
	if err != nil {
		t.Fatal(err)
	}
	processes := []Process{{PID: 1, ImagePath: `\Device\Volume\app.exe`}}
	encodedProcesses, err := encodeProcesses(processes)
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{`\Device\Volume\app.exe`}
	encodedPaths, err := encodeConfiguration(paths)
	if err != nil {
		t.Fatal(err)
	}
	eventReply := unhex(t, loadFixture(t).Events.Start)
	d := &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateInitialized)},
		{code: ioctlRegisterProcesses, input: encodedProcesses},
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateReady)},
		{code: ioctlRegisterAddresses, input: encodedAddresses},
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateEngaged)},
		{code: ioctlGetAddresses, outputSize: addressesSize, reply: encodedAddresses},
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateReady)},
		{code: ioctlSetConfiguration, input: encodedPaths},
		{code: ioctlDequeueEvent, outputSize: eventBufferSize, reply: eventReply},
		{code: ioctlReset},
	}}
	c := newController(d)
	defer closeController(t, c)
	if err := c.RegisterProcesses(context.Background(), processes); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAddresses(context.Background(), addresses); err != nil {
		t.Fatal(err)
	}
	if got, err := c.Addresses(context.Background()); err != nil || got != addresses {
		t.Fatalf("addresses = %#v, %v; want %#v", got, err, addresses)
	}
	if err := c.SetExcludedDevicePaths(context.Background(), paths); err != nil {
		t.Fatal(err)
	}
	if event, err := c.ReadEvent(context.Background()); err != nil || event.ID != EventStartSplitting {
		t.Fatalf("event = %#v, %v", event, err)
	}
	if err := c.Reset(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.steps) != 0 {
		t.Fatalf("%d wire operations were not issued", len(d.steps))
	}
}

func TestMalformedSizeProbeDoesNotAllocateOrFetch(t *testing.T) {
	for name, reply := range map[string][]byte{
		"short":     make([]byte, 7),
		"too small": stateReply(configHeaderSize - 1),
		"too large": bytes.Repeat([]byte{255}, 8),
	} {
		t.Run(name, func(t *testing.T) {
			d := &scriptedTransport{steps: []step{
				{code: ioctlGetState, outputSize: 8, reply: stateReply(StateReady)},
				{code: ioctlGetConfiguration, outputSize: 8, reply: reply},
			}}
			c := newController(d)
			defer closeController(t, c)
			if _, err := c.ExcludedDevicePaths(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("accepted malformed size probe: %v", err)
			}
		})
	}
}

type functionTransport struct {
	fn      func(context.Context, uint32, []byte, []byte) (uint32, error)
	onClose func() error
}

func (f *functionTransport) ioctl(ctx context.Context, code uint32, in, out []byte) (uint32, error) {
	return f.fn(ctx, code, in, out)
}
func (f *functionTransport) close() error { return f.onClose() }

func TestCloseCancelsAndDrainsEventsWithoutBlockingControl(t *testing.T) {
	started := make(chan struct{})
	finished := make(chan error, 1)
	var drained atomic.Bool
	d := &functionTransport{
		fn: func(ctx context.Context, code uint32, in, out []byte) (uint32, error) {
			if code == ioctlGetState {
				copy(out, stateReply(StateReady))
				return 8, nil
			}
			if code != ioctlDequeueEvent {
				return 0, fmt.Errorf("unexpected IOCTL %#x", code)
			}
			close(started)
			<-ctx.Done()
			drained.Store(true)
			return 0, ctx.Err()
		},
		onClose: func() error {
			if !drained.Load() {
				return errors.New("handle closed before event I/O drained")
			}
			return nil
		},
	}
	c := newController(d)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _, err := c.ReadEvent(ctx); finished <- err }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("event call did not start")
	}
	if state, err := c.State(ctx); err != nil || state != StateReady {
		t.Fatalf("event read blocked command lane: %s, %v", state, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("close-caused cancellation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("Close did not unblock event reader")
	}
	if _, err := c.State(context.Background()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("operation after Close: %v", err)
	}
	if err := c.SetExcludedPaths(context.Background(), []string{"invalid"}); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("path resolution ran after Close: %v", err)
	}
}

func TestConcurrentCloseRejectsQueuedAndNewOperations(t *testing.T) {
	started := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	var closes atomic.Int32
	d := &functionTransport{
		fn: func(ctx context.Context, code uint32, _, _ []byte) (uint32, error) {
			if code != ioctlGetState {
				return 0, fmt.Errorf("unexpected IOCTL %#x", code)
			}
			if calls.Add(1) != 1 {
				return 0, errors.New("queued operation issued an IOCTL during close")
			}
			close(started)
			<-ctx.Done()
			close(canceled)
			<-release
			return 0, ctx.Err()
		},
		onClose: func() error {
			closes.Add(1)
			return nil
		},
	}
	c := newController(d)
	const waiters = 32
	results := make(chan error, waiters)
	for range waiters {
		go func() {
			_, err := c.State(context.Background())
			results <- err
		}()
	}
	<-started

	const closers = 8
	closeResults := make(chan error, closers)
	for range closers {
		go func() { closeResults <- c.Close() }()
	}
	<-canceled
	for range waiters {
		if _, err := c.State(context.Background()); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("new operation during close = %v; want os.ErrClosed", err)
		}
	}
	close(release)

	for range waiters {
		if err := <-results; !errors.Is(err, os.ErrClosed) {
			t.Errorf("operation racing close = %v; want os.ErrClosed", err)
		}
	}
	for range closers {
		if err := <-closeResults; err != nil {
			t.Errorf("concurrent Close = %v", err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("IOCTL calls = %d; want 1", got)
	}
	if got := closes.Load(); got != 1 {
		t.Fatalf("transport closes = %d; want 1", got)
	}
}

func TestCancelledRequestDoesNotIssueIOCTL(t *testing.T) {
	d := &scriptedTransport{}
	c := newController(d)
	defer closeController(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.State(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: %v", err)
	}
}

func TestCancelledCommandLaneWaitDoesNotIssueIOCTL(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	d := &functionTransport{
		fn: func(_ context.Context, code uint32, _, output []byte) (uint32, error) {
			if code != ioctlGetState {
				return 0, fmt.Errorf("unexpected IOCTL %#x", code)
			}
			if calls.Add(1) != 1 {
				return 0, errors.New("queued command issued an IOCTL")
			}
			close(started)
			<-release
			copy(output, stateReply(StateReady))
			return 8, nil
		},
		onClose: func() error { return nil },
	}
	c := newController(d)
	defer closeController(t, c)
	first := make(chan error, 1)
	go func() {
		_, err := c.State(context.Background())
		first <- err
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.State(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lane wait: %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("IOCTL calls = %d; want 1", got)
	}
}

func TestShutdownClosesEvenIfResetFails(t *testing.T) {
	resetErr := errors.New("driver reset failed")
	d := &scriptedTransport{steps: []step{{code: ioctlReset, err: resetErr}}}
	c := newController(d)
	if err := c.Shutdown(context.Background()); !errors.Is(err, resetErr) || d.closed != 1 {
		t.Fatalf("shutdown hid reset failure or leaked handle: %v, %d", err, d.closed)
	}
}

func TestCloseReturnsTransportError(t *testing.T) {
	closeErr := errors.New("close failed")
	d := &functionTransport{
		fn:      func(context.Context, uint32, []byte, []byte) (uint32, error) { return 0, nil },
		onClose: func() error { return closeErr },
	}
	c := newController(d)
	if err := c.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("close error = %v", err)
	}
	if err := c.Close(); !errors.Is(err, closeErr) {
		t.Fatalf("repeated close error = %v", err)
	}
	var nilController *Controller
	if err := nilController.Close(); err != nil {
		t.Fatalf("nil close = %v", err)
	}
}

func TestQueryProcessValidatesRequestAndResponse(t *testing.T) {
	fixture := unhex(t, loadFixture(t).Query)
	request := make([]byte, 8)
	le.PutUint64(request, 42)
	d := &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateEngaged)},
		{code: ioctlQueryProcess, input: request, outputSize: processBufferSize, reply: fixture},
	}}
	c := newController(d)
	defer closeController(t, c)
	process, err := c.QueryProcess(context.Background(), 42)
	if err != nil || process.PID != 42 || process.ParentPID != 7 || !process.Split {
		t.Fatalf("query process: %+v, %v", process, err)
	}
	if _, err := c.QueryProcess(context.Background(), 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("zero PID: %v", err)
	}

	wrongPID := bytes.Clone(fixture)
	le.PutUint64(wrongPID, 43)
	d = &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateReady)},
		{code: ioctlQueryProcess, input: request, outputSize: processBufferSize, reply: wrongPID},
	}}
	c = newController(d)
	defer closeController(t, c)
	if _, err := c.QueryProcess(context.Background(), 42); !errors.Is(err, ErrProtocol) {
		t.Fatalf("different response PID: %v", err)
	}
}

func TestControllerRejectsInvalidCallsAndTransportResponses(t *testing.T) {
	var nilController *Controller
	if _, err := nilController.State(context.Background()); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("nil controller: %v", err)
	}
	d := &scriptedTransport{}
	c := newController(d)
	defer closeController(t, c)
	//nolint:staticcheck // The public method must reject a nil context safely.
	if _, err := c.State(nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("nil context: %v", err)
	}
	if _, err := c.exchange(context.Background(), ioctlGetState, nil, -1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("negative output size: %v", err)
	}
	if _, err := c.exchange(context.Background(), ioctlGetState, make([]byte, maxBufferSize+1), 0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized input: %v", err)
	}
	if _, err := c.exchange(context.Background(), ioctlGetState, nil, maxBufferSize+1); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("oversized output: %v", err)
	}

	excessive := &functionTransport{
		fn: func(context.Context, uint32, []byte, []byte) (uint32, error) {
			return 9, nil
		},
		onClose: func() error { return nil },
	}
	c = newController(excessive)
	defer closeController(t, c)
	if _, err := c.State(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("excessive byte count: %v", err)
	}
}

func TestSetExcludedPathsChecksBoundsAndCancellationFirst(t *testing.T) {
	d := &scriptedTransport{}
	c := newController(d)
	defer closeController(t, c)
	if err := c.SetExcludedPaths(context.Background(), make([]string, maxRecords+1)); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("too many paths: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.SetExcludedPaths(ctx, []string{"not-an-absolute-path"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled resolution: %v", err)
	}
}

// uncertainMutationTransport applies one mutation but reports the caller's
// deadline. It models the important DeviceIoControl ambiguity: completion can
// win in the driver after a caller has requested cancellation.
type uncertainMutationTransport struct {
	mu          sync.Mutex
	state       State
	addresses   Addresses
	paths       []string
	timeoutCode uint32
}

func (u *uncertainMutationTransport) close() error { return nil }

func (u *uncertainMutationTransport) ioctl(ctx context.Context, code uint32, input, output []byte) (uint32, error) {
	u.mu.Lock()
	switch code {
	case ioctlGetState:
		copy(output, stateReply(u.state))
		u.mu.Unlock()
		return 8, nil
	case ioctlGetAddresses:
		encoded, err := encodeAddresses(u.addresses)
		copy(output, encoded)
		u.mu.Unlock()
		return uint32(len(encoded)), err
	case ioctlGetConfiguration:
		encoded := make([]byte, configHeaderSize)
		le.PutUint64(encoded[8:], configHeaderSize)
		if len(u.paths) != 0 {
			var err error
			encoded, err = encodeConfiguration(u.paths)
			if err != nil {
				u.mu.Unlock()
				return 0, err
			}
		}
		if len(output) == 8 {
			le.PutUint64(output, uint64(len(encoded)))
			u.mu.Unlock()
			return 8, nil
		}
		copy(output, encoded)
		u.mu.Unlock()
		return uint32(len(encoded)), nil
	}

	if code != u.timeoutCode {
		u.mu.Unlock()
		return 0, fmt.Errorf("unexpected IOCTL %#x", code)
	}
	var err error
	switch code {
	case ioctlInitialize:
		u.state = StateInitialized
	case ioctlRegisterProcesses:
		u.state = StateReady
	case ioctlRegisterAddresses:
		u.addresses, err = decodeAddresses(input)
	case ioctlSetConfiguration:
		u.paths, err = decodeConfiguration(input)
	case ioctlClearConfiguration:
		u.paths = nil
	case ioctlReset:
		u.state = StateStarted
		u.addresses = Addresses{}
		u.paths = nil
	}
	u.mu.Unlock()
	if err != nil {
		return 0, err
	}
	<-ctx.Done()
	return 0, ctx.Err()
}

func deadlineContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

func requireDeadline(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("mutation did not report its uncertain deadline: %v", err)
	}
}

func TestTimedOutMutationsCanBeReconciled(t *testing.T) {
	guidA, _ := ParseGUID("00112233-4455-6677-8899-aabbccddeeff")
	guidB, _ := ParseGUID("ffeeddcc-bbaa-9988-7766-554433221100")
	wantAddresses := Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.64.0.2"),
		InternetIPv4: netip.MustParseAddr("192.0.2.2"),
		TunnelIPv6:   netip.MustParseAddr("fd00::2"),
		InternetIPv6: netip.MustParseAddr("2001:db8::2"),
	}
	wantPaths := []string{`\Device\HarddiskVolume1\Program Files\test.exe`}

	t.Run("initialize/state", func(t *testing.T) {
		d := &uncertainMutationTransport{state: StateStarted, timeoutCode: ioctlInitialize}
		c := newController(d)
		defer closeController(t, c)
		requireDeadline(t, c.Initialize(deadlineContext(t), Sublayers{guidA, guidB}))
		if got, err := c.State(context.Background()); err != nil || got != StateInitialized {
			t.Fatalf("reconcile initialize: %v, %v", got, err)
		}
	})

	t.Run("register processes/state", func(t *testing.T) {
		d := &uncertainMutationTransport{state: StateInitialized, timeoutCode: ioctlRegisterProcesses}
		c := newController(d)
		defer closeController(t, c)
		requireDeadline(t, c.RegisterProcesses(deadlineContext(t), []Process{{PID: 1}}))
		if got, err := c.State(context.Background()); err != nil || got != StateReady {
			t.Fatalf("reconcile process registration: %v, %v", got, err)
		}
	})

	t.Run("set addresses/query", func(t *testing.T) {
		d := &uncertainMutationTransport{state: StateReady, timeoutCode: ioctlRegisterAddresses}
		c := newController(d)
		defer closeController(t, c)
		requireDeadline(t, c.SetAddresses(deadlineContext(t), wantAddresses))
		if got, err := c.Addresses(context.Background()); err != nil || !reflect.DeepEqual(got, wantAddresses) {
			t.Fatalf("reconcile addresses: %#v, %v", got, err)
		}
	})

	t.Run("set exclusions/query", func(t *testing.T) {
		d := &uncertainMutationTransport{state: StateReady, timeoutCode: ioctlSetConfiguration}
		c := newController(d)
		defer closeController(t, c)
		requireDeadline(t, c.SetExcludedDevicePaths(deadlineContext(t), wantPaths))
		if got, err := c.ExcludedDevicePaths(context.Background()); err != nil || !reflect.DeepEqual(got, wantPaths) {
			t.Fatalf("reconcile exclusions: %#v, %v", got, err)
		}
	})

	t.Run("clear exclusions/query", func(t *testing.T) {
		d := &uncertainMutationTransport{state: StateEngaged, paths: wantPaths, timeoutCode: ioctlClearConfiguration}
		c := newController(d)
		defer closeController(t, c)
		requireDeadline(t, c.ClearConfiguration(deadlineContext(t)))
		if got, err := c.ExcludedDevicePaths(context.Background()); err != nil || len(got) != 0 {
			t.Fatalf("reconcile cleared exclusions: %#v, %v", got, err)
		}
	})

	t.Run("reset/state", func(t *testing.T) {
		d := &uncertainMutationTransport{state: StateEngaged, addresses: wantAddresses, paths: wantPaths, timeoutCode: ioctlReset}
		c := newController(d)
		defer closeController(t, c)
		requireDeadline(t, c.Reset(deadlineContext(t)))
		if got, err := c.State(context.Background()); err != nil || got != StateStarted {
			t.Fatalf("reconcile reset: %v, %v", got, err)
		}
	})
}
