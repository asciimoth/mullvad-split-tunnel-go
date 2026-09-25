package splittunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
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

func TestMalformedSizeProbeDoesNotAllocateOrFetch(t *testing.T) {
	d := &scriptedTransport{steps: []step{
		{code: ioctlGetState, outputSize: 8, reply: stateReply(StateReady)},
		{code: ioctlGetConfiguration, outputSize: 8, reply: bytes.Repeat([]byte{255}, 8)},
	}}
	c := newController(d)
	defer closeController(t, c)
	if _, err := c.ExcludedDevicePaths(context.Background()); !errors.Is(err, ErrProtocol) {
		t.Fatalf("accepted unbounded driver allocation: %v", err)
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

func TestShutdownClosesEvenIfResetFails(t *testing.T) {
	resetErr := errors.New("driver reset failed")
	d := &scriptedTransport{steps: []step{{code: ioctlReset, err: resetErr}}}
	c := newController(d)
	if err := c.Shutdown(context.Background()); !errors.Is(err, resetErr) || d.closed != 1 {
		t.Fatalf("shutdown hid reset failure or leaked handle: %v, %d", err, d.closed)
	}
}
