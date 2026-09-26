//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
	"unsafe"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
	"golang.org/x/sys/windows"
)

var (
	kernel32              = windows.NewLazySystemDLL("kernel32.dll")
	getCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	getProcessHandleCount = kernel32.NewProc("GetProcessHandleCount")
)

type resourceCounts struct {
	handles    uint32
	goroutines int
}

func resourcesGrowPersistently(measurements []resourceCounts) bool {
	if len(measurements) < 2 {
		return false
	}
	first := measurements[0]
	last := measurements[len(measurements)-1]
	handlesGrow := last.handles > first.handles+2
	goroutinesGrow := last.goroutines > first.goroutines+2
	for i := 1; i < len(measurements); i++ {
		handlesGrow = handlesGrow && measurements[i].handles > measurements[i-1].handles
		goroutinesGrow = goroutinesGrow && measurements[i].goroutines > measurements[i-1].goroutines
	}
	return handlesGrow || goroutinesGrow
}

func processResourceCounts(t *testing.T) resourceCounts {
	t.Helper()
	handle, _, _ := getCurrentProcess.Call()
	var handles uint32
	ok, _, err := getProcessHandleCount.Call(handle, uintptr(unsafe.Pointer(&handles)))
	if ok == 0 {
		t.Fatalf("GetProcessHandleCount: %v", err)
	}
	return resourceCounts{handles: handles, goroutines: runtime.NumGoroutine()}
}

func driverGUID(t *testing.T, g string) splittunnel.GUID {
	t.Helper()
	result, err := splittunnel.ParseGUID(g)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDriverLifecycle(t *testing.T) {
	for iteration := 0; iteration < 4; iteration++ {
		t.Run("warm-up-"+string(rune('A'+iteration)), func(t *testing.T) { runLifecycle(t) })
	}
	time.Sleep(250 * time.Millisecond)
	runtime.GC()
	measurements := make([]resourceCounts, 0, 4)
	for iteration := 0; iteration < 4; iteration++ {
		t.Run(string(rune('A'+iteration)), func(t *testing.T) { runLifecycle(t) })
		time.Sleep(250 * time.Millisecond)
		runtime.GC()
		counts := processResourceCounts(t)
		measurements = append(measurements, counts)
		t.Logf("complete session %d: handles=%d goroutines=%d", iteration+1, counts.handles, counts.goroutines)
	}
	if resourcesGrowPersistently(measurements) {
		t.Fatalf("complete sessions show persistent resource growth: measurements=%+v", measurements)
	}
}

func TestResourcesGrowPersistently(t *testing.T) {
	for _, test := range []struct {
		name         string
		measurements []resourceCounts
		want         bool
	}{
		{name: "stable", measurements: []resourceCounts{{100, 2}, {100, 2}, {100, 2}, {100, 2}}},
		{name: "tolerated drift", measurements: []resourceCounts{{100, 2}, {101, 3}, {102, 4}}},
		{name: "handle initialization plateaus", measurements: []resourceCounts{{100, 2}, {106, 2}, {108, 2}, {108, 2}}},
		{name: "handles grow", measurements: []resourceCounts{{100, 2}, {101, 2}, {102, 2}, {103, 2}}, want: true},
		{name: "goroutines grow", measurements: []resourceCounts{{100, 2}, {100, 3}, {100, 4}, {100, 5}}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := resourcesGrowPersistently(test.measurements); got != test.want {
				t.Fatalf("resourcesGrowPersistently(%+v) = %v, want %v", test.measurements, got, test.want)
			}
		})
	}
}

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SPLIT_TUNNEL_HELPER") != "1" {
		return
	}
	time.Sleep(45 * time.Second)
}

func TestInjectedSetupFailureRecovery(t *testing.T) {
	for _, phase := range []string{"wfp", "open", "initialize", "register", "configure"} {
		t.Run(phase, func(t *testing.T) {
			injectSetupFailure(t, phase)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			controller, err := splittunnel.Open()
			if err != nil {
				t.Fatalf("open after injected %s failure: %v", phase, err)
			}
			defer controller.Close()
			state, err := controller.State(ctx)
			if err != nil || state != splittunnel.StateStarted {
				t.Fatalf("state after injected %s failure: %v, %v", phase, state, err)
			}
		})
	}
}

func TestPathResolutionFailurePreservesConfiguration(t *testing.T) {
	s := newLiveSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	executable := mustExecutable(t)
	if err := s.c.SetExcludedPaths(ctx, []string{executable}); err != nil {
		t.Fatal(err)
	}
	want, err := s.c.ExcludedDevicePaths(ctx)
	if err != nil || len(want) != 1 {
		t.Fatalf("initial exclusions = %v, %v", want, err)
	}
	missing := t.TempDir() + `\missing.exe`
	if err := s.c.SetExcludedPaths(ctx, []string{executable, missing}); err == nil {
		t.Fatal("missing executable path was accepted")
	}
	got, err := s.c.ExcludedDevicePaths(ctx)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("exclusions after resolution failure = %v, %v; want %v", got, err, want)
	}
}

func TestInvalidStateTransitionsPreserveDriverState(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := newInitializedSession(t)

	wantStateError := func(name string, err error) {
		t.Helper()
		if !errors.Is(err, splittunnel.ErrState) {
			t.Fatalf("%s error = %v; want ErrState", name, err)
		}
	}
	wantState := func(want splittunnel.State) {
		t.Helper()
		got, err := s.c.State(ctx)
		if err != nil || got != want {
			t.Fatalf("state = %v, %v; want %v", got, err, want)
		}
	}

	// Initialize has completed, but process registration has not. Operations
	// that need Ready or Engaged must fail without changing state.
	wantState(splittunnel.StateInitialized)
	wantStateError("addresses before registration", s.c.SetAddresses(ctx, splittunnel.Addresses{}))
	wantStateError("configuration before registration", s.c.ClearConfiguration(ctx))
	if _, err := s.c.ExcludedDevicePaths(ctx); !errors.Is(err, splittunnel.ErrState) {
		t.Fatalf("exclusions before registration error = %v; want ErrState", err)
	}
	wantState(splittunnel.StateInitialized)

	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.c.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		t.Fatal(err)
	}
	wantState(splittunnel.StateReady)

	// Each setup operation is one-shot. Rejected repetitions must leave the
	// valid session usable so cleanup can reset it normally.
	wantStateError("second initialize", s.c.Initialize(ctx, splittunnel.Sublayers{
		Baseline: driverGUID(t, s.fixture.keys[0].String()),
		DNS:      driverGUID(t, s.fixture.keys[1].String()),
	}))
	wantStateError("second registration", s.c.RegisterProcesses(ctx, snapshot.Processes))
	if _, err := s.c.QueryProcess(ctx, 0); !errors.Is(err, splittunnel.ErrInvalidArgument) {
		t.Fatalf("zero PID query error = %v; want ErrInvalidArgument", err)
	}
	wantState(splittunnel.StateReady)
}

func TestShutdownResetsAndClosesController(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s := newLiveSession(t)

	if err := s.c.SetExcludedPaths(ctx, []string{mustExecutable(t)}); err != nil {
		t.Fatal(err)
	}
	if err := s.c.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	s.reset = true
	if _, err := s.c.State(ctx); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("state after shutdown error = %v; want os.ErrClosed", err)
	}

	reopened, err := splittunnel.Open()
	if err != nil {
		t.Fatalf("open after shutdown: %v", err)
	}
	defer reopened.Close()
	state, err := reopened.State(ctx)
	if err != nil || state != splittunnel.StateStarted {
		t.Fatalf("state after shutdown = %v, %v; want started", state, err)
	}
}

func injectSetupFailure(t *testing.T, phase string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture, err := newWFPFixture()
	if err != nil {
		t.Fatal(err)
	}
	deleteSublayers := true
	defer func() {
		if err := fixture.close(deleteSublayers); err != nil {
			t.Error(err)
		}
	}()
	if phase == "wfp" {
		return
	}
	controller, err := splittunnel.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Close()
	if phase == "open" {
		return
	}
	if err := controller.Initialize(ctx, splittunnel.Sublayers{
		Baseline: driverGUID(t, fixture.keys[0].String()),
		DNS:      driverGUID(t, fixture.keys[1].String()),
	}); err != nil {
		t.Fatal(err)
	}
	deleteSublayers = false
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cleanupCancel()
		if err := controller.Reset(cleanupCtx); err != nil {
			t.Errorf("reset after injected %s failure: %v", phase, err)
			return
		}
		deleteSublayers = true
	}()
	if phase == "initialize" {
		return
	}
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		t.Fatal(err)
	}
	if phase == "register" {
		return
	}
	if err := controller.SetExcludedPaths(ctx, []string{mustExecutable(t)}); err != nil {
		t.Fatal(err)
	}
}

func mustExecutable(t *testing.T) string {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func readProcessEvent(t *testing.T, c *splittunnel.Controller, pid uint32, id splittunnel.EventID) {
	t.Helper()
	readProcessEvents(t, c, map[uint32]splittunnel.EventID{pid: id})
}

func readProcessEvents(t *testing.T, c *splittunnel.Controller, wanted map[uint32]splittunnel.EventID) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for len(wanted) != 0 {
		event, err := c.ReadEvent(ctx)
		if err != nil {
			t.Fatalf("read events for PIDs %v: %v", wanted, err)
		}
		if id, ok := wanted[event.PID]; ok {
			if event.ID != id || event.Reason == 0 {
				t.Fatalf("event for PID %d: %#v; want ID %v with a reason", event.PID, event, id)
			}
			delete(wanted, event.PID)
		}
	}
}

func readExactProcessEvent(
	t *testing.T,
	c *splittunnel.Controller,
	pid uint32,
	id splittunnel.EventID,
	reason splittunnel.Reason,
) splittunnel.Event {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		event, err := c.ReadEvent(ctx)
		if err != nil {
			t.Fatalf("read event for PID %d: %v", pid, err)
		}
		if event.PID != pid {
			continue
		}
		if event.ID != id || event.Reason != reason {
			t.Fatalf("event for PID %d: %#v; want ID %v and reason %v", pid, event, id, reason)
		}
		return event
	}
}

func waitProcessSplit(t *testing.T, c *splittunnel.Controller, pid uint32, want bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		status, err := c.QueryProcess(ctx, pid)
		if err == nil && status.Split == want {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PID %d split=%v was not observed: %v", pid, want, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type liveSession struct {
	t       *testing.T
	c       *splittunnel.Controller
	fixture *wfpFixture
	reset   bool
}

func newInitializedSession(t *testing.T) *liveSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f, err := newWFPFixture()
	if err != nil {
		t.Fatal(err)
	}
	c, err := splittunnel.Open()
	if err != nil {
		_ = f.close(false)
		t.Fatal(err)
	}
	s := &liveSession{t: t, c: c, fixture: f}
	t.Cleanup(s.cleanup)
	if err := c.Initialize(ctx, splittunnel.Sublayers{
		Baseline: driverGUID(t, f.keys[0].String()),
		DNS:      driverGUID(t, f.keys[1].String()),
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func newLiveSession(t *testing.T) *liveSession {
	t.Helper()
	s := newInitializedSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.c.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s *liveSession) cleanup() {
	if s.c == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !s.reset {
		if err := s.c.Reset(ctx); err != nil {
			s.t.Errorf("reset live session: %v", err)
		} else {
			s.reset = true
		}
	}
	if err := s.c.Close(); err != nil {
		s.t.Errorf("close live session: %v", err)
	}
	if err := s.fixture.close(s.reset); err != nil {
		s.t.Errorf("close WFP fixture: %v", err)
	}
	s.c = nil
}

func TestSnapshotRegistrationReplaysProcessChanges(t *testing.T) {
	s := newInitializedSession(t)
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		t.Fatal(err)
	}

	arriving := startHelper(t, mustExecutable(t))
	departing := exec.Command(mustExecutable(t), "-test.run=^TestHelperProcess$")
	departing.Env = append(os.Environ(), "SPLIT_TUNNEL_HELPER=1")
	if err := departing.Start(); err != nil {
		t.Fatal(err)
	}
	departingPID := uint32(departing.Process.Pid)
	if err := departing.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := departing.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.c.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		t.Fatal(err)
	}
	arrivingPID := uint32(arriving.Process.Pid)
	if arrivingPID == departingPID {
		t.Fatalf("test helpers unexpectedly reused PID %d", arrivingPID)
	}
	status := processStatus(t, s.c, arrivingPID, false)
	if status.PID != arrivingPID {
		t.Fatalf("arrival replay returned PID %d, want %d", status.PID, arrivingPID)
	}
	if _, err := s.c.QueryProcess(ctx, departingPID); err == nil {
		t.Fatalf("departed PID %d remained in the driver registry", departingPID)
	}
}

func TestArrivalAndDepartureEventReasons(t *testing.T) {
	s := newLiveSession(t)
	if err := s.c.SetAddresses(context.Background(), splittunnel.Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.64.0.2"),
		InternetIPv4: netip.MustParseAddr("10.0.2.15"),
	}); err != nil {
		t.Fatal(err)
	}
	executable := mustExecutable(t)
	copyPath := t.TempDir() + `\event-helper.exe`
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copyPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.c.SetExcludedPaths(context.Background(), []string{copyPath}); err != nil {
		t.Fatal(err)
	}
	helper := startHelper(t, copyPath)
	pid := uint32(helper.Process.Pid)
	readExactProcessEvent(t, s.c, pid, splittunnel.EventStartSplitting,
		splittunnel.ReasonConfig|splittunnel.ReasonArriving)
	if err := helper.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := helper.Wait(); err == nil {
		t.Fatal("killed helper exited successfully")
	}
	readExactProcessEvent(t, s.c, pid, splittunnel.EventStopSplitting,
		splittunnel.ReasonDeparting)
}

func TestResetCompletesPendingEventRead(t *testing.T) {
	s := newLiveSession(t)
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := s.c.ReadEvent(context.Background())
		done <- err
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := s.c.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	s.reset = true
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("pending event read succeeded during reset")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reset did not complete the pending event read")
	}
	if state, err := s.c.State(ctx); err != nil || state != splittunnel.StateStarted {
		t.Fatalf("state after reset with pending event read: %v, %v", state, err)
	}
}

func cancelBlockedEvent(t *testing.T, c *splittunnel.Controller, checkControl bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := c.ReadEvent(ctx)
		done <- err
	}()
	<-started
	// Give DeviceIoControl time to enter the pending state. The request cannot
	// complete because these stress sessions never install an exclusion.
	time.Sleep(2 * time.Millisecond)
	if checkControl {
		controlCtx, controlCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer controlCancel()
		if state, err := c.State(controlCtx); err != nil || state != splittunnel.StateReady {
			t.Fatalf("state query during event read: %v, %v", state, err)
		}
		if _, err := c.Addresses(controlCtx); err != nil {
			t.Fatalf("address query during event read: %v", err)
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("event cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("event cancellation did not complete")
	}
}

func TestEventCancellationStress(t *testing.T) {
	s := newLiveSession(t)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.c.ReadEvent(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation before event read: %v", err)
	}

	const warmup = 10
	for range warmup {
		cancelBlockedEvent(t, s.c, true)
	}
	runtime.GC()
	baseline := processResourceCounts(t)
	t.Logf("cancellation warm-up: handles=%d goroutines=%d", baseline.handles, baseline.goroutines)

	const (
		batches  = 4
		perBatch = 25
	)
	measurements := make([]resourceCounts, 0, batches)
	for batch := range batches {
		for range perBatch {
			cancelBlockedEvent(t, s.c, true)
		}
		runtime.GC()
		counts := processResourceCounts(t)
		measurements = append(measurements, counts)
		t.Logf("cancellation batch %d/%d: cycles=%d handles=%d goroutines=%d",
			batch+1, batches, (batch+1)*perBatch, counts.handles, counts.goroutines)
	}
	if resourcesGrowPersistently(append([]resourceCounts{baseline}, measurements...)) {
		t.Fatalf("cancellation stress shows persistent resource growth: baseline=%+v batches=%+v", baseline, measurements)
	}
}

func TestEventCancellationWhileControllerCloses(t *testing.T) {
	s := newLiveSession(t)
	done := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		_, err := s.c.ReadEvent(context.Background())
		done <- err
	}()
	<-started
	time.Sleep(10 * time.Millisecond)
	if err := s.c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("close cancellation: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller close did not drain the event read")
	}

	// Close does not reset policy. Reopen the exclusive device and reconcile it
	// so test cleanup can reset before deleting the WFP sublayers.
	reopened, err := splittunnel.Open()
	if err != nil {
		t.Fatalf("reopen after close cancellation: %v", err)
	}
	s.c = reopened
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if state, err := reopened.State(ctx); err != nil || state != splittunnel.StateReady {
		t.Fatalf("state after close cancellation: %v, %v", state, err)
	}
}

func startHelper(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(path, "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "SPLIT_TUNNEL_HELPER=1")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd
}

func processStatus(t *testing.T, c *splittunnel.Controller, pid uint32, wantSplit bool) splittunnel.ProcessStatus {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		status, err := c.QueryProcess(ctx, pid)
		if err == nil && status.Split == wantSplit && status.ImagePath != "" {
			return status
		}
		select {
		case <-ctx.Done():
			t.Fatalf("PID %d split=%v with an image path was not observed: %v", pid, wantSplit, err)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func TestHardLinkAndAlternateLaunchPaths(t *testing.T) {
	s := newLiveSession(t)
	if err := s.c.SetAddresses(context.Background(), splittunnel.Addresses{
		TunnelIPv4:   netip.MustParseAddr("10.64.0.2"),
		InternetIPv4: netip.MustParseAddr("10.0.2.15"),
	}); err != nil {
		t.Fatal(err)
	}
	executable := mustExecutable(t)
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	original := directory + `\helper.exe`
	hardLink := directory + `\helper-hardlink.exe`
	if err := os.WriteFile(original, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(original, hardLink); err != nil {
		t.Fatal(err)
	}
	originalDevice, err := splittunnel.ResolveDevicePath(original)
	if err != nil {
		t.Fatal(err)
	}
	hardLinkDevice, err := splittunnel.ResolveDevicePath(hardLink)
	if err != nil {
		t.Fatal(err)
	}
	if strings.EqualFold(originalDevice, hardLinkDevice) {
		t.Fatalf("hard-link names resolved to one path: %q", originalDevice)
	}
	if err := s.c.SetExcludedPaths(context.Background(), []string{original}); err != nil {
		t.Fatal(err)
	}

	originalProcess := startHelper(t, original)
	extendedProcess := startHelper(t, `\\?\`+original)
	hardLinkProcess := startHelper(t, hardLink)
	originalStatus := processStatus(t, s.c, uint32(originalProcess.Process.Pid), true)
	extendedStatus := processStatus(t, s.c, uint32(extendedProcess.Process.Pid), true)
	hardLinkStatus := processStatus(t, s.c, uint32(hardLinkProcess.Process.Pid), false)
	t.Logf("ordinary launch: configured=%q driver=%q", originalDevice, originalStatus.ImagePath)
	t.Logf("extended-path launch: configured=%q driver=%q", originalDevice, extendedStatus.ImagePath)
	t.Logf("hard-link launch: link=%q driver=%q", hardLinkDevice, hardLinkStatus.ImagePath)
	if !strings.EqualFold(originalStatus.ImagePath, originalDevice) ||
		!strings.EqualFold(extendedStatus.ImagePath, originalDevice) ||
		!strings.EqualFold(hardLinkStatus.ImagePath, hardLinkDevice) {
		t.Fatalf("driver path identity differs from resolved launch paths: ordinary=%q extended=%q hard-link=%q",
			originalStatus.ImagePath, extendedStatus.ImagePath, hardLinkStatus.ImagePath)
	}
	readProcessEvents(t, s.c, map[uint32]splittunnel.EventID{
		uint32(originalProcess.Process.Pid): splittunnel.EventStartSplitting,
		uint32(extendedProcess.Process.Pid): splittunnel.EventStartSplitting,
	})

	if err := s.c.SetExcludedPaths(context.Background(), []string{original, hardLink}); err != nil {
		t.Fatal(err)
	}
	processStatus(t, s.c, uint32(hardLinkProcess.Process.Pid), true)
	readProcessEvent(t, s.c, uint32(hardLinkProcess.Process.Pid), splittunnel.EventStartSplitting)
}

func runLifecycle(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	f, err := newWFPFixture()
	if err != nil {
		t.Fatal(err)
	}
	reset := false
	defer func() {
		// Keep persistent sublayers if reset failed. The retained overlay then
		// preserves the exact failure state for diagnosis.
		if err := f.close(reset); err != nil {
			t.Error(err)
		}
	}()
	c, err := splittunnel.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	state, err := c.State(ctx)
	if err != nil || state != splittunnel.StateStarted {
		t.Fatalf("initial state: %v, %v", state, err)
	}
	if second, err := splittunnel.Open(); err == nil {
		second.Close()
		t.Fatal("second controller handle opened")
	}
	if err := c.Initialize(ctx, splittunnel.Sublayers{Baseline: driverGUID(t, f.keys[0].String()), DNS: driverGUID(t, f.keys[1].String())}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		t.Fatal(err)
	}
	if state, err = c.State(ctx); err != nil || state != splittunnel.StateReady {
		t.Fatalf("ready state: %v, %v", state, err)
	}

	addresses := []splittunnel.Addresses{
		{},
		{TunnelIPv4: netip.MustParseAddr("10.64.0.2"), InternetIPv4: netip.MustParseAddr("10.0.2.15")},
		{TunnelIPv6: netip.MustParseAddr("fd00::2"), InternetIPv6: netip.MustParseAddr("fd00::3")},
		{TunnelIPv4: netip.MustParseAddr("10.64.0.2"), InternetIPv4: netip.MustParseAddr("10.0.2.15"), TunnelIPv6: netip.MustParseAddr("fd00::2"), InternetIPv6: netip.MustParseAddr("fd00::3")},
	}
	for _, want := range addresses {
		if err := c.SetAddresses(ctx, want); err != nil {
			t.Fatal(err)
		}
		got, err := c.Addresses(ctx)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("addresses: %#v, %v; want %#v", got, err, want)
		}
	}
	// No splitting event can be queued before configuration is set. Cancel in
	// this state so an earlier event cannot race cancellation and make the test
	// nondeterministic. A control query must continue while the event lane waits.
	eventCtx, eventCancel := context.WithCancel(ctx)
	eventDone := make(chan error, 1)
	eventStarted := make(chan struct{})
	go func() {
		close(eventStarted)
		_, err := c.ReadEvent(eventCtx)
		eventDone <- err
	}()
	<-eventStarted
	if _, err := c.Addresses(ctx); err != nil {
		t.Fatalf("control operation during event wait: %v", err)
	}
	eventCancel()
	select {
	case err := <-eventDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("event cancellation: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("event cancellation did not complete")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	unicodeCopy := executable + "-é.exe"
	data, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unicodeCopy, data, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(unicodeCopy)
	if err := c.SetExcludedPaths(ctx, []string{unicodeCopy, executable}); err != nil {
		t.Fatal(err)
	}
	paths, err := c.ExcludedDevicePaths(ctx)
	if err != nil || len(paths) != 2 {
		t.Fatalf("exclusions: %v, %v", paths, err)
	}
	currentPID := uint32(os.Getpid())
	waitProcessSplit(t, c, currentPID, true)
	readProcessEvent(t, c, currentPID, splittunnel.EventStartSplitting)

	helperCopy := executable + "-child.exe"
	if err := os.WriteFile(helperCopy, data, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(helperCopy)
	helper := exec.Command(helperCopy, "-test.run=^TestHelperProcess$")
	helper.Env = append(os.Environ(), "SPLIT_TUNNEL_HELPER=1")
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	}()
	helperPID := uint32(helper.Process.Pid)
	waitProcessSplit(t, c, helperPID, true)
	readProcessEvent(t, c, helperPID, splittunnel.EventStartSplitting)

	// Replacement keeps the current process split, removes the non-ASCII exact
	// path, and does not disturb the inherited child.
	if err := c.SetExcludedPaths(ctx, []string{executable}); err != nil {
		t.Fatal(err)
	}
	if paths, err = c.ExcludedDevicePaths(ctx); err != nil || len(paths) != 1 {
		t.Fatalf("replaced exclusions: %v, %v", paths, err)
	}
	if _, err := c.QueryProcess(ctx, currentPID); err != nil {
		t.Fatal(err)
	}
	if err := c.ClearConfiguration(ctx); err != nil {
		t.Fatal(err)
	}
	waitProcessSplit(t, c, currentPID, false)
	waitProcessSplit(t, c, helperPID, false)
	readProcessEvents(t, c, map[uint32]splittunnel.EventID{
		currentPID: splittunnel.EventStopSplitting,
		helperPID:  splittunnel.EventStopSplitting,
	})
	if paths, err = c.ExcludedDevicePaths(ctx); err != nil || len(paths) != 0 {
		t.Fatalf("cleared exclusions: %v, %v", paths, err)
	}

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cleanupCancel()
	if err := c.Reset(cleanupCtx); err != nil {
		t.Fatal(err)
	}
	reset = true
	if state, err = c.State(cleanupCtx); err != nil || state != splittunnel.StateStarted {
		t.Fatalf("reset state: %v, %v", state, err)
	}
}
