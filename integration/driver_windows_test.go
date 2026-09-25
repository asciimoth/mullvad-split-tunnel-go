//go:build windows && winintegration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
)

func driverGUID(t *testing.T, g string) splittunnel.GUID {
	t.Helper()
	result, err := splittunnel.ParseGUID(g)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDriverLifecycle(t *testing.T) {
	for iteration := 0; iteration < 2; iteration++ {
		t.Run(string(rune('A'+iteration)), func(t *testing.T) { runLifecycle(t) })
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
