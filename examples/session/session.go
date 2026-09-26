// Package session shows a complete controller ownership sequence. It assumes
// the caller already owns committed, non-dynamic WFP sublayers and a configured
// TUN. See splittunnel.Sublayers for the lifetime requirements.
package session

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
)

// Run temporarily owns driver policy while work executes. The caller must keep
// its WFP sublayers and adapter resources alive through cleanup. A returned
// cleanup error means recovery must inspect driver state before removing them.
func Run(ctx context.Context, layers splittunnel.Sublayers, addresses splittunnel.Addresses,
	executables []string, work func(context.Context, *splittunnel.Controller) error,
) (err error) {
	if work == nil {
		return fmt.Errorf("work callback is required")
	}
	c, err := splittunnel.Open()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, c.Close()) }()
	state, err := c.State(ctx)
	if err != nil {
		return err
	}
	if state != splittunnel.StateStarted {
		return fmt.Errorf("existing driver state %s requires explicit recovery", state)
	}
	// Once initialization is attempted it may have changed driver state even if
	// its completion is cancelled. Attempt cleanup with a fresh context.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err = errors.Join(err, c.Shutdown(cleanup))
	}()
	if err = c.Initialize(ctx, layers); err != nil {
		return err
	}
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		return err
	}
	// A real application should expose these diagnostics to its logger/UI.
	// Some protected/system processes normally cannot be fully queried.
	for _, warning := range snapshot.Warnings {
		log.Printf("process snapshot PID %d, %s: %v", warning.PID, warning.Operation, warning.Err)
	}
	if err = c.RegisterProcesses(ctx, snapshot.Processes); err != nil {
		return err
	}
	if err = c.SetAddresses(ctx, addresses); err != nil {
		return err
	}
	if err = c.SetExcludedPaths(ctx, executables); err != nil {
		return err
	}
	// work should run a ReadEvent loop with a child context, monitor underlay
	// changes, and stop/join those workers before returning.
	return work(ctx, c)
}
