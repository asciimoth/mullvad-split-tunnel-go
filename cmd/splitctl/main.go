// splitctl is a diagnostic client for an already installed/running driver.
// It does not initialize, reset, install, or configure the driver.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() (err error) {
	timeout := flag.Duration("timeout", 5*time.Second, "deadline for the diagnostic operation")
	pid := flag.Uint("pid", 0, "query this process after printing state")
	event := flag.Bool("event", false, "wait for and consume one driver event")
	flag.Parse()
	if uint64(*pid) > uint64(^uint32(0)) {
		return fmt.Errorf("PID exceeds uint32")
	}
	parent, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(parent, *timeout)
	defer cancel()
	c, err := splittunnel.Open()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, c.Close()) }()
	state, err := c.State(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("State: %s; controller ABI: %s (binary version not detected)\n", state, splittunnel.TargetDriverVersion)
	if *pid != 0 {
		p, err := c.QueryProcess(ctx, uint32(*pid))
		if err != nil {
			return err
		}
		fmt.Printf("PID=%d parent=%d split=%t image=%q\n", p.PID, p.ParentPID, p.Split, p.ImagePath)
	}
	if *event {
		e, err := c.ReadEvent(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("Event: %+v\n", e)
	}
	return nil
}
