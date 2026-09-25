//go:build windows && (amd64 || arm64)

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"time"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
)

func runPlatform(configuration config) (result error) {
	parent, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stopSignal()
	controller, err := splittunnel.Open()
	if err != nil {
		return fmt.Errorf("open split-tunnel driver; another owner may be active: %w", err)
	}
	defer func() { result = errors.Join(result, controller.Close()) }()
	setupContext, cancelSetup := context.WithTimeout(parent, 30*time.Second)
	defer cancelSetup()
	state, err := controller.State(setupContext)
	if err != nil {
		return err
	}
	if state != splittunnel.StateStarted {
		return fmt.Errorf("driver state is %s; an existing configuration requires explicit recovery", state)
	}

	wfp, err := createWFPResources()
	if err != nil {
		return err
	}
	deleteSublayers := true
	defer func() {
		if err := wfp.close(deleteSublayers); err != nil {
			result = errors.Join(result, err)
		}
	}()
	tun, err := createTUN(configuration)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, tun.close()) }()

	layers, err := wfp.sublayers()
	if err != nil {
		return err
	}
	initializationAttempted := true
	if err = controller.Initialize(setupContext, layers); err != nil {
		return cleanupController(controller, configuration.cleanupWait, initializationAttempted, wfp, &deleteSublayers, err)
	}
	snapshot, err := splittunnel.SnapshotProcesses()
	if err != nil {
		return cleanupController(controller, configuration.cleanupWait, initializationAttempted, wfp, &deleteSublayers, err)
	}
	for _, warning := range snapshot.Warnings {
		fmt.Fprintf(os.Stderr, "snapshot pid=%d operation=%s warning=%v\n", warning.PID, warning.Operation, warning.Err)
	}
	if err = controller.RegisterProcesses(setupContext, snapshot.Processes); err == nil {
		err = controller.SetAddresses(setupContext, splittunnel.Addresses{
			TunnelIPv4: configuration.tunnelIPv4.Addr(), InternetIPv4: configuration.internetIPv4,
			TunnelIPv6: configuration.tunnelIPv6.Addr(), InternetIPv6: configuration.internetIPv6,
		})
	}
	if err == nil {
		err = controller.SetExcludedPaths(setupContext, configuration.exclusions)
	}
	if err != nil {
		return cleanupController(controller, configuration.cleanupWait, initializationAttempted, wfp, &deleteSublayers, err)
	}

	workerContext, cancelWorkers := context.WithCancel(parent)
	var workers sync.WaitGroup
	workerErrors := make(chan error, 2)
	workers.Add(2)
	go func() {
		defer workers.Done()
		workerErrors <- runEventConsumer(workerContext, controller)
	}()
	go func() {
		defer workers.Done()
		workerErrors <- runPacketTransport(workerContext, tun.session, configuration.peer)
	}()
	fmt.Printf("adapter=%q index=%d baseline=%s dns=%s\n", configuration.adapter, tun.index, layers.Baseline, layers.DNS)
	fmt.Printf("tunnel ipv4=%s route=%s ipv6=%s route=%s peer=%s\n", configuration.tunnelIPv4, configuration.routeIPv4, configuration.tunnelIPv6, configuration.routeIPv6, configuration.peer)
	fmt.Printf("bypass ipv4=%s ipv6=%s exclusions=%q\n", configuration.internetIPv4, configuration.internetIPv6, configuration.exclusions)
	fmt.Println("status=ready")

	stopFile := watchStopFile(workerContext, configuration.stopFile)
	select {
	case <-parent.Done():
	case <-stopFile:
	case err = <-workerErrors:
		if err != nil && !errors.Is(err, context.Canceled) {
			result = errors.Join(result, fmt.Errorf("worker: %w", err))
		}
	}
	cancelWorkers()
	workers.Wait()
	cleanupErr := cleanupController(controller, configuration.cleanupWait, initializationAttempted, wfp, &deleteSublayers, nil)
	return errors.Join(result, cleanupErr)
}

func runEventConsumer(ctx context.Context, controller *splittunnel.Controller) error {
	for {
		event, err := controller.ReadEvent(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		fmt.Printf("event id=%d pid=%d reason=%d image=%q status=%#x message=%q\n", event.ID, event.PID, event.Reason, event.ImagePath, event.NTStatus, event.Message)
	}
}

func watchStopFile(ctx context.Context, path string) <-chan struct{} {
	stopped := make(chan struct{})
	if path == "" {
		return stopped
	}
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := os.Stat(path); err == nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return stopped
}

func cleanupController(controller *splittunnel.Controller, timeout time.Duration, attempted bool, wfp *wfpResources, deleteSublayers *bool, cause error) error {
	if !attempted {
		return cause
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := controller.Reset(ctx); err != nil {
		*deleteSublayers = false
		fmt.Fprintf(os.Stderr, "reset failed; preserving WFP sublayers baseline=%s dns=%s for recovery\n", wfp.keys[0], wfp.keys[1])
		return errors.Join(cause, fmt.Errorf("reset split-tunnel driver: %w", err))
	}
	return cause
}
