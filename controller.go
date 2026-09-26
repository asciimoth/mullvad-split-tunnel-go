package splittunnel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
)

// transport must not return until the OS has stopped using input/output memory.
type transport interface {
	ioctl(context.Context, uint32, []byte, []byte) (uint32, error)
	close() error
}

// Controller owns one exclusive device handle. It must not be copied.
type Controller struct {
	device   transport
	life     context.Context
	cancel   context.CancelFunc
	commands chan struct{}
	events   chan struct{}

	mu        sync.Mutex
	closed    bool
	active    sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func newController(device transport) *Controller {
	life, cancel := context.WithCancel(context.Background())
	return &Controller{
		device: device, life: life, cancel: cancel,
		commands: make(chan struct{}, 1), events: make(chan struct{}, 1),
	}
}

// Open opens the global driver handle without changing its state. It does not
// install/start the service or verify the package's version/signature.
func Open() (*Controller, error) {
	device, err := openTransport()
	if err != nil {
		return nil, fmt.Errorf("splittunnel: open: %w", err)
	}
	return newController(device), nil
}

// run holds a logical operation alive until all of its I/O has completed.
// Close cancels lane waiters and active I/O before closing the native handle.
func (c *Controller) run(ctx context.Context, event bool, operation string, f func(context.Context) error) error {
	if ctx == nil {
		return fmt.Errorf("%w: nil context", ErrInvalidArgument)
	}
	if c == nil {
		return os.ErrClosed
	}
	c.mu.Lock()
	if c.closed || c.device == nil {
		c.mu.Unlock()
		return os.ErrClosed
	}
	c.active.Add(1)
	c.mu.Unlock()
	defer c.active.Done()

	opctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.life, cancel)
	defer func() { stop(); cancel() }()
	lane := c.commands
	if event {
		lane = c.events
	}
	var err error
	select {
	case lane <- struct{}{}:
		defer func() { <-lane }()
		if err = opctx.Err(); err == nil {
			err = f(opctx)
		}
	case <-opctx.Done():
		err = opctx.Err()
	}
	if err != nil {
		// Preserve a caller deadline; distinguish cancellation caused by Close.
		if c.life.Err() != nil && ctx.Err() == nil && errors.Is(err, context.Canceled) {
			err = os.ErrClosed
		}
		return fmt.Errorf("splittunnel: %s: %w", operation, err)
	}
	return nil
}

func (c *Controller) exchange(ctx context.Context, code uint32, input []byte, outputSize int) ([]byte, error) {
	if outputSize < 0 || outputSize > maxBufferSize || len(input) > maxBufferSize {
		return nil, fmt.Errorf("%w: IOCTL buffer exceeds local limit", ErrInvalidArgument)
	}
	output := make([]byte, outputSize)
	n, err := c.device.ioctl(ctx, code, input, output)
	if err != nil {
		return nil, err
	}
	if uint64(n) > uint64(len(output)) {
		return nil, fmt.Errorf("%w: IOCTL returned an excessive byte count", ErrProtocol)
	}
	return output[:int(n)], nil
}

func (c *Controller) state(ctx context.Context) (State, error) {
	b, err := c.exchange(ctx, ioctlGetState, nil, 8)
	if err != nil {
		return 0, err
	}
	return decodeState(b)
}

func (c *Controller) requireState(ctx context.Context, allowed ...State) error {
	state, err := c.state(ctx)
	if err != nil {
		return err
	}
	for _, value := range allowed {
		if state == value {
			return nil
		}
	}
	return fmt.Errorf("%w: got %s, expected %v", ErrState, state, allowed)
}

// State returns the current state of the driver.
func (c *Controller) State(ctx context.Context) (state State, err error) {
	err = c.run(ctx, false, "state", func(ctx context.Context) error {
		var e error
		state, e = c.state(ctx)
		return e
	})
	return
}

// Initialize initializes the 1.3 ABI with two existing WFP sublayers.
// It requires Started and never resets another owner's configuration.
// See Sublayers for WFP lifetime requirements. Do not hold an open caller WFP
// transaction while invoking this or other driver operations that modify WFP.
func (c *Controller) Initialize(ctx context.Context, sublayers Sublayers) error {
	return c.run(ctx, false, "initialize", func(ctx context.Context) error {
		b, err := encodeSublayers(sublayers)
		if err != nil {
			return err
		}
		if err := c.requireState(ctx, StateStarted); err != nil {
			return err
		}
		_, err = c.exchange(ctx, ioctlInitialize, b, 0)
		return err
	})
}

// RegisterProcesses seeds the process registry exactly once after Initialize.
// Take the snapshot AFTER Initialize: the driver then buffers process changes.
// SnapshotProcesses is a convenience helper; inspect its Warnings.
func (c *Controller) RegisterProcesses(ctx context.Context, processes []Process) error {
	return c.run(ctx, false, "register processes", func(ctx context.Context) error {
		b, err := encodeProcesses(processes)
		if err != nil {
			return err
		}
		if err := c.requireState(ctx, StateInitialized); err != nil {
			return err
		}
		_, err = c.exchange(ctx, ioctlRegisterProcesses, b, 0)
		return err
	})
}

// SetAddresses replaces the tunnel and Internet addresses. It requires Ready
// or Engaged. An invalid or unspecified address marks that role as unavailable.
func (c *Controller) SetAddresses(ctx context.Context, addresses Addresses) error {
	return c.run(ctx, false, "set addresses", func(ctx context.Context) error {
		b, err := encodeAddresses(addresses)
		if err != nil {
			return err
		}
		if err := c.requireState(ctx, StateReady, StateEngaged); err != nil {
			return err
		}
		_, err = c.exchange(ctx, ioctlRegisterAddresses, b, 0)
		return err
	})
}

// Addresses returns the addresses that are registered with the driver.
func (c *Controller) Addresses(ctx context.Context) (addresses Addresses, err error) {
	err = c.run(ctx, false, "get addresses", func(ctx context.Context) error {
		if e := c.requireState(ctx, StateReady, StateEngaged); e != nil {
			return e
		}
		b, e := c.exchange(ctx, ioctlGetAddresses, nil, addressesSize)
		if e != nil {
			return e
		}
		addresses, e = decodeAddresses(b)
		return e
	})
	return
}

// SetExcludedDevicePaths replaces the entire exclusion set with exact NT device
// paths. An empty set clears configuration. The driver applies child inheritance.
// Caller-provided slices and their elements must not be mutated during the call.
func (c *Controller) SetExcludedDevicePaths(ctx context.Context, paths []string) error {
	return c.run(ctx, false, "set exclusions", func(ctx context.Context) error {
		return c.setExcludedDevicePaths(ctx, paths)
	})
}

func (c *Controller) setExcludedDevicePaths(ctx context.Context, paths []string) error {
	var b []byte
	var err error
	code := ioctlClearConfiguration
	if len(paths) != 0 {
		b, err = encodeConfiguration(paths)
		if err != nil {
			return err
		}
		code = ioctlSetConfiguration
	}
	if err := c.requireState(ctx, StateReady, StateEngaged); err != nil {
		return err
	}
	_, err = c.exchange(ctx, code, b, 0)
	return err
}

// SetExcludedPaths resolves existing absolute executable paths before changing
// driver policy. A resolution error leaves the exclusion set untouched.
// Resolution is synchronous filesystem work and is not forcibly cancellable.
func (c *Controller) SetExcludedPaths(ctx context.Context, paths []string) error {
	return c.run(ctx, false, "resolve and set exclusions", func(ctx context.Context) error {
		if len(paths) > maxRecords {
			return fmt.Errorf("%w: too many paths", ErrInvalidArgument)
		}
		resolved := make([]string, len(paths))
		for i, path := range paths {
			if err := ctx.Err(); err != nil {
				return err
			}
			var err error
			resolved[i], err = ResolveDevicePath(path)
			if err != nil {
				return fmt.Errorf("resolve path %d: %w", i, err)
			}
		}
		return c.setExcludedDevicePaths(ctx, resolved)
	})
}

// ExcludedDevicePaths uses the driver's special eight-byte size probe before
// retrieving its configuration. Returned paths are driver-normalized; order is
// not stable. This method does not convert them back to drive-letter paths.
func (c *Controller) ExcludedDevicePaths(ctx context.Context) (paths []string, err error) {
	err = c.run(ctx, false, "get exclusions", func(ctx context.Context) error {
		if e := c.requireState(ctx, StateReady, StateEngaged); e != nil {
			return e
		}
		size, e := c.exchange(ctx, ioctlGetConfiguration, nil, 8)
		if e != nil {
			return e
		}
		if len(size) != 8 {
			return fmt.Errorf("%w: invalid configuration size probe", ErrProtocol)
		}
		required := le.Uint64(size)
		if required < configHeaderSize || required > maxBufferSize {
			return fmt.Errorf("%w: configuration size out of bounds", ErrProtocol)
		}
		b, e := c.exchange(ctx, ioctlGetConfiguration, nil, int(required))
		if e != nil {
			return e
		}
		paths, e = decodeConfiguration(b)
		return e
	})
	return
}

// ClearConfiguration removes every executable exclusion.
func (c *Controller) ClearConfiguration(ctx context.Context) error {
	return c.SetExcludedDevicePaths(ctx, nil)
}

// QueryProcess returns the driver's current classification for pid.
func (c *Controller) QueryProcess(ctx context.Context, pid uint32) (process ProcessStatus, err error) {
	err = c.run(ctx, false, "query process", func(ctx context.Context) error {
		if pid == 0 {
			return fmt.Errorf("%w: PID zero", ErrInvalidArgument)
		}
		if e := c.requireState(ctx, StateReady, StateEngaged); e != nil {
			return e
		}
		input := make([]byte, 8)
		le.PutUint64(input, uint64(pid))
		b, e := c.exchange(ctx, ioctlQueryProcess, input, processBufferSize)
		if e != nil {
			return e
		}
		process, e = decodeProcess(b)
		if e == nil && process.PID != pid {
			e = fmt.Errorf("%w: process query returned a different PID", ErrProtocol)
		}
		return e
	})
	return
}

// ReadEvent waits for one event. Control operations can run concurrently.
// Use one reader to preserve delivery order. Cancellation is not transactional:
// an event may already have been consumed when cancellation wins completion.
func (c *Controller) ReadEvent(ctx context.Context) (event Event, err error) {
	err = c.run(ctx, true, "read event", func(ctx context.Context) error {
		b, e := c.exchange(ctx, ioctlDequeueEvent, nil, eventBufferSize)
		if e != nil {
			return e
		}
		event, e = decodeEvent(b)
		return e
	})
	return
}

// Reset tears down driver subsystems, exclusions, process state, and events.
// It is explicit because closing a handle is not authorization to erase policy.
func (c *Controller) Reset(ctx context.Context) error {
	return c.run(ctx, false, "reset", func(ctx context.Context) error {
		_, err := c.exchange(ctx, ioctlReset, nil, 0)
		return err
	})
}

// Shutdown attempts Reset and then closes the handle, returning both errors.
// Cancel your event-consumer context before calling this. If Reset fails, inspect
// the driver state during recovery before removing its WFP sublayers.
func (c *Controller) Shutdown(ctx context.Context) error {
	return errors.Join(c.Reset(ctx), c.Close())
}

// Close is idempotent. It cancels/drains local I/O and closes the handle.
// It does NOT clear or reset the driver, stop its service, or delete WFP objects.
func (c *Controller) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		if c.cancel != nil {
			c.cancel()
		}
		c.mu.Unlock()
		c.active.Wait()
		if c.device != nil {
			c.closeErr = c.device.close()
		}
	})
	return c.closeErr
}
