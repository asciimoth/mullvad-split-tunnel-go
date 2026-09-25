//go:build windows && (amd64 || arm64)

package splittunnel

import (
	"context"
	"errors"
	"runtime"

	"golang.org/x/sys/windows"
)

type windowsTransport struct {
	handle windows.Handle
}

func openTransport() (transport, error) {
	path, err := windows.UTF16PtrFromString(DevicePath)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(path,
		windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	return &windowsTransport{handle: handle}, nil
}

func (t *windowsTransport) close() error {
	return windows.CloseHandle(t.handle)
}

func (t *windowsTransport) ioctl(ctx context.Context, code uint32, input, output []byte) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(event)
	overlapped := &windows.Overlapped{HEvent: event}
	// Windows retains these pointers beyond DeviceIoControl. Keep them pinned
	// until actual completion, including on cancellation, not just syscall return.
	var pinned runtime.Pinner
	pinned.Pin(overlapped)
	defer pinned.Unpin()
	var in, out *byte
	if len(input) != 0 {
		in = &input[0]
		pinned.Pin(in)
	}
	if len(output) != 0 {
		out = &output[0]
		pinned.Pin(out)
	}
	err = windows.DeviceIoControl(t.handle, code, in, uint32(len(input)),
		out, uint32(len(output)), nil, overlapped)
	if err != nil && !errors.Is(err, windows.ERROR_IO_PENDING) {
		return 0, err
	}
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		// Register AFTER issuing the request, avoiding a cancel-before-issue race.
		// Join the callback before releasing OVERLAPPED or closing its event.
		done := make(chan struct{})
		stop := context.AfterFunc(ctx, func() {
			defer close(done)
			_ = windows.CancelIoEx(t.handle, overlapped)
		})
		defer func() {
			if !stop() {
				<-done
			}
		}()
	}
	var transferred uint32
	// Always drain. CancelIoEx merely requests cancellation; it does not complete
	// the operation. Waiting here also handles immediate synchronous success.
	err = windows.GetOverlappedResult(t.handle, overlapped, &transferred, true)
	runtime.KeepAlive(input)
	runtime.KeepAlive(output)
	if errors.Is(err, windows.ERROR_OPERATION_ABORTED) && ctx.Err() != nil {
		return 0, ctx.Err()
	}
	return transferred, err
}
