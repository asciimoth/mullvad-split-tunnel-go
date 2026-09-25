//go:build windows && winintegration

package integration

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const rpcCAuthnWinNT = 10

var (
	fwpuclnt              = windows.NewLazySystemDLL("fwpuclnt.dll")
	fwpmEngineOpen0       = fwpuclnt.NewProc("FwpmEngineOpen0")
	fwpmEngineClose0      = fwpuclnt.NewProc("FwpmEngineClose0")
	fwpmTransactionBegin  = fwpuclnt.NewProc("FwpmTransactionBegin0")
	fwpmTransactionCommit = fwpuclnt.NewProc("FwpmTransactionCommit0")
	fwpmTransactionAbort  = fwpuclnt.NewProc("FwpmTransactionAbort0")
	fwpmSubLayerAdd0      = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	fwpmSubLayerDelete0   = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
)

type fwpByteBlob struct {
	size uint32
	data *byte
}

type fwpmDisplayData struct {
	name        *uint16
	description *uint16
}

type fwpmSubLayer struct {
	key          windows.GUID
	display      fwpmDisplayData
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type wfpFixture struct {
	engine windows.Handle
	keys   [2]windows.GUID
	added  int
}

func wfpCall(name string, proc *windows.LazyProc, args ...uintptr) error {
	result, _, _ := proc.Call(args...)
	if result != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(result))
	}
	return nil
}

func newWFPFixture() (*wfpFixture, error) {
	f := &wfpFixture{}
	if err := wfpCall("FwpmEngineOpen0", fwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&f.engine))); err != nil {
		return nil, err
	}
	for i := range f.keys {
		key, err := windows.GenerateGUID()
		if err != nil {
			_ = f.close(false)
			return nil, err
		}
		f.keys[i] = key
	}
	if err := wfpCall("FwpmTransactionBegin0", fwpmTransactionBegin, uintptr(f.engine), 0); err != nil {
		_ = f.close(false)
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = fwpmTransactionAbort.Call(uintptr(f.engine))
		}
	}()
	for i := range f.keys {
		name, _ := windows.UTF16PtrFromString(fmt.Sprintf("split tunnel Go integration %d", i))
		sublayer := fwpmSubLayer{key: f.keys[i], display: fwpmDisplayData{name: name}, weight: uint16(0x7000 + i)}
		if err := wfpCall("FwpmSubLayerAdd0", fwpmSubLayerAdd0, uintptr(f.engine), uintptr(unsafe.Pointer(&sublayer)), 0); err != nil {
			_ = f.close(false)
			return nil, err
		}
		f.added++
	}
	if err := wfpCall("FwpmTransactionCommit0", fwpmTransactionCommit, uintptr(f.engine)); err != nil {
		_ = f.close(false)
		return nil, err
	}
	committed = true
	return f, nil
}

func (f *wfpFixture) close(deleteSublayers bool) error {
	if f == nil || f.engine == 0 {
		return nil
	}
	var result error
	if deleteSublayers {
		for i := f.added - 1; i >= 0; i-- {
			if err := wfpCall("FwpmSubLayerDeleteByKey0", fwpmSubLayerDelete0, uintptr(f.engine), uintptr(unsafe.Pointer(&f.keys[i]))); err != nil {
				result = fmt.Errorf("%v; %w", result, err)
			}
		}
	}
	if err := wfpCall("FwpmEngineClose0", fwpmEngineClose0, uintptr(f.engine)); err != nil {
		result = fmt.Errorf("%v; %w", result, err)
	}
	f.engine = 0
	return result
}
