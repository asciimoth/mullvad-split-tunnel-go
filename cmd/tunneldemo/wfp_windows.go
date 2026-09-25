//go:build windows && (amd64 || arm64)

package main

import (
	"errors"
	"fmt"
	"unsafe"

	splittunnel "github.com/asciimoth/mullvad-split-tunnel-go"
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

type wfpResources struct {
	engine windows.Handle
	keys   [2]windows.GUID
	added  int
}

func callWFP(name string, procedure *windows.LazyProc, arguments ...uintptr) error {
	result, _, _ := procedure.Call(arguments...)
	if result != 0 {
		return fmt.Errorf("%s: %w", name, windows.Errno(result))
	}
	return nil
}

func createWFPResources() (*wfpResources, error) {
	resources := &wfpResources{}
	if err := callWFP("open WFP engine", fwpmEngineOpen0, 0, rpcCAuthnWinNT, 0, 0, uintptr(unsafe.Pointer(&resources.engine))); err != nil {
		return nil, err
	}
	for index := range resources.keys {
		key, err := windows.GenerateGUID()
		if err != nil {
			return nil, errors.Join(fmt.Errorf("generate WFP sublayer key: %w", err), resources.close(false))
		}
		resources.keys[index] = key
	}
	if err := callWFP("begin WFP transaction", fwpmTransactionBegin, uintptr(resources.engine), 0); err != nil {
		return nil, errors.Join(err, resources.close(false))
	}
	for index := range resources.keys {
		name, _ := windows.UTF16PtrFromString(fmt.Sprintf("Mullvad split tunnel demo %d", index))
		sublayer := fwpmSubLayer{
			key: resources.keys[index], display: fwpmDisplayData{name: name},
			weight: uint16(0x7100 + index),
		}
		if err := callWFP("add WFP sublayer", fwpmSubLayerAdd0, uintptr(resources.engine), uintptr(unsafe.Pointer(&sublayer)), 0); err != nil {
			_, _, _ = fwpmTransactionAbort.Call(uintptr(resources.engine))
			resources.added = 0
			return nil, errors.Join(err, resources.close(false))
		}
		resources.added++
	}
	if err := callWFP("commit WFP transaction", fwpmTransactionCommit, uintptr(resources.engine)); err != nil {
		_, _, _ = fwpmTransactionAbort.Call(uintptr(resources.engine))
		resources.added = 0
		return nil, errors.Join(err, resources.close(false))
	}
	return resources, nil
}

func (resources *wfpResources) sublayers() (splittunnel.Sublayers, error) {
	baseline, err := splittunnel.ParseGUID(resources.keys[0].String())
	if err != nil {
		return splittunnel.Sublayers{}, err
	}
	dns, err := splittunnel.ParseGUID(resources.keys[1].String())
	return splittunnel.Sublayers{Baseline: baseline, DNS: dns}, err
}

func (resources *wfpResources) close(deleteSublayers bool) error {
	if resources == nil || resources.engine == 0 {
		return nil
	}
	var result error
	if deleteSublayers && resources.added != 0 {
		if err := callWFP("begin WFP cleanup transaction", fwpmTransactionBegin, uintptr(resources.engine), 0); err != nil {
			result = errors.Join(result, err)
		} else {
			committed := false
			for index := resources.added - 1; index >= 0; index-- {
				err := callWFP("delete WFP sublayer", fwpmSubLayerDelete0, uintptr(resources.engine), uintptr(unsafe.Pointer(&resources.keys[index])))
				if err != nil {
					result = errors.Join(result, err)
					break
				}
			}
			if result == nil {
				if err := callWFP("commit WFP cleanup transaction", fwpmTransactionCommit, uintptr(resources.engine)); err != nil {
					result = errors.Join(result, err)
				} else {
					committed = true
					resources.added = 0
				}
			}
			if !committed {
				_, _, _ = fwpmTransactionAbort.Call(uintptr(resources.engine))
			}
		}
	}
	if err := callWFP("close WFP engine", fwpmEngineClose0, uintptr(resources.engine)); err != nil {
		result = errors.Join(result, err)
	} else {
		resources.engine = 0
	}
	return result
}
