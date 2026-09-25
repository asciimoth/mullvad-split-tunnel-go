//go:build windows && winintegration

package integration

import (
	"fmt"
	"runtime"
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
	fwpmFilterAdd0        = fwpuclnt.NewProc("FwpmFilterAdd0")
	fwpmFilterDelete0     = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
)

const (
	fwpUint16      = 2
	fwpUint64      = 4
	fwpMatchEqual  = 0
	fwpActionBlock = 0x00001001
)

var (
	fwpmLayerALEAuthConnectV4 = mustWindowsGUID("{c38d57d1-05a7-4c33-904f-7fbceee60e82}")
	fwpmLayerALEAuthConnectV6 = mustWindowsGUID("{4a72393b-319f-44bc-84c3-ba54dcb3b6b4}")
	fwpmConditionIPRemotePort = mustWindowsGUID("{c35a604d-d22b-4e1a-91b4-68f674ee674b}")
)

func mustWindowsGUID(value string) windows.GUID {
	guid, err := windows.GUIDFromString(value)
	if err != nil {
		panic(err)
	}
	return guid
}

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

// These structures mirror the 64-bit WFP ABI used by the amd64 and arm64
// integration targets. Each union holds its largest pointer-sized member.
type fwpValue struct {
	type_ uint32
	value uintptr
}

type fwpConditionValue struct {
	type_ uint32
	value uintptr
}

type fwpmFilterCondition struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpConditionValue
}

type fwpmAction struct {
	type_      uint32
	filterType windows.GUID
}

type fwpmFilter struct {
	key                 windows.GUID
	display             fwpmDisplayData
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	sublayerKey         windows.GUID
	weight              fwpValue
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition
	action              fwpmAction
	context             [16]byte
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue
}

type wfpFixture struct {
	engine  windows.Handle
	keys    [2]windows.GUID
	added   int
	filters []windows.GUID
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

func (f *wfpFixture) addRestrictiveFilters(sublayer int, remotePort uint16) ([]windows.GUID, error) {
	if sublayer < 0 || sublayer >= len(f.keys) {
		return nil, fmt.Errorf("invalid WFP sublayer index %d", sublayer)
	}
	if err := wfpCall("FwpmTransactionBegin0", fwpmTransactionBegin, uintptr(f.engine), 0); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = fwpmTransactionAbort.Call(uintptr(f.engine))
		}
	}()
	keys := make([]windows.GUID, 0, 2)
	weight := new(uint64)
	*weight = ^uint64(0) - 20
	defer runtime.KeepAlive(weight)
	condition := fwpmFilterCondition{
		fieldKey:  fwpmConditionIPRemotePort,
		matchType: fwpMatchEqual,
		conditionValue: fwpConditionValue{
			type_: fwpUint16,
			value: uintptr(remotePort),
		},
	}
	for i, layer := range []windows.GUID{fwpmLayerALEAuthConnectV4, fwpmLayerALEAuthConnectV6} {
		key, err := windows.GenerateGUID()
		if err != nil {
			return nil, err
		}
		name, _ := windows.UTF16PtrFromString(fmt.Sprintf("split tunnel Go restrictive filter %d", i))
		filter := fwpmFilter{
			key: key, display: fwpmDisplayData{name: name}, layerKey: layer,
			sublayerKey:         f.keys[sublayer],
			weight:              fwpValue{type_: fwpUint64, value: uintptr(unsafe.Pointer(weight))},
			numFilterConditions: 1, filterCondition: &condition,
			action: fwpmAction{type_: fwpActionBlock},
		}
		if err := wfpCall("FwpmFilterAdd0", fwpmFilterAdd0, uintptr(f.engine), uintptr(unsafe.Pointer(&filter)), 0, 0); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if err := wfpCall("FwpmTransactionCommit0", fwpmTransactionCommit, uintptr(f.engine)); err != nil {
		return nil, err
	}
	committed = true
	f.filters = append(f.filters, keys...)
	return keys, nil
}

func (f *wfpFixture) removeFilters(keys []windows.GUID) error {
	if len(keys) == 0 {
		return nil
	}
	if err := wfpCall("FwpmTransactionBegin0", fwpmTransactionBegin, uintptr(f.engine), 0); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_, _, _ = fwpmTransactionAbort.Call(uintptr(f.engine))
		}
	}()
	for i := len(keys) - 1; i >= 0; i-- {
		if err := wfpCall("FwpmFilterDeleteByKey0", fwpmFilterDelete0, uintptr(f.engine), uintptr(unsafe.Pointer(&keys[i]))); err != nil {
			return err
		}
	}
	if err := wfpCall("FwpmTransactionCommit0", fwpmTransactionCommit, uintptr(f.engine)); err != nil {
		return err
	}
	committed = true
	remaining := f.filters[:0]
	for _, candidate := range f.filters {
		found := false
		for _, key := range keys {
			if candidate == key {
				found = true
				break
			}
		}
		if !found {
			remaining = append(remaining, candidate)
		}
	}
	f.filters = remaining
	return nil
}

func (f *wfpFixture) close(deleteSublayers bool) error {
	if f == nil || f.engine == 0 {
		return nil
	}
	var result error
	if deleteSublayers {
		if err := f.removeFilters(append([]windows.GUID(nil), f.filters...)); err != nil {
			result = err
		}
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
