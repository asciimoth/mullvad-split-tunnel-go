//go:build windows && winintegration

package integration

import (
	"testing"
	"unsafe"
)

func TestWFPStructureLayout(t *testing.T) {
	for _, test := range []struct {
		name string
		got  uintptr
		want uintptr
	}{
		{name: "FWP_VALUE0", got: unsafe.Sizeof(fwpValue{}), want: 16},
		{name: "FWP_CONDITION_VALUE0", got: unsafe.Sizeof(fwpConditionValue{}), want: 16},
		{name: "FWPM_FILTER_CONDITION0", got: unsafe.Sizeof(fwpmFilterCondition{}), want: 40},
		{name: "FWPM_ACTION0", got: unsafe.Sizeof(fwpmAction{}), want: 20},
		{name: "FWPM_FILTER0", got: unsafe.Sizeof(fwpmFilter{}), want: 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("structure size = %d; want %d", test.got, test.want)
			}
		})
	}
}
