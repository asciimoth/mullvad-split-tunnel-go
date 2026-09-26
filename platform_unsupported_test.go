//go:build !windows || (!amd64 && !arm64)

package splittunnel

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatform(t *testing.T) {
	if _, err := Open(); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("Open: %v", err)
	}
	if _, err := ResolveDevicePath("/tmp/app"); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("ResolveDevicePath: %v", err)
	}
	if _, err := SnapshotProcesses(); !errors.Is(err, ErrUnsupportedPlatform) {
		t.Fatalf("SnapshotProcesses: %v", err)
	}
}
