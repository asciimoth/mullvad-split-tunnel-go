//go:build !windows || (!amd64 && !arm64)

package main

import (
	"strings"
	"testing"
)

func TestRunPlatformIsUnsupported(t *testing.T) {
	if err := runPlatform(config{}); err == nil || !strings.Contains(err.Error(), "requires Windows") {
		t.Fatalf("runPlatform: %v", err)
	}
}
