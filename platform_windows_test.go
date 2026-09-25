//go:build windows && (amd64 || arm64)

package splittunnel

import (
	"os"
	"strings"
	"testing"
)

// These tests need Windows, but not the Mullvad driver or an elevated account.
func TestResolveOwnExecutableAndSnapshot(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exeInfo, err := os.Stat(exe)
	if err != nil {
		t.Fatal(err)
	}
	path, err := ResolveDevicePath(exe)
	if err != nil || !strings.HasPrefix(strings.ToLower(path), "\\device\\") {
		t.Fatalf("native executable path: %q, %v", path, err)
	}
	snapshot, err := SnapshotProcesses()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range snapshot.Processes {
		if p.PID == uint32(os.Getpid()) {
			if !strings.HasPrefix(strings.ToLower(p.ImagePath), "\\device\\") || p.CreationTime == 0 {
				t.Fatalf("self metadata: %+v, want %q", p, path)
			}
			imageInfo, err := os.Stat(`\\?\GLOBALROOT` + p.ImagePath)
			if err != nil {
				t.Fatalf("stat snapshot image %q: %v", p.ImagePath, err)
			}
			if !os.SameFile(imageInfo, exeInfo) {
				t.Fatalf("snapshot image %q is not executable %q", p.ImagePath, path)
			}
			return
		}
	}
	t.Fatal("current process missing from snapshot")
}

func TestRejectDirectoryAndRelativeExecutable(t *testing.T) {
	if _, err := ResolveDevicePath(t.TempDir()); err == nil {
		t.Fatal("directory accepted as executable")
	}
	if _, err := ResolveDevicePath("app.exe"); err == nil {
		t.Fatal("relative executable accepted")
	}
}
