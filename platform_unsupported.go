//go:build !windows || (!amd64 && !arm64)

package splittunnel

func openTransport() (transport, error) {
	return nil, ErrUnsupportedPlatform
}

// ResolveDevicePath resolves an existing absolute local executable path to its
// exact NT device path on supported Windows systems.
func ResolveDevicePath(string) (string, error) {
	return "", ErrUnsupportedPlatform
}

// SnapshotProcesses returns the process tree and partial-information warnings
// on supported Windows systems.
func SnapshotProcesses() (Snapshot, error) {
	return Snapshot{}, ErrUnsupportedPlatform
}
