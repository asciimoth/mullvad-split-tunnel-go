//go:build !windows || (!amd64 && !arm64)

package splittunnel

func openTransport() (transport, error) {
	return nil, ErrUnsupportedPlatform
}

func ResolveDevicePath(string) (string, error) {
	return "", ErrUnsupportedPlatform
}

func SnapshotProcesses() (Snapshot, error) {
	return Snapshot{}, ErrUnsupportedPlatform
}
