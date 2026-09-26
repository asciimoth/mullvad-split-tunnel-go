package splittunnel

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	// DevicePath is the global, exclusively opened driver device.
	DevicePath = "\\\\.\\MULLVADSPLITTUNNEL"
	// TargetDriverVersion identifies the ABI implemented here, not a detected version.
	TargetDriverVersion = "1.3.0.0"
	// UpstreamCommit pins the definitions used to implement this package.
	UpstreamCommit = "0a0eb97f67d1dbcb3d08bda66d3b24f465d95475"
)

var (
	// ErrUnsupportedPlatform means the package is not running on Windows amd64
	// or arm64.
	ErrUnsupportedPlatform = errors.New("requires Windows amd64 or arm64")
	// ErrInvalidArgument means the caller supplied a value that cannot be sent
	// safely to the driver.
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrProtocol means the driver returned a malformed or unsupported response.
	ErrProtocol = errors.New("invalid driver response")
	// ErrState means the requested operation is not valid in the current driver
	// state.
	ErrState = errors.New("operation is invalid in current driver state")
)

// State values follow src/defs/state.h. In the pinned driver, 5 means Zombie,
// despite some historical userspace definitions calling it Terminating.
type State uint64

const (
	StateNone State = iota
	StateStarted
	StateInitialized
	StateReady
	StateEngaged
	StateZombie
)

// String returns the protocol name of s.
func (s State) String() string {
	names := [...]string{"none", "started", "initialized", "ready", "engaged", "zombie"}
	if uint64(s) < uint64(len(names)) {
		return names[s]
	}
	return fmt.Sprintf("unknown(%d)", s)
}

// GUID holds a Windows GUID in its 16-byte in-memory wire representation.
// Prefer ParseGUID to constructing these bytes by hand.
type GUID [16]byte

// ParseGUID parses the standard dashed or braced text representation of a GUID.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	if len(s) == 38 && s[0] == '{' && s[37] == '}' {
		s = s[1:37]
	}
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return g, fmt.Errorf("%w: malformed GUID", ErrInvalidArgument)
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return g, fmt.Errorf("%w: malformed GUID", ErrInvalidArgument)
	}
	copy(g[:], b)
	g[0], g[1], g[2], g[3] = b[3], b[2], b[1], b[0]
	g[4], g[5] = b[5], b[4]
	g[6], g[7] = b[7], b[6]
	return g, nil
}

// String returns the standard lowercase dashed representation of g.
func (g GUID) String() string {
	b := g
	b[0], b[1], b[2], b[3] = g[3], g[2], g[1], g[0]
	b[4], b[5] = g[5], g[4]
	b[6], b[7] = g[7], g[6]
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// Sublayers must identify existing caller-owned WFP sublayers. Baseline holds
// general redirect, permit, and block filters; DNS holds DNS-specific permits.
// Create them in a non-dynamic session: the driver uses its own dynamic session,
// whose objects cannot reference dynamic objects from a different session.
// Commit the caller's WFP transaction before Initialize. These sublayers are not
// created here and must remain alive until driver Reset has completed.
type Sublayers struct {
	Baseline GUID
	DNS      GUID
}

// Addresses contains one local address per role/family. Tunnel addresses belong
// to the VPN/TUN interface. Internet addresses belong to the selected non-tunnel
// interface; they are not gateways or remote endpoints. An invalid or
// unspecified address encodes zero (unavailable). Scoped/link-local IPv6 cannot
// be expressed safely by this ABI and is rejected. Selecting and monitoring the
// addresses is the caller's job. The driver accepts only the availability modes
// documented in its operation matrix when exclusions become engaged.
type Addresses struct {
	TunnelIPv4   netip.Addr
	InternetIPv4 netip.Addr
	TunnelIPv6   netip.Addr
	InternetIPv6 netip.Addr
}

// Process is an initial process-registry entry. ImagePath is an NT device path.
// An empty ImagePath preserves a process whose image could not be queried.
// CreationTime is a Windows FILETIME value used locally to detect recycled
// parent PIDs; it is not part of the driver's registration message.
type Process struct {
	PID          uint32
	ParentPID    uint32
	ImagePath    string
	CreationTime uint64
}

// Snapshot preserves partial-information diagnostics instead of hiding them.
type Snapshot struct {
	Processes []Process
	Warnings  []ProcessWarning
}

// ProcessWarning describes process metadata that SnapshotProcesses could not
// read. The corresponding process remains in the snapshot.
type ProcessWarning struct {
	PID       uint32
	Operation string
	Err       error
}

// ProcessStatus is driver process-tree information, not socket-owner metadata.
// Split is true when the process is excluded from the VPN tunnel.
type ProcessStatus struct {
	PID       uint32
	ParentPID uint32
	Split     bool
	ImagePath string
}

// EventID identifies one driver event payload.
type EventID uint32

const (
	EventStartSplitting EventID = 0
	EventStopSplitting  EventID = 1
	// EventErrorStartSplitting is defined by the ABI, but the pinned 1.3.0.0
	// driver incorrectly emits EventErrorStopSplitting for start failures too.
	EventErrorStartSplitting EventID = 0x80000001
	EventErrorStopSplitting  EventID = 0x80000002
	EventErrorMessage        EventID = 0x80000003
)

// IsSplittingError reports whether id contains a process splitting error.
// Do not use the specific error ID to infer the failed direction with the
// pinned driver: it labels both start and stop failures as stop failures.
func (id EventID) IsSplittingError() bool {
	return id == EventErrorStartSplitting || id == EventErrorStopSplitting
}

// Reason is a bit field that explains a process-classification event.
type Reason uint32

const (
	ReasonInheritance Reason = 1
	ReasonConfig      Reason = 2
	ReasonArriving    Reason = 4
	ReasonDeparting   Reason = 8
)

// Event represents a driver event. Fields unused by its ID remain zero.
// Unknown IDs retain their payload in Raw, so diagnostics are not silently lost.
type Event struct {
	ID        EventID
	PID       uint32
	Reason    Reason
	ImagePath string
	NTStatus  uint32
	Message   string
	Raw       []byte
}
