# Plan: Mullvad Windows driver controller in Go

This plan records the design and remaining integration work for
`mullvad-split-tunnel-go`.

## Decision and scope

Create a small, independent Go module that owns a handle to the Mullvad Windows
split-tunneling driver and implements its control protocol. Keep `gonnect`, TUN
creation, routing, DNS policy, and UI dependencies out of its core.

Target the 1.3.0.0 ABI first, on Windows amd64 and arm64. Pin a known driver
package rather than attempting to discover compatibility by sending mutating
IOCTLs.

The useful primitive is **exclude exact executable paths and their descendants
from the tunnel**, with one tunnel and one underlying Internet address per
family. The stock driver is not a general routing rule engine. Include-only
routing, per-socket protection, user/group predicates, packet capture, DNS
attribution, and an application-wide kill switch require separate work.

The authoritative protocol sources are `src/defs/ioctl.h`,
`src/procmgmt/procmgmt.cpp`, and `src/firewall/firewall.cpp` in the
[pinned upstream source][upstream].

## Module boundary and tools

- **Native API calls**
  - **Choice:** `golang.org/x/sys/windows`, currently pinned to v0.44.0
  - **Ownership:** Core library
- **Binary encoding**
  - **Choice:** `encoding/binary` and explicit offsets
  - **Ownership:** Core library
- **Cancellation**
  - **Choice:** Overlapped I/O, `CancelIoEx`, completion draining
  - **Ownership:** Core library
- **Process snapshot**
  - **Choice:** Toolhelp + `QueryFullProcessImageName` + `GetProcessTimes`
  - **Ownership:** Convenience helper
- **Executable normalization**
  - **Choice:** `GetFinalPathNameByHandleW` with NT volume names
  - **Ownership:** Convenience helper
- **Service installation**
  - **Choice:** Service Control Manager; optional `windows/svc/mgr` package
  - **Ownership:** Installer or later optional package
- **Signature/version checks**
  - **Choice:** Authenticode verification and signed package manifest
  - **Ownership:** Deployment layer
- **WFP objects**
  - **Choice:** Direct WFP bindings or an audited wrapper such as `inet.af/wf`
  - **Ownership:** Consumer, initially
- **TUN, routes, DNS, network change monitoring**
  - **Choice:** Wintun/IP Helper/Windows DNS APIs
  - **Ownership:** `sysnet-windows`

The controller uses direct Go Windows bindings; it does not require cgo or a
Rust/C++ bridge. The C++ tool is a development fixture generator, not a runtime
dependency.

## Public API

- **`Open() (*Controller, error)`**
  - **Purpose:** Open the global device without initializing or resetting it
- **`State(ctx)`**
  - **Purpose:** Read the native state, including unknown future values
- **`Initialize(ctx, Sublayers)`**
  - **Purpose:** Initialize ABI 1.3 using two existing WFP sublayer GUIDs
- **`SnapshotProcesses()`; `RegisterProcesses(ctx, []Process)`**
  - **Purpose:** Seed existing processes after monitoring has started
- **`SetAddresses(ctx, Addresses)`; `Addresses(ctx)`**
  - **Purpose:** Set/read tunnel and underlying interface addresses
- **`ResolveDevicePath(path)`**
  - **Purpose:** Convert an existing local executable path to a native device
    path
- **`SetExcludedPaths`; `SetExcludedDevicePaths`**
  - **Purpose:** Replace the complete exclusion set
- **`ExcludedDevicePaths`; `ClearConfiguration`**
  - **Purpose:** Read/clear the set
- **`QueryProcess(ctx, pid)`**
  - **Purpose:** Read the driver's classification and parent/image metadata
- **`ReadEvent(ctx)`**
  - **Purpose:** Receive one classification/error event
- **`Reset(ctx)`; `Shutdown(ctx)`; `Close()`**
  - **Purpose:** Explicit driver teardown, combined teardown/close, local close

Keep service management out of `Open`. Opening a handle is not permission to
replace a running owner's configuration.

Control operations serialize through one lane. Event reads use a separate lane
so a blocked event read cannot prevent an address update or reset. Caller input
slices must remain unchanged during a call. Filesystem path resolution and
process enumeration are synchronous helpers; they do not promise an
interruptible deadline.

## Protocol requirements

- **Initialize**
  - **Pinned ABI requirement:** `0x80000004`, buffered input containing two
    GUIDs, 32 bytes
- **State**
  - **Pinned ABI requirement:** Output is eight-byte `SIZE_T`, not a four-byte C
    enum
- **Configuration**
  - **Pinned ABI requirement:** 16-byte header; 16-byte entries; string offsets
    relative to the string region
- **Processes**
  - **Pinned ABI requirement:** 16-byte header; 32-byte entries; 64-bit
    PID/parent fields
- **Strings**
  - **Pinned ABI requirement:** UTF-16LE; lengths in bytes; no implicit NUL
    terminator
- **Addresses**
  - **Pinned ABI requirement:** 40 bytes: tunnel IPv4, Internet IPv4, tunnel
    IPv6, Internet IPv6
- **Configuration read**
  - **Pinned ABI requirement:** Eight-byte size probe succeeds, then fetch the
    reported buffer size
- **Process query**
  - **Pinned ABI requirement:** Image begins at byte 20; returned size includes
    the upstream structure's trailing padding
- **Events**
  - **Pinned ABI requirement:** 16-byte header, then ID-dependent payload
- **State 5**
  - **Pinned ABI requirement:** `Zombie` in the pinned driver header

These details come from `src/defs` and `src/ioctl.cpp` in the
[pinned upstream source][upstream]. Avoid copying an older userspace structure
without checking both.

Use explicit offsets instead of serializing Go structs or assuming
`binary.Write` inserts C padding. Bound lengths and record counts before
allocation. Reject malformed UTF-16 and offsets. Preserve unknown event payloads
for diagnostics. Use the clear IOCTL for an empty exclusion set.

Keep both IO buffers and `OVERLAPPED` alive until actual completion.
Cancellation requests alone do not make them reusable. This is implemented in
the controller, but still needs native stress testing. See the
[Microsoft I/O cancellation documentation][ioapiset].

## WFP and resource ownership

Create the baseline and DNS sublayers through a **non-dynamic WFP session**,
commit them, then pass their GUIDs to the driver. The driver creates its own
dynamic session; WFP forbids references to dynamic objects belonging to another
session. Reset the driver before deleting referenced sublayers. See
`src/firewall/firewall.cpp` in the [upstream source][upstream] and the
[Microsoft WFP documentation][wfp].

Do not hold a caller WFP transaction across an IOCTL that modifies WFP: the
driver's separate transaction can contend with it.

Use application-owned provider/sublayer identifiers, suitable ACLs, and a
cleanup ledger. The sublayer weight policy belongs to the consumer and must be
tested together with the driver's filters. Unreferenced sublayers are safe to
remove only after ownership has been established.

The stock device name is `\\.\MULLVADSPLITTUNNEL` and is opened exclusively. The
driver also has fixed internal provider/callout/filter identifiers. Renaming its
SCM service does not provide coexistence with another copy. Treat
sharing/access-denied failures as ownership conflicts; never automatically stop
another VPN service. See `src/driverentry.cpp` and `src/firewall/identifiers.h`
in the [upstream source][upstream].

## Initialization, updates, and teardown

1. Deployment verifies and starts the supported signed package. The consumer
   prepares its WFP resources and adapter configuration.
1. Open the driver and inspect state. A fresh session should be `Started`.
   Unexpected state enters an explicit recovery path after ownership checks.
1. Initialize. Only then take the initial process snapshot, because
   initialization starts the process watcher and buffers subsequent changes.
1. Register the snapshot. Keep unknown-image entries and expose warnings. Clear
   unverifiable/recycled parent links instead of attributing a process to an
   unrelated parent.
1. Register actual TUN and underlying interface addresses, then replace the
   exclusions.
1. Run an event reader and a consumer-owned adapter monitor. Serialize
   address/configuration replacements. Re-read state after a timeout or other
   uncertain mutation.
1. On shutdown, cancel and join workers, reset with a fresh cleanup context,
   close the device, then release consumer resources. A failed reset must be
   surfaced to recovery.

The upstream production controller provides a useful comparison for snapshot
ordering and parent creation-time handling:
[Mullvad Windows controller][mullvad-app].

Path normalization is snapshot-based. Preserve the user's original DOS path
separately from its resolved NT path so a consumer can refresh exclusions after
drive remounts or executable changes. Hard links and alternate launch paths need
explicit tests. The controller rejects network executable paths and glob rules.

## Milestones and acceptance gates

- **C0: ABI baseline**
  - **Deliverables:** Current codecs, constants, golden fixtures, API
  - **Completion gate:** Native-header fixture generator reproduces committed
    fixtures; Go golden tests pass
- **C1: Native runtime**
  - **Deliverables:** Current overlapped transport and lifecycle
  - **Completion gate:** Native amd64 tests pass; ARM64 compile and native smoke
    tests pass; no handle leak after repeated event cancellation
- **C2: Controlled driver session**
  - **Deliverables:** Small privileged integration harness creates/deletes test
    WFP objects and uses this API
  - **Completion gate:** Initialize/register/configure/query/reset succeeds on
    the pinned driver; failure at every step leaves recoverable owned state
- **C3: Deployment**
  - **Deliverables:** Package manifest, architecture selection,
    signature/hash/version checks, SCM management, ownership lock
  - **Completion gate:** Fresh install/start/stop/upgrade/uninstall tested with
    Secure Boot and Memory Integrity enabled on supported systems
- **C4: Operational resilience**
  - **Deliverables:** Service-host integration, diagnostics, explicit recovery,
    bounded retry, refreshed paths
  - **Completion gate:** Sleep/resume, BFE restart, user process crash, driver
    failure, network switch, and repeated start/stop tested
- **C5: First public release**
  - **Deliverables:** Stable API, CI, support matrix, notices, release artifacts
  - **Completion gate:** All applicable gates above pass; no unsupported
    capability is advertised

**Current delivery:** C0/C1 code, unit and fuzz tests, a diagnostic command, and
a session example. Portable tests and Windows cross-builds pass. Native Windows
tests, the native-driver harness, driver installation, signature verification,
WFP creation, and crash recovery remain to implement.

C2 is the first integration task to do next. It should test normal and
IPv4-only/IPv6-only address combinations, exact paths with non-ASCII characters,
already-running and newly spawned descendants, removal of exclusions, and
long-lived TCP/UDP flows. Record what happens to existing flows when a rule
changes; do not infer instantaneous migration from a successful IOCTL.

## Version and distribution policy

Maintain a compatibility table containing driver version, source commit, package
hash, architecture, signer, controller version, and minimum supported Windows
build. Obtain a known signed package through your own deployment flow; do not
assume every binary shipped by another VPN is interchangeable.

Amnezia's pinned recipe illustrates the mismatch risk: it references 1.2.5.0,
whose initialization differs from 1.3. Supporting it later should use an
explicit ABI adapter selected from verified package metadata.
[Amnezia recipe][amnezia].

If you need independent device/provider names or new semantics, that becomes a
driver fork and signed-driver distribution project. The Go controller alone
cannot provide it. Consult `LICENSE-MPL.txt` and `LICENSE-GPL.md` in the
[upstream source][upstream], plus Microsoft's
[driver installation documentation][driver-install], when defining distribution.

[amnezia]: https://github.com/amnezia-vpn/amnezia-client/tree/327e598
[driver-install]: https://learn.microsoft.com/windows-hardware/drivers/install/
[ioapiset]: https://learn.microsoft.com/windows/win32/api/ioapiset/
[mullvad-app]: https://github.com/mullvad/mullvadvpn-app/tree/643a4cd
[upstream]: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97
[wfp]: https://learn.microsoft.com/windows/win32/fwp/
