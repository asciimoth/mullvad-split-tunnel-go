# Mullvad split-tunnel driver controller for Go

An unofficial Go library for controlling the Mullvad Windows split-tunneling
driver.

The primary application for this package is
[sysnet-windows](https://github.com/asciimoth/sysnet-windows) and
[Almagest](https://github.com/asciimoth/almagest). You can also use it as the
Linux backend of another VPN application that needs one cross-platform
system-networking abstraction.

> [!WARNING]
> This library is in a pre-release state. It has not been independently audited
> for security. Do not rely on it for production use without your own review and
> testing.

<!-- Separate the GitHub alerts into distinct block quotes. -->

> [!NOTE]
> This independent project is not affiliated with, endorsed by, or sponsored by
> Mullvad VPN AB. Mullvad is a trademark of its respective owner.

The controller targets driver **1.3.0.0** on Windows **amd64/arm64**. Static
analysis, race tests, fuzz tests, and Windows cross-builds pass. Native Windows
and live-driver tests still require a prepared Windows host. Native
qualification is accepted for the Windows configurations listed below.

## Repository contents

- [Application integration guide](docs/integration.md)
- [Minimal tunnel demonstration](docs/tunneldemo.md)
- [Validation status and commands](VALIDATION.md)
- Controller source, diagnostic command, lifecycle example, protocol fixtures,
  tests, and CI workflow.

## What the library does

This package is the user-mode controller for one Windows kernel driver. It lets
an application give the driver a list of executable paths that must bypass the
VPN. The driver treats all other processes as included; the caller must provide
the VPN route and firewall policy.

For an excluded process, the driver redirects socket binds away from the tunnel
interface, permits traffic on the non-tunnel interface, and blocks existing
tunnel connections. It tracks new and departing processes, applies exclusion to
children of excluded processes, and can reclassify running processes when the
path list changes. IPv4 and IPv6 are supported.

The package provides:

- Controller operations for state, initialization, process registration,
  addresses, exclusions, queries, events, reset, and shutdown.
- Explicit 64-bit protocol layouts, IOCTL constants, UTF-16 paths, GUID byte
  order, and bounded response parsing.
- Overlapped `DeviceIoControl` transport with context cancellation, completion
  draining, and pinned buffers.
- Process snapshot and native executable path helpers with partial-information
  warnings and parent PID reuse checks.
- C++ fixtures from pinned upstream headers, plus protocol, lifecycle, fuzz, and
  Windows helper tests.

The package does not carry VPN packets. Windows routing sends included traffic
to a TUN interface that the application owns. The driver steers excluded traffic
through the physical or other non-tunnel interface. The caller must install and
start the driver, create the TUN and Windows Filtering Platform (WFP) resources,
configure routes and DNS, monitor interface changes, and provide any kill switch
if needed.

The Windows-only `cmd/tunneldemo` command creates enough of these resources for
an isolated example. Its WFP, Wintun, routing, and packet transport code is not
part of the library API and is not a production VPN implementation.

## API model in brief

`Open` acquires the driver's single global device. The handle is exclusive, so
one application must own the complete session. Opening the handle does not
change driver policy. In particular, `Close` only releases local resources; it
does not undo an initialized or engaged driver.

The normal state sequence is:

```text
Started --Initialize--> Initialized --RegisterProcesses--> Ready
                                                          ^   |
                                  clear/no tunnel address |   | exclusions and
                                                          |   | supported addresses
                                                          |   v
                                                        Engaged
```

`Ready` means that process tracking is active but traffic splitting is not.
`Engaged` means that the exclusion set is nonempty and a supported address
combination with at least one tunnel address is available. `Reset` returns a
healthy controller to `Started`. A failed driver teardown can produce `Zombie`,
which requires recovery outside the normal controller API.

The API uses these terms:

- **Tunnel address:** a local unicast address assigned to the VPN/TUN interface.
- **Internet address:** a local unicast address of the current non-tunnel
  interface. It is not a gateway, VPN relay, or public address reported by a web
  service.
- **Excluded or split process:** a process whose traffic bypasses the VPN.
  Therefore, `ProcessStatus.Split == true` means that the process is excluded.
- **WFP sublayer:** a caller-created ordering container for Windows firewall
  filters. It is not a network layer or a TUN interface.

See the [application integration guide](docs/integration.md) for the state and
method contract, WFP resource ownership, valid address combinations, event
handling, and recovery.

## Development environment

Enter the pinned Nix development shell:

```sh
nix develop
```

If direnv is installed, run `direnv allow` once instead. The shell installs the
Git hooks and provides Go, gopls, golangci-lint, govulncheck, the C++ compiler,
and the repository support tools.

Use `just` to list commands. Run all formatting, linting, vetting, builds,
host-harness checks, and test suites with:

```sh
just check
```

Run only the test suites, including the disposable Windows baseline and the
signed-driver gate, with:

```sh
just test-total
```

`test-total` skips its Linux-hosted VM portion on Windows. `check` includes
`test-total`, so it also boots both disposable guests on non-Windows systems.
See the [Windows VM guide](dev/winvm/README.md) for media setup, individual
gates, and failure recovery.

Run the Nix-managed repository checks without entering the shell with:

```sh
nix flake check
```

## Build and inspect

Install Go 1.25 or newer. From this directory:

```sh
go mod download
go mod verify
go fmt ./...
go vet ./...
go test ./...
go build ./...
```

On Windows, with the compatible driver already running and an elevated terminal:

```powershell
go run ./cmd/splitctl
go run ./cmd/splitctl -pid 1234
go run ./cmd/splitctl -event -timeout 10s
```

The diagnostic command opens the exclusive device and reads state. It does not
initialize or reset policy. The `-event` option consumes one queued event; do
not run it alongside the application that owns the driver.

## Pinned Windows driver packages

The Nix development environment downloads the signed 1.3.0.0 driver packages for
amd64 and arm64 from the pinned
[`mullvadvpn-app-binaries` commit][driver-binaries]. It verifies every file with
a SHA-256 hash. In `nix develop`, `MULLVAD_SPLIT_TUNNEL_DRIVER_DIR` identifies a
directory with this layout:

```text
amd64/mullvad-split-tunnel.{cat,inf,sys}
arm64/mullvad-split-tunnel.{cat,inf,sys}
```

Build the same self-contained directory without entering the shell:

```sh
nix build .#windows-test-drivers
```

Copy the package for the target architecture to the dedicated Windows test VM.
The package is an input for opt-in live-driver tests. It does not make ordinary
`go test ./...` install or modify a driver. The live tests also need the WFP and
network resources listed in [VALIDATION.md](VALIDATION.md).

## Initialize a session

After `Open` confirms `StateStarted`, create persistent WFP sublayers, configure
the TUN, and identify the underlay addresses. Do this before `Initialize`. Keep
the sublayers alive until the driver has been reset successfully.

The driver sequence is:

1. `Open` and inspect `State`. Expect `StateStarted`; handle existing state
   through explicit recovery.
1. Create and commit the caller-owned WFP and network resources.
1. `Initialize(ctx, sublayers)`.
1. `SnapshotProcesses()`, inspect warnings, then `RegisterProcesses`.
1. `SetAddresses` with the TUN and actual underlying interface addresses.
1. `SetExcludedPaths` with existing absolute executable paths.
1. Consume `ReadEvent` in a cancellable worker; replace exclusions or addresses
   as needed.
1. Stop and join workers, then `Shutdown`. Release caller WFP resources after
   successful driver reset.

[examples/session/session.go](examples/session/session.go) implements this
lifecycle with cleanup on errors. The example accepts already-created WFP and
network resources.

`Close` cancels and drains local I/O, then closes the handle. **It does not
reset driver policy.** `Shutdown` attempts `Reset` and then `Close`. A cancelled
mutation may already have taken effect; inspect and reconcile state after an
uncertain completion.

## API status and scope

This project is pre-alpha. The exported API of the root `splittunnel` package is
not stable and can change without notice. It includes the controller, wire-level
value types, sentinel errors, process snapshot helper, and executable-path
resolver. The commands, `examples/session`, `integration`, `internal`, and `dev`
trees are demonstrations and development infrastructure. They are not part of
the library API.

The API contract targets only driver 1.3.0.0 at upstream commit `0a0eb97`.
`Open` cannot detect or verify the installed driver version. Deployment must
verify the signed driver package before it starts the service. Driver behavior,
WFP policy, routing, DNS, adapter monitoring, and resource ownership remain the
caller's responsibility.

The qualification targets are:

| Status   | Architecture | Windows configuration             |
| -------- | ------------ | --------------------------------- |
| Accepted | amd64        | Windows Server 2022, build 20348+ |
| Accepted | arm64        | Windows 11 24H2, build 26100+     |

The native qualification evidence is summarized in
[VALIDATION.md](VALIDATION.md). A cross-build or a successful run on another
Windows build does not qualify an entry.

## Limits and known driver behavior

- Each encoded or decoded IOCTL buffer has a 16 MiB local limit. A process
  snapshot or exclusion configuration has a 65,536-record local limit.
- `SetExcludedPaths` accepts existing absolute local drive-letter paths. The
  resolver does not support UNC or other network executable paths. Resolution
  runs outside the controller command lane. Cancellation abandons the wait, but
  a blocked synchronous Windows filesystem call can continue in a background
  goroutine until Windows completes it.
- Exclusions use the exact resolved NT device path. They do not use file
  identity. A rename, replacement, hard link, or volume remount can require a
  configuration update. A hard-link path must be excluded separately.
- Windows normally sends resolver traffic through the `dnscache` service under
  `svchost`. The driver cannot attribute that traffic to the requesting process,
  so an excluded application's ordinary DNS traffic normally remains in the
  tunnel. An application-specific DoH or DoT configuration can avoid the system
  resolver.
- An excluded UDP client that does not explicitly bind to `127.0.0.1` can fail
  to communicate with localhost. There is no general workaround.
- Multicast reception can fail without an API error because the redirected
  socket bind and the `inaddr_any` group membership do not match. There is no
  general workaround.
- Driver 1.3.0.0 incorrectly labels both start- and stop-splitting failures as
  `EventErrorStopSplitting`. Handle both error IDs with
  `EventID.IsSplittingError` and do not infer the failed direction from the ID.

These last four items are limitations of the pinned upstream driver. The
isolated port-53 tests qualify WFP filter arbitration only; they do not qualify
Windows resolver behavior, localhost UDP, or multicast reception.

## Error handling

Controller operations preserve error causes for `errors.Is`, and commands add
operation context. Check for `context.Canceled`, `context.DeadlineExceeded`,
`os.ErrClosed`, and the package sentinels. Treat `ErrProtocol` as an
incompatible or faulty driver response and stop changing policy. Treat
`ErrState` as a request to inspect `State`; reset only through an explicit
ownership or recovery path.

Cancellation is not a transaction boundary. After a cancelled `Initialize` or
`RegisterProcesses`, read `State`. After a cancelled address or exclusion
change, read `Addresses` or `ExcludedDevicePaths`. After a cancelled `Reset`,
read `State` with a fresh context; reopen only if the handle is no longer
usable. Keep caller-owned WFP sublayers alive until reset is confirmed. Inspect
every `Snapshot.Warnings` entry because the snapshot keeps processes whose
metadata could not be read.

Stop and join the event reader before `Shutdown`. If `Shutdown` returns a reset
error, preserve the WFP objects and perform explicit recovery. Calling `Close`
alone only releases local resources and can leave active driver policy.

## Driver scope

Executable exclusions also apply to descendants according to the driver. An
exclusion matches an exact NT path. A normal drive-letter launch and an
extended-prefix launch of the same name resolve to the same NT path. A hard-link
name is a separate path and must be configured separately. There is no arbitrary
PID/include-only routing API, packet capture API, or socket-owner query API
here. `QueryProcess` returns the driver's process classification.

The target ABI is pinned to [win-split-tunnel commit 0a0eb97][upstream]. Version
1.2.5 uses a different initialization protocol. The driver has no version-query
IOCTL, so `TargetDriverVersion` reports the library's target, not a detected
installed version.

The stock driver has a global exclusive device and fixed WFP identifiers.
Coordinate ownership with other applications using it. A different service name
does not create an independent driver instance.

Driver binaries are not committed to or distributed with the Go module. Nix can
fetch the pinned test packages separately. This project uses the GNU General
Public License, version 3 or later; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for upstream and dependency
details.

[driver-binaries]: https://github.com/mullvad/mullvadvpn-app-binaries/commit/5b6f46cde692acb77ee74b37b9fd3f1678c45a52
[upstream]: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97
