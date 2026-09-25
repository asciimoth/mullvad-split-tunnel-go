# Mullvad split-tunnel driver controller for Go

An unofficial Go controller for the Mullvad Windows split-tunneling driver. It
is intended for use as a separate dependency of `sysnet-windows`.

The controller targets driver **1.3.0.0** on Windows **amd64/arm64**. Portable
compilation, static analysis, race tests, fuzz tests, and Windows cross-builds
pass. Native Windows and live-driver tests still require a prepared Windows
host.

## Repository contents

- [Controller implementation plan](docs/mullvad-controller-plan.md)
- [sysnet-windows implementation plan](docs/sysnet-windows-plan.md)
- Controller source, diagnostic command, lifecycle example, protocol fixtures,
  tests, and CI workflow.

## Included

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

It does not install the driver, create WFP sublayers, create a TUN, change
routes or DNS, monitor adapters, or implement a kill switch.

## Development environment

Enter the pinned Nix development shell:

```sh
nix develop
```

If direnv is installed, run `direnv allow` once instead. The shell installs the
Git hooks and provides Go, gopls, golangci-lint, govulncheck, the C++ compiler,
and the repository support tools.

Use `just` to list commands. Run the complete portable check set with:

```sh
just check
```

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

## Initialize a session

The caller must first create the WFP sublayers and configure the TUN and
underlay addresses. The sublayers must satisfy the non-dynamic lifetime
requirement described in the [controller plan](docs/mullvad-controller-plan.md).

The driver sequence is:

1. `Open` and inspect `State`. Expect `StateStarted`; handle existing state
   through explicit recovery.
1. `Initialize(ctx, sublayers)`.
1. `SnapshotProcesses()`, inspect warnings, then `RegisterProcesses`.
1. `SetAddresses` with the TUN and actual underlying interface addresses.
1. `SetExcludedPaths` with existing absolute executable paths.
1. Consume `ReadEvent` in a cancellable worker; replace exclusions or addresses
   as needed.
1. Stop and join workers, then `Shutdown`. Release caller WFP resources after
   successful driver reset.

[examples/session/session.go](examples/session/session.go) implements the driver
portion of that lifecycle with cleanup on errors. It is a library example
accepting already-created resources, not a complete VPN executable.

`Close` cancels and drains local I/O, then closes the handle. **It does not
reset driver policy.** `Shutdown` attempts `Reset` and then `Close`. A cancelled
mutation may already have taken effect; inspect and reconcile state after an
uncertain completion.

## Compatibility and scope

Executable exclusions also apply to descendants according to the driver. There
is no arbitrary PID/include-only routing API, packet capture API, or
socket-owner query API here. `QueryProcess` returns the driver's process
classification.

The target ABI is pinned to [win-split-tunnel commit 0a0eb97][upstream]. Version
1.2.5 uses a different initialization protocol. The driver has no version-query
IOCTL, so `TargetDriverVersion` reports the library's target, not a detected
installed version.

The stock driver has a global exclusive device and fixed WFP identifiers.
Coordinate ownership with other applications using it. A different service name
does not create an independent driver instance.

Driver binaries are not bundled. This project uses the GNU General Public
License, version 3 or later; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for upstream and dependency
details.

[upstream]: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97
