# Validation status and commands

Updated 26 September 2026.

## Verified on Linux

The following checks pass in the pinned Nix development environment:

- Go formatting and module tidiness.
- golangci-lint and `go vet`.
- Unit tests with the race detector.
- A 10-second `FuzzDriverDecoders` run.
- Native Linux compilation of the unsupported-platform implementation.
- Windows amd64 and arm64 cross-compilation with cgo disabled.
- Windows amd64 and arm64 test-binary compilation.
- `govulncheck`, with no known vulnerabilities reported.
- Nix, GitHub Actions, spelling, and repository configuration checks.
- Host-only VM harness tests for locks, packaging, overlays, QGA/QMP, bounded
  output, timeouts, cleanup, and packet-evidence acceptance and rejection.

Run every quality check and test gate with:

```sh
just check
```

Run only the test suites, including both disposable Windows VM runs on Linux,
with:

```sh
just test-total
```

`just check` includes `test-total`. The standalone `test-total` recipe does not
run formatting, linting, vetting, or build-only checks.

The protocol tests compare Go encoders and decoders with independent C++
fixtures. They exercise malformed data and controller cancellation and lifecycle
behavior through a fake transport. They do not invoke the kernel driver.

The committed ABI fixture was generated from the pinned upstream headers and
passed its original C++ layout assertions. This validation session did not
regenerate it because the upstream checkout was not available.

## Verified in the Windows VM

The amd64 Windows Server 2022 VM gates pass with the locked installation and
VirtIO media and the pinned signed driver 1.3.0.0:

- Native path resolution and process snapshot tests run as the standard `winvm`
  account.
- The dirty working tree passes module verification, tidiness, vet, tests, and
  build in the guest.
- The live gate verifies the staged and installed driver hashes, version,
  service configuration, and Authenticode signer before service start.
- Four warm-up and four measured controller lifecycles pass as `SYSTEM`,
  including WFP fixture creation, initialization, process registration, IPv4 and
  IPv6 address round-trips, Unicode exclusions, descendant state, configuration
  changes, events, cancellation, and reset.
- One hundred measured event-read cancellations pass after warm-up while state
  and address queries run. The four batches stay at 161 handles and two
  goroutines in the recorded run.
- Cancellation before a read, during pending I/O, and during controller close
  passes. The close case reopens and reconciles the retained driver state.
- Normal and extended-prefix launches resolve to one driver path. A hard-link
  launch uses its separate hard-link path and needs a separate exclusion.
- Recovery passes after setup exits at the WFP, open, initialize, register, and
  configure phases. The driver service is stopped after the gate.
- Invalid calls in the `Initialized` and `Ready` states preserve driver state.
  `Shutdown` resets policy, closes the controller, and permits a new controller
  to observe `Started`.
- The live gate saves a native controller coverage profile and per-function
  report. The recorded run covered 80.1% of controller-package statements.
- The isolated two-guest flow gate validates 1,486 packet observations. Its
  first 1,472 observations cover TCP and UDP, IPv4 and IPv6, request-response
  and long-lived flows, all three process roles, all nine driver address modes,
  restrictive filters in the baseline and DNS sublayers, active configuration
  and address changes, and a complete reset and reinitialization cycle.
- The other 14 observations run `cmd/tunneldemo` with a real Wintun adapter and
  controlled peer. Included traffic uses the encapsulated path. An exact
  exclusion and its descendant use the direct underlay. Two included UDP flows
  use 1,100-byte payloads. The command consumes a process event, returns the
  driver to `Started`, removes its adapter, rejects a competing owner before it
  creates resources, and starts and cleans up again.
- Link captures confirm every selected path and reject markers on the opposite
  link. The observed change contracts are recorded in
  [Controller Step 2 validation](docs/controller-step2-validation.md) and
  [Controller Step 3 validation](docs/controller-step3-validation.md).

The workflow now runs the native unit and signed-driver suites on Windows amd64
and arm64 GitHub-hosted runners. Native arm64 execution has not run in this
local validation session. Native arm64 packet-flow tests have not run.

On Windows amd64, `go test ./...` exercises native path resolution and process
snapshotting without requiring the driver or elevation. Cross-compile arm64
separately:

```powershell
$env:GOOS = 'windows'
$env:GOARCH = 'arm64'
$env:CGO_ENABLED = '0'
go build ./...
go test -c -o controller-arm64.test.exe .
```

Cross-compilation does not replace tests on a Windows arm64 host.

## Reproduce the upstream fixture check

Check out `mullvad/win-split-tunnel` at commit `0a0eb97` next to this
repository, then run:

```sh
just abi
```

The underlying commands use a 64-bit C++17 compiler:

```sh
g++ -std=c++17 -Wall -Wextra -Werror \
  -I ../win-split-tunnel/src \
  -I tools/abi_compat tools/abi_fixture.cpp -o abi-fixture
./abi-fixture > abi-generated.json
cmp testdata/abi.json abi-generated.json
```

The fixture verifies structure sizes and offsets and emits reference buffers. It
is not a Windows WDK build or evidence that kernel behavior works.

## Native-driver gate

The privileged integration harness validates the controller against the driver
in a dedicated disposable VM. It uses the compatible driver, test-owned
persistent WFP sublayers, and no competing owner. Run it alone with:

```sh
just test-windows-e2e
just test-windows-flow
```

The live gate exercises initialization, process registration, addresses,
configuration, queries, events, cancellation, reset, Unicode paths, descendants,
and rule changes. The separate flow gate covers packet paths, controlled
adapter-address changes, and the Wintun-backed tunnel example.

Live-driver tests remain separate from ordinary `go test ./...`. They are part
of the explicit `test-total` gate. Neither unit tests nor the diagnostic command
changes the installed driver.

The Nix development environment provides the pinned signed driver package for
each supported architecture. Enter `nix develop` and copy the matching directory
from `$MULLVAD_SPLIT_TUNNEL_DRIVER_DIR` to the dedicated Windows test VM. You
can also build a transferable directory with `nix build .#windows-test-drivers`.
The package contains the catalog, setup-information file, and driver binary. It
does not provide the integration harness, WFP sublayers, TUN, routes, or DNS
policy.
