# Validation status and commands

Updated 25 September 2026.

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

Run the same portable check set with:

```sh
just check
```

The protocol tests compare Go encoders and decoders with independent C++
fixtures. They exercise malformed data and controller cancellation and lifecycle
behavior through a fake transport. They do not invoke the kernel driver.

The committed ABI fixture was generated from the pinned upstream headers and
passed its original C++ layout assertions. This validation session did not
regenerate it because the upstream checkout was not available.

## Checks that require Windows

The following checks have not run in this environment:

- Native Windows path resolution and process snapshot tests.
- Native arm64 execution.
- Live signed-driver initialization, routing, events, and cancellation.
- Handle-leak and recovery tests against the kernel driver.

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
  tools/abi_fixture.cpp -o abi-fixture
./abi-fixture > abi-generated.json
cmp testdata/abi.json abi-generated.json
```

The fixture verifies structure sizes and offsets and emits reference buffers. It
is not a Windows WDK build or evidence that kernel behavior works.

## Required native-driver gate

Implement the privileged integration harness described by controller-plan
milestone C2. Use a dedicated Windows test VM with the compatible driver,
application-owned WFP sublayers, a working TUN, and no competing owner.

Exercise initialization, process registration, addresses, configuration,
queries, events, and reset. Reject occupied or unexpected state. Stress event
cancellation while control IOCTLs run. Verify that repeated shutdown does not
leak handles. Test Unicode paths, descendants, rule changes, adapter changes,
and traffic for both IP families.

Keep live-driver tests opt-in and separate from ordinary `go test ./...`.
Neither the unit tests nor the diagnostic command installs a driver or creates a
complete routing environment.
