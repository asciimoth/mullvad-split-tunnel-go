# Remaining plan: Mullvad Windows driver controller library

This document lists the remaining work for `mullvad-split-tunnel-go` in the
order in which it should be done. See the [README](../README.md) for the
implemented API and [VALIDATION.md](../VALIDATION.md) for current test evidence.

## Starting point

The controller API, ABI codecs, overlapped I/O, cancellation, process helpers,
and lifecycle handling are implemented. Portable tests, Windows cross-builds,
and the disposable Windows amd64 live-driver gate pass.

The live-driver gate covers WFP fixture creation, initialization, process
registration, address round-trips, Unicode exclusions, descendants,
configuration changes, events, cancellation, reset, and setup-exit recovery. The
controller exposes all IOCTLs in the pinned driver. The remaining work adds a
small end-to-end tunnel command, qualifies the supported Windows matrix, and
prepares the public API release.

## Fixed rules

- Support exact executable-path exclusions and their descendants.
- Use pinned, Mullvad-signed driver binaries. Do not build or modify the driver.
- Support driver 1.3.0.0, pinned to upstream commit `0a0eb97`.
- Treat the global, exclusive `\\.\MULLVADSPLITTUNNEL` device as a shared-system
  resource. Do not interfere with another process that owns it.
- Run live tests only with verified driver files that have the expected hash,
  architecture, signer, version, and ABI.

## Step 1: Complete controller-level validation

This step is implemented. The portable suite, signed-driver suite, and ABI CI
gate contain the tests below. Native execution evidence is stored with each
Windows CI run.

The automated coverage and its resource, reconciliation, and path-identity
contracts are recorded in
[Controller Step 1 validation](controller-step1-validation.md).

### Step 1 tests

1. Repeat event cancellation while control operations run.
1. Cover cancellation before an event read starts, while it is pending, and
   while the controller closes.
1. Run at least 100 read-and-cancel cycles after a warm-up period. Record the
   process handle and goroutine counts between equal-sized batches.
1. Repeat complete open, initialize, event-read, reset, and close cycles.
1. Confirm that address and state queries continue while an event read blocks.
1. Inject timeouts into each mutating operation and verify that the caller can
   read and reconcile the resulting state.
1. Test exclusions through hard links and alternate executable launch paths.
   Record how the driver identifies each path.
1. Start and stop processes between the initial snapshot and process
   registration. Confirm that buffered arrival and departure notifications leave
   the driver with the correct process registry.
1. Verify arrival and departure event reasons, and reset the driver while an
   event dequeue is pending.
1. Extend the C++ ABI fixture to cover `ST_IP_ADDRESSES`, every state, event ID,
   and reason value, and every event payload variant. Add matching decoder and
   malformed-response tests.
1. Run the native unit suite and the live-driver smoke suite on Windows arm64.

### Step 1 completion gate

- All pending I/O completes or is drained before its buffers are reused.
- Cancellation returns the correct context error and does not block later
  control operations.
- Handle and goroutine counts do not show persistent growth across stress
  batches or complete session cycles.
- Every uncertain mutation has a tested reconciliation path.
- Hard-link and alternate-launch behavior is documented and has regression
  coverage.
- Process changes during snapshot registration are not lost or assigned to a
  recycled PID.
- The committed ABI fixture independently covers every public wire structure and
  enum used by the controller.
- The same native smoke suite passes on Windows amd64 and arm64 with the pinned
  driver package for that architecture.

## Step 2: Record packet-flow behavior

This step is implemented. The isolated topology, complete automated matrix,
observed contracts, and retained artifacts are described in
[Controller Step 2 validation](controller-step2-validation.md).

Extend the isolated live-driver harness with a controlled network topology:

### Step 2 tests

1. Create isolated tunnel and underlay endpoints with distinct observable
   routes. Do not use the developer's active network as a test target.
1. Run TCP connect, TCP long-lived stream, UDP request-response, and long-lived
   UDP tests over IPv4 and IPv6.
1. Run each case for an excluded executable, its descendant, and a non-excluded
   executable.
1. Repeat the matrix with dual-stack, IPv4-only, and IPv6-only addresses.
1. Cover all nine address-availability modes documented by the driver, including
   tunnel-only and Internet-only families. Verify the explicit block and permit
   behavior; do not treat every incomplete address pair as normal tunnel policy.
1. Add, replace, and clear exclusions while flows are active.
1. Replace tunnel and underlay addresses while flows are active.
1. Record whether each existing flow moves, stops, or keeps its previous policy.
   Then test the policy of a new flow from the same process.
1. Confirm that traffic does not use an unintended path during each change.
1. Add restrictive synthetic WFP filters to the caller-owned baseline and DNS
   sublayers. Verify the driver's permit and block behavior against those
   filters, including the DNS-sublayer interaction. If this cannot be tested,
   document it as unqualified behavior.
1. Repeat the matrix after driver reset and reinitialization.

Do not infer packet behavior from a successful IOCTL. Characterize behavior
first, review the result, and then convert it into regression assertions.

### Step 2 completion gate

- The matrix covers TCP and UDP, IPv4 and IPv6, new and existing flows, and
  excluded, descendant, and non-excluded processes.
- The matrix covers all nine driver address modes, including asymmetric address
  availability and fail-closed behavior.
- Packet observations prove the selected path; API return values alone are not
  accepted as evidence.
- WFP interaction tests prove the documented permit and block behavior, or the
  release documentation explicitly excludes that behavior from qualification.
- Address and exclusion changes have documented, repeatable behavior.
- No test leaks traffic to the unintended tunnel or underlay path.
- Reset and reinitialization restore the initial behavior without a guest
  rebuild.

## Step 3: Add a minimal tunnel example

This step is implemented. The command, controlled peer, isolated regression
gate, resource contracts, and walkthrough are described in
[Controller Step 3 validation](controller-step3-validation.md) and
[Minimal tunnel demonstration](tunneldemo.md).

Add a Windows-only `cmd/tunneldemo` command that creates a real TUN-backed
tunnel to a controlled peer and uses the public controller API to apply split
tunneling. Keep it small and test-oriented. It is an executable usage example,
not a production VPN client.

### Step 3 implementation and tests

1. Create and configure the TUN adapter, routes, addresses, and required WFP
   sublayers. Keep ownership of each resource explicit.
1. Implement the minimum packet transport needed to exchange IPv4 and IPv6
   traffic with a controlled peer. Document the transport and its security
   limits; do not describe it as suitable for untrusted networks.
1. Open and initialize the split-tunnel driver, register the process snapshot,
   set tunnel and underlay addresses, and configure executable exclusions.
1. Accept exclusions and tunnel configuration through command-line flags. Make
   the selected tunnel and bypass paths visible in concise diagnostic output.
1. Use the controller's event API to keep process registration correct while the
   command runs.
1. Demonstrate one non-excluded process using the tunnel and one excluded
   process, including a descendant, using the underlay.
1. Shut down workers in order, reset the driver, and remove only the TUN, route,
   and WFP resources that the command created. Preserve resources needed for
   recovery if reset fails.
1. Reject an unexpected driver state or an existing owner without changing its
   configuration. Do not install, update, stop, or remove the driver.
1. Add an isolated VM test that runs the command against the controlled peer and
   proves the path used by TCP and UDP traffic. Do not use the developer's
   active network or a public service as test evidence.
1. Document a short, reproducible walkthrough that builds the command, starts
   the peer, selects an executable exclusion, verifies both paths, and performs
   cleanup.

### Step 3 completion gate

- A user can run the documented walkthrough on a prepared Windows test system
  and observe tunneled and excluded traffic through distinct paths.
- The command uses only the published library API; it does not depend on test
  internals or repository-local package replacements.
- The isolated test proves packet paths independently of controller return
  values.
- Normal shutdown leaves no command-owned driver policy, TUN adapter, route, or
  WFP object behind. Failure output identifies resources that require recovery.
- The documentation clearly separates the example from a production VPN and
  lists its security and operational limitations.

## Step 4: Qualify the library on supported Windows configurations

Run the controller lifecycle and packet-flow suites on each supported
architecture and Windows version.

### Step 4 tests

1. Define the proposed support matrix before qualification starts.
1. Record the OS build, architecture, driver identity, and controller revision.
1. Run native unit, live-driver, packet-flow, cancellation, and lifecycle tests
   on each matrix entry.
1. Run an extended controller session with repeated configuration changes and
   event cancellation.
1. Save driver verification results, test results, logs, and resource
   measurements as qualification evidence.

### Step 4 completion gate

- Every advertised matrix entry has a successful native run with the exact
  pinned Mullvad-signed driver files.
- Controller lifecycle and packet-flow tests pass on amd64 and arm64.
- Extended controller sessions do not leak handles or goroutines and do not
  leave stale driver policy after a successful reset.
- Failed matrix entries are fixed and rerun, or removed from the support matrix.
  Cross-build results alone do not qualify a platform.

## Step 5: Prepare the first public library release

### Step 5 tests

1. Define the stable API and support matrix.
1. Build a clean example program from the published module interface and run the
   controller lifecycle on a qualified system.
1. Run all portable, fuzz, cross-build, native, live-driver, traffic,
   cancellation, and lifecycle gates from the release revision.
1. Run vulnerability, license, module-integrity, formatting, lint, and vet
   checks.
1. Complete notices, API documentation, lifecycle examples, and controller
   error-handling guidance.
1. Build and run `cmd/tunneldemo` from the published module interface on a
   qualified system. Confirm that the documented split-tunnel demonstration
   still works.
1. Document the controller's 16 MiB buffer limit, 65,536-record limit, exact
   path behavior, and unsupported UNC resolver paths.
1. Document the upstream DNS, localhost UDP, and multicast limitations.
1. Remove stale `starter` and `future sysnet-windows` wording from package and
   example documentation.
1. Review the `golang.org/x/sys` version and either update it or record why the
   existing pin is retained.
1. Verify the module from a clean checkout and from a separate Go module.
1. Check that documentation does not advertise untested capabilities or
   platforms.
1. Confirm that live tests use only the approved pinned Mullvad-signed driver
   files.

### Step 5 completion gate

- All required gates pass from the exact release revision.
- The clean example test passes without repository-local paths or uncommitted
  files.
- The published module contains the documented packages and no unintended files.
- Notices cover the module and its dependencies, and the documentation records
  the external driver provenance used for live tests.
- The support matrix links to the qualification evidence from Step 4.
- The minimal tunnel walkthrough passes from the release revision and uses only
  documented public APIs.
- Known controller limitations and error-handling requirements are documented.
- No release documentation claims untested driver behavior or a platform without
  native evidence.

## Protocol references

Protocol authority remains `src/defs/ioctl.h`, `src/procmgmt/procmgmt.cpp`, and
`src/firewall/firewall.cpp` in the [pinned upstream source][upstream].

[upstream]: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97
