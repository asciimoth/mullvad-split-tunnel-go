# Remaining plan: Mullvad Windows driver controller in Go

This document lists the remaining work for `mullvad-split-tunnel-go` in the
order in which it should be done. See the [README](../README.md) for the
implemented API and [VALIDATION.md](../VALIDATION.md) for current test evidence.

## Starting point

The controller API, ABI codecs, overlapped I/O, cancellation, process helpers,
and lifecycle handling are implemented. Portable tests, Windows cross-builds,
and the disposable Windows amd64 live-driver gate pass.

The live-driver gate covers WFP fixture creation, initialization, process
registration, address round-trips, Unicode exclusions, descendants,
configuration changes, events, cancellation, reset, and setup-exit recovery.

## Fixed rules

- Support exact executable-path exclusions and their descendants.
- Use pinned, Mullvad-signed driver binaries. Do not build or modify the driver.
- Support driver 1.3.0.0, pinned to upstream commit `0a0eb97`.
- Keep driver deployment, TUN management, routing, DNS policy, and WFP resource
  ownership outside the core package.
- Treat the global, exclusive `\\.\MULLVADSPLITTUNNEL` device as a shared-system
  resource. Do not stop another VPN service to claim it.
- Accept only a verified package with the expected hash, architecture, signer,
  version, and ABI.

## Step 1: Complete controller-level validation

Add the remaining tests that do not require a complete VPN service.

The automated coverage and its resource, reconciliation, and path-identity
contracts are recorded in
[Controller Step 1 validation](controller-step1-validation.md). Native execution
evidence is stored with each Windows CI run.

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
- The same native smoke suite passes on Windows amd64 and arm64 with the pinned
  driver package for that architecture.

## Step 2: Record packet-flow behavior

Extend the isolated live-driver harness with a controlled network topology:

### Step 2 tests

1. Create isolated tunnel and underlay endpoints with distinct observable
   routes. Do not use the developer's active network as a test target.
1. Run TCP connect, TCP long-lived stream, UDP request-response, and long-lived
   UDP tests over IPv4 and IPv6.
1. Run each case for an excluded executable, its descendant, and a non-excluded
   executable.
1. Repeat the matrix with dual-stack, IPv4-only, and IPv6-only addresses.
1. Add, replace, and clear exclusions while flows are active.
1. Replace tunnel and underlay addresses while flows are active.
1. Record whether each existing flow moves, stops, or keeps its previous policy.
   Then test the policy of a new flow from the same process.
1. Confirm that traffic does not use an unintended path during each change.
1. Repeat the matrix after driver reset and reinitialization.

Do not infer packet behavior from a successful IOCTL. Characterize behavior
first, review the result, and then convert it into regression assertions.

### Step 2 completion gate

- The matrix covers TCP and UDP, IPv4 and IPv6, new and existing flows, and
  excluded, descendant, and non-excluded processes.
- Packet observations prove the selected path; API return values alone are not
  accepted as evidence.
- Address and exclusion changes have documented, repeatable behavior.
- No test leaks traffic to the unintended tunnel or underlay path.
- Reset and reinitialization restore the initial behavior without a guest
  rebuild.

## Step 3: Build the deployment component

Build this component outside the core package:

### Step 3 implementation and tests

1. Define a package manifest for each supported architecture.
1. Record the driver version, source commit, package hashes, signer, controller
   version, and minimum Windows build.
1. Verify the package hash, Authenticode signature, signer, version, and
   architecture before installation.
1. Add SCM install, start, stop, upgrade, and uninstall operations.
1. Add an ownership lock and a recoverable cleanup ledger.
1. Reject unexpected driver state or a device owned by another application.
1. Unit-test manifest parsing, architecture selection, and version comparison.
1. Verify rejection of a changed file, an unsigned file, a wrong signer, a wrong
   architecture, a wrong version, and an incomplete package.
1. Test fresh installation and the already-installed expected package.
1. Test restart, same-version repair, supported upgrade, rollback after a failed
   upgrade, and uninstall.
1. Inject failure after every state-changing operation. Restart the deployment
   process and recover from the cleanup ledger.
1. Test concurrent deployment attempts and an active device owner.
1. Confirm that uninstall removes only resources recorded as owned.

The existing VM harness verifies its pinned test package, but it is not the
production deployment component.

### Step 3 completion gate

- No package reaches SCM before all identity checks pass.
- Architecture selection works on native amd64 and arm64 systems.
- Install, repair, restart, upgrade, rollback, and uninstall pass on fresh
  disposable machines.
- Recovery succeeds after interruption at every recorded mutation point.
- Concurrent or foreign ownership produces a clear error and does not change the
  other owner's service, device, or WFP state.
- A successful uninstall leaves no owned service, package, lock, or ledger
  entry. Failed cleanup leaves enough ledger data for the next recovery run.

## Step 4: Integrate the controller into the service host

Implement one service-owned session in this order:

1. Verify and start the pinned signed package.
1. Create application-owned baseline and DNS sublayers in a non-dynamic WFP
   session. Commit them before driver initialization.
1. Create the TUN and configure caller-owned network resources.
1. Open the driver and require the expected fresh state. Use an explicit
   recovery path for any other state.
1. Initialize the driver.
1. Take and register the process snapshot. Initialization must come first
   because it starts the process watcher.
1. Set the TUN and underlying interface addresses.
1. Set the executable exclusions.
1. Start event reading and network-change monitoring.
1. Refresh addresses and exclusions when external state changes. Reconcile state
   after a timed-out or otherwise uncertain mutation.
1. On shutdown, stop workers, reset with a fresh cleanup context, and close the
   device.
1. Delete referenced WFP objects and other caller-owned resources only after a
   successful reset. Send reset failures to recovery logic.

Do not use dynamic caller WFP sublayers. Do not hold a caller WFP transaction
across a driver IOCTL that changes WFP state.

Keep original DOS executable paths in addition to resolved NT paths. Refresh
them after drive remounts or executable changes. Network executable paths and
glob rules remain unsupported.

### Step 4 tests

1. Unit-test the service state machine with failures before and after every
   setup and teardown operation.
1. Run the complete lifecycle in the disposable live-driver VM.
1. Exit the service after WFP creation, TUN creation, open, initialize, process
   registration, address configuration, and exclusion configuration. Restart it
   and verify recovery.
1. Test an empty and a partial process snapshot. Preserve warnings without
   assigning a recycled parent PID to the wrong process.
1. Start processes before the snapshot, during registration, and after
   configuration. Verify that none are lost from classification.
1. Block an event read while addresses and exclusions change.
1. Test a second service instance and an existing foreign driver owner.
1. Force reset failure. Confirm that referenced WFP objects remain and the
   ledger retains enough information for recovery.
1. Remount a drive or replace an executable and verify path refresh from the
   stored DOS path.
1. Stop the service during active events and control operations.

### Step 4 completion gate

- The state-machine tests cover every transition and cleanup edge.
- The live session reaches ready state and shuts down cleanly from every
  completed startup phase.
- Successful shutdown leaves no controller handle, worker, referenced WFP
  object, TUN, route, or DNS setting owned by the session.
- Failed reset preserves referenced resources and produces an actionable
  recovery record.
- Process startup races do not leave an unclassified process.
- A second or foreign owner is not reset, stopped, or reconfigured.
- Path refresh updates exclusions without losing the user's original path.

## Step 5: Add operational recovery

Add diagnostics, bounded retries, and explicit recovery. Test each condition:

### Step 5 tests

1. Sleep and resume.
1. Base Filtering Engine restart.
1. Service or user-process crash.
1. Driver failure.
1. Adapter and default-route changes.
1. Repeated service start and stop.
1. Loss and restoration of IPv4, IPv6, and dual-stack connectivity.
1. Drive remount and executable replacement while an exclusion is active.
1. Corrupt or incomplete cleanup ledger data.
1. Retry exhaustion and service restart after exhaustion.

For every case, record detection time, retry count, recovery time, final driver
state, final network state, and retained owned resources. Run repeated
start-and-stop and suspend-and-resume loops to expose cumulative leaks.

### Step 5 completion gate

- Each fault either restores the documented ready state within a configured
  bound or enters one stable failure state with an actionable diagnostic.
- Retries are bounded and do not form a busy loop.
- Recovery does not delete or reconfigure resources owned by another
  application.
- A service restart can continue recovery from every retained ledger state.
- Event readers, controller handles, WFP objects, adapters, routes, and DNS
  settings do not show cumulative growth across repeated loops.
- Network changes result in the expected address and path refresh.

## Step 6: Qualify supported Windows configurations

Run the deployment, lifecycle, traffic, and recovery suites on each supported
architecture and Windows version. Include systems with Secure Boot and Memory
Integrity enabled.

### Step 6 tests

1. Define the proposed support matrix before qualification starts.
1. Start each matrix entry from a clean Windows installation.
1. Record the OS build, architecture, firmware mode, Secure Boot state, Memory
   Integrity state, driver package identity, and controller revision.
1. Run deployment, service lifecycle, packet-flow, fault-recovery, restart, and
   uninstall tests on each entry.
1. Reboot after installation and during retained recovery state.
1. Run an extended session with repeated configuration changes and event
   cancellation.
1. Save logs, package verification results, test results, and final cleanup
   checks as qualification evidence.

### Step 6 completion gate

- Every advertised matrix entry has a successful native run with the exact
  pinned Mullvad-signed package.
- Secure Boot and Memory Integrity are measured as enabled for entries that
  claim them; configuration intent is not sufficient evidence.
- Each entry passes install through uninstall, including traffic and recovery
  tests.
- Reboot and extended-session tests do not produce persistent leaks or stale
  policy.
- Failed matrix entries are fixed and rerun, or removed from the support matrix.
  Cross-build results alone do not qualify a platform.

## Step 7: Prepare the first public release

### Step 7 tests

1. Define the stable API and support matrix.
1. Build a clean consumer program from the published module interface and run
   its basic lifecycle on a qualified system.
1. Run all portable, fuzz, cross-build, native, live-driver, traffic,
   deployment, and recovery gates from the release revision.
1. Run vulnerability, license, module-integrity, formatting, lint, and vet
   checks.
1. Complete notices, API documentation, lifecycle examples, and recovery
   instructions.
1. Build release artifacts from a clean checkout. Record their hashes and verify
   them on a second clean machine.
1. Check that documentation does not advertise untested capabilities or
   platforms.
1. Confirm that the release uses only the approved pinned Mullvad-signed driver
   packages.

### Step 7 completion gate

- All required gates pass from the exact release revision.
- The clean consumer test passes without repository-local paths or uncommitted
  files.
- Release artifacts are reproducible through the documented build process and
  match their published hashes.
- Notices cover the module and dependencies, and the documentation records the
  external driver package provenance.
- The support matrix links to the qualification evidence from Step 6.
- Known limitations and recovery actions are documented.
- No release documentation claims untested driver behavior or a platform without
  native evidence.

## Protocol references

Protocol authority remains `src/defs/ioctl.h`, `src/procmgmt/procmgmt.cpp`, and
`src/firewall/firewall.cpp` in the [pinned upstream source][upstream]. The
upstream production controller is also useful for lifecycle comparisons:
[Mullvad Windows controller][mullvad-app].

[mullvad-app]: https://github.com/mullvad/mullvadvpn-app/tree/643a4cd
[upstream]: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97
