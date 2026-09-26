# Application integration guide

This guide explains how to integrate the `splittunnel` package into a VPN
application. It assumes no detailed knowledge of the Windows network stack. The
contract is limited to Mullvad split-tunnel driver 1.3.0.0 at upstream commit
`0a0eb97`.

## Mental model

There are three separate components:

1. The application owns the VPN connection, TUN interface, routes, DNS policy,
   firewall policy, and the driver service.
1. This Go package sends configuration and queries to the driver.
1. The kernel driver tracks processes and applies WFP filters to selected
   processes.

Traffic normally follows these paths:

```text
included process -> Windows route -> TUN -> application VPN transport
excluded process -> driver bind redirect and WFP filters -> underlay interface
```

An **included** process uses the normal VPN path. An **excluded** process
bypasses the VPN. The driver and its ABI call exclusion "splitting," so a
`ProcessStatus` with `Split == true` describes an excluded process.

The driver does not create a tunnel or move packets through one. It makes
process-aware changes at Windows socket and firewall layers. Windows routes and
the caller's TUN implementation still provide the included path.

## Features

The package and target driver support:

- exclusion by executable path, with case-insensitive path comparison in the
  driver;
- inheritance by processes that start as children of excluded processes;
- an initial process-tree snapshot followed by continuous arrival and departure
  tracking;
- replacement of the exclusion set while processes are running;
- replacement of IPv4 and IPv6 tunnel and underlay addresses;
- blocking of an excluded process's existing tunnel connections when its
  classification changes;
- process classification and error events;
- process classification queries; and
- cancellable driver I/O with bounded protocol parsing.

Exclusion is not a general per-PID routing mechanism. There is no include-only
list, packet capture, socket-owner query, DNS attribution, TUN implementation,
route manager, driver installer, or kill switch in the package.

## Caller-owned resources

The controller does not take ownership of its dependencies.

| Resource                   | Caller responsibility and lifetime                                                                                                            |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Driver package and service | Install, verify, and start the compatible signed driver before `Open`. Stop or update it only after policy is reset and the handle is closed. |
| TUN and VPN transport      | Create the interface, assign its addresses, install routes, and carry packets. Keep it usable for the full engaged session.                   |
| Underlay selection         | Select the current non-tunnel interface address for each family and monitor address or default-route changes.                                 |
| WFP sublayers              | Create the baseline and DNS sublayers before `Initialize`. Keep them until `Reset` is confirmed.                                              |
| DNS and firewall policy    | Define DNS, leak-prevention, LAN, and kill-switch behavior around the driver filters.                                                         |
| Controller                 | Ensure that only one component owns the global device and its recovery state.                                                                 |

WFP is the Windows Filtering Platform, the system API used for firewall and
socket filters. A WFP sublayer groups filters and determines their ordering
relative to filters from the VPN firewall. The driver puts its general filters
in `Sublayers.Baseline` and its DNS-specific permit filters in `Sublayers.DNS`.

Both sublayers must already exist, have distinct nonzero GUIDs, and be
compatible with the caller's filter ordering. Create them in a non-dynamic WFP
session and commit the WFP transaction before `Initialize`. The driver creates
its own dynamic session, which cannot refer to dynamic objects from another
session. Do not keep a caller WFP transaction open while a controller call
changes WFP.

If initialization was attempted, keep the sublayers until reset succeeds even
when `Initialize` returned an error or its context expired. The operation can
have reached the driver before cancellation was reported.

## Driver state and allowed operations

The driver uses a fixed bootstrap sequence.

| State              | Meaning                                                                                                | Controller operations                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| `StateStarted`     | The service and device exist, but driver subsystems are not initialized.                               | `State`, `Initialize`, `Reset`                           |
| `StateInitialized` | WFP, eventing, and process monitoring are initialized. The initial process tree is not registered yet. | `State`, `RegisterProcesses`, `ReadEvent`, `Reset`       |
| `StateReady`       | The process registry is complete. No exclusion is currently active.                                    | Address, exclusion, query, and event operations; `Reset` |
| `StateEngaged`     | At least one supported traffic-splitting mode is active.                                               | The same operations as `Ready`; `Reset`                  |
| `StateZombie`      | Driver teardown failed. Normal requests and another reset are rejected by this driver version.         | `State`; recovery is outside the normal controller API   |

`StateNone` is an internal pre-start value. A normally opened, fully loaded
driver is not expected to expose it.

The controller checks the required state before most commands. It never resets
an unexpected state automatically. If `Open` succeeds and `State` is not
`StateStarted`, assume that policy from an earlier or current owner exists. Do
not overwrite or reset it until the application has established ownership and
chosen an explicit recovery action.

All control operations on one `Controller` are serialized. One `ReadEvent` can
run at the same time as a control operation. Use only one event reader to retain
delivery order. The controller must not be copied.

### Public API map

| API                                         | Purpose and state requirement                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `Open`                                      | Open the exclusive device without changing state. The driver must already be installed and running.                     |
| `State`                                     | Read any driver state. Use it before assuming ownership or after an uncertain mutation.                                 |
| `Initialize`                                | Supply the two caller-owned WFP sublayers. Requires `Started`.                                                          |
| `SnapshotProcesses`                         | Take the Windows process snapshot. Call it after `Initialize`; inspect `Snapshot.Warnings`.                             |
| `RegisterProcesses`                         | Seed the process registry once. Requires `Initialized`.                                                                 |
| `SetAddresses`, `Addresses`                 | Replace or read all four address roles. Require `Ready` or `Engaged`.                                                   |
| `SetExcludedPaths`                          | Resolve Win32 executable paths and replace the full exclusion set. Requires `Ready` or `Engaged` for the policy change. |
| `SetExcludedDevicePaths`                    | Replace the full set using exact NT device paths. This advanced form requires `Ready` or `Engaged`.                     |
| `ExcludedDevicePaths`, `ClearConfiguration` | Read normalized NT paths or clear the set. Require `Ready` or `Engaged`.                                                |
| `QueryProcess`                              | Read one process-tree classification. Requires `Ready` or `Engaged`.                                                    |
| `ReadEvent`                                 | Wait for one queued event. The driver accepts it in `Initialized`, `Ready`, or `Engaged`.                               |
| `Reset`                                     | Tear down driver subsystems and policy. A successful call returns the driver to `Started`.                              |
| `Shutdown`                                  | Attempt `Reset`, then always `Close`, and return both errors.                                                           |
| `Close`                                     | Cancel and drain local I/O, then close the handle. It never resets driver policy.                                       |
| `ResolveDevicePath`, `ParseGUID`            | Convert application inputs to driver wire values. `ResolveDevicePath` accesses the Windows filesystem.                  |

## Correct startup sequence

Use this order for a new session:

1. Verify and start the pinned driver package.
1. Call `Open`, then `State`. Continue only from `StateStarted`. This
   establishes exclusive ownership before the application creates session
   resources.
1. Create and configure the TUN, routes, VPN transport, firewall, and two
   persistent WFP sublayers.
1. Call `Initialize` with the two sublayer GUIDs. On success, the state becomes
   `StateInitialized`, and the driver starts buffering process changes.
1. Call `SnapshotProcesses` **after** `Initialize`. Log every warning, but keep
   the corresponding process entries. Protected system processes can have
   incomplete metadata.
1. Call `RegisterProcesses` once with the complete snapshot. The driver merges
   process changes that arrived while the snapshot was taken and enters
   `StateReady`.
1. Call `SetAddresses` with current local tunnel and underlay addresses.
1. Call `SetExcludedPaths` with the complete list of executable paths. This can
   move the driver to `StateEngaged`.
1. Start one `ReadEvent` loop. Also monitor the underlay, TUN, routes, excluded
   files, and application policy. Replace driver values when they change.
1. During shutdown, stop and join the event and monitoring workers. Call
   `Shutdown` with a fresh bounded context. Release WFP sublayers and network
   resources only after reset succeeds.

[The session example](../examples/session/session.go) implements the controller
part of this sequence. It intentionally accepts WFP and network resources that
the application has already created.

### Process bootstrap

The order of `Initialize`, `SnapshotProcesses`, and `RegisterProcesses` closes a
process-tracking race. Initialization activates the driver's process monitor.
The user-mode snapshot can then run while the driver buffers new process events.
Registration seeds the initial tree, and the driver reconciles buffered events.

Do not take the snapshot before initialization. Do not remove entries only
because their image path or creation time could not be read. An entry with an
empty image path still helps the driver preserve the process tree. The helper
clears parent references that it cannot verify safely against PID reuse.

## Address model

`Addresses` contains one local address for each role and IP family:

- `TunnelIPv4` and `TunnelIPv6` are addresses assigned to the VPN/TUN interface.
- `InternetIPv4` and `InternetIPv6` are addresses assigned to the selected
  physical or other non-tunnel interface.

An Internet address is not the default gateway, a remote VPN server, the public
NAT address, or a destination address. The ABI can hold only one address for
each role and family. The application must choose the effective underlay
interface and update the driver when it changes.

Use an invalid `netip.Addr`, such as `netip.Addr{}`, for an unavailable role. An
unspecified address also encodes as unavailable. The package rejects an address
in the wrong family, an address with an IPv6 zone, loopback or multicast
addresses, and IPv6 link-local addresses. An IPv4 field accepts an IPv4-mapped
IPv6 value and encodes its unmapped IPv4 address; an IPv6 field rejects such a
value. For each family, the tunnel and Internet addresses must differ.

The driver becomes engaged only when the exclusion set is nonempty, at least one
tunnel address is available, and the four availability flags form one of these
driver modes:

| Mode | Internet v4 | Tunnel v4 | Internet v6 | Tunnel v6 | Driver action for excluded processes      |
| ---: | :---------: | :-------: | :---------: | :-------: | ----------------------------------------- |
|    1 |     yes     |    yes    |     yes     |    yes    | Exclude IPv4 and IPv6                     |
|    2 |     yes     |    yes    |     no      |    no     | Exclude IPv4                              |
|    3 |     yes     |    yes    |     yes     |    no     | Exclude IPv4; permit non-tunnel IPv6      |
|    4 |     yes     |    yes    |     no      |    yes    | Exclude IPv4; block tunnel IPv6           |
|    5 |     no      |    no     |     yes     |    yes    | Exclude IPv6                              |
|    6 |     yes     |    no     |     yes     |    yes    | Exclude IPv6; permit non-tunnel IPv4      |
|    7 |     no      |    yes    |     yes     |    yes    | Exclude IPv6; block tunnel IPv4           |
|    8 |     no      |    yes    |     yes     |    no     | Block tunnel IPv4; permit non-tunnel IPv6 |
|    9 |     yes     |    no     |     no      |    yes    | Block tunnel IPv6; permit non-tunnel IPv4 |

Here, **exclude** means redirect socket binds away from the tunnel, permit
non-tunnel traffic, and block existing tunnel connections. Explicit block modes
prevent traffic from leaking into a tunnel when no corresponding underlay
address is available. Explicit permit modes let excluded traffic pass the
caller's restrictive VPN firewall when no tunnel exists for that family.

The common configurations are all four addresses for dual stack, or one matched
Tunnel/Internet pair for a single IP family. Other combinations in the table
support safe transition states. A combination outside the table can pass local
Go validation but the driver rejects it when it tries to engage.

Setting both tunnel roles unavailable returns an engaged driver to `StateReady`.
It preserves the stored exclusion set. Restoring a supported tunnel address
combination engages it again. Clearing the exclusion set also returns the driver
to `StateReady` while preserving its addresses.

## Exclusion paths

`SetExcludedPaths` is the normal application API. It accepts existing absolute
local drive-letter paths, such as `C:\Program Files\Example\app.exe`, resolves
them through file handles, and replaces the complete exclusion set. Resolution
accounts for volume mappings and junctions. An empty slice clears the set.

The driver stores lower-case NT device paths, such as
`\Device\HarddiskVolume3\Program Files\Example\app.exe`, and compares paths
without case sensitivity. The path is not a persistent file identity. Rename,
replacement, hard-link, or volume-mount changes can require a new configuration.
A hard link with another name must be excluded separately. UNC and other network
executable paths are not supported.

`SetExcludedDevicePaths` is the lower-level form for callers that already have
exact NT device paths. `ExcludedDevicePaths` returns those normalized driver
paths, not drive-letter paths. Returned order is not stable. Both setter methods
replace the full set; they do not add one entry.

The driver applies a path match to current and new processes. A child that
starts from an excluded parent inherits exclusion even when its own image path
is not listed. Inheritance follows the actual Windows process tree. For example,
asking an already-running browser process to open a window over IPC does not
create a child of the requesting excluded process.

## Events and queries

Run one cancellable event loop after process registration. `ReadEvent` returns
one event for each call and can wait while other controller methods run.

| Event                 | Relevant fields              | Meaning                                                    |
| --------------------- | ---------------------------- | ---------------------------------------------------------- |
| `EventStartSplitting` | `PID`, `Reason`, `ImagePath` | The process became excluded.                               |
| `EventStopSplitting`  | `PID`, `Reason`, `ImagePath` | The process stopped being excluded or departed.            |
| Splitting error IDs   | `PID`, `ImagePath`           | The driver could not complete a process splitting change.  |
| `EventErrorMessage`   | `NTStatus`, `Message`        | A driver or WFP operation reported an error.               |
| Unknown ID            | `Raw`                        | A future or unknown payload was preserved for diagnostics. |

`Reason` is a bit field for inheritance, configuration change, process arrival,
and process departure. More than one flag can be present, such as arrival plus
configuration. Driver 1.3.0.0 incorrectly emits `EventErrorStopSplitting` for
both start and stop failures. Test error IDs with `EventID.IsSplittingError` and
do not infer a direction from the specific ID.

`QueryProcess` returns the driver's process-tree classification. It is not a
query for a socket owner or an assurance about a packet path. Packet capture on
the tunnel and underlay is the appropriate end-to-end validation.

## Driver limitations visible to users

The application must account for these behaviors of driver 1.3.0.0:

- Windows normally performs a process's DNS request through the `dnscache`
  service in a `svchost` process. The driver sees `svchost`, not the requesting
  excluded process, so ordinary DNS normally remains in the VPN. An application
  that performs its own DoH or DoT can avoid the system resolver.
- An excluded UDP client can fail to communicate with IPv4 localhost unless it
  explicitly binds to `127.0.0.1`. Windows can first show an unbound socket as
  bound to all interfaces, and the driver redirects that bind to the underlay.
- Multicast reception can fail without a socket API error. The driver redirects
  the socket bind, but an `inaddr_any` multicast membership can remain
  associated with a different interface.
- Process inheritance follows the process tree, not user intent. IPC to an
  existing process, such as an existing browser, does not transfer the caller's
  excluded classification.

There is no general driver workaround for localhost UDP or multicast reception.
Document these limits in the product UI or support material when affected
applications can use those protocols.

## Reconfiguration

Both configuration setters are replacement operations:

- call `SetAddresses` whenever the TUN or selected underlay address changes;
- call `SetExcludedPaths` whenever the desired executable set or a resolved file
  path changes; and
- call `ClearConfiguration` to remove all exclusions.

Address monitoring must cover adapter, address, and default-route changes. The
driver does not select the primary interface. When the VPN is temporarily down,
mark tunnel roles unavailable instead of leaving stale tunnel addresses.

Changes that affect active WFP state use driver transactions and reauthorize
affected connections. Changes made while the driver is idle can update stored
configuration without changing WFP. A successful setter has replaced the whole
value. A context deadline is different: cancellation of `DeviceIoControl` is not
a transaction boundary, so the driver might have committed the change before the
caller receives the cancellation error.

After a cancelled mutation, reconcile with a fresh context:

- read `State` after `Initialize` or `RegisterProcesses`;
- read `Addresses` after `SetAddresses`;
- read `ExcludedDevicePaths` after an exclusion change; and
- after a cancelled `Reset`, inspect `State` on the same controller with a fresh
  context; close and reopen only if the handle is no longer usable.

## Shutdown and recovery

`Close` is idempotent. It cancels and drains local I/O, closes the Windows
handle, and causes later calls to match `os.ErrClosed`. It does **not** clear
exclusions, tear down driver subsystems, remove filters, stop the service, or
delete caller resources.

`Shutdown` calls `Reset` and then `Close`, and returns both errors with
`errors.Join`. Before calling it, cancel and join the event reader so shutdown
does not race application work. Use a new timeout context for cleanup instead of
a request context that is already cancelled.

If reset succeeds, the driver returns to `StateStarted`; the caller can then
delete its WFP sublayers and tear down the TUN and routes. If reset fails, keep
the sublayers and any recovery metadata. Removing referenced WFP objects can
make recovery harder. A reset teardown failure can put this driver version in
`StateZombie`, where it rejects another reset. Preserve diagnostic and ownership
data, and use a deployment-specific recovery procedure. Do not delete referenced
WFP objects or continue policy mutations.

For crash recovery, use stable ownership metadata for the driver service and WFP
sublayer GUIDs. On the next start, inspect state before changing anything. An
open handle excludes a concurrent controller, but policy in a non-`Started`
state can depend on persistent resources from an earlier owner. Reset it only
through an explicit recovery path.

## Error handling and concurrency

Controller commands include operation context, and controller methods preserve
causes for `errors.Is`. In addition to Windows errors, handle:

- `ErrInvalidArgument`: a value cannot be represented safely by this ABI;
- `ErrState`: the operation is not valid in the observed driver state;
- `ErrProtocol`: the installed driver returned malformed or incompatible data;
- `context.Canceled` and `context.DeadlineExceeded`; and
- `os.ErrClosed` after or during `Close`.

Treat `ErrProtocol` as a compatibility or driver fault and stop policy changes.
Treat `ErrState` as an ownership or recovery signal and inspect state. Do not
modify slices passed to controller methods until the call returns.

Control calls are serialized, so only one control IOCTL runs at a time.
Submission order between racing goroutines is not an API contract. Use one
application policy owner to sequence address and exclusion updates.

Path resolution is separate from the command lane, so a slow filesystem lookup
does not block `State` or another control command. Windows path resolution is a
synchronous filesystem call. Cancellation stops waiting for it, but the helper
goroutine can remain until Windows completes the call. The controller permits
only one such resolution job at a time.

## Evidence and further reading

The behavior in this guide is based on the package implementation and tests, the
committed C++ ABI fixture, and the pinned upstream source:

- [controller implementation](../controller.go)
- [public value types](../types.go)
- [complete controller lifecycle example](../examples/session/session.go)
- [pinned upstream driver architecture and mode matrix][upstream-readme]
- [pinned upstream state definitions][upstream-state]
- [pinned upstream IOCTL definitions][upstream-ioctl]
- [repository validation record](../VALIDATION.md)

[upstream-ioctl]: https://github.com/mullvad/win-split-tunnel/blob/0a0eb97f67d1dbcb3d08bda66d3b24f465d95475/src/defs/ioctl.h
[upstream-readme]: https://github.com/mullvad/win-split-tunnel/blob/0a0eb97f67d1dbcb3d08bda66d3b24f465d95475/README.md
[upstream-state]: https://github.com/mullvad/win-split-tunnel/blob/0a0eb97f67d1dbcb3d08bda66d3b24f465d95475/src/defs/state.h
