# Plan: sysnet-windows using the Mullvad controller

This is an implementation plan for a separate Windows `sysnet.System` backend.
This repository implements only the driver controller used by that backend.

## Target and architectural decision

Implement `github.com/asciimoth/gonnect/sysnet.System` in a new `sysnet-windows`
module. Use Wintun for IP packet I/O, Windows networking APIs for adapter
configuration, and the separate Mullvad controller for executable-tree
exclusions.

Pin the interface before starting: this plan uses
[gonnect commit 7b8016f][gonnect] and compares
[sysnet-linux commit 2e947b8][sysnet-linux]. Copy Linux's separation of TUN
management, routing, DNS, rule validation, ownership, and rollback. Implement
Windows mechanisms independently.

For the first release, target Windows amd64/arm64 and a supported Windows build
at least as new as Windows 10 build 19041, which is required by the proposed
interface-DNS API. A lower Windows minimum requires a different DNS backend. See
the [Microsoft NetIO API documentation][netioapi].

The basic product is a default TUN with optional exact executable-tree
exclusions, protected outbound networking/DNS, and best-effort socket matchers.
Include-only routing and strict mode are later projects.

## Components and tools

- **Packet I/O**
  - **Implementation direction:** Reuse `github.com/asciimoth/tuntap`'s Windows
    backend, which already returns a `gonnect/tun.Tun` and exposes
    `LUID() uint64`
- **Adapter addresses, routes, metrics, MTU**
  - **Implementation direction:**
    `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg` or narrow IP Helper
    bindings
- **Excluded executable trees**
  - **Implementation direction:** The separate `mullvad-split-tunnel-go`
    controller
- **WFP objects and later firewall policy**
  - **Implementation direction:** Direct `Fwpm*` bindings or audited
    `inet.af/wf` support
- **Socket protection**
  - **Implementation direction:** `IP_UNICAST_IF` / `IPV6_UNICAST_IF` in socket
    creation hooks
- **DNS configuration**
  - **Implementation direction:** `GetInterfaceDnsSettings`,
    `SetInterfaceDnsSettings`, explicit resolver transport
- **Socket attribution**
  - **Implementation direction:** Existing gonnect `sockowner` Windows
    implementation, with correctness fixes and caching
- **Privileged hosting**
  - **Implementation direction:** Caller runs elevated, or a dedicated Windows
    service hosts this backend and exposes application-specific IPC
- **Monitoring and lifecycle**
  - **Implementation direction:** IP Helper route/address/interface
    notifications; gonnect `Spawner`; explicit resource ownership

Sources: [tuntap Windows backend][tuntap], [winipcfg API][w],
[WFP wrapper API](https://pkg.go.dev/inet.af/wf),
[Wintun distribution](https://www.wintun.net/).

The current `tuntap` Windows `ForceMTU` updates its local value and event
stream; the backend must also set the native interface MTU. Treat DLL/driver
deployment as an application responsibility. Pin compatible Go dependency
versions when the new module is created.

Suggested package layout: root `System` and TUN wrappers, plus internal
`adapter`, `underlay`, `outnet`, `dnsconfig`, `wfpolicy`, `owner`, and
`lifecycle` packages. Keep driver IOCTLs exclusively in the controller module.

## Initial capability contract

- **`Features.Tun`**
  - **First supported release:** True once ordinary TUN construction/cleanup is
    verified
- **`Features.DefaultTun`**
  - **First supported release:** True once default routing, DNS, and protected
    outbound traffic are verified
- **`DynTun` / `DynDefaultTun`**
  - **First supported release:** False; unsupported mutations require rebuilding
- **`TunNames` / `DefaultTunNames`**
  - **First supported release:** False initially; choose internal unique names
- **`StrictMode`**
  - **First supported release:** False
- **`DefaultTunOpts.Exclude`**
  - **First supported release:** Exact executable paths with descendant
    inheritance, when the driver dependency is available
- **`DefaultTunOpts.Include`**
  - **First supported release:** `sysnet.ErrNotSupported`
- **Both Include and Exclude**
  - **First supported release:** Validation error before changing any OS
    resource
- **PID/user/group/command-line routing**
  - **First supported release:** Not advertised
- **Matcher support**
  - **First supported release:** Independently negotiated; initially PID and
    exact executable path, using socket-owner lookup

`Features` describes backend capability, not whether every resource acquisition
will succeed. Probe dependencies without taking over existing policy. If the
driver is absent, ordinary TUNs and a default TUN without exclusions can still
be supported; leave `TunRules` empty. A busy global driver should produce an
actionable error when exclusions are requested.

Prefer an explicit initial routing rule name such as `exec-tree`, whose value is
one absolute executable path and whose description states that descendants
inherit exclusion. This is a proposed Windows rule name. Linux's `exec` accepts
broader patterns, so silently accepting that syntax would mislead callers.
Windows matchers may separately advertise `pid` and `exec` with exact-path
semantics.

`RulesInfo` cannot express “this routing rule supports Exclude but not Include.”
Document that distinction and enforce it in `VerifyDefaultTunOpts`.

## Map every sysnet method

- **`Features`, `ListRules`**
  - **Planned behavior:** Return independent copies of capabilities/rule
    descriptions; list only implemented semantics
- **`AllocIP`, `AllocSubnet`**
  - **Planned behavior:** Compose gonnect allocators with current
    interface/route coverage and owned reservations; release owned reservations
    on close
- **`RuleVerify`, `RuleCompl`**
  - **Planned behavior:** Validate the selected rule grammar; completion may
    return no suggestions; never mutate driver state
- **`TunNameVerify`**
  - **Planned behavior:** Return unsupported status until custom naming is
    implemented
- **`OutNet`**
  - **Planned behavior:** Owned network wrapper whose sockets bypass every owned
    DefaultTun; failure to protect a socket fails that operation
- **`OutDNS`**
  - **Planned behavior:** Explicit resolver transported over protected `OutNet`,
    independent of DNS settings installed by DefaultTun
- **`LocalNet`**
  - **Planned behavior:** Loopback-only network; validate listen/dial addresses
    and own created resources
- **`BuildMatcher`**
  - **Planned behavior:** Compile a supported rule; query/cached owner metadata
    per flow; return lookup errors for unknown/ambiguous owners
- **`BuildTun`, `VerifyTunOpts`**
  - **Planned behavior:** Validate/normalize, allocate Wintun, set
    addresses/routes/MTU, register ownership, roll back on error
- **`BuildDefaultTun`, `VerifyDefaultTunOpts`**
  - **Planned behavior:** Validate full options first, then create the
    coordinated TUN/DNS/routing/optional-driver session
- **`DefaultTun.SetDns`**
  - **Planned behavior:** Atomically switch resolver; `nil` silently drops
    incoming DNS requests
- **`TunWarnings`, `DefaultTunWarnings`**
  - **Planned behavior:** Return a copied current warning slice; nil for
    unknown, stale, closed, or unsupported values
- **`SetTunMTU`, `SetTunAddrs`, `AddTunAddr`**
  - **Planned behavior:** Initially `ErrNotSupported` for owned TUNs; add only
    with real dynamic-update support
- **`GetTunAddrs`**
  - **Planned behavior:** Return owned current addresses from authoritative
    state
- **`SetTunRoutes`, `AddTunRoute`**
  - **Planned behavior:** Initially `ErrNotSupported` for owned TUNs
- **`GetTunRotue`**
  - **Planned behavior:** Implement this exact spelling; return owned route
    state
- **`SetTunName`**
  - **Planned behavior:** Preserve its `([]string, error)` signature;
    unsupported initially; never rename DefaultTun
- **`Close`**
  - **Planned behavior:** Idempotently stop workers and close all owned TUNs,
    networks, matchers, sockets/listeners, DNS resources, and OS policy

For TUN-specific accessors/mutators, check ownership first and return
`sysnet.ErrUnknownTun` for foreign or stale objects. Warning accessors are the
explicit exception: they return nil.

Use compile-time interface assertions for `System`, `DefaultTun`, and `Matcher`
against the pinned gonnect version. Respect option normalization in the
interface: ignore loopback addresses/routes, use a sensible MTU for zero/too-low
values, ignore a `DnsIP` outside `TunAddrs`, and allocate safe defaults only for
DefaultTun's empty address list.

## OutNet and OutDNS: implement before default routing

The controller cannot exempt one socket from the tunnel. Excluding the entire Go
executable would also exempt unrelated sockets created by that application and
cannot implement the per-network contract.

Select an underlying interface separately for IPv4 and IPv6, excluding this
System's owned tunnel adapters. Preserve its LUID, interface index, source
address, next hop, and resolver configuration. This upstream interface may
itself be another VPN; make that a deliberate selection policy.

Set unicast interface options before connect/bind using
`gonnect.NativeConfig.ControlContext` and `ListenCfg.Control` or a dedicated
wrapper. IPv4's option takes the interface index in network byte order; IPv6
uses host byte order. Establish source-address binding where required and verify
it against WFP redirection. Reuse existing underlay routes instead of deleting
the machine's default routes. See the
[Microsoft Winsock documentation][winsock].

The existing `sockopt/sockopt_windows.go` helper in [gonnect] accepts an
existing `net.Conn`; do not rely on calling it after the initial packet has
already left.

Cover all network entry points: generic and typed TCP/UDP dial/listen methods,
packet listeners used for QUIC, configured listeners, resolver calls, and
multicast where offered. Reject unsupported entry points instead of silently
using an unprotected native operation. Compose caller socket controls without
permitting them to override mandatory protection.

The `Network.IsNative` contract permits consumers to use native fast paths that
bypass methods. Return false for the protection wrapper unless those paths can
preserve its guarantees. Track created connections/listeners so closing `System`
closes them too. See `ftypes.go` and `native.go` in [gonnect].

For `OutDNS`, retain explicit upstream resolver addresses obtained from the
selected underlay before DefaultTun changes DNS. Send their traffic through
protected sockets and refresh this set on network changes. Avoid hostname
bootstrap through the DNS configuration you just replaced.

Test protection while the driver is engaged and while defaults/routes change.
Until that gate passes, return `gonnect.RejectNetwork` where the interface
requires a fallback and do not advertise a fully working DefaultTun.

## Default TUN, DNS, and lifecycle

Use a resource transaction/rollback stack for multi-API setup; WFP, IP Helper,
DNS, and driver changes cannot be one atomic transaction.

1. Validate options and resolve all executable rules before side effects. Reject
   unsupported Include/Strict requests here.
1. Serialize DefaultTun replacement. Document that rebuilding may interrupt
   connectivity. Close the previous DefaultTun with its owned artifacts, then
   establish a fresh baseline.
1. Snapshot relevant DNS/route/interface state; reserve addresses. Create the
   new Wintun and set native MTU and addresses before adding traffic-attracting
   routes.
1. Establish protected `OutNet`/`OutDNS` and selected underlay state. Decide
   coverage per IP family; do not silently promise a family without a working
   tunnel/underlay path.
1. If exclusions are requested, prepare the controller's baseline/DNS sublayers
   using the [controller plan](mullvad-controller-plan.md). Commit WFP changes
   before driver calls. Initialize, then snapshot/register processes, set
   addresses, and apply exclusions.
1. Start a DNS endpoint on the selected TUN address, then install the owned
   default/extra routes and interface DNS settings in the reviewed order.
   Publish the DefaultTun only after setup succeeds.
1. Run joined workers for driver events, interface/route/address changes, DNS
   state, and warnings. Update selected addresses on changes even though the
   public dynamic-TUN option setters initially remain unsupported.
1. On close, stop/join workers, remove owned traffic redirection and restore
   owned DNS changes, reset/close the driver, remove caller WFP objects after
   successful reset, release adapter resources and reservations. Continue
   independent cleanup after an error and aggregate failures.

Record what this instance wrote so cleanup preserves unrelated administrator,
DHCP, or other-application changes. A failed reset requires explicit recovery
before removing referenced WFP resources. Use the normal lifecycle for process
shutdown and an owned-state recovery ledger for interrupted cleanup.

DNS needs dedicated attention:

- `SetDns(nil)` must discard requests without forwarding or sending SERVFAIL.
  Current the `dns/transport.go` server in [gonnect] is UDP-only and returns
  SERVFAIL when detached. Add a true silent-drop path and TCP DNS support,
  either upstream or in a Windows adapter.
- Resolver switching must cancel old work and suppress stale responses. Closing
  DefaultTun restores DNS settings it owns.
- Configuring a TUN DNS server alone does not prove exclusive DNS routing across
  Windows adapters. Report `WarningDefaultTunDNSRouteNotExclusive` whenever the
  backend cannot establish that guarantee.
- System DNS is often performed by a shared resolver service; do not infer the
  originating application's identity from that service's socket. DoH and
  application-specific DNS require separate policy.

Changing interface metrics alone is insufficient proof that every intended DNS
request reaches the provider. Any later WFP DNS policy must be tested with the
driver's DNS exemptions, TCP and UDP DNS, and encrypted DNS behavior.

## Socket ownership and matchers

Start from `sockowner/sockowner_windows.go` in [gonnect]: TCP/UDP owner tables
give PIDs; process queries enrich metadata. Mullvad `QueryProcess` only
supplements classification after a PID is known.

Before advertising matchers:

1. Fix empty-table handling and retry bounded table-size races. Add IPv6 and UDP
   wildcard-bind cases.
1. Keep ambiguous UDP ownership an error. The UDP table contains local endpoint
   ownership, not a remote-endpoint five-tuple.
1. Resolve full executable paths separately; current `SocketOwner.ProcName` is
   only a basename. Cache with PID and creation time so PID reuse cannot inherit
   old metadata.
1. Cache table snapshots briefly or maintain a flow cache to avoid enumerating
   all sockets for every TUN packet. Document attribution as best effort for
   short-lived/racing flows.
1. Honor the flow direction and “same System” restrictions of `Matcher.Match`
   and `sysnet.MatchConn`. Close matcher resources through System ownership.

Do not advertise Linux UID/GID, command-line, or arbitrary process-tree matcher
semantics without implementing their Windows equivalent. The driver's process
events do not form a complete socket event stream.

WinDivert or ETW can be evaluated later if table-based attribution is
inadequate. WinDivert is not required for this MVP and would add a second
driver; its packet and flow/socket metadata layers have different information.
[WinDivert documentation](https://reqrypt.org/windivert-doc.html)

## Milestones and acceptance gates

- **W0: Contract skeleton**
  - **Work:** Module pins, config/dependency injection, ownership registry,
    truthful feature/rule reporting, interface assertions
  - **Gate:** Every method compiles; unsupported requests fail before side
    effects
- **W1: Ordinary TUN**
  - **Work:** Wintun wrapper, LUID-based config, addresses/routes/MTU,
    allocators, cleanup
  - **Gate:** IPv4/IPv6 packet round trip and exact owned-resource cleanup
- **W2: Protected networks**
  - **Work:** All OutNet socket paths, explicit OutDNS, LocalNet, network
    notifications
  - **Gate:** TCP/UDP/QUIC and DNS bypass owned default routes without
    recursion; failure never silently falls back
- **W3: Default TUN and DNS**
  - **Work:** Default routing, DNS server/configuration, silent drop, warnings,
    replacement/rollback
  - **Gate:** `SetDns(nil)` emits no DNS response; closing restores owned state;
    fault injection at each setup stage
- **W4: Driver exclusions**
  - **Work:** Caller WFP objects, controller lifecycle, exec-tree rules,
    refreshed addresses
  - **Gate:** Excluded executable trees use underlay; ordinary traffic reaches
    TUN; IPv4/IPv6, spawn/exit, rule removal, reconnect tests
- **W5: Matchers**
  - **Work:** Corrected owner lookup, full-path/PID caches, ambiguity handling
  - **Gate:** TCP/UDP, wildcard sockets, IPv6, PID reuse, short-lived flows, and
    LocalNet peer matching covered
- **W6: Release hardening**
  - **Work:** Installer integration, support matrix, state recovery, repeatable
    VM tests
  - **Gate:** Sleep/resume, Wi-Fi/Ethernet switch, DHCP renewal, BFE restart,
    occupied driver, process crash, repeated DefaultTun rebuild pass

Build W1-W3 without the split-tunnel driver first; W4 then adds exclusions to an
already working networking backend. Run the controller's C2 native integration
gate before relying on it in W4.

## Later features

Add dynamic address/route/MTU changes only with coherent driver updates,
rollback, and truthful `DynTun`/`DynDefaultTun` reporting. Add naming after
native rename behavior and uniqueness are verified.

Include-only routing needs a new steering design or driver extension. An inverse
snapshot of currently running processes is not a durable include policy.

Strict mode means excluded or non-included traffic is **dropped**, not sent over
the underlay. Implement and test a separate WFP policy against all relevant
layers, weights, driver permit callouts, and protected OutNet sockets before
setting `StrictMode=true`. A persistent crash-resistant kill switch is a further
explicitly configured policy; ordinary close/reset does not provide it.

The release criterion is interface fidelity within the advertised capabilities.
A smaller Windows feature set is acceptable; returning successful results for
semantics the platform has not implemented is not.

[gonnect]: https://github.com/asciimoth/gonnect/tree/7b8016f
[netioapi]: https://learn.microsoft.com/windows/win32/api/netioapi/
[sysnet-linux]: https://github.com/asciimoth/sysnet-linux/tree/2e947b8
[tuntap]: https://github.com/asciimoth/tuntap/tree/f0c4c7e
[w]: https://pkg.go.dev/golang.zx2c4.com/wireguard/windows/tunnel/winipcfg
[winsock]: https://learn.microsoft.com/windows/win32/winsock/
