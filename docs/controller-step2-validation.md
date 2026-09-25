# Controller Step 2 validation

Step 2 uses a dedicated two-guest Windows VM gate. The test guest and the echo
endpoint have two private, point-to-point Ethernet links. One link represents
the tunnel. The other link represents the underlay. Neither link is connected to
the host network or to the Internet.

The test guest has competing routes to the documentation addresses `203.0.113.1`
and `2001:db8:ffff::1`. Each request contains a unique marker. QEMU records one
packet capture for each link. The host gate checks every marker and fails if it
occurs on the wrong link. Thus, a socket return value or local bind address
cannot provide the packet-path evidence by itself.

Run the gate with:

```sh
just test-windows-flow
```

The gate writes `packet-flow-evidence.json`, `tunnel.pcap`, `underlay.pcap`, the
guest route and address snapshots, the JSON Go test stream, and the source
archive to its `.artifacts/winvm/run-*` directory.

## New-flow matrix

The gate runs TCP request-response, long-lived TCP, UDP request-response, and
long-lived UDP flows over IPv4 and IPv6. Each case runs from an excluded
executable, its inherited descendant, and a non-excluded executable.

The observed new-flow policy covers all nine address modes from the pinned
driver documentation:

| Mode | Available addresses                     | Excluded IPv4                | Excluded IPv6                |
| ---- | --------------------------------------- | ---------------------------- | ---------------------------- |
| 1    | Internet and tunnel IPv4/IPv6           | Underlay                     | Underlay                     |
| 2    | Internet and tunnel IPv4                | Underlay                     | Tunnel                       |
| 3    | Internet and tunnel IPv4; Internet IPv6 | Underlay                     | Tunnel, explicitly permitted |
| 4    | Internet and tunnel IPv4; tunnel IPv6   | Underlay                     | Blocked                      |
| 5    | Internet and tunnel IPv6                | Tunnel                       | Underlay                     |
| 6    | Internet IPv4; Internet and tunnel IPv6 | Tunnel, explicitly permitted | Underlay                     |
| 7    | Tunnel IPv4; Internet and tunnel IPv6   | Blocked                      | Underlay                     |
| 8    | Tunnel IPv4; Internet IPv6              | Blocked                      | Tunnel, explicitly permitted |
| 9    | Internet IPv4; tunnel IPv6              | Tunnel, explicitly permitted | Blocked                      |

Descendants have the same result as excluded executables. Non-excluded
executables use the tunnel in every mode. An excluded family uses the underlay
only when the driver has both addresses for that family. A tunnel-only family
fails closed. An Internet-only family has no redirect rule, so it keeps the
normal route, but the driver explicitly permits it through caller firewall
policy.

## WFP interactions

The gate adds lower-priority block filters at the IPv4 and IPv6 outbound ALE
authorization layers. It tests these filters first in the caller-owned baseline
sublayer on port 47823 and then in the caller-owned DNS sublayer on port 53. It
repeats both restrictive-filter matrices in all nine address modes. The port 53
endpoint carries the test echo payload; the test qualifies WFP sublayer
arbitration, not Windows DNS resolver behavior.

For TCP and UDP over IPv4 and IPv6, an installed driver permit overrides the
restrictive filter for the excluded executable and its descendant. A complete
address pair uses the underlay, while an Internet-only family keeps the normal
tunnel route in this topology. A tunnel-only family remains blocked. A family
with neither address is also blocked because the driver does not add a permit
for it. The same filters block every non-excluded flow. Capture markers prove
each permitted path and prove that blocked flows use neither link. This
qualifies both the permit behavior and the restrictive caller policy, including
the port-53 permit filters in the DNS sublayer.

## Active-flow changes

The following behavior was observed for TCP and UDP over both address families:

| Change                                | Existing flow                               | New flow from same process              |
| ------------------------------------- | ------------------------------------------- | --------------------------------------- |
| Add exclusion                         | Tunnel flow stops                           | Uses underlay                           |
| Remove exclusion                      | Underlay flow keeps its path                | Uses tunnel                             |
| Replace one exclusion with another    | Applies the two rules above to each process | Uses the replacement policy             |
| Clear exclusions                      | Existing underlay flow keeps its path       | Uses tunnel                             |
| Replace tunnel and underlay addresses | Flow bound to a removed address stops       | Uses the replacement address and policy |

A flow that stops can send retransmissions on its old path before the socket
reports an error. No marker was observed on the opposite path. The regression
gate permits an old-path retransmission during teardown, but rejects all
opposite-path traffic.

Reset and reinitialization repeat the complete matrix, WFP interaction tests,
and all active-change cases without rebuilding either guest. The recorded run on
25 September 2026 validated 1,472 observations: 736 before reset and 736 after
reinitialization. All observations had the expected path.

## Safety boundary

The test targets use RFC 2544, unique-local, and documentation prefixes with
explicit routes over the two private links. They cannot resolve to the
developer's active network. QEMU SLiRP provides a separate management adapter
and accepts its SSH forwarding only on host loopback. The endpoint firewall is
disabled only inside its disposable overlay so the echo process can receive on
both private links. The test guest keeps the Windows strong-host model. This
setting prevents a source address from leaving through the other link.
