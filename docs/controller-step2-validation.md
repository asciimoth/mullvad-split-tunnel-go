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

The observed new-flow policy is:

| Configured addresses | Excluded and descendant IPv4 | Excluded and descendant IPv6 | Non-excluded |
| -------------------- | ---------------------------- | ---------------------------- | ------------ |
| Dual stack           | Underlay                     | Underlay                     | Tunnel       |
| IPv4 only            | Underlay                     | Tunnel                       | Tunnel       |
| IPv6 only            | Tunnel                       | Underlay                     | Tunnel       |

An excluded family uses the underlay only when the driver has both the tunnel
and Internet address for that family. If the pair is incomplete, the new flow
keeps the normal tunnel policy.

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

Reset and reinitialization repeat the complete matrix and all active-change
cases without rebuilding either guest. The recorded run on 25 September 2026
validated 528 markers across the two cycles.

## Safety boundary

The test targets use RFC 2544, unique-local, and documentation prefixes with
explicit routes over the two private links. They cannot resolve to the
developer's active network. QEMU SLiRP provides a separate management adapter
and accepts its SSH forwarding only on host loopback. The endpoint firewall is
disabled only inside its disposable overlay so the echo process can receive on
both private links. The test guest keeps the Windows strong-host model. This
setting prevents a source address from leaving through the other link.
