# Minimal tunnel demonstration

`cmd/tunneldemo` is a Windows-only executable example. It creates one Wintun
adapter, adds IPv4 and IPv6 addresses and routes, creates two WFP sublayers, and
uses the public `splittunnel` API to configure the Mullvad split-tunnel driver.
It is not a VPN client.

The companion `cmd/tunnelpeer` accepts one IP packet per UDP datagram and sends
minimal TCP or UDP echo replies. The eight-byte header contains `MSTD`, version
1, and three zero bytes. The protocol has no encryption, authentication, peer
identity, replay protection, padding, key exchange, congestion control, or
anti-spoofing. It drops fragmented IPv4 packets, IPv6 extension headers, and
protocols other than TCP and UDP. Use it only on an isolated, trusted test
network.

## Prepared test systems

Use two disposable systems on an isolated network. The Windows client needs:

- the pinned Mullvad split-tunnel driver 1.3.0.0 installed, running, and in the
  `Started` state;
- an elevated terminal and no other process that owns `\\.\MULLVADSPLITTUNNEL`;
- the official Wintun 0.14.1 DLL for its architecture next to `tunneldemo.exe`;
- a transport route to the peer and a separate underlay route to the echo
  service addresses;
- actual bypass-interface addresses for `-internet-ipv4` and `-internet-ipv6`.

The peer needs a transport address that the client can reach. For the bypass
comparison, also assign `203.0.113.1` and `2001:db8:ffff::1` to its underlay and
start `flowecho`. These documentation prefixes must not be routed to a public
network.

The example does not install, update, start, stop, or remove the Mullvad driver.
Wintun can install its own signed driver when it creates the adapter. The
example removes its adapter but does not uninstall the shared Wintun driver
package.

## Reproducible walkthrough

Build the programs from the repository:

```powershell
New-Item -ItemType Directory -Force .\demo-bin | Out-Null
go build -o .\demo-bin\tunneldemo.exe .\cmd\tunneldemo
go build -o .\demo-bin\tunnelpeer.exe .\cmd\tunnelpeer
go build -o .\demo-bin\flowecho.exe .\cmd\flowecho
go build -o .\demo-bin\flowprobe.exe .\cmd\flowprobe
```

Copy the architecture-matched `wintun.dll` from the official Wintun 0.14.1
archive into `demo-bin` on the client. Copy `tunnelpeer.exe` and `flowecho.exe`
to the peer. The commands below use the same addresses as the isolated VM test.
On the peer, run:

```powershell
.\tunnelpeer.exe -listen 198.18.0.1:51900
.\flowecho.exe -ipv4 203.0.113.1 -ipv6 2001:db8:ffff::1 -port 47823
```

On the client, make two separate executable identities. The second one starts a
descendant:

```powershell
Copy-Item .\demo-bin\flowprobe.exe .\demo-bin\excluded-probe.exe
Copy-Item C:\Windows\System32\cmd.exe .\demo-bin\excluded-parent.exe
```

Start the example from an elevated terminal. Replace the two Internet addresses
if the prepared client uses different underlay addresses:

```powershell
.\demo-bin\tunneldemo.exe `
  -peer 198.18.0.1:51900 `
  -internet-ipv4 198.18.1.2 `
  -internet-ipv6 fd00:18:1::2 `
  -exclude (Resolve-Path .\demo-bin\excluded-probe.exe) `
  -exclude (Resolve-Path .\demo-bin\excluded-parent.exe)
```

Wait for `status=ready`. The preceding output lists the TUN addresses, routed
service prefixes, peer, bypass addresses, exclusions, adapter index, and WFP
sublayer keys.

In a second client terminal, exercise TCP and UDP. Repeat the four commands with
the IPv6 address in brackets and `tcp6` or `udp6`.

```powershell
.\demo-bin\flowprobe.exe -network tcp4 -address 203.0.113.1:47823 -token INCLUDED_TCP
.\demo-bin\flowprobe.exe -network udp4 -address 203.0.113.1:47823 -token INCLUDED_UDP
.\demo-bin\excluded-probe.exe -network tcp4 -address 203.0.113.1:47823 -token EXCLUDED_TCP
.\demo-bin\excluded-parent.exe /c .\demo-bin\flowprobe.exe -network udp4 -address 203.0.113.1:47823 -token DESCENDANT_UDP
```

The included probes report local addresses `10.77.0.2` and `fd00:77::2`. The
excluded executable and its descendant report the prepared underlay addresses. A
capture on the transport link shows the included tokens inside UDP port 51900. A
capture on the bypass link shows the excluded tokens as direct TCP or UDP
payload. This packet observation, not an IOCTL result, proves the path.

Press Ctrl+C in `tunneldemo`. It stops the event reader and packet workers,
resets and closes the split-tunnel controller, deletes its exact routes and
addresses, removes its Wintun adapter, and deletes its two WFP sublayers. It
does not delete pre-existing routes, adapters, sublayers, or drivers.

If reset fails, the command keeps its non-dynamic WFP sublayers and prints their
keys. Do not delete those sublayers until recovery confirms that the driver no
longer references them. Inspect the driver state and reset it before manual WFP
cleanup. The TUN adapter and its routes are still removed when the process
exits.

## Automated isolated test

`just test-windows-flow` runs `TestPacketFlowTunnelDemo` after the broader flow
matrix. The harness starts the peer on one isolated QEMU link and the direct
echo service on another. It runs new TCP and UDP flows over IPv4 and IPv6 from
an included executable, an excluded executable, and an excluded parent's
descendant. It checks the local source address, captures both links, finds each
unique token only on its expected path, and confirms that the driver returns to
`Started` and the Wintun adapter is absent after normal shutdown.
