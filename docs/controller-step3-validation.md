# Controller Step 3 validation

Step 3 adds an executable tunnel example and an isolated regression gate.

## Implementation

- `cmd/tunneldemo` creates caller-owned Wintun, route, address, and persistent
  WFP sublayer resources. It uses only the public controller API for driver
  operations.
- `cmd/tunnelpeer` implements the controlled raw-packet peer. The transport
  contract and its security limits are in [the walkthrough](tunneldemo.md).
- `cmd/flowprobe` provides reproducible TCP and UDP observations.
- The command opens and checks the exclusive driver before it creates any
  network or WFP object. It rejects every state except `Started`.
- One cancellable event reader drains driver events while the example runs.
  Shutdown joins the event and packet workers before reset.
- Successful reset authorizes deletion of the exact WFP keys. A reset failure
  preserves those sublayers and prints their keys for recovery.

## Automated evidence

The `flow` VM gate uses two disposable Windows Server guests and two isolated
QEMU links. `TestPacketFlowTunnelDemo` runs the built command with the official,
hash-locked Wintun 0.14.1 DLL. It covers TCP and UDP over IPv4 and IPv6 for:

- a non-excluded executable through the UDP-encapsulated TUN path;
- an exact excluded executable through the direct underlay path; and
- a child of an excluded executable through the direct underlay path.

Each flow has a unique payload marker. The host validates the markers in the two
independent packet captures. The test also checks the selected local address,
the final `Started` driver state, and removal of the command-owned TUN adapter.
Run the gate with:

```console
just test-windows-flow
```

The run retains console output, command logs, JSONL observations, both packet
captures, and `packet-flow-evidence.json` under `.artifacts/winvm/run-ID/`.

The recorded run on 25 September 2026 passed `TestPacketFlowTunnelDemo` against
the pinned signed driver. Its 12 demo observations covered both protocols and
address families: four included flows appeared only on the tunnel link, and
eight excluded or descendant flows appeared only on the underlay link. The
combined Step 2 and Step 3 capture validation accepted 1,484 observations.
