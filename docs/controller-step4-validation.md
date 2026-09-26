# Controller Step 4 qualification

Step 4 defines two proposed Windows configurations and a fail-closed evidence
gate. A matrix entry is supported only after this gate produces
`qualification.json` from one clean controller revision.

## Proposed support matrix

| Matrix entry                | Native architecture | Windows family      | Minimum build |
| --------------------------- | ------------------- | ------------------- | ------------: |
| `windows-server-2022-amd64` | amd64               | Windows Server 2022 |         20348 |
| `windows-11-arm64`          | arm64               | Windows 11 24H2     |         26100 |

The machine-readable matrix is
[`qualification-matrix.json`](../dev/winvm/qualification-matrix.json). These are
qualification targets, not a claim that all later Windows releases work. Each
result records the full build number that was tested.

## Required runs

Run all tests natively on the matrix entry. Cross-builds are not evidence.

1. Run `dev/winvm/test.ps1` and retain `native-unit-evidence.json`.
1. Run the signed-driver gate and retain `live-driver-evidence.json`, the JSONL
   test stream, driver evidence from before and after the run, coverage, and
   logs.
1. Run the complete isolated packet-flow gate and retain
   `packet-flow-suite-evidence.json`, its observations, both packet captures,
   and the `packet-flow-evidence.json` output from `flow-pcap.py`.

The live-driver gate requires `TestExtendedControllerSession`. This test keeps
one controller session open for 110 configuration changes and event
cancellations. It records handles and goroutines after equal batches, rejects
persistent growth, resets the driver, and verifies the `Started` state.

The packet-flow run must include `TestPacketFlowCharacterization` and
`TestPacketFlowTunnelDemo`. The external capture validator must accept at least
1,486 observations. This prevents controller return values or cross-builds from
being used as packet-path evidence.

## Evidence acceptance

Put the four normalized evidence files in one directory and run, for example:

```console
just qualify-windows windows-server-2022-amd64 ./qualification-evidence
```

The qualifier rejects evidence unless all suites:

- passed on the same native architecture, exact OS identity, and full Git
  revision from a clean worktree;
- used driver 1.3.0.0 from upstream commit `0a0eb97` with the pinned hashes and
  Mullvad package signer;
- include the extended session and complete packet-flow tests; and
- stopped the driver after each privileged run and have valid independent path
  observations.

The resulting `qualification.json` contains hashes of every input. Retain it
with the original logs, JSONL streams, resource measurements, packet captures,
and driver verification files. Do not commit VM disks, private keys, or Windows
installation media.

## Current status

The Step 4 development run passed the baseline, live-driver, extended-session,
and 1,486-observation packet-flow gates on the disposable amd64 Windows Server
2022 guest. It used a dirty development tree, so the qualifier correctly does
not accept it as release evidence. There is no retained native arm64 packet-flow
evidence for the current revision.

Therefore, neither proposed entry is advertised as qualified by this document.
Run the complete gate on both configurations and retain the two accepted
`qualification.json` files before changing this status or using this matrix in
release documentation.
