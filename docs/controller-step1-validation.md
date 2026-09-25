# Controller Step 1 validation

Step 1 uses portable fault-injection tests and an opt-in native driver suite.
The native suite must run on a disposable Windows host. It installs no TUN and
does not change routes or DNS.

## Cancellation and resource checks

`TestEventCancellationStress` cancels 10 warm-up reads and then runs four
batches of 25 read-and-cancel cycles. A state query and an address query run
while each event read is pending. The test records the process handle count and
Go goroutine count after warm-up and after each batch. The final values can be
at most two above the warm-up values.

The native suite also tests a context that is canceled before `ReadEvent`, a
pending event read, and a pending read during `Controller.Close`. The close test
reopens the device, reads the retained driver state, and resets it. Thus, the
test verifies that close drains the request without treating close as
authorization to reset driver policy.

`TestDriverLifecycle` runs four warm-up cycles and four measured cycles. Each
cycle creates a WFP fixture, opens and initializes the controller, reads an
event, resets the driver, and closes the controller. The test records handles
and goroutines after each measured cycle. The last values can be at most two
above the first measured values.

## Mutation reconciliation

`TestTimedOutMutationsCanBeReconciled` uses a transport that applies a mutation
and then returns `context.DeadlineExceeded`. This is the uncertain result that a
caller must handle after overlapped I/O cancellation. The test covers each
mutating IOCTL and uses these reconciliation reads:

| Timed-out operation      | Reconciliation read   |
| ------------------------ | --------------------- |
| `Initialize`             | `State`               |
| `RegisterProcesses`      | `State`               |
| `SetAddresses`           | `Addresses`           |
| `SetExcludedDevicePaths` | `ExcludedDevicePaths` |
| `ClearConfiguration`     | `ExcludedDevicePaths` |
| `Reset`                  | `State`               |

The transport does not return until the canceled request is complete. The next
query therefore also checks that the controller does not reuse request buffers
while the transport can still access them.

## Executable path identity

The driver and controller use an exact NT device path, not a file identity.
`TestHardLinkAndAlternateLaunchPaths` records the configured path and the image
path that the driver reports for each process. Its regression contract is:

- A normal drive-letter launch and a `\\?\` launch of the same name produce the
  same NT device path and match one exclusion.
- A hard link to the same executable produces the NT device path of the hard
  link name. An exclusion for the first name does not match this process.
- Adding the hard-link name to the exclusion set changes the existing hard-link
  process to split mode.

Callers must keep the original DOS path and refresh the resolved NT path after a
rename, replacement, hard-link change, or volume remount. A caller that wants to
exclude more than one hard-link name must configure each name.

## Architecture gates

The GitHub Actions Windows matrix runs the ordinary native suite and the signed
driver suite on `amd64` and `arm64`. The live job downloads only the pinned
package for the native architecture, verifies each SHA-256 hash and the Mullvad
signature, and refuses a host with an existing service or installed driver file.
It runs the tagged suite as `SYSTEM` and saves the JSON event stream, resource
measurements, driver identity, and final service state as artifacts.

For a separate disposable host, run:

```powershell
./dev/winvm/test.ps1
./dev/winvm/host-e2e.ps1 -AllowDisposableHost
```

`host-e2e.ps1` stages and starts the pinned test driver. Do not run it on a
workstation or a host that another VPN service uses.
