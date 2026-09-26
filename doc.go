// Package splittunnel controls the Mullvad Windows split tunneling driver.
//
// This unofficial library targets the 64-bit driver 1.3.0.0 ABI at upstream
// commit 0a0eb97f67d1dbcb3d08bda66d3b24f465d95475. It requires Windows amd64
// or arm64, an installed/running compatible driver, and an elevated caller.
// The driver does not expose a version-query IOCTL. Open does not verify the
// binary version or signature: deployment must pin and verify the package.
//
// The caller owns WFP sublayers, TUN creation, DNS, routes, network monitoring,
// and driver installation. Open never initializes or resets existing state.
// Close cancels outstanding local I/O and closes the device handle; it does
// not reset driver policy. An owner should call Shutdown, or Reset then Close,
// before releasing its WFP resources. Cancellation of a mutating operation
// does not imply that the driver rolled the operation back.
//
// The controller serializes control operations and allows one concurrent
// event read. After Close, operations return an error matching os.ErrClosed.
// Native cancellation requests are drained before their buffers are released,
// so deadlines and Close can take longer if the driver delays completion.
//
// The package limits each encoded or decoded IOCTL buffer to 16 MiB and each
// process or exclusion list to 65,536 records. SetExcludedPaths accepts existing
// absolute local drive-letter paths. It does not accept UNC or other network
// paths. Exclusions match exact resolved NT paths, not file identities. Path
// resolution does not block controller commands. Cancellation can abandon a
// resolver while its synchronous Windows filesystem call finishes in the
// background.
//
// The upstream driver cannot attribute ordinary system-resolver DNS traffic to
// the process that requested it. It also has known limits for localhost UDP and
// multicast reception from excluded processes. Driver 1.3.0.0 also labels both
// start- and stop-splitting failures as EventErrorStopSplitting. See the module
// README before using the package in a VPN client.
//
// Executable exclusions apply to descendants as determined by the driver.
// This is not a general packet-capture, PID-routing, include-only routing,
// DNS-attribution, or kill-switch API.
package splittunnel
