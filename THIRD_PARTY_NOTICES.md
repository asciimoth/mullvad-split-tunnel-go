# Third-party components

This is an unofficial controller. It is not affiliated with or endorsed by
Mullvad VPN AB.

The Go implementation and accompanying plans use the GNU General Public License,
version 3 or later, in LICENSE. That license does not relicense third-party
drivers, libraries, or sources.

- The controller's wire definitions are based on the public protocol in
  [mullvad/win-split-tunnel][upstream]. The upstream driver offers
  GPL-3.0-or-later or MPL-2.0 terms. No driver binary or upstream source tree is
  committed to the Go module.
- The Nix development environment can download the signed amd64 and arm64 driver
  packages from the pinned
  [mullvadvpn-app-binaries publication][driver-binaries]. The flake records a
  SHA-256 hash for each catalog, setup-information file, and driver binary.
- The optional fixture generator includes headers from a separately obtained
  upstream checkout. Retain upstream notices if you redistribute those headers.
- golang.org/x/sys v0.44.0 is an external dependency under the Go project's
  BSD-style license. It is referenced through go.mod, not vendored.
- Wintun and winipcfg are discussed as dependencies of the future sysnet-windows
  project; they are not dependencies of this controller.

Any future binary distribution should record the exact driver package, signature
verification result, architecture, hashes, and applicable license notices
independently of the Go module version.

[driver-binaries]: https://github.com/mullvad/mullvadvpn-app-binaries/commit/5b6f46cde692acb77ee74b37b9fd3f1678c45a52
[upstream]: https://github.com/mullvad/win-split-tunnel/tree/0a0eb97
