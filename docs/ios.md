# iPhone development preview

SwiftUI application, Packet Tunnel extension and small WidgetKit extension,
using the shared Rust profile, transport, mobile routing and packet stack.
This is an experimental port; physical-device VPN acceptance is still required.

## Features

- Multiple profiles, default selection, rename/delete, migration from the old
  single-profile vault. Imports require preview and explicit confirmation.
- File/text/link imports (`tt://`, `hy2://`, `hysteria2://`), QR camera scanner
  and local QR recognition from a photo. No automatic connection from a link.
- JSON, endpoint TOML, CLI TOML, link and configuration exports through the
  system file exporter, with conversion losses and explicit credential warning.
- Portal v2 HTTPS enrollment, manual downloads, revision-pinned profile exports,
  upload preview/commit with explicit confirmation, and opt-in background refresh.
  iOS schedules background refresh at its discretion; hourly execution is not guaranteed.
- Shared Android/iOS policy adaptation: included/excluded IP routes, flow-routing
  mode/exclusions, DNS, MTU, IPv6 handling. Unsupported policies fail explicitly.
- Connect/disconnect, transport reconnect and VPN On Demand. Explicit disconnect
  disables On Demand so it cannot immediately reconnect against the user's intent.
- Russian/English UI and a privacy overlay when inactive or screen capture is
  reported. This does not prevent individual screenshots.

The small Home Screen widget and circular Lock Screen widget open the application
and toggle the already authorized VPN on iOS 17+. Device authentication is required.
Connect once in the app to install/authorize its configuration. On iOS 16 the
widget opens the app for manual control. Add it through Home Screen editing →
Add Widget → R-TrustTunnel. Status is labeled as the last observation and expires;
WidgetKit refresh is not a real-time connection monitor.

## Security and platform boundaries

Profiles and portal tokens live in one validated Keychain vault shared only by
app/provider, using `AfterFirstUnlockThisDeviceOnly`. VPN preferences and the
widget App Group contain no credentials. The App Group stores only status/time.
Portal requests use an ephemeral session, HTTPS origins, bounded bodies and no
redirects; credentials are not included in server error messages. Upload/export
requires explicit user action. Forgetting enrollment removes its downloaded
profiles while preserving local profiles.

The provider uses public `NEPacketTunnelFlow`, bounded queues and tunneled DNS.
TLS uses WebPKI roots or the profile's explicit CA; user-installed iOS roots are
not automatically imported. Startup succeeds only after server health and UDP
channel setup, with a 30-second deadline. IPv6 is captured and locally refused
when unsupported by the server. Reconnect keeps tunnel settings installed;
terminal authentication/TLS failure requires explicit disconnect/reconnect.

On Demand is not Android Always-on/lockdown. Profiles requiring lockdown are
rejected. Managed per-app VPN is not offered in this consumer app. Actual route
isolation, DNS/egress, system exceptions, handoff, extension memory and battery
usage require real-iPhone validation. Simulator Connect is deliberately disabled.

## Build and run

Requires Xcode with iPhone SDK/license/first-launch setup, Python 3 and Cargo.

```sh
rustup target add aarch64-apple-ios aarch64-apple-ios-sim
scripts/build-ios.sh device
scripts/build-ios.sh simulator
scripts/run-ios-simulator.sh [simulator-UDID]
```

Device output: `target/ios-xcode/Build/Products/Release-iphoneos/R-TrustTunnel.app`,
with `PacketTunnel.appex` and `VPNWidget.appex`. It is **unsigned**, not an
installable IPA. Simulator uses ad-hoc signing and a simulator-only Keychain
prefix. The launcher supports Xcode 27 Device Hub and older Simulator versions.
Generate the Xcode project with `scripts/generate-ios-project.py`; build the Rust
library with the build script before using Xcode directly.

```sh
APPLE_TEAM_ID=YOUR_TEAM IOS_BUNDLE_ID=your.registered.identifier \
  scripts/build-ios.sh archive
```

Configure provisioning for the app, `.PacketTunnel` and `.VPNWidget` targets.
All three require App Group `group.<bundle-id>`; app/provider additionally need
Packet Tunnel capability and Keychain group `<AppIdentifierPrefix><bundle-id>.shared`.
Export a signed IPA through Xcode Organizer with the appropriate profiles and
registered device/distribution method. Never commit signing keys or profiles.

## Validation

```sh
cargo test --locked -p rtrust-ios -p rtrust-mobile -p rtrust-tun -p rtrust-android --lib
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild \
  -project apps/ios/RTrustTunnel.xcodeproj -scheme RTrustTunnel \
  -configuration Debug -destination 'platform=iOS Simulator,name=R-TrustTunnel Test' \
  -derivedDataPath target/ios-tests test CODE_SIGNING_ALLOWED=YES \
  CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO AppIdentifierPrefix=SIMULATOR.
```

Host tests cover policy adaptation, ABI/lifecycle, queue bounds and packet stack.
Hosted XCTest covers codec/credential preservation, vault validation, QR image
recognition, portal origin validation, fixture downloads and sanitized failures.
Portal fixtures do not establish compatibility with a deployed server.

Local validation on 2026-10-06: 33 host Rust tests and 5 hosted iOS tests passed;
unsigned device and ad-hoc simulator builds succeeded, including both extensions.
Simulator smoke covers legacy migration, adding a second synthetic profile,
selection, export consent, and adding/rendering the small Home Screen widget.
The system document exporter timed out in the
local iOS 27 simulator; completed file saving remains unverified. Camera capture,
background scheduling, signed installation and real VPN/widget toggling need a
physical iPhone. Before distribution test clean install/upgrade, locked-device
Keychain sharing, DNS/HTTPS/public egress, IPv4/IPv6 TCP/UDP, every transport,
Wi-Fi/cellular handoff, credential revocation, provider crash and disconnect
recovery. Neither unit tests nor unsigned builds prove VPN acceptance.

References: [Apple Packet Tunnel](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider),
[interactive widgets](https://developer.apple.com/documentation/widgetkit/adding-interactivity-to-widgets-and-live-activities).
