# R-TrustTunnel

[English](Readme.md) · [Русский](readme_ru.md)

R-TrustTunnel is a native VPN client written in Rust for **TrustTunnel**, **Hysteria 2**, **AmneziaWG 3** and **VLESS over a CDN** (WebSocket + TLS, preview). It implements the transports itself and does **not** wrap the official TrustTunnel or Hysteria CLI.

The repository contains the Windows, Linux and macOS desktop clients with their privileged tunnel services, the Android VpnService app, an iOS Network Extension preview and the shared Rust crates for transport, profiles, storage and control. The server belongs to [onixus/tunnel](https://github.com/onixus/tunnel).

> **Development preview.** [v0.7.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.0) was published on October 28, 2026 from `232fd7b` (workspace 0.7.0, update sequence 13). Publication does not establish installed-package acceptance or production readiness: see [project status and open gates](docs/project-status.md).

## Contents

- [Download](#download)
- [Screenshots](#screenshots)
- [What's new in 0.7.0](#whats-new-in-070)
- [Features](#features)
- [Platform status](#platform-status)
- [Build](#build)
- [Using the client](#using-the-client)
- [Validation highlights](#validation-highlights)
- [Repository layout](#repository-layout)
- [Documentation](#documentation)

## Download

| Platform | Asset from [v0.7.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.0) | Notes |
| --- | --- | --- |
| Windows x64 | `R-TrustTunnel-Windows-x64-Setup.exe` | Not Authenticode signed; SmartScreen may warn. Update/rollback of this exact package has not been accepted. |
| macOS Apple Silicon | `R-TrustTunnel-macOS-arm64-UI-Choices.dmg` | Native, WebView and Both PKGs in one DMG: install exactly one. Ad-hoc sealed, not Developer ID signed or notarized. System-VPN acceptance is incomplete ([release assets](docs/releases/README.md)). |
| Android 10+, arm64 / x86_64 | `R-TrustTunnel-Android.apk` | 0.7.0 / 70001, release key introduced in 0.6.0. Installs over 0.6.x and keeps profiles; 0.5.x and older must be uninstalled first, which removes local profiles. |
| Linux x86_64, Wayland | Native / WebView / Both Flatpaks and `rtrust-host-0.7.0-6` | System VPN needs the separate host package; update it together with the app. |
| iOS arm64 / Simulator | Archives from [v0.5.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0) | No iOS assets since v0.6.0. The device archive requires Apple signing and is not an installable IPA. |

The release includes `SHA256SUMS` and the source identity and manifest. Their presence is not independent signature, provenance or update-channel verification. Desktop app and service must come from the same release. A vault with a VLESS profile cannot be read by 0.6.x, so do not roll back after adding one.

Release records: [v0.7.0](docs/releases/v0.7.0.md) · [v0.6.2](docs/releases/v0.6.2.md) · [v0.6.1](docs/releases/v0.6.1.md) · [all releases](docs/releases/).

## Screenshots

Desktop UI of 0.7.0 with synthetic profiles, not connected:

| Native | WebView |
| --- | --- |
| ![Native home screen](docs/screenshots/native-home-0.7.0.jpg) | ![WebView home screen](docs/screenshots/webview-home-0.7.0.jpg) |

Profiles, import, checks, network, sync, settings, the light theme and how the images were made are in the [screenshot gallery](docs/screenshots/README.md). Android blocks screenshots with `FLAG_SECURE`.

## What's new in 0.7.0

Since v0.6.2:

- **VLESS over a CDN, preview** ([#112](https://github.com/onixus/Rust-trustvpn/pull/112)). `vless://` links from the server's CDN panel import as profiles and connect over WebSocket + TLS without an Xray binary. See [VLESS](docs/vless.md).
- **Connection failure journal** ([#114](https://github.com/onixus/Rust-trustvpn/pull/114)). The desktop services and automatic SOCKS recovery keep a local, bounded (7 days, 15 MB) journal of failed connects and reconnects without addresses or credentials. See [diagnostics journal](docs/diagnostics-journal.md).
- **Transport stop reasons on macOS** ([#113](https://github.com/onixus/Rust-trustvpn/pull/113)). The service journal names who closed the transport and which reconnect step failed.
- **macOS managed access freshness** ([#115](https://github.com/onixus/Rust-trustvpn/pull/115)). Managed profiles with a finite lease connect in whole-computer mode again; the service enforces the lease itself.
- **Windows guard probe** ([#116](https://github.com/onixus/Rust-trustvpn/pull/116)). A probe datagram dropped by our own WFP filter now proves the guard, so Protection and DNS no longer show a false failure.

Plain-language notes and upgrade steps are in [docs/releases/v0.7.0.md](docs/releases/v0.7.0.md). Earlier changes (wake reconnect, guard proofs, UI variant 3, honest connection status, guarded recovery) are in the [release records](docs/releases/).

## Features

### Client and profiles

- Native Rust/iced desktop UI, an optional Tauri WebView frontend and a Linux terminal client ([TUI](docs/tui.md)). See [UI choices](docs/ui-choices.md).
- Native Android app on VpnService with the shared Rust core.
- Import of TrustTunnel endpoint/client TOML, R-TrustTunnel JSON, Hysteria YAML/JSON, AmneziaWG `awg-quick` files and `tt://`, `hy2://`, `hysteria2://`, `vless://` links, with a preview before anything is saved.
- Encrypted profile vault. Desktop keeps the key in the OS credential store, Android in Android Keystore. There is no plaintext fallback.
- Honest connection status: transport, route, DNS, guard and reachability are reported as passed, failed, unknown, stale or unsupported, never inferred from "connected". See [VPN observations](docs/vpn-observations.md) and [system diagnostics](docs/system-diagnostics.md).
- Opt-in recovery through up to three backup profiles with the guard kept up. See [failover](docs/failover.md) and [recovery](docs/recovery.md).
- Device enrollment and scoped profile synchronization through the TrustTunnel portal. See [profile exchange](docs/portal.md).

### Protocols

| Protocol | Selected by | Support | Details |
| --- | --- | --- | --- |
| TrustTunnel | TOML, JSON, `tt://` | HTTP/2 and HTTP/3 chosen by the profile, no silent fallback. IPv4/IPv6 TCP and UDP, DNS, ICMP where the platform dataplane supports it. | [HTTP/3](docs/http3.md) |
| Hysteria 2 | `hy2://`, `hysteria2://`, Hysteria YAML/JSON | QUIC + HTTP/3 auth, TCP and UDP, Salamander and Gecko obfuscation, port hopping, Brutal/BBR/Reno, pinSHA256, custom CA and mTLS. No ICMP; insecure TLS, ECH, Realms and fingerprint parroting are rejected. | [Hysteria 2](docs/hysteria2.md) |
| AmneziaWG 3 | `awg-quick` `.conf` | In-process WireGuard with the AmneziaWG obfuscation layer. Verified against `amneziawg-go` 3.1 on loopback only. | [AmneziaWG](docs/amneziawg.md) |
| VLESS (preview) | `vless://` | WebSocket + TLS behind a CDN, TCP and UDP up to 8190 bytes, no ICMP. XHTTP imports but does not connect; `fp=chrome` is not emulated. | [VLESS](docs/vless.md) |

## Platform status

| Platform | Current state | Important remaining work |
| --- | --- | --- |
| Windows x64 | Native UI, Wintun/SCM service and WFP guard. Production full-tunnel checks passed for TrustTunnel and Hysteria 2. A real 30-minute S3 sleep/wake Hysteria session passed, including reconnect and traffic checks; Always-on also remained blocked until automatic recovery. | Cold-boot coverage, broader sleep/network combinations, installer signing. |
| Linux x86_64 / ARM64 | Wayland-only desktop, TUN host service, nftables and systemd-resolved. Native/WebView/Both packaging, physical KDE/Wayland smoke, signed Flatpak flow, TrustTunnel/Hysteria full-tunnel and network-handoff coverage exist. | More physical reboot/sleep coverage and final installer polish across distributions. |
| macOS Apple Silicon | Native/WebView/Both preview, root LaunchDaemon and utun system tunnel. TrustTunnel live IPv4/IPv6 TCP/UDP/ICMP, DNS, reconnect and service-crash recovery passed. Installed sleep/wake passed on two Macs. | Boot Always-on, roam/network handoff, clean install on another Mac, signed automatic update/rollback, Developer ID/notarization, installed Hysteria full-tunnel acceptance. |
| Android arm64 / x86_64 | Native VpnService, encrypted vault, file/text/QR import, app selection, portal sync, Always-on/lockdown and TrustTunnel/Hysteria support. Physical POCO and Huawei testing covers real traffic and recovery paths; POCO passed 30 minutes of forced deep Doze. | More OEMs (Pixel/Samsung), reboot-before-first-unlock and long soak. MIUI force-stop can leave lockdown active without restarting the VPN service. While the VPN process is dead, lockdown is incomplete: on an Android 16 emulator other apps' DNS and Google Play services traffic went direct. A profile imported without the portal resolves its endpoint before the blocking TUN exists. |
| iOS | Swift/Network Extension preview: import/export, QR, portal sync, On Demand, widget. | Apple signing and a device-installable build. See [iOS](docs/ios.md). |

## Build

The workspace requires **Rust 1.89+**; CI uses Rust 1.98.1.

```bash
git clone https://github.com/onixus/Rust-trustvpn.git
cd Rust-trustvpn
cargo run -p rtrust-native --locked
```

Desktop and service binaries:

```bash
cargo build --release -p rtrust-native -p rtrust-tun -p rtrust-inspect -p rtrust-tui --locked
```

Standard checks:

```bash
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

| Platform | Packaging entry point | Prerequisites and limits |
| --- | --- | --- |
| Windows | `python ci/package_windows.py` | [Windows service](docs/windows-service.md) |
| macOS | `python3 scripts/package-macos-system.py` | [macOS system VPN](docs/macos-system.md) |
| Linux | `python3 scripts/package-flatpak.py` | [Linux service](docs/linux-service.md) |
| Android | `python3 scripts/build-android.py` | [Android](docs/android.md) |

CI runs on Jenkins; see [Jenkins](docs/jenkins.md). Run the GUI as a normal desktop user. System VPN requires the privileged host service, installed separately; the Flatpak itself stays unprivileged.

## Using the client

### Desktop

1. Import a profile file or open/paste a `tt://`, `hy2://`, `hysteria2://` or `vless://` link, review the preview and add it.
2. Choose the connection mode on **Network**: whole computer (system VPN), selected networks, or a local SOCKS5 proxy. System VPN needs the platform service installed first.
3. Connect from **Home**. Closing the Native window keeps the app in the tray. Profile changes are saved to the encrypted vault automatically.

SOCKS5 listens on `127.0.0.1:1080` by default and does not change system routes or DNS. BIND, SOCKS UDP domain addressing and SOCKS UDP fragmentation are not supported.

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

In selected-networks mode the configured DNS server becomes the system resolver only when the selected networks route it through the tunnel (for example, everything except the LAN); LAN-only names such as `router.lan` then stop resolving, as in whole-computer mode. On Windows port 53 is then allowed only through the tunnel and loopback. If the system cannot accept a resolver (no systemd-resolved on Linux, failed macOS DNS preflight), DNS is left unchanged instead of failing the connection.

See [desktop lifecycle](docs/desktop-lifecycle.md) and [Always-on](docs/always-on.md).

### Android

1. Install the APK and import a file, pasted profile/link or QR code.
2. Select a profile, tap Connect and accept Android VPN consent. Widgets and automatic connection use the separately assigned default profile.
3. Optionally limit the VPN to selected apps.
4. For fail-closed behaviour after process death, enable Android **Always-on VPN** and **Block connections without VPN**.

The source declares minSdk 29 and targetSdk 36. See [Android](docs/android.md).

## Validation highlights

- Official Hysteria 2.12.3 interop: TCP, UDP, authentication/TLS rejection, Salamander, Gecko + mTLS, port hopping and Brutal.
- Windows production TrustTunnel and Hysteria 2 full-tunnel tests with WFP fail-closed behaviour, exact route recovery and 30-minute S3 sleep/wake including Always-on.
- Physical Android TrustTunnel/Hysteria testing on POCO X3 and Huawei, with 30 minutes of forced deep Doze on POCO.
- macOS live TrustTunnel IPv4/IPv6, DNS, reconnect and crash-recovery acceptance.
- Linux system-service, Wayland, Flatpak and network-handoff coverage; container lab with packet-level failover, Always-on recovery and route-explain lanes.

A passing test on one platform or protocol does not mean every published package was rebuilt with the newest main. The platform documents state the exact evidence and open items.

## Repository layout

| Path | Purpose |
| --- | --- |
| `apps/native` | Native desktop client |
| `apps/webview` | Optional Tauri WebView desktop frontend |
| `apps/tui` | Linux terminal client |
| `apps/tun` | Desktop TUN/Wintun/utun dataplane and services |
| `apps/macos` | macOS application and system integration |
| `apps/android` | Android VpnService app and JNI/Rust integration |
| `apps/ios` | iOS Swift/Network Extension preview |
| `apps/inspect`, `apps/codec` | Diagnostics and profile tooling |
| `crates` | Shared profile, transport, storage, control, desktop, mobile, portal-client and update logic |
| `deploy`, `packaging`, `scripts` | Service/update deployment assets, packaging and interop helpers |
| `ci`, `Jenkinsfile*` | Build, security and runtime validation |
| `vendor/h2`, `vendor/h3` | Patched HTTP/2 and HTTP/3 dependencies |
| `docs` | Architecture, platform status, releases and acceptance evidence |

This repository contains the VPN clients, the client side of the portal integration and the [portal API contract](docs/profile-api.md). The server implementation, administration UI and server deployment belong to [onixus/tunnel](https://github.com/onixus/tunnel).

## Documentation

- **Overview:** [Project status](docs/project-status.md) · [Implementation status](docs/implementation.md) · [Architecture](docs/architecture.md) · [Delivery and acceptance](docs/delivery.md) · [Technical debt](docs/technical-debt.md)
- **Releases:** [Release records](docs/releases/) · [Package acceptance](docs/package-acceptance.md) · [Secure updates](docs/secure-updates.md) · [Evidence](docs/evidence.md)
- **Protocols:** [HTTP/3](docs/http3.md) · [Hysteria 2](docs/hysteria2.md) · [AmneziaWG](docs/amneziawg.md) · [VLESS](docs/vless.md)
- **Connection behaviour:** [Event journal](docs/diagnostics-journal.md) · [VPN observations](docs/vpn-observations.md) · [System diagnostics](docs/system-diagnostics.md) · [Route explain](docs/route-explain.md) · [Routing policy](docs/routing-policy.md) · [Failover](docs/failover.md) · [Recovery](docs/recovery.md) · [Always-on](docs/always-on.md) · [Desktop lifecycle](docs/desktop-lifecycle.md)
- **Desktop:** [Desktop apps](docs/desktop-apps.md) · [UI choices](docs/ui-choices.md) · [Terminal client](docs/tui.md) · [Windows service](docs/windows-service.md) · [macOS system VPN](docs/macos-system.md) · [Linux service](docs/linux-service.md) · [Linux full tunnel](docs/linux-full-tunnel.md) · [Screenshots](docs/screenshots/README.md)
- **Mobile:** [Android](docs/android.md) · [iOS](docs/ios.md) · [Mobile flow observations](docs/mobile-flow-observations.md)
- **Portal and managed profiles:** [Profile exchange](docs/portal.md) · [Profile API](docs/profile-api.md) · [Managed devices](docs/managed-devices.md) · [Access scope validation](docs/access-scope-validation.md)
- **CI and labs:** [Jenkins](docs/jenkins.md) · [Linux lab](docs/linux-lab.md) · [Linux acceptance](docs/linux-acceptance.md) · [Android on macOS](docs/android-macos.md) · [macOS sleep recovery](docs/macos-sleep-recovery-validation.md)
- **Contributing:** [Issue agent team](docs/issue-agent-team.md) (roles and gates for agent-assisted issue work; see `AGENTS.md`)

Some historical documents describe older milestones. When they conflict, prefer the current platform-specific document and the newest release evidence.

## License

[Apache License 2.0](LICENSE). Vendored dependencies retain their own licenses.
