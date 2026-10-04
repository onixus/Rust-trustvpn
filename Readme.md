# R-TrustTunnel

[English](Readme.md) · [Русский](readme_ru.md)

R-TrustTunnel is a native VPN client written in Rust for **TrustTunnel** and **Hysteria 2**. It includes desktop clients, an Android VpnService implementation, shared Rust transport/profile/storage crates, privileged system-tunnel services, and the TrustTunnel profile-exchange portal extension.

The client implements its own transport and does **not** wrap the official TrustTunnel or Hysteria CLI.

> **Project status: development preview, October 3, 2026.**
>
> The latest published package set is **v0.4.0** from October 3. It adds the AmneziaWG 3 transport and includes the Hysteria 2, Windows, profile-link and Android changes made after v0.3.2-ui.2. What was and was not validated for these packages is listed in the [release scope](docs/releases/v0.4.0.md).

## Download

Latest published preview: **[v0.4.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.4.0)**.

| Platform | Package | Notes |
| --- | --- | --- |
| macOS Apple Silicon | [Native / WebView / Both DMG](https://github.com/onixus/Rust-trustvpn/releases/download/v0.4.0/R-TrustTunnel-macOS-arm64-UI-Choices.dmg) | Choose one PKG from the DMG. Administrator authorization is required. No Developer ID signing or notarization yet. |
| Linux x86_64, Wayland | [Native](https://github.com/onixus/Rust-trustvpn/releases/download/v0.4.0/R-TrustTunnel-Linux-x86_64.flatpak) · [WebView](https://github.com/onixus/Rust-trustvpn/releases/download/v0.4.0/R-TrustTunnel-Linux-x86_64-webview.flatpak) · [Both](https://github.com/onixus/Rust-trustvpn/releases/download/v0.4.0/R-TrustTunnel-Linux-x86_64-both.flatpak) | The Flatpak contains the unprivileged UI. System VPN also needs the separate host service. |
| Android 10+, arm64 / x86_64 | [Signed APK](https://github.com/onixus/Rust-trustvpn/releases/download/v0.4.0/R-TrustTunnel-Android.apk) | versionCode 40001, versionName 0.4.0-preview.1. |
| Windows x64 | [Installer](https://github.com/onixus/Rust-trustvpn/releases/download/v0.4.0/R-TrustTunnel-Windows-x64-Setup.exe) | Not Authenticode-signed. This build of the installer was not installed on a physical host before publication. |

The release also contains SHA256SUMS, signatures, provenance/validation evidence and the signed Linux host package. See the [release scope](docs/releases/v0.4.0.md).

## What is new in v0.4.0

Compared with v0.3.2-ui.2, the published packages now contain:

- an **AmneziaWG 3** transport: awg-quick configuration import and the 3.1 obfuscation set, see [AmneziaWG](docs/amneziawg.md);
- substantially expanded **Hysteria 2** compatibility: port hopping, Brutal bandwidth mode, BBR/Reno selection, QUIC windows/timeouts, Salamander and Gecko obfuscation, leaf-certificate pinSHA256 checking, and embedded mutual-TLS client credentials;
- production Windows full-tunnel checks for both TrustTunnel and Hysteria 2;
- real Windows S3 sleep/wake validation, including an Always-on session that stayed fail-closed and reconnected after resume;
- a 30-minute forced deep-Doze test on a physical POCO X3 with traffic remaining inside the tunnel;
- a refreshed Android home screen with a status card, profile cards and compact action tiles;
- desktop registration for tt:// and hy2:// profile links on Windows, macOS and Flatpak;
- removal of the former unified server console from this repository. That console now lives in the separate [onixus/tunnel](https://github.com/onixus/tunnel) project; this repository keeps only the TrustTunnel profile-exchange portal extension.

## Features

### Client and profile management

- Native Rust/iced desktop UI and an optional Tauri WebView frontend.
- Native Android application using VpnService plus the shared Rust core.
- Import of endpoint TOML, full client TOML, R-TrustTunnel JSON, tt://, hy2:// and hysteria2://.
- Preview and validation before profile replacement.
- Automatic encrypted profile persistence. Desktop stores the encryption key in the OS credential store; Android uses Android Keystore. There is no plaintext fallback.
- System tray, startup options, autoconnect preference, diagnostics and explicit recovery flows.
- Server-side device enrollment and scoped profile synchronization through the TrustTunnel portal extension.

### TrustTunnel

- Native Rust HTTP/2 transport for system VPN.
- SOCKS5 mode over HTTP/2 or HTTP/3.
- IPv4/IPv6 TCP and UDP handling, DNS, ICMP where supported by the platform dataplane, bounded fragmentation handling, reconnect and fail-closed protection.
- Imported TrustTunnel HTTP/3 profiles are preserved, but **TrustTunnel HTTP/3 system VPN is still deferred**. System-tunnel sessions currently use HTTP/2.

### Hysteria 2

The shared engine automatically selects Hysteria 2 for hy2://, hysteria2:// and supported Hysteria YAML/JSON profiles.

Current main supports:

- QUIC + HTTP/3 authentication;
- multiplexed TCP and UDP datagrams;
- Salamander and Gecko obfuscation;
- server port hopping and hop intervals;
- bandwidth negotiation and Brutal upload control;
- BBR/Reno selection plus the default congestion controller;
- QUIC receive windows, idle timeout, keepalive and fixed-MTU behaviour;
- TLS SNI and pinSHA256 validation in addition to normal CA/hostname verification;
- embedded custom CA and mutual-TLS certificate/key in R-TrustTunnel JSON.

Unsupported or intentionally rejected options include insecure TLS, ECH, Hysteria Realms, Chrome QUIC fingerprint parroting, mimic, fastOpen/lazy and non-standard BBR profiles. Hysteria 2 has no ICMP relay.

See [Hysteria 2 support and limits](docs/hysteria2.md).

AmneziaWG 3 `awg-quick` configurations select an in-process WireGuard transport with the AmneziaWG obfuscation layer (junk and signature packets, prefixes, type ranges, header protection, padding). It is verified against the official `amneziawg-go` 3.1 on loopback only; see [supported options and limits](docs/amneziawg.md).

## Platform status

| Platform | Current state | Important remaining work |
| --- | --- | --- |
| Windows x64 | Native UI, Wintun/SCM service and WFP guard. Production full-tunnel checks passed for TrustTunnel and Hysteria 2. A real 30-minute S3 sleep/wake Hysteria session passed, including reconnect and traffic checks; Always-on also remained blocked until automatic recovery. | Cold-boot coverage, broader sleep/network combinations, refreshed public installer delivery and signing. |
| Linux x86_64 / ARM64 | Wayland-only desktop, TUN host service, nftables and systemd-resolved. Native/WebView/Both packaging, physical KDE/Wayland smoke, signed Flatpak flow, TrustTunnel/Hysteria full-tunnel and network-handoff coverage exist. | More physical reboot/sleep coverage and final installer polish across distributions. |
| macOS Apple Silicon | Native/WebView/Both preview, root LaunchDaemon and utun system tunnel. TrustTunnel live IPv4/IPv6 TCP/UDP/ICMP, DNS, reconnect and service-crash recovery passed. | Boot Always-on, sleep/network handoff, clean install on another Mac, signed automatic update/rollback, Developer ID/notarization. Installed macOS Hysteria full-tunnel acceptance is still incomplete. |
| Android arm64 / x86_64 | Native VpnService, encrypted vault, file/text/QR import, app selection, portal sync, Always-on/lockdown and TrustTunnel/Hysteria support. Physical POCO and Huawei testing covers real traffic and recovery paths; POCO passed 30 minutes of forced deep Doze. | More OEMs such as Pixel/Samsung, reboot-before-first-unlock and overnight/long soak. MIUI force-stop can leave lockdown active without automatically restarting the VPN service. |

Desktop Native/WebView/Both details are in [UI choices](docs/ui-choices.md). Linux is Wayland-only.

## Screenshots

The current gallery contains real Native and WebView desktop captures from the v0.3.2 UI refresh:

| Native | WebView |
| --- | --- |
| ![Native home](docs/screenshots/native-home-0.3.2-ui.1.jpg) | ![WebView home](docs/screenshots/webview-home-0.3.2-ui.1.jpg) |

See [screenshots and connection settings](docs/screenshots/README.md).

The refreshed Android home screen is included in the v0.4.0 APK.

## Build

The workspace requires **Rust 1.89+**. Current CI uses Rust 1.98.1.

Clone and run the native UI:

    git clone https://github.com/onixus/Rust-trustvpn.git
    cd Rust-trustvpn
    cargo run -p rtrust-native --locked

Build the main desktop/service binaries:

    cargo build --release -p rtrust-native -p rtrust-tun -p rtrust-inspect --locked

Run the standard Rust checks:

    cargo fmt --all --check
    cargo test --workspace --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings

Platform packaging entry points:

- **Windows:** python ci/package_windows.py
- **macOS:** python3 scripts/package-macos-system.py
- **Android:** python3 scripts/build-android.py
- **Linux:** python3 scripts/package-flatpak.py

Platform-specific prerequisites and acceptance limits are documented in:

- [Windows service](docs/windows-service.md)
- [Linux service](docs/linux-service.md)
- [macOS system VPN](docs/macos-system.md)
- [Android](docs/android.md)
- [Jenkins / CI](docs/jenkins.md)

Run the GUI as a normal desktop user. System VPN on desktop requires the privileged host service installed separately. The Flatpak itself is intentionally unprivileged.

## Using the client

### Desktop

1. Import a profile file or open/paste a tt://, hy2:// or hysteria2:// link.
2. Review the parsed profile and add or replace it.
3. Select the default profile and connection mode.
4. For system VPN, install the matching platform service first.
5. Connect from the main screen. Closing the native window normally keeps the application available in the tray.
6. Profile changes are written automatically to the encrypted vault.

SOCKS5 mode listens on 127.0.0.1:1080 by default:

    curl --socks5-hostname 127.0.0.1:1080 https://example.com

SOCKS5 mode does not change system routes or DNS. BIND, SOCKS UDP domain addressing and SOCKS UDP fragmentation are not supported.

See [desktop lifecycle](docs/desktop-lifecycle.md) and [Always-on](docs/always-on.md).

### Android

1. Install the APK and import a file, pasted profile/link or QR code.
2. Select the default profile and tap Connect.
3. Accept Android VPN consent.
4. Optionally configure an app allowlist in VPN apps.
5. For fail-closed behaviour after process death, enable Android **Always-on VPN** and **Block connections without VPN**.
6. Server profiles can be enrolled and synchronized through the portal integration.

The source tree currently declares Android minSdk 29, targetSdk 36, versionCode 40001 and versionName 0.4.0-preview.1.

See [Android documentation](docs/android.md) and [profile exchange](docs/portal.md).

## Validation highlights

Current evidence includes:

- official Hysteria 2.12.3 interop fixtures for TCP, UDP, authentication/TLS rejection, Salamander, Gecko + mTLS, port hopping and Brutal behaviour;
- Windows production TrustTunnel and Hysteria 2 full-tunnel tests with WFP fail-closed behaviour and exact route recovery;
- Windows 30-minute S3 sleep/wake checks, including Always-on recovery;
- physical Android TrustTunnel/Hysteria testing on POCO X3 and Huawei devices;
- 30-minute forced deep Doze on POCO with tunnel egress retained;
- macOS live TrustTunnel IPv4/IPv6, DNS, reconnect and crash-recovery acceptance;
- Linux system-service, Wayland, Flatpak and network-handoff coverage.

Passing one platform or protocol test does not imply every release package has been rebuilt with the newest main-branch changes. See the linked platform documents for exact evidence and open items.

## Repository layout

| Path | Purpose |
| --- | --- |
| apps/native | Native desktop client |
| apps/webview | Optional Tauri WebView desktop frontend |
| apps/tun | Desktop TUN/Wintun/utun dataplane and services |
| apps/android | Android application and shared JNI/Rust integration |
| apps/inspect, apps/codec | Diagnostics and profile tooling |
| crates | Shared profile, transport, storage, IPC, desktop, portal and update logic |
| server | TrustTunnel profile-exchange portal extension and tests |
| deploy | Portal deployment tooling |
| packaging, scripts | Packaging and interoperability helpers |
| ci, Jenkinsfile* | Build, security and runtime validation |
| vendor/h2 | Patched HTTP/2 dependency |
| docs | Architecture, platform status, releases and acceptance evidence |

The former unified administration console has moved to [onixus/tunnel](https://github.com/onixus/tunnel). Start server-side integration here with [server/README.md](server/README.md) and [deploy/README.md](deploy/README.md).

## Documentation

- [Implementation status](docs/implementation.md)
- [Architecture](docs/architecture.md)
- [Delivery and acceptance](docs/delivery.md)
- [Hysteria 2](docs/hysteria2.md)
- [Android](docs/android.md)
- [Desktop lifecycle](docs/desktop-lifecycle.md)
- [Secure updates](docs/secure-updates.md)
- [Profile exchange API](docs/profile-api.md)
- [Technical debt](docs/technical-debt.md)

Some historical documents describe older milestones. When they conflict, prefer the current platform-specific document and the newest release evidence.

## License

[Apache License 2.0](LICENSE). Vendored dependencies retain their own licenses.
