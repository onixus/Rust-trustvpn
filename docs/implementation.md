# Состояние реализации — 7 октября 2026

Текущая версия workspace: **0.5.0**.

Публичные preview-наборы:
- desktop rebuild: [v0.5.0-rebuild.9](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0-rebuild.9), опубликован 6 октября 2026;
- Android/iOS и исходный 0.5.0 package set: [v0.5.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0).

`main` уже разделён по ответственности: серверная реализация и её deployment удалены из этого репозитория и живут в [onixus/tunnel](https://github.com/onixus/tunnel). Здесь остаются клиенты, shared Rust core, desktop system services, client-side portal integration и контракт API.

## Реализовано

| Область | Текущее состояние |
| --- | --- |
| Профили | Endpoint/client TOML, R-TrustTunnel JSON, tt://, hy2://, hysteria2://, Hysteria YAML/JSON и awg-quick; preview/validation, loss-aware export, redaction секретов. |
| Хранилище | Зашифрованный vault без plaintext fallback. Desktop использует OS credential store; Android — Android Keystore. |
| TrustTunnel | Нативные Rust HTTP/2 и HTTP/3 transports, TCP/UDP, DNS и системный TUN dataplane. Явный выбор transport без скрытого fallback для профиля с фиксированным protocol. |
| Hysteria 2 | QUIC/HTTP3 auth, TCP/UDP, Salamander/Gecko, port hopping, Brutal, congestion settings, TLS SNI/pinSHA256, custom CA и mTLS credentials. |
| AmneziaWG 3 | In-process WireGuard transport с AmneziaWG 3.1 obfuscation и импортом awg-quick. |
| Windows | Native desktop, Wintun/SCM service, WFP fail-closed, full-tunnel acceptance, sleep/wake recovery и signed metadata updater. |
| Linux | Wayland desktop, TUN host service, nftables/systemd-resolved, Native/WebView/Both Flatpak, signed install/update/rollback flow. |
| macOS | Native/WebView/Both packaging, LaunchDaemon/utun system path, glass UI toggle, live TrustTunnel acceptance; часть system-VPN/update acceptance ещё открыта. |
| Android | VpnService, encrypted vault, file/text/QR import, app routing, portal sync, Always-on/lockdown, widget; minSdk 29, targetSdk 36, versionCode 50001, versionName 0.5.0-preview.1. |
| iOS | Preview на Swift/Network Extension: import/export, QR, portal sync, On Demand, widget; device archive требует Apple signing. |
| Routing | Desktop IPv4 TUN include/exclude, LAN bypass, profile routing и server-assigned route groups. Route groups не используются Android/iOS. |
| Proxy | SOCKS5 и HTTP-запросы на mixed desktop proxy port. |
| Обновления | Desktop sequence 9 исправляет ошибку идентичности старой 0.5.0 сборки. На Windows пройден реальный 7→9 update, forced unhealthy install, rollback на 7 и повторный update на 9. |

## Проверки, относящиеся к 0.5.0 rebuild.9

- GitHub Actions прошли на Linux, macOS и Windows.
- Jenkins native build 10 завершён SUCCESS: Windows/macOS packaging, protocol E2E и полный Linux ARM64 service/TUN/full-tunnel/Always-on набор.
- Jenkins Linux build 12 прошёл x86_64 unit, Wayland и network suite.
- Packaging restart 13 завершён SUCCESS: isolated signed Flatpak install/update/rollback и отказ от unsigned update.
- Windows latest переведён на update sequence 9; installed updater распознаёт sequence 9 как текущую.
- macOS automatic-update promotion пока withheld.
- Android/iOS binaries в rebuild.9 не пересобирались; используются артефакты исходного v0.5.0.

## Ограничения preview

- Windows installer не Authenticode-signed.
- macOS packages ad-hoc sealed и не Developer-ID notarized.
- Полная macOS system-VPN acceptance остаётся незавершённой.
- iOS device archive не является готовым IPA и требует подписи Apple.
- Route groups desktop-only.
- Дополнительные physical-device/reboot/long-soak сценарии для mobile остаются release-hardening работой.

## Сборка и проверки

Workspace требует Rust **1.89+**.

```sh
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Основные entry points упаковки:
- Windows: `python ci/package_windows.py`
- macOS: `python3 scripts/package-macos-system.py`
- Android: `python3 scripts/build-android.py`
- Linux: `python3 scripts/package-flatpak.py`

Подробные platform-specific ограничения и acceptance evidence находятся в:
[Windows](windows-service.md), [Linux](linux-service.md), [macOS](macos-system.md),
[Android](android.md), [iOS](ios.md), [Hysteria 2](hysteria2.md),
[AmneziaWG](amneziawg.md), [secure updates](secure-updates.md) и
[release v0.5.0](releases/v0.5.0.md).
