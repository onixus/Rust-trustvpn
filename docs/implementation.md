# Состояние реализации — 14 октября 2026

Текущая версия workspace: **0.6.1** (desktop update sequence 11, Android
0.6.1-preview.1 / 60101, iOS 0.6.1 / 60101); изменения — [v0.6.1](releases/v0.6.1.md),
предыдущий релиз — [v0.6.0](releases/v0.6.0.md). Ни один из них не объявлен
production-ready. Приёмка установленных пакетов и устройств для 0.6.1 не
проводилась; перевод `latest` на sequence 11 в release record отмечен как NOT RUN.

Публичные preview-наборы:
- [v0.6.1](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.6.1) (Latest, 13 октября 2026): Windows, macOS, Android;
- [v0.6.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.6.0) (13 октября 2026): последний набор с Linux Flatpak и `rtrust-host-0.6.0-7`;
- [v0.5.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0): архивы iOS.

После 0.6.1 в main вошёл #62 (PR #69): health check сессии, которая не пропускает
трафик, теперь проваливается; см. [HTTP/3](http3.md#dead-session-detection).

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
| Android | VpnService, encrypted vault, file/text/QR import, app routing, portal sync, Always-on/lockdown, resizable widget и Quick Settings tile, managed recovery, следование за предпочтительной сетью после handoff, настройка учёта трафика VPN; minSdk 29, targetSdk 36, versionCode 60101, versionName 0.6.1-preview.1 (релиз v0.6.1, ключ подписи из 0.6.0). |
| iOS | Preview на Swift/Network Extension: import/export, QR, portal sync, On Demand, widget; device archive требует Apple signing. |
| Routing | Desktop IPv4 TUN include/exclude, LAN bypass, profile routing и server-assigned route groups. Route groups не используются Android/iOS. |
| Proxy | SOCKS5 и HTTP-запросы на mixed desktop proxy port. |
| Обновления | Опубликованный desktop sequence 9 исправляет ошибку идентичности старой 0.5.0 сборки; на Windows пройден реальный 7→9 update, forced unhealthy install, rollback на 7 и повторный update на 9. Релизы 0.6.0 и 0.6.1 компилируются как sequence 10 и 11 соответственно; исходники main — sequence 11. Для автоотката 10→9 служба Windows допускает от апдейтера sequence 9 (control IPC v1) только `PrepareUpdate` и отвечает в форме v1; покрыто unit-тестами; 2026-10-13 на Windows-стенде пройден 9→10 с принудительным откатом и повтором на манифестах с лабораторной подписью (продакшен-подпись sequence 10 и Authenticode не проверялись) (см. [v0.6.0](releases/v0.6.0.md#compatibility)). |
| Наблюдения и диагностика | Типизированные observations с generations, события сети/пробуждения, route explain, system-path diagnostics с verdict/actions и автоматическими проверками; control IPC v6. |
| Recovery | Opt-in восстановление через разрешённые резервные профили (обычная сессия на desktop; Always-on — только Linux/Windows), guard не снимается; macOS/mobile Always-on recovery не поддерживается. |

## Проверки, относящиеся к 0.5.0 rebuild.9 (история)

- GitHub Actions прошли на Linux, macOS и Windows.
- Jenkins native build 10 завершён SUCCESS: Windows/macOS packaging, protocol E2E и полный Linux ARM64 service/TUN/full-tunnel/Always-on набор.
- Jenkins Linux build 12 прошёл x86_64 unit, Wayland и network suite.
- Packaging restart 13 завершён SUCCESS: isolated signed Flatpak install/update/rollback и отказ от unsigned update.
- Windows latest переведён на update sequence 9; installed updater распознаёт sequence 9 как текущую.
- macOS automatic-update promotion пока withheld.
- Android/iOS binaries в rebuild.9 не пересобирались; используются артефакты исходного v0.5.0.

## Ограничения 0.6.0 и 0.6.1

- Для 0.6.0 пройдены только две installed-package/device проверки: Windows
  9 → 10 с откатом на лабораторно подписанных манифестах и Android preview.2 на
  Huawei DEL-LX9. Остальные статусы NOT RUN/BLOCKED с владельцами перечислены в
  [v0.6.0](releases/v0.6.0.md#acceptance-status). Для 0.6.1 installed-package и
  device acceptance не выполнялась ([v0.6.1](releases/v0.6.1.md#acceptance-status)).
- Ни один runner не делает независимый packet capture физического интерфейса:
  отсутствие утечек подтверждено только активными пробами и атрибуцией в
  контейнере/эмуляторе.
- Dependency audit (`cargo audit`/`cargo deny`) не настроен; есть только Trivy fs
  в Jenkins.
- Бюджеты recovery/ресурсов и soak ≥24 ч не утверждены.

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
