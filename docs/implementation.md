# Состояние реализации — 28 октября 2026

Workspace: **0.7.0** (desktop update sequence 13, Android
0.7.0 / 70001, iOS 0.7.0 / 70001). Готовится релиз [v0.7.0](releases/v0.7.0.md):
VLESS через CDN (#112), журнал неудачных подключений (#114), причины остановки
транспорта на macOS (#113), managed access freshness на macOS (#115) и
проверка guard на Windows (#116).

[v0.6.2](releases/v0.6.2.md) опубликован 21 октября из `4123160`:
Windows, macOS (UI Choices DMG), Linux (Flatpak, `rtrust-host-0.6.2-12`) и Android.

Тег `v0.6.2` соответствует main `4123160`; в него вошли UI v3, Linux TUI,
service system probes, IPC v7 и исправления wake/liveness/SOCKS recovery
(#69–#106). Архивы iOS по-прежнему опубликованы только в v0.5.0.
Основание сверки — исходники тега, диффы merged PR и открытый
[документационный PR #109](https://github.com/onixus/Rust-trustvpn/pull/109).
[Сводка issue и доказательств](project-status.md) отделяет реализацию,
публикацию и приёмку точного установленного пакета.

Серверная реализация и deployment принадлежат
[onixus/tunnel](https://github.com/onixus/tunnel); здесь остаются клиенты,
shared Rust core, desktop services и client-side portal integration.

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
| Android | VpnService, encrypted vault, file/text/QR import, app routing, portal sync, Always-on/lockdown, resizable widget и Quick Settings tile, managed recovery, следование за предпочтительной сетью после handoff, настройка учёта трафика VPN; minSdk 29, targetSdk 36, versionCode 60202, versionName 0.6.2; APK опубликован в v0.6.2. UI вариант 3, VPN-bound checks (#73), исправление start/stop (#80), обработка link changes (#86/#89) и sleep recovery (#92). |
| iOS | Preview на Swift/Network Extension: import/export, QR, portal sync, On Demand, widget; device archive требует Apple signing. |
| Routing | Desktop IPv4 TUN include/exclude, LAN bypass, profile routing и server-assigned route groups. Route groups не используются Android/iOS. |
| Linux TUI | `apps/tui` поверх общего desktop Controller: профили, connect/disconnect, SOCKS/TUN/Full настройки; portal/export/system diagnostics остаются в GUI. Installed TUN/full acceptance через TUI — NOT RUN. |
| Proxy | SOCKS5 и HTTP-запросы на mixed desktop proxy port. Native UI при Degraded останавливает listener и повторяет тот же профиль/порт с recovery budget (#104); без смены режима или direct fallback. Обычные health errors и неудачный ручной Start не запускают этот retry. |
| Обновления | Опубликованный desktop sequence 9 исправляет ошибку идентичности старой 0.5.0 сборки; на Windows пройден реальный 7→9 update, forced unhealthy install, rollback на 7 и повторный update на 9. Текущие исходники — sequence 12; v0.6.2 опубликован. Наличие release assets не подтверждает продвижение update-channel latest или подписи точного пакета. Для автоотката 10→9 служба Windows допускает от апдейтера sequence 9 (control IPC v1) только `PrepareUpdate` и отвечает в форме v1; покрыто unit-тестами; 2026-10-13 на Windows-стенде пройден 9→10 с принудительным откатом и повтором на манифестах с лабораторной подписью (продакшен-подпись sequence 10 и Authenticode не проверялись) (см. [v0.6.0](releases/v0.6.0.md#compatibility)). |
| Наблюдения и диагностика | Типизированные observations с generations, события сети/пробуждения, route explain, system-path diagnostics с verdict/actions и автоматическими проверками; control IPC v7 (system probes только при просмотре UI). |
| Recovery | Opt-in восстановление через разрешённые резервные профили (обычная сессия на desktop; Always-on — только Linux/Windows), guard не снимается; macOS/iOS Always-on fallback recovery не поддерживается. Android Always-on reconnect на текущей сети добавлен в #63; переключение на резервный профиль этим не подтверждается. |

## Проверки, относящиеся к 0.5.0 rebuild.9 (история)

- GitHub Actions прошли на Linux, macOS и Windows.
- Jenkins native build 10 завершён SUCCESS: Windows/macOS packaging, protocol E2E и полный Linux ARM64 service/TUN/full-tunnel/Always-on набор.
- Jenkins Linux build 12 прошёл x86_64 unit, Wayland и network suite.
- Packaging restart 13 завершён SUCCESS: isolated signed Flatpak install/update/rollback и отказ от unsigned update.
- Windows latest переведён на update sequence 9; installed updater распознаёт sequence 9 как текущую.
- macOS automatic-update promotion пока withheld.
- Android/iOS binaries в rebuild.9 не пересобирались; используются артефакты исходного v0.5.0.

## Приёмка 0.6.2 и границы исторических результатов

- [Issue #99](https://github.com/onixus/Rust-trustvpn/issues/99#issuecomment-6291062141)
  закрыта после installed macOS sleep/wake на двух Mac с пакетом из `da92864`:
  reconnect за 3–4 с и передача данных без ручного Stop/Start. Это evidence
  для указанного пакета, а не приёмка артефактов тега `4123160`.
- Итоги CI, Jenkins и тестовых бинарников, перенесённые из PR #109, указаны в
  [v0.6.2](releases/v0.6.2.md#acceptance-status). Новые прогоны этой
  документационной сверкой не выполнялись. Точные опубликованные пакеты,
  upgrade Android с beta.1, SOCKS wake и handoff через сон — NOT RUN.

### Исторические пакеты 0.6.0 и 0.6.1

- Для 0.6.0 пройдены только две installed-package/device проверки: Windows
  9 → 10 с откатом на лабораторно подписанных манифестах и Android preview.2 на
  Huawei DEL-LX9. Остальные статусы NOT RUN/BLOCKED с владельцами перечислены в
  [v0.6.0](releases/v0.6.0.md#acceptance-status). Для 0.6.1 installed-package и
  device acceptance не выполнялась ([v0.6.1](releases/v0.6.1.md#acceptance-status)).
- Linux lab добавил packet-level capture failover/Always-on (#87) и
  runtime route-explain (#88) в изолированной сети. macOS #96 добавил
  BPF-доказательство конкретных guard probes. Эти проверки ограничены
  своими сценариями и не доказывают отсутствие всех DNS/IPv6 leaks на
  каждом опубликованном пакете.
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
