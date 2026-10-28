# R-TrustTunnel

[English](Readme.md) · [Русский](readme_ru.md)

R-TrustTunnel — нативный VPN-клиент на Rust для **TrustTunnel**, **Hysteria 2**, **AmneziaWG 3** и **VLESS через CDN** (WebSocket + TLS, preview). Транспорты реализованы в самом клиенте; это **не оболочка** над официальными CLI TrustTunnel или Hysteria.

В репозитории находятся desktop-клиенты Windows, Linux и macOS с привилегированными службами туннеля, Android-приложение на VpnService, preview iOS Network Extension и общие Rust-крейты транспорта, профилей, хранилища и управления. Сервер относится к [onixus/tunnel](https://github.com/onixus/tunnel).

> **Development preview.** [v0.7.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.0) опубликован 28 октября 2026 года из `232fd7b` (workspace 0.7.0, update sequence 13). Публикация не доказывает приёмку установленного пакета или готовность к production: см. [состояние проекта и открытые gates](docs/project-status.md).

## Содержание

- [Скачать](#скачать)
- [Скриншоты](#скриншоты)
- [Что нового в 0.7.0](#что-нового-в-070)
- [Возможности](#возможности)
- [Статус платформ](#статус-платформ)
- [Сборка](#сборка)
- [Использование](#использование)
- [Проверки](#проверки)
- [Структура репозитория](#структура-репозитория)
- [Документация](#документация)

## Скачать

| Платформа | Файл из [v0.7.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.0) | Ограничения |
| --- | --- | --- |
| Windows x64 | `R-TrustTunnel-Windows-x64-Setup.exe` | Без Authenticode-подписи, SmartScreen может предупредить. Update/rollback именно этого пакета не принят. |
| macOS Apple Silicon | `R-TrustTunnel-macOS-arm64-UI-Choices.dmg` | PKG Native, WebView и Both в одном DMG: установите ровно один. Ad-hoc sealed, без Developer ID и notarization. Приёмка системного VPN не завершена ([состав релиза](docs/releases/README.md)). |
| Android 10+, arm64 / x86_64 | `R-TrustTunnel-Android.apk` | 0.7.0 / 70001, ключ релиза введён в 0.6.0. Ставится поверх 0.6.x с сохранением профилей; 0.5.x и старше нужно сначала удалить, локальные профили при этом удаляются. |
| Linux x86_64, Wayland | Native / WebView / Both Flatpak и `rtrust-host-0.7.0-6` | Системному VPN нужен отдельный host package; обновляйте его вместе с приложением. |
| iOS arm64 / Simulator | Архивы из [v0.5.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0) | Начиная с v0.6.0 iOS assets нет. Device archive требует Apple signing и не является готовым IPA. |

В релизе есть `SHA256SUMS`, source identity и manifest. Наличие файлов не заменяет проверку подписи, provenance или канала обновлений. Desktop-приложение и служба должны быть из одного релиза. Хранилище с профилем VLESS не читается версиями 0.6.x, поэтому после добавления такого профиля не откатывайтесь.

Записи релизов: [v0.7.0](docs/releases/v0.7.0.md) · [v0.6.2](docs/releases/v0.6.2.md) · [v0.6.1](docs/releases/v0.6.1.md) · [все релизы](docs/releases/).

## Скриншоты

Desktop-интерфейс 0.7.0 с синтетическими профилями, без подключения:

| Native | WebView |
| --- | --- |
| ![Главная Native](docs/screenshots/native-home-0.7.0.jpg) | ![Главная WebView](docs/screenshots/webview-home-0.7.0.jpg) |

Профили, импорт, проверки, сеть, синхронизация, настройки, светлая тема и способ съёмки — в [галерее](docs/screenshots/README.md). Android блокирует скриншоты через `FLAG_SECURE`.

## Что нового в 0.7.0

По сравнению с v0.6.2:

- **VLESS через CDN, preview** ([#112](https://github.com/onixus/Rust-trustvpn/pull/112)). Ссылки `vless://` из CDN-панели сервера импортируются как профили и подключаются через WebSocket + TLS без программы Xray. См. [VLESS](docs/vless.md).
- **Журнал неудачных подключений** ([#114](https://github.com/onixus/Rust-trustvpn/pull/114)). Desktop-службы и автоматическое восстановление SOCKS ведут локальный ограниченный (7 дней, 15 МБ) журнал неудачных подключений и переподключений без адресов и учётных данных. См. [журнал событий](docs/diagnostics-journal.md).
- **Причины остановки транспорта на macOS** ([#113](https://github.com/onixus/Rust-trustvpn/pull/113)). В журнале службы видно, кто закрыл транспорт и на каком шаге не удалось переподключиться.
- **Свежесть управляемого доступа на macOS** ([#115](https://github.com/onixus/Rust-trustvpn/pull/115)). Управляемые профили с ограниченным сроком снова подключаются в режиме «весь компьютер»; срок контролирует сама служба.
- **Проверка защиты на Windows** ([#116](https://github.com/onixus/Rust-trustvpn/pull/116)). Пробный пакет, отброшенный собственным фильтром WFP, теперь доказывает работу защиты, и строки «Защита» и «DNS» больше не показывают ложную ошибку.

Описание простым языком и порядок обновления — в [docs/releases/v0.7.0.md](docs/releases/v0.7.0.md). Более ранние изменения (переподключение после сна, доказательства защиты, UI вариант 3, честный статус подключения, восстановление с защитой) — в [записях релизов](docs/releases/).

## Возможности

### Клиент и профили

- Нативный desktop-интерфейс на Rust/iced, дополнительный Tauri WebView и консольный клиент для Linux ([TUI](docs/tui.md)). См. [выбор UI](docs/ui-choices.md).
- Нативное Android-приложение на VpnService с общим Rust-ядром.
- Импорт TrustTunnel endpoint/client TOML, R-TrustTunnel JSON, Hysteria YAML/JSON, файлов AmneziaWG `awg-quick` и ссылок `tt://`, `hy2://`, `hysteria2://`, `vless://` с предпросмотром до сохранения.
- Зашифрованное хранилище профилей. На desktop ключ хранится в системном credential store, на Android — в Android Keystore. Plaintext fallback отсутствует.
- Честный статус подключения: транспорт, маршрут, DNS, защита и доступность показываются как пройдено, ошибка, нет данных, устарело или не поддерживается и не выводятся из «подключено». См. [наблюдения VPN](docs/vpn-observations.md) и [системную диагностику](docs/system-diagnostics.md).
- Опциональное восстановление через до трёх резервных профилей с сохранением защиты. См. [failover](docs/failover.md) и [recovery](docs/recovery.md).
- Регистрация устройства и синхронизация разрешённых профилей через TrustTunnel portal. См. [обмен профилями](docs/portal.md).

### Протоколы

| Протокол | Выбирается по | Поддержка | Подробности |
| --- | --- | --- | --- |
| TrustTunnel | TOML, JSON, `tt://` | HTTP/2 и HTTP/3 по выбору профиля, без скрытой смены. IPv4/IPv6 TCP и UDP, DNS, ICMP там, где его поддерживает платформенный dataplane. | [HTTP/3](docs/http3.md) |
| Hysteria 2 | `hy2://`, `hysteria2://`, Hysteria YAML/JSON | QUIC + HTTP/3 auth, TCP и UDP, обфускация Salamander и Gecko, port hopping, Brutal/BBR/Reno, pinSHA256, custom CA и mTLS. Без ICMP; insecure TLS, ECH, Realms и подделка отпечатка отклоняются. | [Hysteria 2](docs/hysteria2.md) |
| AmneziaWG 3 | `awg-quick` `.conf` | Встроенный WireGuard со слоем обфускации AmneziaWG. Проверено против `amneziawg-go` 3.1 только на loopback. | [AmneziaWG](docs/amneziawg.md) |
| VLESS (preview) | `vless://` | WebSocket + TLS за CDN, TCP и UDP до 8190 байт, без ICMP. XHTTP импортируется, но не подключается; `fp=chrome` не эмулируется. | [VLESS](docs/vless.md) |

## Статус платформ

| Платформа | Текущее состояние | Что ещё не закрыто |
| --- | --- | --- |
| Windows x64 | Native UI, Wintun/SCM-служба и WFP guard. Production full-tunnel проверки прошли для TrustTunnel и Hysteria 2. Реальный 30-минутный S3 sleep/wake с Hysteria прошёл reconnect и traffic checks; Always-on также оставался заблокированным до автоматического восстановления. | Cold boot, более широкий набор sleep/network сценариев, подпись установщика. |
| Linux x86_64 / ARM64 | Wayland-only desktop, TUN host service, nftables и systemd-resolved. Есть Native/WebView/Both packaging, физический KDE/Wayland smoke, подписанный Flatpak flow, TrustTunnel/Hysteria full-tunnel и network handoff. | Больше физических reboot/sleep проверок и финальная полировка установки на разных дистрибутивах. |
| macOS Apple Silicon | Native/WebView/Both preview, root LaunchDaemon и системный туннель через utun. Для TrustTunnel пройдены live IPv4/IPv6 TCP/UDP/ICMP, DNS, reconnect и восстановление после падения службы. Sleep/wake установленного пакета прошёл на двух Mac. | Boot Always-on, roam/network handoff, clean install на другом Mac, подписанное auto update/rollback, Developer ID/notarization, приёмка установленного Hysteria full-tunnel. |
| Android arm64 / x86_64 | Native VpnService, encrypted vault, file/text/QR import, выбор приложений, portal sync, Always-on/lockdown и TrustTunnel/Hysteria. Физические POCO и Huawei проверены на реальном трафике и восстановлении; POCO прошёл 30 минут forced deep Doze. | Дополнительные OEM (Pixel/Samsung), reboot-before-first-unlock и длительный soak. На MIUI force-stop может оставить lockdown активным без рестарта VPN-службы. Пока процесс VPN мёртв, lockdown неполный: на эмуляторе Android 16 DNS других приложений и трафик Google Play services шли напрямую. Профиль, импортированный без портала, резолвит endpoint до появления блокирующего TUN. |
| iOS | Preview на Swift/Network Extension: import/export, QR, portal sync, On Demand, widget. | Apple signing и сборка для установки на устройство. См. [iOS](docs/ios.md). |

## Сборка

Workspace требует **Rust 1.89+**; CI использует Rust 1.98.1.

```bash
git clone https://github.com/onixus/Rust-trustvpn.git
cd Rust-trustvpn
cargo run -p rtrust-native --locked
```

Desktop- и service-бинарники:

```bash
cargo build --release -p rtrust-native -p rtrust-tun -p rtrust-inspect -p rtrust-tui --locked
```

Стандартные проверки:

```bash
cargo fmt --all --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

| Платформа | Точка входа упаковки | Зависимости и ограничения |
| --- | --- | --- |
| Windows | `python ci/package_windows.py` | [Служба Windows](docs/windows-service.md) |
| macOS | `python3 scripts/package-macos-system.py` | [Системный VPN macOS](docs/macos-system.md) |
| Linux | `python3 scripts/package-flatpak.py` | [Служба Linux](docs/linux-service.md) |
| Android | `python3 scripts/build-android.py` | [Android](docs/android.md) |

CI работает на Jenkins, см. [Jenkins](docs/jenkins.md). GUI запускайте от обычного пользователя. Для системного VPN нужна отдельно установленная привилегированная служба; сам Flatpak остаётся непривилегированным.

## Использование

### Desktop

1. Импортируйте файл профиля или откройте/вставьте ссылку `tt://`, `hy2://`, `hysteria2://` или `vless://`, проверьте предпросмотр и добавьте профиль.
2. На странице **Сеть** выберите режим: весь компьютер (системный VPN), выбранные сети или локальный SOCKS5-прокси. Для системного VPN сначала установите службу платформы.
3. Подключайтесь на **Главной**. Закрытие Native-окна оставляет приложение в трее. Изменения профилей автоматически сохраняются в зашифрованное хранилище.

SOCKS5 по умолчанию слушает `127.0.0.1:1080` и не меняет системные маршруты и DNS. BIND, SOCKS UDP domain addressing и SOCKS UDP fragmentation не поддерживаются.

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
```

В режиме выбранных сетей DNS из настроек становится системным резолвером, только если выбранные сети ведут его через туннель (например, «всё, кроме LAN»); тогда, как и в режиме «весь компьютер», имена только из LAN вроде `router.lan` перестают резолвиться. На Windows порт 53 в этом случае открыт только через туннель и loopback. Если система не может принять резолвер (на Linux нет systemd-resolved, на macOS не прошла DNS-проверка), DNS не меняется и подключение не прерывается.

См. [desktop lifecycle](docs/desktop-lifecycle.md) и [Always-on](docs/always-on.md).

### Android

1. Установите APK и импортируйте файл, текст/ссылку или QR.
2. Выберите профиль, нажмите «Подключить» и подтвердите системное разрешение Android VPN. Виджеты и автоподключение используют отдельно назначенный профиль по умолчанию.
3. При необходимости ограничьте VPN выбранными приложениями.
4. Для fail-closed поведения после гибели процесса включите в Android **Always-on VPN** и **Block connections without VPN**.

В исходниках заданы minSdk 29 и targetSdk 36. См. [Android](docs/android.md).

## Проверки

- Interop с официальным Hysteria 2.12.3: TCP, UDP, auth/TLS rejection, Salamander, Gecko + mTLS, port hopping и Brutal.
- Windows production full-tunnel для TrustTunnel и Hysteria 2 с WFP fail-closed, точным восстановлением маршрутов и 30-минутным S3 sleep/wake, включая Always-on.
- Физические Android-проверки TrustTunnel/Hysteria на POCO X3 и Huawei, 30 минут forced deep Doze на POCO.
- macOS live TrustTunnel IPv4/IPv6, DNS, reconnect и crash recovery.
- Linux system-service, Wayland, Flatpak и network handoff; контейнерная лаборатория с прогонами failover, восстановления Always-on и объяснения маршрута на уровне пакетов.

Успешный тест одной платформы или протокола не означает, что все опубликованные пакеты пересобраны с последним main. Точная граница доказательств и открытых задач — в платформенных документах.

## Структура репозитория

| Путь | Назначение |
| --- | --- |
| `apps/native` | Нативный desktop-клиент |
| `apps/webview` | Дополнительный Tauri WebView frontend |
| `apps/tui` | Консольный клиент для Linux |
| `apps/tun` | Desktop TUN/Wintun/utun dataplane и службы |
| `apps/macos` | Интеграция приложения и системы macOS |
| `apps/android` | Android VpnService и JNI/Rust интеграция |
| `apps/ios` | iOS Swift/Network Extension preview |
| `apps/inspect`, `apps/codec` | Диагностика и инструменты профилей |
| `crates` | Общая логика профилей, транспорта, storage, control, desktop, mobile, portal client и updates |
| `deploy`, `packaging`, `scripts` | Assets развёртывания служб и обновлений, упаковка и interop helpers |
| `ci`, `Jenkinsfile*` | Build, security и runtime проверки |
| `vendor/h2`, `vendor/h3` | Патченные зависимости HTTP/2 и HTTP/3 |
| `docs` | Архитектура, статусы платформ, релизы и acceptance evidence |

Здесь находятся VPN-клиенты, клиентская часть интеграции с панелью и [контракт API панели](docs/profile-api.md). Серверная реализация, administration UI и server deployment относятся к [onixus/tunnel](https://github.com/onixus/tunnel).

## Документация

- **Обзор:** [Состояние проекта](docs/project-status.md) · [Состояние реализации](docs/implementation.md) · [Архитектура](docs/architecture.md) · [Delivery и критерии приёмки](docs/delivery.md) · [Technical debt](docs/technical-debt.md)
- **Релизы:** [Записи релизов](docs/releases/) · [Приёмка пакетов](docs/package-acceptance.md) · [Secure updates](docs/secure-updates.md) · [Evidence](docs/evidence.md)
- **Протоколы:** [HTTP/3](docs/http3.md) · [Hysteria 2](docs/hysteria2.md) · [AmneziaWG](docs/amneziawg.md) · [VLESS](docs/vless.md)
- **Поведение подключения:** [Журнал событий](docs/diagnostics-journal.md) · [Наблюдения VPN](docs/vpn-observations.md) · [Системная диагностика](docs/system-diagnostics.md) · [Объяснение маршрута](docs/route-explain.md) · [Routing policy](docs/routing-policy.md) · [Failover](docs/failover.md) · [Recovery](docs/recovery.md) · [Always-on](docs/always-on.md) · [Desktop lifecycle](docs/desktop-lifecycle.md)
- **Desktop:** [Desktop-приложения](docs/desktop-apps.md) · [Выбор UI](docs/ui-choices.md) · [Консольный клиент](docs/tui.md) · [Служба Windows](docs/windows-service.md) · [Системный VPN macOS](docs/macos-system.md) · [Служба Linux](docs/linux-service.md) · [Linux full tunnel](docs/linux-full-tunnel.md) · [Скриншоты](docs/screenshots/README.md)
- **Mobile:** [Android](docs/android.md) · [iOS](docs/ios.md) · [Mobile flow observations](docs/mobile-flow-observations.md)
- **Панель и управляемые профили:** [Обмен профилями](docs/portal.md) · [Profile API](docs/profile-api.md) · [Managed devices](docs/managed-devices.md) · [Access scope validation](docs/access-scope-validation.md)
- **CI и лаборатории:** [Jenkins](docs/jenkins.md) · [Linux lab](docs/linux-lab.md) · [Linux acceptance](docs/linux-acceptance.md) · [Android на macOS](docs/android-macos.md) · [Восстановление macOS после сна](docs/macos-sleep-recovery-validation.md)
- **Участие в разработке:** [Команда агентов для issue](docs/issue-agent-team.md) (роли и gates; см. `AGENTS.md`)

Часть исторических документов описывает старые этапы. При расхождении ориентируйтесь на актуальный платформенный документ и наиболее свежие release evidence.

## Лицензия

[Apache License 2.0](LICENSE). Vendored dependencies сохраняют собственные лицензии.
