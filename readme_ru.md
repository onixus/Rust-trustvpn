# R-TrustTunnel

[English](Readme.md) · [Русский](readme_ru.md)

R-TrustTunnel — нативный VPN-клиент на Rust с поддержкой **TrustTunnel**, **Hysteria 2** и **AmneziaWG 3**. В репозитории находятся Windows/Linux desktop-клиенты, macOS desktop/system-VPN упаковка, Android VpnService, preview iOS Network Extension, общее Rust-ядро транспорта/профилей/хранилища/mobile и привилегированные desktop-службы туннеля.

Клиент реализует транспорт самостоятельно и **не является оболочкой** над официальными CLI TrustTunnel или Hysteria.

> **Статус проекта: development preview, 7 октября 2026 года.**
>
> Версия workspace — **0.5.0**. Последняя desktop-пересборка — **v0.5.0-rebuild.9** от 6 октября; Android и iOS артефакты остаются в исходном релизе **v0.5.0**. Rebuild исправляет идентичность desktop update/rollback sequence и собран уже после разделения клиентского и серверного репозиториев. См. [описание v0.5.0](docs/releases/v0.5.0.md).

## Скачать

Актуальные preview-релизы:

- **Desktop rebuild:** [v0.5.0-rebuild.9](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0-rebuild.9)
- **Mobile-артефакты и исходный набор 0.5.0:** [v0.5.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0)

| Платформа | Актуальный артефакт | Примечание |
| --- | --- | --- |
| Windows x64 | `R-TrustTunnel-Windows-x64-Setup.exe` из v0.5.0-rebuild.9 | Signed update metadata sequence 9; Authenticode-подписи у пакета нет. Реальный signed update 7→9, принудительный unhealthy install, rollback на 7 и повторный update на 9 прошли. |
| Linux x86_64, Wayland | Native / WebView / Both Flatpak из v0.5.0-rebuild.9 | Проверены подписанные install/update/rollback и отказ от unsigned update; системному VPN по-прежнему нужен отдельный host package. |
| macOS Apple Silicon | UI Choices / system candidate из v0.5.0-rebuild.9 | Ad-hoc sealed, без Developer ID/notarization. Автоматическое обновление не промотировано; приёмка system VPN ещё не закрыта полностью. |
| Android 10+, arm64 / x86_64 | `R-TrustTunnel-Android.apk` из v0.5.0 | versionCode 50001, versionName 0.5.0-preview.1. |
| iOS arm64 / Simulator | Device и Simulator archives из v0.5.0 | Preview. Device archive требует Apple signing и не является готовым IPA. |

В релизах опубликованы SHA256SUMS, подписи и evidence-файлы.

## Что нового в v0.5.0 / rebuild.9

По сравнению с v0.4.0:

- preview iOS с import/export профилей, QR, portal sync, On Demand и VPN widget;
- Android VPN widget и обновлённая общая mobile routing-policy логика;
- macOS glass appearance с persistent toggle в Settings и accessibility fallback;
- desktop IPv4 TUN include/exclude, LAN bypass и серверные route groups;
- HTTP-запросы на смешанном desktop proxy port;
- update sequence **9** для desktop rebuild, исправляющий старую ошибку sequence-7 identity/rollback;
- серверная реализация и deployment удалены из этого репозитория и перенесены в [onixus/tunnel](https://github.com/onixus/tunnel).

Route groups относятся только к desktop. Android/iOS продолжают использовать routing policy внутри профиля и отдельный group API не читают.
## Возможности

### Клиент и профили

- Нативный desktop-интерфейс на Rust/iced и дополнительный Tauri WebView.
- Нативное Android-приложение на VpnService с общим Rust-ядром.
- Импорт endpoint TOML, полного client TOML, R-TrustTunnel JSON, tt://, hy2:// и hysteria2://.
- Предпросмотр и проверка перед заменой профиля.
- Автоматическое зашифрованное хранение профилей. На desktop ключ хранится в системном credential store, на Android — в Android Keystore. Plaintext fallback отсутствует.
- Системный трей, запуск при входе, опциональный autoconnect, диагностика и явные сценарии восстановления.
- Регистрация устройства и синхронизация разрешённых профилей через TrustTunnel portal extension.

### TrustTunnel

- Собственный Rust HTTP/2 transport для системного VPN.
- Нативные Rust-транспорты HTTP/2 и HTTP/3 для системного VPN и SOCKS5; транспорт задаёт профиль, без скрытой смены, см. [HTTP/3](docs/http3.md).
- IPv4/IPv6 TCP и UDP, DNS, ICMP там, где это реализовано платформенным dataplane, ограниченная обработка фрагментации, reconnect и fail-closed защита.
- HTTP/3 для системного VPN есть в текущем main, но не в пакетах v0.4.0: там системный туннель всё ещё идёт по HTTP/2.

### Hysteria 2

Общее ядро автоматически выбирает Hysteria 2 для hy2://, hysteria2:// и поддерживаемых Hysteria YAML/JSON профилей.

В текущем main реализованы:

- QUIC + HTTP/3 authentication;
- multiplexed TCP и UDP datagrams;
- Salamander и Gecko obfuscation;
- port hopping и интервалы переключения портов;
- bandwidth negotiation и Brutal для upload;
- BBR/Reno и стандартный congestion controller;
- QUIC receive windows, idle timeout, keepalive и фиксированное MTU-поведение;
- TLS SNI и pinSHA256 вместе с обычной проверкой CA/hostname;
- встроенные custom CA и mutual-TLS certificate/key в R-TrustTunnel JSON.

Намеренно не поддерживаются или отклоняются: insecure TLS, ECH, Hysteria Realms, Chrome QUIC fingerprint parroting, mimic, fastOpen/lazy и нестандартные BBR-профили. В Hysteria 2 нет ICMP relay.

Подробности: [Hysteria 2 — поддержка и ограничения](docs/hysteria2.md).

Конфиги `awg-quick` AmneziaWG 3 выбирают встроенный транспорт WireGuard со слоем обфускации AmneziaWG (junk- и signature-пакеты, префиксы, диапазоны типов, защита заголовков, паддинг). Проверено только против официального `amneziawg-go` 3.1 на loopback: [поддерживаемые параметры и ограничения](docs/amneziawg.md).

## Статус платформ

| Платформа | Текущее состояние | Что ещё не закрыто |
| --- | --- | --- |
| Windows x64 | Native UI, Wintun/SCM-служба и WFP guard. Production full-tunnel проверки прошли для TrustTunnel и Hysteria 2. Реальный 30-минутный S3 sleep/wake с Hysteria прошёл reconnect и traffic checks; Always-on также оставался заблокированным до автоматического восстановления. | Cold boot, более широкий набор sleep/network сценариев, выпуск свежего публичного установщика и подпись. |
| Linux x86_64 / ARM64 | Wayland-only desktop, TUN host service, nftables и systemd-resolved. Есть Native/WebView/Both packaging, физический KDE/Wayland smoke, подписанный Flatpak flow, TrustTunnel/Hysteria full-tunnel и network handoff. | Больше физических reboot/sleep проверок и финальная полировка установки на разных дистрибутивах. |
| macOS Apple Silicon | Native/WebView/Both preview, root LaunchDaemon и системный туннель через utun. Для TrustTunnel пройдены live IPv4/IPv6 TCP/UDP/ICMP, DNS, reconnect и восстановление после падения службы. | Boot Always-on, sleep/network handoff, clean install на другом Mac, подписанное auto update/rollback, Developer ID/notarization. Installed macOS Hysteria full-tunnel всё ещё не закрыт полноценной приёмкой. |
| Android arm64 / x86_64 | Native VpnService, encrypted vault, file/text/QR import, выбор приложений, portal sync, Always-on/lockdown и TrustTunnel/Hysteria. Физические POCO и Huawei проверены на реальном трафике и восстановлении; POCO прошёл 30 минут forced deep Doze. | Дополнительные OEM, прежде всего Pixel/Samsung, reboot-before-first-unlock и overnight/long soak. На MIUI force-stop может оставить lockdown активным без автоматического рестарта VPN-службы. |

Про Native/WebView/Both: [варианты UI](docs/ui-choices.md). Linux поддерживает только Wayland.

## Скриншоты

В галерее лежат реальные desktop-скриншоты Native и WebView из UI refresh:

| Native | WebView |
| --- | --- |
| ![Главный экран Native](docs/screenshots/native-home-0.3.2-ui.1.jpg) | ![Главный экран WebView](docs/screenshots/webview-home-0.3.2-ui.1.jpg) |

См. [галерею и настройки подключения](docs/screenshots/README.md).

Обновлённый главный экран Android входит в APK v0.4.0.

## Сборка

Workspace требует **Rust 1.89+**. Текущий CI использует Rust 1.98.1.

Клонирование и запуск Native UI:

    git clone https://github.com/onixus/Rust-trustvpn.git
    cd Rust-trustvpn
    cargo run -p rtrust-native --locked

Основные desktop/service бинарники:

    cargo build --release -p rtrust-native -p rtrust-tun -p rtrust-inspect --locked

Стандартные проверки:

    cargo fmt --all --check
    cargo test --workspace --locked
    cargo clippy --workspace --all-targets --locked -- -D warnings

Точки входа упаковки:

- **Windows:** python ci/package_windows.py
- **macOS:** python3 scripts/package-macos-system.py
- **Android:** python3 scripts/build-android.py
- **Linux:** python3 scripts/package-flatpak.py

Платформенные зависимости и ограничения:

- [Windows service](docs/windows-service.md)
- [Linux service](docs/linux-service.md)
- [macOS system VPN](docs/macos-system.md)
- [Android](docs/android.md)
- [Jenkins / CI](docs/jenkins.md)

Desktop GUI следует запускать от обычного пользователя. Для системного VPN нужна отдельно установленная привилегированная служба. Flatpak намеренно остаётся непривилегированным.

## Использование

### Desktop

1. Импортируйте файл профиля либо откройте/вставьте ссылку tt://, hy2:// или hysteria2://.
2. Проверьте результат разбора и добавьте либо замените профиль.
3. Выберите профиль по умолчанию и режим подключения.
4. Для системного VPN предварительно установите соответствующую платформенную службу.
5. Подключайтесь с главного экрана. Закрытие Native-окна обычно оставляет приложение в трее.
6. Изменения профилей автоматически сохраняются в encrypted vault.

SOCKS5 по умолчанию слушает 127.0.0.1:1080:

    curl --socks5-hostname 127.0.0.1:1080 https://example.com

SOCKS5 не меняет системные маршруты и DNS. BIND, SOCKS UDP domain addressing и SOCKS UDP fragmentation не поддерживаются.

В split-режиме системного VPN DNS из настроек становится системным резолвером, если выбранные сети ведут его через туннель (например, «всё, кроме LAN»). Как и в полном режиме, имена только из LAN (например, `router.lan`) после этого не резолвятся. Иначе DNS не меняется. На Windows в этом случае порт 53 открыт только через туннель и loopback. Если система не может принять резолвер (на Linux нет systemd-resolved, на macOS не прошла DNS-проверка), DNS пропускается и подключение не прерывается.

См. [desktop lifecycle](docs/desktop-lifecycle.md) и [Always-on](docs/always-on.md).

### Android

1. Установите APK и импортируйте файл, текст/ссылку или QR.
2. Выберите профиль по умолчанию и нажмите Connect.
3. Подтвердите системное разрешение Android VPN.
4. При необходимости настройте allowlist приложений в VPN apps.
5. Для fail-closed поведения после гибели процесса включите в Android **Always-on VPN** и **Block connections without VPN**.
6. Server profiles можно регистрировать и синхронизировать через portal integration.

В текущих исходниках заданы Android minSdk 29, targetSdk 36, versionCode 50001 и versionName 0.5.0-preview.1.

См. [Android](docs/android.md) и [обмен профилями](docs/portal.md).

## Проверки

Актуальные проверки включают:

- interop с официальным Hysteria 2.12.3: TCP, UDP, auth/TLS rejection, Salamander, Gecko + mTLS, port hopping и Brutal;
- Windows production full-tunnel для TrustTunnel и Hysteria 2 с WFP fail-closed и точным восстановлением маршрутов;
- 30-минутный Windows S3 sleep/wake, включая Always-on восстановление;
- физические Android-проверки TrustTunnel/Hysteria на POCO X3 и Huawei;
- 30 минут forced deep Doze на POCO с сохранением VPN egress;
- macOS live TrustTunnel IPv4/IPv6, DNS, reconnect и crash recovery;
- Linux system-service, Wayland, Flatpak и network-handoff проверки.

Успешный тест конкретной платформы или протокола не означает, что все опубликованные пакеты уже пересобраны с последним main. Точная граница доказательств и открытых задач находится в платформенных документах.

## Структура репозитория

| Путь | Назначение |
| --- | --- |
| apps/native | Нативный desktop-клиент |
| apps/webview | Дополнительный Tauri WebView frontend |
| apps/tun | Desktop TUN/Wintun/utun dataplane и службы |
| apps/android | Android VpnService и JNI/Rust интеграция |
| apps/ios | iOS Swift/Network Extension preview и общее Rust-ядро |
| apps/macos | macOS application/system integration |
| apps/inspect, apps/codec | Диагностика и инструменты профилей |
| crates | Общая логика профилей, транспорта, storage, control, desktop, mobile, portal client и updates |
| deploy | Клиентские service/update deployment assets |
| packaging, scripts | Упаковка и interop helpers |
| ci, Jenkinsfile* | Build, security и runtime проверки |
| vendor/h2 | Патченная HTTP/2 зависимость |
| docs | Архитектура, статусы платформ, релизы и acceptance evidence |

Серверная реализация, administration UI и server deployment относятся к [onixus/tunnel](https://github.com/onixus/tunnel). Здесь находятся VPN-клиенты, клиентская portal integration и [контракт API панели](docs/profile-api.md).

## Документация

- [Состояние реализации](docs/implementation.md)
- [Архитектура](docs/architecture.md)
- [Delivery и критерии приёмки](docs/delivery.md)
- [Hysteria 2](docs/hysteria2.md)
- [Android](docs/android.md)
- [Desktop lifecycle](docs/desktop-lifecycle.md)
- [Secure updates](docs/secure-updates.md)
- [Profile exchange API](docs/profile-api.md)
- [Technical debt](docs/technical-debt.md)

Часть исторических документов описывает старые этапы. При расхождении следует ориентироваться на актуальный платформенный документ и наиболее свежие release evidence.

## Лицензия

[Apache License 2.0](LICENSE). Vendored dependencies сохраняют собственные лицензии.
