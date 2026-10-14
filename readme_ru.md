# R-TrustTunnel

[English](Readme.md) · [Русский](readme_ru.md)

R-TrustTunnel — нативный VPN-клиент на Rust с поддержкой **TrustTunnel**, **Hysteria 2** и **AmneziaWG 3**. В репозитории находятся Windows/Linux desktop-клиенты, macOS desktop/system-VPN упаковка, Android VpnService, preview iOS Network Extension, общее Rust-ядро транспорта/профилей/хранилища/mobile и привилегированные desktop-службы туннеля.

Клиент реализует транспорт самостоятельно и **не является оболочкой** над официальными CLI TrustTunnel или Hysteria.

> **Статус проекта: development preview, 14 октября 2026 года.**
>
> Последний опубликованный релиз — **[v0.6.1](docs/releases/v0.6.1.md)** (13 октября; workspace 0.6.1, desktop update sequence 11, Android/iOS 60101). Он не production-ready: приёмка установленных пакетов и устройств для артефактов 0.6.1 не проводилась. **[v0.6.0](docs/releases/v0.6.0.md)**, опубликованный в тот же день, — самый новый релиз с Linux-пакетами. Архивы iOS по-прежнему есть только в [v0.5.0](docs/releases/v0.5.0.md).

## Скачать

- **[v0.6.1](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.6.1)**: Windows, macOS, Android.
- **[v0.6.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.6.0)**: Linux Flatpak и Linux host package.
- **[v0.5.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0)**: iOS device и Simulator archives.

| Платформа | Актуальный артефакт | Примечание |
| --- | --- | --- |
| Windows x64 | `R-TrustTunnel-Windows-x64-Setup.exe` из v0.6.1 | Без Authenticode-подписи. Для 0.6.0 прошёл lab-signed update 9 → 10 с принудительным rollback на 9. Метаданные с production-ключом и перевод `latest` в release record отмечены как NOT RUN. |
| Linux x86_64, Wayland | Native / WebView / Both Flatpak и `rtrust-host-0.6.0-7` из v0.6.0 | В v0.6.1 Linux-пакетов нет. Системному VPN нужен отдельный host package. |
| macOS Apple Silicon | UI Choices, preview и system-candidate DMG/PKG из v0.6.1 | Ad-hoc sealed, без Developer ID и notarization. Автоматическое обновление не промотировано. |
| Android 10+, arm64 / x86_64 | `R-TrustTunnel-Android.apk` из v0.6.1 | versionCode 60101, versionName 0.6.1-preview.1. Подписан ключом, введённым в 0.6.0: 0.6.0 обновляется поверх, а 0.5.x и старше нужно переустановить, локальные профили при этом удаляются. |
| iOS arm64 / Simulator | Device и Simulator archives из v0.5.0 | Preview. Device archive требует Apple signing и не является готовым IPA. |

В релизах опубликованы SHA256SUMS и source manifests.

## Что нового в 0.6.0 и 0.6.1

По сравнению с v0.5.0-rebuild.9:

- **Честный статус подключения.** Типизированные наблюдения (passed, failed, configured, unknown, stale, unsupported) вместо «подключено — значит работает». С 0.6.1 в статусе только проверки, давшие результат, например «Транспорт: запущен». См. [наблюдения VPN](docs/vpn-observations.md).
- **Диагностика на desktop.** Проверка системного пути через активный туннель при подключении и каждые 30 секунд, с типизированным вердиктом, проверкой endpoint и следующими действиями. Офлайн-объяснение маршрута тем же вычислителем, что и dataplane. См. [системную диагностику](docs/system-diagnostics.md) и [объяснение маршрута](docs/route-explain.md).
- **Защищённое восстановление.** По желанию — переключение на до трёх одобренных резервных профилей; защита при этом не снимается. Always-on восстановление через резервные профили — только Linux и Windows. См. [failover](docs/failover.md) и [recovery](docs/recovery.md).
- **Desktop control IPC v6.** GUI и служба должны быть из одного пакета.
- **macOS.** Восстановление VPN после сна; служба продолжает вести VPN после отключения GUI.
- **Android.** Компактный виджет и плитка быстрых настроек. После смены Wi-Fi/мобильной сети VPN идёт через сеть, которую предпочитает Android. Необязательная настройка учёта трафика VPN. Новый ключ подписи релизов.
- **Управляемые профили.** Сохраняют происхождение, назначенную маршрутизацию и офлайн-квитанции. Ответы панели о лимите профилей объясняются на desktop, Android и iOS. См. [managed devices](docs/managed-devices.md).

Main после 0.6.1 также проваливает health check сессии, которая не пропускает трафик, и переподключает её (#62). См. [HTTP/3](docs/http3.md#dead-session-detection).

Route groups относятся только к desktop. Android/iOS используют routing policy внутри профиля.
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

- Нативные Rust-транспорты HTTP/2 и HTTP/3 для системного VPN и SOCKS5; транспорт задаёт профиль, без скрытой смены, см. [HTTP/3](docs/http3.md).
- IPv4/IPv6 TCP и UDP, DNS, ICMP там, где это реализовано платформенным dataplane, ограниченная обработка фрагментации, reconnect и fail-closed защита.

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

Desktop-интерфейс версии 0.6.1 с синтетическими профилями:

| Native | WebView |
| --- | --- |
| ![Профили Native](docs/screenshots/native-profiles-0.6.1.jpg) | ![Профили WebView](docs/screenshots/webview-profiles-0.6.1.jpg) |

Остальные экраны (импорт, настройки, синхронизация, диагностика) и способ съёмки — в [галерее](docs/screenshots/README.md). Android блокирует скриншоты через `FLAG_SECURE`.

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

В текущих исходниках заданы Android minSdk 29, targetSdk 36, versionCode 60101 и versionName 0.6.1-preview.1 ([v0.6.1](docs/releases/v0.6.1.md)); APK подписывается релизным ключом, введённым в v0.6.0, и не обновляет установки 0.5.0 и старше.

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

Обзор:

- [Состояние реализации](docs/implementation.md) · [Архитектура](docs/architecture.md) · [Delivery и критерии приёмки](docs/delivery.md) · [Technical debt](docs/technical-debt.md)
- [Записи релизов](docs/releases/) · [Приёмка пакетов](docs/package-acceptance.md) · [Secure updates](docs/secure-updates.md) · [Evidence](docs/evidence.md)

Протоколы: [HTTP/3](docs/http3.md) · [Hysteria 2](docs/hysteria2.md) · [AmneziaWG](docs/amneziawg.md)

Поведение подключения: [Наблюдения VPN](docs/vpn-observations.md) · [Системная диагностика](docs/system-diagnostics.md) · [Объяснение маршрута](docs/route-explain.md) · [Routing policy](docs/routing-policy.md) · [Failover](docs/failover.md) · [Recovery](docs/recovery.md) · [Always-on](docs/always-on.md) · [Desktop lifecycle](docs/desktop-lifecycle.md)

Платформы:

- Desktop: [Desktop-приложения](docs/desktop-apps.md) · [Выбор UI](docs/ui-choices.md) · [Служба Windows](docs/windows-service.md) · [Системный VPN macOS](docs/macos-system.md) · [Служба Linux](docs/linux-service.md) · [Linux full tunnel](docs/linux-full-tunnel.md)
- Mobile: [Android](docs/android.md) · [iOS](docs/ios.md) · [Mobile flow observations](docs/mobile-flow-observations.md)

Панель и управляемые профили: [Обмен профилями](docs/portal.md) · [Profile API](docs/profile-api.md) · [Managed devices](docs/managed-devices.md) · [Access scope validation](docs/access-scope-validation.md)

CI и лаборатории: [Jenkins](docs/jenkins.md) · [Linux lab](docs/linux-lab.md) · [Linux acceptance](docs/linux-acceptance.md) · [Android на macOS](docs/android-macos.md) · [Восстановление macOS после сна](docs/macos-sleep-recovery-validation.md)

Часть исторических документов описывает старые этапы. При расхождении следует ориентироваться на актуальный платформенный документ и наиболее свежие release evidence.

## Лицензия

[Apache License 2.0](LICENSE). Vendored dependencies сохраняют собственные лицензии.
