# Вторая волна: Android и macOS

Статус: запланировано по запросу пользователя после Windows/Linux. Реализации, сборок и проверки на устройствах пока нет. Начало продуктовой разработки — после M4 первой волны; общие interfaces подготавливаются заранее, без задержки её релиза.

## Объём и платформы

| Платформа | Приложение | VPN integration | Поставка |
|---|---|---|---|
| Android | Kotlin + Jetpack Compose, Rust core через bindings | VpnService, TUN file descriptor, foreground lifecycle | Подписанный APK; AAB для Google Play отдельным каналом |
| macOS | SwiftUI/AppKit Native по умолчанию; дополнительный Tauri WebView | Network Extension packet tunnel provider с Rust engine | Подписанный и notarized installer/app, Apple silicon сначала |

Предлагаемый baseline для spike: Android 10/API 29+ arm64-v8a; macOS 13+ arm64. Это стартовая инженерная цель, а не обещание поддержки всех старых версий. Минимальные ОС, target SDK и ABI закрепляются после проверки toolchain, зависимостей и требований канала поставки. Intel macOS включается только при прохождении отдельной матрицы; x86_64 Android нужен для emulator CI, armv7 не входит в первый Android release.

Обе платформы получают: профиль из TOML/tt/JSON, preview, QR, portal enrollment, Connect/Disconnect, состояния защиты/DNS, авто-восстановление, диагностику с редактированием секретов и экспорт. Функции, ограниченные ОС, отражаются в capability matrix и UI; unsupported routing/kill-switch настройки не игнорируются.

## Общее Rust-ядро

Переиспользовать `profile-model`, `profile-codec`, `tt-wire`, `tt-transport`, `ip-stack` и общую бизнес-логику controller. Создать `platform-api`: packet read/write, protected socket creation, network change events, DNS/routes plan, secret reference resolution, lifecycle cancellation и bounded events.

Rust core не вызывает systemd, shell, WFP, nftables или GUI frameworks напрямую. Платформенные adapters получают решения core и применяют их системными API. Общее состояние сессии не означает одинаковый процессный lifecycle всех ОС.

Kotlin/Swift bindings — узкая versioned граница с явным ownership handles, cancel/join, очередями ограниченной длины и callback threading. Кандидат — UniFFI для control API; packet path должен передавать batches/FD либо работать в Rust без allocation/JNI-вызова на каждый пакет. Выбор binding tool и throughput проверяются spike. Panic не пересекает FFI, повторный stop безопасен, после close callbacks отменяются. Credentials не превращаются в общедоступные debug strings.

## Android

Системная оболочка строится вокруг [Android VpnService](https://developer.android.com/develop/connectivity/vpn). Пользователь подтверждает системное разрешение VPN; root не требуется. Созданный TUN FD принадлежит service/engine, UI Activity лишь управляет состоянием. Уничтожение Activity не должно закрывать туннель. OS revoke/другой VPN/force-stop — отдельные состояния, а не бесконечный retry.

Все transport sockets Rust, включая QUIC и reconnect, проходят `VpnService.protect()` до подключения, чтобы не попасть обратно в свой туннель. Network selection/binding при Wi-Fi↔mobile выполняется платформенным adapter. Меняются только разрешённые socket routes; не включать глобальный bypass приложений ради bootstrap.

Foreground service, notification и правила запуска проверяются для выбранного target SDK. Для гарантии блокировки после смерти процесса используется системный always-on/«Блокировать соединения без VPN», включаемый пользователем в настройках Android. Встроенный session guard не выдаётся за OS lockdown. При включённом lockdown действие Disconnect ведёт к соответствующим системным настройкам и объясняет сохранение блокировки. Не обещать работу после force-stop или недоступного OEM background permission.

Native UI — стандартный Android APK, без терминала и без браузера для обычного использования. Bottom navigation: подключение, профили, настройки; уведомление и Quick Settings tile для быстрых действий. Системный Android installer не поддерживает наш экран выбора компонентов как Windows Setup. В Android-релизе второй волны поставляется Native UI; альтернативный WebView UI при необходимости добавляется отдельно с выбором при первом запуске, а не вымышленным выбором внутри системной установки APK.

Импорт/экспорт файлов — Storage Access Framework и временные content URI grants, без запроса полного доступа к файловой системе. Deep link и Share intent только открывают preview. QR сканируется локально после разрешения камеры; файл остаётся fallback. Проверенный HTTPS App Link для контролируемого portal domain требует site association; произвольный сторонний портал использует browser enrollment/ручной выбор origin. Device token не передаётся между приложениями в URI.

Keystore хранит ключ шифрования local secret store; backup rules исключают credentials/device tokens. Always-on после reboot отдельно проверяется до/после первого unlock. Если ключ требует разблокировки, UI показывает ожидание; не ослаблять защиту ключа автоматически. Per-app include/exclude — последующая Android capability с явной политикой, не перенос desktop app paths.

## macOS

Обычное `R-TrustTunnel.app`: Applications, Dock, menu bar status item, native file dialogs, notifications, Keychain и file/tt handlers. Native UI реализуется на SwiftUI/AppKit поверх того же Rust controller; дополнительный WebView frontend использует тот же host contract. Это платформенная оболочка, Rust VPN/codec не переписываются на Swift.

Networking выполняет [NEPacketTunnelProvider](https://developer.apple.com/documentation/networkextension/nepackettunnelprovider), принимающий/возвращающий IP packets через packetFlow. Swift adapter связывает его с Rust flow stack и применяет network settings. Управление VPN profile — через системный manager, без ручного редактирования resolver files или отдельного root daemon для штатного туннеля. Закрытие основного окна не завершает provider.

Первый канал — direct distribution: выбрать и проверить подходящую упаковку provider/system extension, provisioning и entitlements на signing spike согласно [Apple TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment). Developer ID, Network Extension capabilities, подпись всех вложенных binaries и notarization — release blockers, пока не подтверждены реальной установкой. Mac App Store — отдельная последующая поставка со своей extension packaging/review, не предполагается автоматически доступной.

Сохранить desktop выбор **Native / WebView / Both** в графическом installer с выбором компонентов; итоговое приложение имеет единый launcher и одну VPN extension. Для Native-only исключить frontend assets дополнительного UI. По смене UI перезапускается только frontend; provider и его session остаются. Все комбинации пакуются/подписываются build pipeline; установщик не патчит содержимое подписанного app bundle. Можно использовать заранее подписанные варианты bundle с одинаковой identity и совместимой extension. DMG может переносить installer, но drag-and-drop DMG сам по себе не предоставляет мастер выбора компонентов.

Платформенное согласие на VPN configuration/extension запрашивается средствами macOS. Пользователь может отказать; приложение показывает этап и повторное действие, не пытается обходить разрешение. Keychain access group и App Group ограничиваются своими targets; в shared settings хранятся secret references, не plaintext password. Команды host→provider ограничены, size-bounded и versioned; произвольные файлы/скрипты не передаются.

Network path changes, sleep/wake, reconnect, DNS и IPv6 покрываются отдельными тестами. On-demand auto-connect и fail-closed routing проектируются на доступных Network Extension API; `includeAllNetworks`/исключения и поведение при остановке/crash проверяются по выбранным версиям ОС. Не считать on-demand эквивалентом безусловного kill switch при любой остановке provider. До прохождения crash/leak tests UI не обещает always-on защиту. Per-app routing на macOS — отдельная feasibility задача с учётом ограничений ОС/управления устройствами.

## Профили и серверная панель

Использовать тот же `/portal/v2`, scopes, revisions, preview/commit и grant model. Не добавлять отдельные Android/macOS пароли в транспортный протокол. Каждое привязанное устройство получает собственные VPN credentials и device token. `platform=android|macos`, app/core version и capabilities служат отображению/совместимости, но не повышают права.

UI панели получает корректные download links для APK и macOS artifacts, version/architecture/checksum и инструкции системного разрешения VPN. Неподписанные/неготовые builds не показываются как стабильные. Email/file/tt export сохраняет совместимость с первой волной. Выбор профиля по HTTP endpoint address не должен выбирать portal origin или передавать ему token автоматически.

Перенос с Windows/Linux проверяет policy: пути программ, WFP/nftables и desktop listener options не исполняются на мобильной/Apple ОС. Preview перечисляет несовместимые поля и предлагает явную адаптацию. Изменение platform-specific local override не переписывает managed endpoint credentials или настройки другого устройства.

## Этапы и критерии приёмки

| Веха | Результат | Условие завершения |
|---|---|---|
| W2.0 | portable core bindings, Android/macOS adapter spikes, signing feasibility | реальный TCP/UDP/DNS tunnel на Android arm64 и Apple silicon, валидная установка extension |
| W2.1 | Android Native beta и APK | import/export/enrollment, background lifecycle, Wi-Fi↔LTE, IPv6/DNS, Keystore и OS lockdown checks |
| W2.2 | macOS Native beta | signed/notarized install, разрешения, Keychain, sleep/wake, menu bar и Network Extension lifecycle |
| W2.3 | macOS WebView/Both, platform parity и релиз | смена frontend без reconnect, update/rollback, privacy/secret tests, реальные device soak runs |

Android release проверяется минимум на физическом Pixel/AOSP-подобном устройстве и Samsung, при выключенном экране/Doze, смене сетей, reboot, force-stop и отзыве VPN permission. Emulator CI не доказывает OEM background behavior. Перед Google Play submission отдельно проверить актуальные target SDK, foreground-service и VPN listing requirements; APK release не зависит от обещанного одобрения магазина.

macOS release проверяется на реальном Apple silicon: чистая установка, отказ/повторное согласие, quit UI, crash provider, system update/перезапуск, смена сети, upgrade/deactivate/uninstall extension. Intel добавляется после аналогичных тестов на Intel hardware. Секреты не попадают в crash reports, backups, deep-link logs или shared containers.

Обе платформы: 24 h soak; трафик через реальный TrustTunnel endpoint; packet capture с внешней стороны для DNS/IPv6/direct-traffic утечек; замеры памяти, CPU и расхода батареи относительно baseline. TLS handshake и зелёный статус панели недостаточны для приёмки.
