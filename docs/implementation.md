# Состояние реализации — 1 октября 2026

Текущий опубликованный клиентский выпуск: [v0.3.2-ui.1](releases/v0.3.2-ui.1.md).
macOS CI №69 и Linux CI №20 завершены успешно; Native/службы обновлены на Mac и
физическом Linux, WebView/Both проверены в KDE Wayland. APK 30208 установлен на
Huawei с сохранением профиля и Always-on/lockdown. Обновлены навигация и оформление;
[скриншоты](screenshots/README.md) показывают реальные macOS Native/WebView окна.
Windows-пакет нового выпуска отсутствует; долгие boot/sleep/soak проверки открыты.

Текущее дополнение: задача 5 и Hysteria 2. Реализованы фоновая Android-синхронизация,
переносимые правила маршрутизации, DoT/DoH через VPN и desktop WebView с вариантами
Native/WebView/Both. Hysteria 2 определяется автоматически при импорте и подключается
общим Rust-ядром. Подробности: [Android](android.md), [выбор UI](ui-choices.md),
[Hysteria 2 и ограничения](hysteria2.md). Android CI №26 проверил оба протокола,
обрыв/восстановление и обновление APK; Windows-проверка дополнения отложена до включения ноды.
Huawei также прошёл Hysteria 2, DoH/DoT и фоновую синхронизацию. Исторические результаты ниже
не означают автоматической приёмки новых функций.

Текущая последовательность: 6 → 5 → 4 → 1 (Flatpak), см. [delivery.md](delivery.md).
Конфликты профилей, серверная синхронизация и подписанное Windows-обновление
с настоящим откатом проверены. Windows 0.3.2 / sequence 6 установлен после полного CI #53, системного runtime
и настоящего обновления/отката 3→6. Setup доставлен в Downloads Windows-пользователя.

Linux и Windows уже имеют IPv4/IPv6 TCP/UDP, ICMP echo и ограниченную
фрагментацию. Linux whole-host режим использует systemd-resolved и nftables,
Windows — Wintun и WFP. Always-on реализован, Linux network handoff проверен;
Windows runtime #53 подтвердил SCM recovery, Stop при обрыве и Ethernet bounce.
Подробности и границы проверки: [always-on.md](always-on.md).
Холодная загрузка и sleep/wake пока не подтверждены полноценным E2E.

macOS system candidate №61 прошёл live IPv4/IPv6 TCP/UDP/ICMP, DNS,
reconnect, аварии GUI/root-службы и восстановление сети. DMG без Developer ID
и notarization; boot always-on, sleep/handoff и автообновление ещё не завершены.
Отчёт (локальный отчёт `reports/macos-runtime/acceptance-61.json`, не входит в Git).
Linux Flatpak ARM64/x86_64 прошли установленный Wayland/tray/IPC smoke на Weston
(x86_64 под QEMU). Физический KDE, host GUI-пакет и совместный lifecycle
установки/обновления/отката ещё не приняты. [Подробности](linux-service.md).
HTTP/3 системного туннеля остаётся в техдолге волны 3.

Остальные записи ниже сохраняют историю отдельных этапов; при расхождении
ориентироваться на актуальный статус выше и ссылки на доказательства.

## Реализовано

| Компонент | Фактическое поведение |
|---|---|
| `crates/profile` | Endpoint TOML, полный CLI TOML, tt v0/v1, собственный JSON, legacy panel JSON. Общая модель, validation, bounded TLV parser, unknown-tag preservation, предупреждения о потерях при экспорте. |
| `crates/engine` | Самостоятельный Rust HTTP/2 (h2/rustls) и HTTP/3 (quinn/h3) CONNECT, Basic auth, `_check`, TCP duplex streams, `_udp2` framing. Loopback SOCKS5 CONNECT/UDP ASSOCIATE, ограничение 128 клиентов и 256 UDP destinations на ассоциацию, счётчики и остановка всех потоков. Официальный CLI не запускается. |
| `crates/store` | ChaCha20Poly1305 для всего файла профилей, случайный ключ в системном keyring, атомарная запись, блокировка и optimistic revision check. Нет plaintext fallback. |
| `apps/native` | Настоящее desktop-окно iced/tiny-skia, русский интерфейс, импорт/preview/список/экспорт/ручное сохранение и автоматическая загрузка хранилища, TCP-диагностика с отменой, запуск/остановка SOCKS5 и счётчики, rename/delete/explicit replacement профилей. |
| `apps/inspect` | Вспомогательная утилита для тестов codec и TCP/UDP data plane; не основной пользовательский интерфейс. |
| `apps/tun` | Linux TUN, smoltcp TCP stack, IPv4 UDP через `_udp2`, bounded queues/flows, остановка по сигналу или ошибке туннеля. Linux-служба с per-UID маршрутами и Windows Wintun/SCM-служба с маршрутами для всей ОС, авторизованный IPC и интеграция с GUI. Полный IPv4 TCP/UDP-туннель и DNS реализованы в Linux; IPv6 блокируется. Windows full tunnel/DNS/WFP реализованы; см. Windows service. |
| `scripts` | Упаковка native preview и воспроизводимый тест с отдельным официальным endpoint. |

Профили принимаются через UI и первый аргумент приложения. Windows Setup предлагает опциональную регистрацию `tt://`; на других ОС регистрация ещё не сделана. Файл экспорта содержит credentials; перед экспортом UI требует отдельного подтверждения. В карточке профиля и ошибках секреты скрыты. Исходный текст, вставленный в редактор, виден до принятия профиля; не следует считать это защищённым password-полем.

Поддерживаются строгая проверка TLS hostname, системные CA или сертификат из профиля. `skip_verification`, отдельный SNI, anti-DPI, `client_random_prefix` и неизвестные execution options сохраняются codec, но блокируют подключение с явной ошибкой. Нельзя считать поддержкой опции только её успешный импорт.

## Проверки

- Первоначальная проверка (исторический результат, новые прогоны ниже): 30 Rust-тестов на macOS: форматы/roundtrip, hostile TLV lengths, неизвестные высокие теги, randomized parser input, redacted errors, TLS/auth, duplex 512 KiB, UDP framing, encrypted storage и atomic write.
- `cargo clippy --workspace --all-targets --locked -- -D warnings` — успешно.
- Официальный endpoint **1.1.0**, macOS universal binary: реальный HTTP 200 и UDP echo по **обоим** транспортам. Неверный пароль и hostname отклоняются для HTTP/2 и HTTP/3. Собственный сертификат доверен только внутри теста; TLS verification не отключается.
- `tt://` из официального endpoint exporter успешно импортирован. Это не полная differential validation всех вариантов codec.
- Реальное native `.app` открыто на macOS: вставка TOML, preview, добавление и JSON-export через системный диалог. Экспорт повторно разобран утилитой и импортирован через системный файловый диалог в обновлённое приложение, Unix permissions `0600`.
- Linux x86_64: отдельная cross-build сборка через GCC из Linux-контейнера; ELF executable собран, запуск на x86_64/KDE не проверен.
- Windows x86_64: теперь проверены нативная MSVC release-сборка, unit, GUI startup smoke и сетевой E2E на Windows-нoде Jenkins. Подробности: [Jenkins CI](jenkins.md). Windows vault и installer lifecycle ещё не проверены.
- Linux aarch64, Debian bookworm / Rust 1.98.1 в Docker: все 30 тестов и сборка native frontend прошли. GUI на KDE и accessibility не считаются проверенными контейнерной сборкой.

### Воспроизведение interop

Скачать официальный `trusttunnel_endpoint` версии 1.1.0 из GitHub releases TrustTunnel/TrustTunnel для своей ОС. Harness требует Python 3, OpenSSL и уже собранный `rtrust-inspect`:

```sh
cargo build -p rtrust-inspect --locked
python3 scripts/interop.py /absolute/path/to/trusttunnel_endpoint
```

Harness создаёт временный сертификат с SAN localhost, синтетическую учётную запись, loopback endpoint и HTTP/UDP echo servers. Production-профили не нужны. Процессы завершаются, временные ключи удаляются при выходе. Private destinations разрешены только в этом изолированном тестовом endpoint.

## Ещё не реализовано

- Boot-level always-on VPN до входа пользователя. Автоподключение при запуске GUI и автозапуск приложения при входе добавлены как отдельные opt-in настройки. Трей и сохранение перед закрытием реализованы (docs/desktop-lifecycle.md). Windows full IPv4/DNS/WFP реализованы. В Linux full IPv4 TCP/UDP, systemd-resolved DNS, nftables kill switch и сохранение блокировки после аварии GUI/службы реализованы. IPv6-туннелирование, IP fragmentation/options и ICMP остаются вне реализации.
- Двусторонняя автоматическая синхронизация: получение серверных изменений реализовано, отправка локальных изменений остаётся явной. Замена внешних серверных профилей через preview/commit реализована.
- Долговременная история версий и полевое слияние профилей. Конфликты хранилища и серверных изменений теперь имеют явный выбор версии/сохранения обеих копий; предыдущий зашифрованный vault доступен для явного восстановления.
- Linux deb/rpm и выбор Native/WebView/Both; auto-update и подпись. Windows Native Setup.exe и опциональная tt URI association реализованы. Workflow описан, но GitHub CI не запускался: у workspace пока нет Git remote.
- Полная функциональная паритетность WebView: расширенные recovery/update/boot-policy экраны и seamless смена UI ещё не приняты.
- Android VpnService/JNI и macOS Network Extension/Swift UI. macOS `.app` текущего preview — проверка общего desktop frontend, не выполнение второй волны.
- Платформенные проверки KWallet/Windows Credential Manager и дополнительные Windows ACL файлов хранилища. Unix файлы имеют `0600`, каталог vault — `0700`; Windows пока полагается на ACL пользовательского каталога.

Следующие этапы: IPv6 transport и оставшиеся UI/мобильные компоненты. Полный режим Windows и Linux блокирует IPv6.

## Собранные preview

`dist/native-preview-windows-x64/R-TrustTunnel.exe`, `dist/native-preview-linux-x64/rtrust-native`, `dist/native-preview-linux/rtrust-native` (ARM64), `dist/native-preview-darwin/R-TrustTunnel Preview.app` (Apple Silicon). Каталог содержит артефакты разных итераций; актуальная Windows-сборка Jenkins — MSVC release, более старые Linux preview — debug/stripped. Пакеты не подписаны, Windows/macOS notarization отсутствует. `dist/SHA256SUMS` фиксирует бинарники этой итерации.

## Компактный UI и подключение профиля по умолчанию

Окно 860×620, основной шрифт 14 px, фон #2c303e, кнопки с радиусом 7 px. Верхняя панель доступна на всех страницах: подключить, отменить попытку, отключить. Кнопка создаёт transport session с аутентификацией и локальный SOCKS5 listener; каждые 15 секунд выполняется health check, счётчики обновляются каждую секунду. При ошибке статус сбрасывается, поздний результат отменённой попытки игнорируется. Полный системный VPN не включается; Linux TUN для выбранных сетей добавлен следующей итерацией ниже.

Первый профиль является профилем по умолчанию. Действие «Использовать по умолчанию» перемещает выбранный профиль на первое место; «Сохранить шифрованно» сохраняет порядок между запусками. Выбор строки для просмотра не меняет default. Во время соединения default менять нельзя; отключение всегда относится к активной session.

Два дополнительных UI state tests проверяют default против selection и отмену/поздние результаты/повторную попытку. В реальном окне проверены подключение к отдельному официальному endpoint 1.1.0 на loopback с синтетическим профилем и отключение. [Снимок](screenshots/native-preview.png).

Кнопка верхней панели адаптивно занимает 40% ширины окна; высота 39 px (примерно +20%). Размер одинаков для подключения, отмены и отключения. Текст центрирован по обеим осям, начертание Semibold.

## Функциональная итерация: SOCKS5 и профили

`crates/engine/src/proxy.rs` реализует loopback-only SOCKS5 по wire format [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928). Доступна только no-auth negotiation локального listener; BIND и другие методы аутентификации не поддерживаются. TCP hostname передаётся endpoint как CONNECT authority без локального DNS. UDP принимает IP destinations, привязывает ассоциацию к IP/порту клиента, проверяет обратные source/destination, закрывает relay вместе с управляющим TCP-соединением. SOCKS UDP fragments и domain destinations отбрасываются. Для TCP сохраняется half-close и ограниченные буферы.

При остановке listener и все его обработчики отменяются; при потере health соединение отключается без прямого fallback. Порт, занятый другим процессом, вызывает понятную ошибку. Системные настройки не меняются. Счётчики учитывают переданные payload bytes (без overhead TLS и SOCKS); errors включает отказы negotiation/CONNECT/I/O, но не каждый отброшенный UDP datagram. Active включает локальные TCP-клиенты, в том числе UDP control connections.

Результаты: новый тест передаёт 512 KiB через настоящий SOCKS клиент, проверяет remote-only имя `.invalid`, half-close, счётчики, закрытие активного tunnel и повторное занятие порта. Проверяются неверная auth negotiation, BIND, malformed domain, invalid ATYP, endpoint authentication failure, port conflict и UI lifecycle. Официальный endpoint 1.1.0: `curl --socks5-hostname`, UDP echo/8 KiB, rejection fragments/wrong source и закрытие UDP association успешно проверены на HTTP/2 и HTTP/3.

Через настоящее native окно включён SOCKS5 на тестовом порту, получено и побайтово проверено 16 KiB HTTP body; UI показал 16 KiB downloaded и ноль ошибок. Нажатие «Отключить» закрыло порт. [Снимок](screenshots/native-proxy-traffic.png). Production-сервер не изменён.

Переименование, удаление и замена выбранного профиля работают только вне подключения; удаление и замена требуют второго нажатия. Изменения сначала происходят в памяти и помечаются как несохранённые. Сохранение пустого списка после удаления последнего профиля поддерживается. Auto-save при выходе не добавлен.

## Linux TUN: проверка data plane

Реализация и ограничения описаны в [TUN preview](tun-preview.md). Проверка выполняется с официальным endpoint 1.1.0 в отдельном Linux network namespace. В обычных приложениях не задаётся SOCKS; TCP и DNS идут по маршруту через настоящий TUN. Production-сервер и сеть macOS не меняются.

Выявлена отдельная проблема совместимости HTTP/3 half-close: сервер получил 524288 байт, но не EOF; контрольный тест через SOCKS воспроизводит это без TUN. Поэтому helper явно отклоняет HTTP/3 до создания интерфейса. Общий HTTP/3 transport и SOCKS остаются экспериментальными; прежняя проверка HTTP 200/UDP не доказывала корректность half-close.

Параллельная нагрузка выявила несовместимость upstream h2 0.4.19 с пустыми DATA-кадрами endpoint 1.1.0. Узкая [локальная поправка](../vendor/h2/RTRUST-PATCH.md) сохраняет burst limit 100 и восстанавливает один credit на 16 KiB потреблённых приложением данных. Старое поведение проваливает regression test с `BudgetExhausted`; исправленное проходит. Проверены 59 самодостаточных unit tests h2 (один upstream test ignored; 382 внешних HPACK fixture tests недоступны в опубликованном crate и явно исключены).

Linux TUN E2E: HTTP 512 KiB, 12 загрузок в 4 параллельных потоках, TCP half-close 512 KiB, системный DNS `getaddrinfo`, UDP 1/512/1472 байта и пустая датаграмма с follow-up. SIGTERM завершает процесс с кодом 0 и удаляет интерфейс; аварийная остановка endpoint завершает helper с ошибкой и также удаляет TUN. HTTP/3 отклоняется до создания интерфейса. Все проверки — в изолированном Linux ARM64 Docker namespace.

Пересобраны native previews для macOS ARM64, Windows x86_64 и Linux ARM64/x86_64 с общей поправкой h2. Добавлены отдельные Linux TUN binaries в `dist/tun-preview-linux` и `dist/tun-preview-linux-x64`. Windows и Linux x86_64 — cross-build, запуск этих сборок на целевых desktop ОС в этой итерации не проверялся.


## Linux-служба и подключение из GUI

Добавлены `crates/control` (версионированный Unix IPC и проверка peer UID), `rtrust-service` (привилегированный TUN lifecycle) и переключатель SOCKS5/TUN в native UI. Служба применяет selected IPv4 CIDR только к настроенному desktop UID. Stop ожидает удаления маршрутов; аварийная блокировка снимается отдельной кнопкой. Есть unit systemd и установщик. [Команды и точные ограничения](linux-service.md).

Проверены реальный HTTP через TUN с тем же IPC-клиентом, что в GUI, независимость другого UID, вторая сессия, некорректные IPC-кадры, восстановление после Stop, падения endpoint и SIGKILL/restart службы при наличии прямого default route. Повторно пройден прежний TUN TCP/UDP/DNS/half-close стенд. Systemd installer lifecycle и реальное окно KDE пока не проверены.

Текущие результаты: 33 Rust-теста на macOS, 34 на Linux (дополнительный Linux UI state test); Clippy workspace и сборки native для четырёх целей успешны. Служба и TUN собраны для Linux ARM64/x86_64; пакеты службы — `dist/service-preview-linux` и `dist/service-preview-linux-x64`.


## Переподключение Linux TUN

Служба автоматически восстанавливает активную сессию после потери endpoint. Повторные попытки используют backoff 2–30 секунд и timeout 30 секунд; стабильные 30 секунд сбрасывают backoff. IPv4 policy rules и unreachable route остаются установленными на всё время восстановления. Смена TUN добавляет только device routes, не дублируя правила. Stop отменяет и ожидающую попытку, и работающий TUN до очистки маршрутов. EOF клиента освобождает сессию; после перезапуска службы по-прежнему нужен явный Recover.

Native UI проверяет состояние TUN каждые две секунды и убирает сообщение об ошибке при восстановлении. SOCKS5 сохраняет прежнее поведение. Изменение проверяется в `scripts/service-interop.py` на официальном endpoint 1.1.0: два сбоя подряд, блокировка с доступным прямым default route, восстановление TCP, отсутствие повторных rules и отмена retry при отключении. Это восстановление новых соединений, не перенос уже открытых TCP/UDP flows.

Regression-проверка выполнена также со старым ARM64-бинарником службы: он провалил ожидание `SERVICE connected` после возвращения endpoint. Новая служба проходит этот сценарий. После Stop стенд ждёт 35 секунд — дольше максимального backoff — и проверяет отсутствие TUN/журнала и восстановленный прямой маршрут.


## Сохранение настроек подключения

Зашифрованный `RTRUST2` хранит профили и общие настройки подключения: режим, порт SOCKS5 и IPv4 CIDR. Кнопка «Сохранить шифрованно» сохраняет их атомарно с прежней проверкой версии файла. При запуске хранилище загружается автоматически; это не автоподключение. Заблокированный keyring возвращает ошибку без незашифрованного fallback. Изменения настроек помечаются как несохранённые; во время записи редактирование заблокировано.

Прежний `RTRUST1` читается с настройками SOCKS5/1080 и пустым списком сетей. Чтение не меняет файл; переход в новый формат происходит при сохранении после изменения профиля/настроек. Ключ keyring не меняется. Старые версии приложения не читают `RTRUST2`; для возврата к ним нужна заранее сохранённая копия старого файла. На Windows/macOS загруженный Linux TUN не активируется, настройки сохраняются при повторной записи, а интерфейс сообщает о доступном SOCKS5. Явный выбор SOCKS5 меняет сохранённый режим.

Проверки покрывают шифрованный roundtrip настроек, миграцию старых профилей через запись/чтение временного файла, stale-writer conflict, подмену версии/AAD, неизвестные поля и недопустимые маршруты/порт. UI-тесты проверяют загрузку без подключения, сохранение Linux-настроек на других ОС, dirty state и блокировку редактирования во время записи. Реальный KWallet/Windows Credential Manager в этой итерации не проверялся.

Проверки этой итерации: 37 тестов macOS, 38 Linux; Clippy workspace прошёл на обеих платформах. Обновлены native preview для macOS ARM64, Windows x86_64, Linux ARM64/x86_64.

Нативный macOS/Windows CI заведён в локальном Jenkins: [успешный прогон #5](http://localhost:8081/job/rtrust-native/5/), Gitleaks/Trivy, unit, GUI startup smoke, сетевой E2E и release-артефакты. См. [условия и результаты](jenkins.md).

## Windows Wintun и SCM-служба

Реализованы Wintun adapter, Windows SCM service, защищённый named pipe, проверка SCM identity клиентом до отправки credentials, native UI mode, маршруты выбранных IPv4-сетей всей ОС, reconnect с удержанием адаптера, install/update/remove и Windows E2E. Первый полный прогон #12 — SUCCESS. [Windows-инструкция и ограничения](windows-service.md), [доказательства Jenkins](jenkins.md). Общий Linux/Windows data-plane регрессий на Linux ARM64 не показал. WFP/default-route/DNS добавлены следующей итерацией; IPv6 блокируется.


## Linux whole-host VPN и Wayland-only — завершённая проверка

[Последний прогон #17](http://localhost:8081/job/rtrust-native/17/) завершён `SUCCESS`: 17 JUnit-групп; 41 Rust workspace test на macOS, 47 на Windows, 42 на Linux. Gitleaks — 0; Trivy HIGH/CRITICAL — 0. Проверены прежние HTTP/2+HTTP/3/SOCKS E2E, Windows Wintun/SCM lifecycle и все Linux packet/service/full-tunnel тесты.

Native Linux собирается **только с Wayland**; X11 backend отключён. `ci/wayland_smoke.py` проверяет feature graph, реальный запуск в headless Weston без DISPLAY/XWayland и `xdg_toplevel.set_app_id("org.rtrusttunnel.Native")`, совпадающий с desktop-файлом. Linux x64 GCC cross-build дополнительно исполнил GUI/app-ID/CLI smoke под Docker amd64-эмуляцией. Реальный Plasma desktop, Discover и установленный systemd lifecycle этой проверкой не покрыты.

Режим «Весь компьютер» включает IPv4 TCP/UDP всех UID и DNS через VPN; блокирует прямой обход, IPv6 и forwarded traffic. Реальные E2E подтверждают обрыв/reconnect, Stop/restore, SIGKILL/restart и аварийное закрытие GUI. Последнее сохраняет блокировку до явного Recover. Нормальное закрытие окна сначала ждёт Stop ACK; при ошибке очистки окно остаётся открытым. Подробности и ограничения — [Linux full tunnel](linux-full-tunnel.md).

## Unsigned macOS DMG и серверный обмен профилями

Добавлен `scripts/package-macos-dmg.py`: unsigned DMG Apple Silicon, ссылка Applications, проверка hdiutil, сравнение SHA-256 вложенного бинарника и GUI smoke из read-only mount. Сертификат Apple Developer не требуется для упаковки; системный VPN macOS это не реализует.

В `server/overlay` реализованы страница `/profiles` и API v2: общий Rust-кодек `rtrust-codec`, preview/commit, зашифрованное хранение импортов, экспорт JSON/TOML/tt, одноразовая привязка устройств, явные grants, отзыв токенов, CSRF и контроль revision. Семь интеграционных тестов используют временную SQLite и настоящий Rust-кодек. В браузере вручную проверен синтетический TOML → preview → сохранение → экспорт; снимок — `dist/portal-ui-smoke.png`.

Обновление 2026-09-30: серверное расширение развёрнуто по HTTPS и подключено к native UI (страница «Серверная панель»). Импорт не создаёт VPN credentials на endpoint; отзыв доступа к API не отзывает уже скачанные VPN-пароли. Системный VPN macOS, Android и installer с выбором UI остаются незавершёнными. Windows full-tunnel/WFP и Native Setup добавлены следующей итерацией. Существующая Windows-нода проверена после разрешения пользователя: активного VPN-адаптера нет, default route идёт через Ethernet. Это проверка пригодности стенда, а не Windows full-tunnel E2E.

## Windows full-tunnel и Setup.exe

Добавлены постоянные WFP-фильтры, default IPv4 routes, DNS на Wintun и журнал восстановления в защищённом каталоге службы. Полный сетевой тест на Windows 11 прошёл передачу TCP/UDP, DNS, обрыв endpoint, аварии GUI/службы, повторное подключение и Stop. При восстановлении удаляется только GUID устройства из журнала, общий Wintun-драйвер сохраняется. В тесте обнаружена и исправлена оставшаяся после SIGKILL запись PnP-адаптера.

Настоящий Inno Setup проверен установкой, обновлением, GUI smoke и удалением. Ошибка установки службы даёт ненулевой exit code; проверен неверный Windows account. MSVC CRT статически включён; PE import table проверяется перед упаковкой. Setup и приложение пока не подписаны.


## Desktop lifecycle correction

Добавлены автосохранение после редактирования и перед закрытием, отказ от выхода
при ошибке записи, системный трей Windows/macOS и StatusNotifierItem для Wayland.
Linux закрывает и заново создаёт только окно; daemon продолжает держать профиль
и VPN-сессию. При отсутствии трея окно минимизируется. Системный TUN использует
HTTP/2-копию импортированного профиля; SOCKS и экспорт сохраняют исходный транспорт.
Подробнее и границы проверок: [desktop lifecycle](desktop-lifecycle.md).

HTTP/3 для Windows/Linux системного туннеля перенесён в [техдолг волны 3](technical-debt.md); текущий SOCKS HTTP/3 сохраняется.

## Opt-in автоподключение

В настройках добавлено подключение профиля по умолчанию при запуске GUI.
По умолчанию выключено; старые хранилища получают false. Настройка сохраняется
шифрованно вместе с параметрами подключения. При загрузке файла/tt, повторном
открытии хранилища, ошибке keyring или несовместимом режиме автоподключения нет.
Одна попытка использует обычный путь подключения/отмены, ошибка возвращает окно.
Это не always-on VPN: до запуска и установления туннеля трафик не защищён.
