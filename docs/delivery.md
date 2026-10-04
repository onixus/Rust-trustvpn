# План реализации и приёмка

Статус: M0/M1 реализованы частично — codec, native UI, encrypted store, HTTP/2 и HTTP/3 transports. Текущее покрытие и проверки указаны в [implementation.md](implementation.md). Приведённые ниже gates ещё не закрыты; сроки не фиксируются до проверки TUN и Windows networking.

## Текущий порядок работ — решение пользователя

1. Пункт 6: конфликты локального хранилища и серверная синхронизация — реализованы
   и проверены (#34). Подписанное обновление Windows клиента/службы и настоящий
   откат — проверены на #36→#37; [доказательства](secure-updates.md).
   Обновления macOS и Linux входят в платформенные этапы 4 и 1.
2. Пункт 5: IPv6, ICMP/фрагментация, системный lifecycle и always-on — код и Linux E2E реализованы; Windows runtime #53 и signed upgrade/rollback 3→6 прошли; 0.3.2 установлен и доставлен. Холодная загрузка/сон ещё не проверены. [Сценарии и ограничения](always-on.md).
3. Пункт 4: системный VPN macOS; unsigned DMG остаётся допустимой упаковкой,
   live-проверка установленной сборки #61 прошла: IPv4/IPv6 TCP/UDP/ICMP,
   DNS, блокировка обхода, reconnect, аварии GUI/службы и восстановление сети.
   [Отчёт](../reports/macos-runtime/acceptance-61.json). Сон/смена сети,
   boot always-on и автоматическое обновление с откатом ещё не закрыты.
4. Пункт 1: Linux через Flatpak вместо первоочередных deb/rpm. UI работает
   без X11; привилегированный сетевой компонент устанавливается на хост отдельно
   и предоставляет ограниченный аутентифицированный IPC. Flatpak не получает
   произвольное выполнение команд хоста. Установка и обновление обоих компонентов
   должны быть проверены вместе.

На 1 октября x86_64 теперь проверяется нативно на физическом Arch Linux,
а не только под QEMU. `rtrust-linux` #7 завершился SUCCESS: security, unit,
Wayland и полный сетевой E2E, включая строгий rp_filter и смену интерфейса.
Пройдены реальная Plasma/Wayland-сессия, трей, KWallet, Document/Background
portals, Arch host package install/update/rollback/uninstall и отдельный
подписанный Flatpak update/rollback с отказом неподписанному commit.
Подписанный HTTPS candidate-репозиторий опубликован и проверен анонимной
установкой. Проверки reboot/sleep ещё открыты.
[Подробности](linux-service.md).

По следующему запросу пользователя после Linux начинается Android.
WebView остаётся в общем плане.
HTTP/3 системного VPN реализован ([HTTP/3](http3.md)). Пункты не считаются завершёнными
до реализации и проверок; старые этапы ниже сохраняют исходный контекст проекта.

## M0 — совместимость и выбор engine

Результат: воспроизводимый Rust interop harness и заключение по стеку.

- Сохранить sanitized fixtures официальных endpoint/CLI TOML, tt v0/v1 и текущего panel JSON.
- Проверить h2/h3 CONNECT к endpoint 1.1.0; TCP download/upload, UDP request/response и tunneled DNS.
- Проверить custom CA, hostname/SNI split, ошибочный сертификат, client_random/mask, anti-DPI и profile fingerprint requirements на отдельных fixture endpoint.
- Доказать TUN-to-flow stack на Linux/Windows; измерить CPU/RAM/throughput и корректность TCP, определить ограничения smoltcp.
- `iced` proof: сборка на обеих ОС, file/URI handling, русский ввод, HiDPI, accessibility, Wayland и tray fallback.
- Desktop packaging spike: Windows Setup.exe/MSI с Native/WebView/Both; Linux native GUI setup и компоненты deb/rpm. Проверить KDE Plasma integration и отсутствие WebView dependencies у Native.

Gate: записанная capability matrix. Если client_random/TLS fingerprint или flow stack не реализуемы выбранными crates, принять ADR до обещания полной совместимости. Один рабочий HTTP CONNECT без TUN/DNS не закрывает M0.

## M1 — codec и локальный импорт/экспорт

Результат: общий Rust crate, fixture corpus, Python binding, UI wizard с preview.

- Пять входных форматов, строгое определение, redacted errors и bounded parsing.
- Golden differential tests против upstream encoder/decoder; намеренные различия с багами oracle документировать.
- Round trip сохраняет общие endpoint поля; экспорт потерь подтверждается отдельно.
- Vault backend, atomic profile save, duplicate/replace/conflict flows.

Gate: codec fuzz без panic/OOM в заданных лимитах, API contract fixtures и запрет исполнения неподдержанных security fields.

## M2 — системная служба и рабочий GUI VPN

Результат: установка без CLI, service IPC, TUN, DNS, firewall, reconnect.

- Linux first, затем Windows с одинаковыми state machine и контрактом IPC.
- HTTP/2 для системного туннеля; UDP/ICMP, IPv6 tunnel-or-block, local stub, bounded buffers. HTTP/3 для TUN/Wintun перенесён в [техдолг волны 3](technical-debt.md); SOCKS HTTP/3 сохраняется.
- Cancel на каждом этапе, смена Wi-Fi/Ethernet, sleep/resume, UI crash, worker crash.
- Kill switch до первого изменения маршрутов, recovery journal и repair UX.
- Windows Setup.exe предоставляет выбор Native/WebView/Both, MSI устанавливает выбранные frontend, одну службу и signed Wintun с фиксированным hash. `R-TrustTunnel.exe` запускается без консоли. Собственные binaries/installer подписываются при наличии signing pipeline; отсутствие подписи не скрывать.
- Linux GUI setup предлагает тот же выбор и устанавливает deb/rpm через системный package backend/polkit. Пакеты доступны через Discover, имеют desktop/AppStream metadata и Plasma tray integration. AppImage/Flatpak не заменяют установку системной службы и отложены.
- Native frontend выпускается первым; WebView — отдельный frontend на общем Rust controller. Полная поставка с выбором UI требует одинакового набора основных функций и переключения без разрыва VPN. Подробности: [desktop-apps.md](desktop-apps.md).

Gate: приложение пригодно для повседневного использования на обеих платформах, все network lifecycle тесты ниже пройдены. Boot-level always-on отдельно от session kill switch.

## M3 — интеграция с панелью

Результат: единый exporter, UI download/upload, preview/commit, scoped device API.

- Сначала удалить расхождение TOML/tt через normalised snapshot, сохранить legacy routes и email.
- Additive schema migration + backup данных/ключей + тест восстановления.
- External imports не меняют endpoint; admin restore через durable apply job.
- Enrollment без долговременного token в URL, per-device grants и отзыв.
- Browser E2E и настоящий путь panel → новый клиент → трафик через VPN.

Gate: старый официальный клиент и действующие пользователи продолжают работать; нет credential leakage или ownership bypass; retry/rollback доказаны.

## M4 — release

M0–M4 относятся к первой волне Windows/Linux. Вторая волна начинается после её приёмки; scope описан ниже и в [android-macos.md](android-macos.md).

Подписанные/проверяемые packages, SBOM и лицензии зависимостей, pin/hash Wintun, воспроизводимые CI artifacts. Автообновление UI/service только согласованным комплектом с versioned IPC; загруженный update проверяется до elevation. Backup profiles/schema до обновления, rollback проверяется на реальной предыдущей версии. При обновлении не снимать guard, пока старая сессия ещё защищает трафик.

Windows CI должен включать VM с реальным Wintun/WFP и reboot; Linux — VM/kernel namespaces с nftables, DNS manager и desktop smoke. Cross-compilation на macOS не доказывает работу VPN на Windows/Linux.

## Вторая волна — Android и macOS

- **W2.0:** portable Rust core, bindings, VpnService/Network Extension spikes, platform signing feasibility.
- **W2.1:** Android Native beta, signed APK, file/tt/QR import, portal enrollment, Keystore, Wi-Fi/mobile reconnect и системный lockdown.
- **W2.2:** macOS Native beta, обычное `.app`, Keychain, signed/notarized distribution, packet tunnel provider, sleep/wake и menu bar.
- **W2.3:** macOS WebView/Both с выбором в installer, parity, upgrade/rollback и проверка на реальных устройствах; выпуск второй волны.

Общий transport/codec/server API сохраняется. Android/macOS не используют Windows/Linux network service напрямую: адаптеры реализуют системный VPN lifecycle каждой ОС. Детальная матрица физических устройств, платформенных ограничений и артефактов — в [проекте второй волны](android-macos.md).

## Матрица обязательных проверок первой волны

| Группа | Сценарии | Доказательство |
|---|---|---|
| Interop | old/current server, h2/h3, TCP/UDP/ICMP, IPv4/IPv6, IP/domain addresses | реальный трафик и идентичное поведение fixture endpoint |
| Config | endpoint/full TOML, old/new tt, Unicode, cert DER/PEM, DNS, prefix aliases | golden fixtures + semantic round trip |
| Parser | unknown tag ≥256, huge varint, overflow, truncated DER, repeated fields, invalid UTF-8, future version | unit/property/fuzz; баговые варианты не проходят |
| TLS | CA/system trust, name mismatch, custom SNI, expiry, server rules | ошибочные сертификаты не допускают CONNECT |
| DNS | system/application DNS, DoH/DoT через tunnel, DNS-only failure | capture на физическом интерфейсе без пользовательских plaintext DNS |
| Kill switch | kill -9 worker/service, h3 block, sleep, network handoff, IPv6-only route | capture без direct user traffic; разрешения guard проверены отдельно |
| Lifecycle | 100 connect/disconnect, concurrent click/cancel, crash at each network step, reboot | без stale route/DNS/WFP objects и orphan processes |
| Privilege | чужой UID/SID, remote pipe, crafted IPC, DLL/path injection | unauthorised network mutation отклонена |
| Profile API | IDOR, blocked user, revoked device, missing CSRF, role mismatch | negative integration tests с независимыми пользователями |
| Atomicity | два redeem одновременно, повтор commit, credential apply failure, panel crash | один result, recoverable journal, рабочая previous revision |
| Secrets | logs/crash dump policy/URL/referrer/clipboard/export | synthetic canary secrets отсутствуют в диагностике и HTTP logs |
| Upgrade | fresh install, upgrade, rollback, uninstall, signed artifact failure | Linux/Windows install E2E, сохранность профилей и сети |
| UI selection | Native/WebView/Both, component add/remove, смена UI при active VPN | Setup.exe/Linux GUI E2E, один controller/service, без разрыва туннеля |
| KDE desktop | Plasma Wayland, Discover/menu/KRunner, StatusNotifierItem, portal dialogs | реальные Linux desktop runs, Native без WebKitGTK |
| UX | screenreader/keyboard/Russian IME/HiDPI/Wayland/no tray | UI checklist + реальные desktop screenshots |
| Performance | 1/100/1000 flows, large transfer, slow endpoint, UDP loss, long idle | bounded RAM, p50/p95 latency, throughput vs upstream на одинаковой сети |

Для производительности сначала снять baseline официального клиента на одном стенде; бюджет регрессии утверждается по измерениям, не выдумывается. Soak beta ≥24 h на каждой ОС. При исправлении найденной ошибки регрессионный тест должен падать на старой версии и проходить на исправленной.

## Выкатка на целевой сервер

Реализацию проверять в отдельном staging endpoint/порте и с временным тестовым пользователем. Не использовать пользовательские passwords в fixtures/CI. Перед production: backup image+DB+config+encryption keys, restore rehearsal, сравнение effective TLS/DNS settings и действующих профилей. Readiness панели не равен readiness endpoint: отдельно проверить TLS, authentication и tunneled TCP/UDP/DNS. После обновления сохранить email/monitoring flows.

В текущем проектировании сервер не перезапускался, профили не создавались/не отзывались, endpoint credentials не читались и не экспортировались. End-to-end VPN тестирование ещё предстоит в M0–M3.

## Третья волна

[Технический долг волны 3](technical-debt.md): HTTP/3 для системного VPN (Windows Wintun и Linux TUN).

## Android native preview implementation (2026-10-01)

The first Android APK now uses native Android widgets with the shared Rust core,
JNI protected sockets, Android VpnService and an encrypted Keystore-backed vault.
An API 36 x86_64 emulator has passed real IPv4/IPv6 TCP/UDP/DNS, endpoint outage,
reconnect, Activity closure and Stop. The outage test also exposed and fixed a
shared TLS classification bug: handshake EOF/reset must remain retryable, while
invalid certificates must not. A regression test failed before the fix and passes
after it. The separate Android Jenkins job adds security, packaging, storage and
APK upgrade checks. This is a preview, not physical-device or stable-release
acceptance. See [android.md](android.md) for exact limits and remaining work.
