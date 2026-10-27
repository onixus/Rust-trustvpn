# Проверка скоупа #32–#36

Изменения проверяются в отдельном managed worktree. Исходный dirty checkout и
локальный VPN Mac не меняются. Mac/iPhone отложены пользователем; Fedora,
Windows и USB Android разрешены для испытаний. Не следует закрывать issues по
одному зелёному набору unit tests.

## Реализованные механизмы

- WebView: атомарная синхронизация, защищённые managed routes, отменяемая
  диагностика без удержания controller lock, свежесть по generation/epoch,
  редактируемый отчёт и только явное сохранение пользователем.
- Android: диагностика через принадлежащий приложению VPN Network, verified
  TLS HEAD без default-network fallback, ограниченные ответы/время, отмена,
  редактирование и локальный SAF export. DNS scope не доказывает DNS egress;
  longest-prefix route обозначает конфигурацию, а не факт передачи пакета.
- Политика Android: offline preview, apply/rollback через тот же evaluator,
  CAS версии, queue cancellation, drain/join старых TCP задач до commit.
  Это session-only flow policy; OS route/DNS/guard не меняются. Managed
  policy закрыта от локальной мутации; дополнительный direct authority
  изменением policy не выдаётся.
- Android group adapter: admin/user IPv4 include/exclude используют desktop
  subtraction, сохраняют embedded flow/DNS/guard policy и блокируют IPv6 вне
  IPv4 group contract. Snapshot хранит group/revision с профилями атомарно;
  конфликт той же ревизии или исчезнувшая capability отвергаются. `exclude_lan`
  пока отвергается целиком: отсутствует корректный lifecycle обновления
  локальных префиксов при handoff. Local routes не выдаются за observed egress.
- Retry Android использует общий jitter/budget/cooldown и лимит установления
  фиксированного соединения; автоматический выбор резервных профилей пока
  отсутствует. Budget tests не заменяют измерения на устройстве.
- Новый server snapshot и индивидуальные credentials описаны в
  [managed-devices.md](managed-devices.md).

## Полученные проверки

На версии перед physical acceptance прошли весь Rust workspace, строгий Clippy,
Windows native tests control/desktop/portal, Fedora Android JNI release build,
APK и instrumented APK build, Android lint. Сервер: 86 scoped API/SQLite tests
для exchange, credentials, agent/routing/protocol contracts. Mock receipts
проверяют транзакции и fencing; не считаются проверкой настоящего endpoint.
Патчи исходников проверены на секреты перед передачей на тестовые машины.

На Fedora дополнительно прошёл тест с настоящим TrustTunnel endpoint в
network-none контейнере: enrollment → unique grant → H2/H3 auth → rotation
(новый auth + старый reject) → revoke (сохранённый пароль reject). Соседнее
managed устройство успешно открыло новые H2/H3 соединения после ротации и
отзыва первого. Это подтверждает endpoint credentials contract в изоляции;
ещё не подтверждает активные туннельные сессии, установленный пакет или SLA.
Windows release build WebView/TUN также прошёл без запуска сервиса.

Exact-commit лаборатория для baef08c прошла build/tests/Clippy, service, H2,
H3 и failover. Manifest: passed=true, cleanup_failures=[]; source archive
SHA-256 6d114c98f068bad4d03aaf7ef55b513f92cd2caa5191abcd7aa44f8f1c2bda5c.
GitHub Ubuntu/macOS/Windows checks для baef08c прошли. Следующие QR/renewal
изменения требуют своих current-head проверок.

Дополнительно реализованы QR origin/expiry/reuse и явный token renewal.
Для них прошли 18 Rust portal tests, desktop Clippy, 90 scoped server tests,
Android APK/test APK/lint. Instrumentation ещё не выполнена: read-only
Fedora API36 emulator трижды упал с SIGSEGV до появления в adb; phone install
по-прежнему требует подтверждения. Упавшие emulator processes завершены,
исходный AVD не сбрасывался и snapshots не записывались.

USB Android отклонил side APK установку с INSTALL_FAILED_USER_RESTRICTED;
ожидается подтверждение пользователя на телефоне. Side package:
`org.rtrusttunnel.android.scopetest`; рабочие пакеты и vault сохраняются.

## Оставшаяся приёмка и реализация

Review QR/renewal diff завершён с частичным security coverage: динамическая
проверка двух timing-вопросов заблокирована автоматической cybersecurity
защитой. Это не означает отсутствия рисков. Следом исправлены потеря ownership
retired TCP tasks при drain, раздельные snapshots Android profile/provenance,
проверка срока token до ожидания SQLite lock, неполный Docker build context
и поздняя регистрация индивидуальных credentials при server startup.
Для исправлений прошли полный Rust workspace/Clippy и 92 scoped server tests.
Regression startup проверяет данные, видимые исходному владельцу endpoint
до его старта; он не запускает endpoint и не заменяет physical restart test.
Дополнительно real endpoint fixture перезапустил сервер в новом Python
процессе с той же synthetic DB: H2/H3 соседнего устройства приняты,
retired credentials отклонены. Это isolated startup acceptance, не physical
installed-package acceptance. Последующие group/session изменения прошли
полный Rust workspace/Clippy, JNI arm64/x86_64, APK/test APK build и lint.
Android instrumentation по-прежнему `not_run`.

Повторная Linux laboratory для `8440fe8` прошла build, service, H2, H3 и
failover: `passed=true`, `cleanup_failures=[]`, source archive SHA-256
`db6101fb5df0d3c314de5e02ec14e0a0c6a4cc9cc481c1f9f2b35f95cd956554`.
Последующие изменения относятся только к mobile IPv4/status; этот lab receipt
не переименовывается в доказательство другого commit. Android connection
label различает подтверждённый transport и непроверенные системные DNS/HTTPS.

| Задача | Что ещё нужно |
| --- | --- |
| #32 | OS route cutover/rollback и физические старые TCP/UDP flows; физическая проверка LAN group handoff |
| #33 | Реальная UI/системная диагностика full/split, IPv6, outage/control loss на разрешённых устройствах |
| #34 | Physical mobile reserve selection; sleep/reboot/handoff/crash/outage, rollback cleanup, измерения retry/CPU/energy |
| #35 / tunnel#22 | Активные сессии и физический SLA; legacy/shared migration, LAN/QR/renewal/freshness physical acceptance |
| #36 | Exact commit/package hashes, installed update/rollback/vault tests, publisher signatures, 24h soak и budgets |

Новый `PolicyChanged` event отличается от физической смены сети. APK/JNI
собираются парой; старые клиенты не должны получать новый observation kind без
проверки совместимости. Endpoint verifier не подключается к сторонним адресам:
каждый адрес stdin-profile должен быть числовым loopback, TLS остаётся проверенным.

## Мобильные резервы, LAN и ограниченный offline доступ

Android позволяет явно выбрать до трёх резервов для выбранного основного
профиля. Общий бюджет — 12 попыток на логическую сессию; смена сети, LAN
и обновление подтверждения срока его не обнуляют. Ошибка доверия/авторизации
исключает только соответствующий разрешённый профиль. Все кандидаты должны
иметь одинаковые маршруты, DNS и защиту. Самостоятельного выбора другого
протокола нет. Изменение набора резервов требует явного действия пользователя.

LAN исключения используют IPv4 префиксы текущего Android LinkProperties.
Без наблюдения локальной сети план с exclude_lan не запускается. Старые
владельцы TCP/UDP завершаются до установки нового плана. Для managed профилей
сохраняется блокирующий TUN на весь IPv4/IPv6; выбор tunnel/direct выполняет
тот же evaluator, который объясняет маршруты. IPv6 managed group не поддержан
и блокируется. Исключения приложений остаются явной настройкой пользователя.

Сервер сообщает offline_freshness=1 и возвращает срок по согласованному запросу
freshness_version=1. Максимальный возраст — 24 часа по умолчанию, настройка
RTRUST_OFFLINE_MAX_AGE_SECONDS допускает 60–86400 секунд. Срок также ограничен
остатком portal token. Клиент отсчитывает его от начала запроса; отсутствие
или исчезновение согласованного подтверждения запрещает новый доступ.
Старые запросы snapshot сохраняют прежнюю форму ответа.

Android хранит receipt вместе с профилями в encrypted vault. Время сна
учитывается; после перезагрузки или отката часов требуется синхронизация.
Истечение/известный отказ доступа останавливают dataplane, сохраняя TUN.
В этом состоянии только запрос к сохранённому HTTPS origin портала может
использовать underlying network для восстановления; редиректы запрещены.
Успешное обновление одного receipt не меняет действующий policy и retry budget.

Linux/Windows/macOS обычные TUN/full соединения передают service конечную lease.
Истечение завершает workers и сохраняет принадлежащую сессии защиту до явного
Stop (на macOS также доступен Recover владельца сессии).
Sleep-aware clocks не позволяют продлить срок сном или наблюдаемым откатом часов.
На macOS используется CLOCK_MONOTONIC_RAW, включающий время сна; отказ часов
не разрешает доступ. Проверки охватывают подготовку, запуск dataplane и reconnect,
а не только подключённое состояние или жизнь GUI. Изменение macOS пока локальное:
installed-package, реальные sleep/wake и packet-level gates NOT RUN; оно не
приписывается ранее опубликованным пакетам.
IPC v5 ввёл freshness; текущий IPC v7 требует совместимого UI/service.
Managed SOCKS и постоянный service-owned Always-on пока не имеют этого
контракта и отклоняются; iPhone отложен. Desktop обновляет подтверждение
при синхронизации перед переподключением, без фонового продления активной lease.

Это конечная клиентская авторизация кешированного managed доступа. Она не
заменяет endpoint revoke/rotation, не отменяет явно созданные независимые
локальные копии и не является защитой от владельца устройства с root.
Наблюдения LAN/boot и отчёты диагностики не отправляются на сервер.
Сборка APK не считается физической проверкой переключения или 24h soak.

Совмещение серверного PR сохраняет уже влитый `rtrust_credentials` из main;
альтернативный lifecycle/verifier удалён из текущего diff. На совмещённой
версии прошли 194 API/SQLite регрессии. Старые network-none verifier receipts
остаются историческими и не считаются доказательством этой серверной версии.

Desktop receipt admission сохраняет managed принадлежность при изменении
названия/локальной политики через credential identity. Если snapshot больше
не выдаёт grant, данные остаются в vault с unavailable marker: новый receipt
для соседних профилей не разрешает старый credential. Другой действующий
grant той же identity может её разрешить; независимые credentials локального
профиля остаются локальными. Явное удаление привязки — отдельное решение
владельца, endpoint revoke по-прежнему проверяется сервером.
