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
  соединения. Budget tests не заменяют измерения на устройстве.
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

| Задача | Что ещё нужно |
| --- | --- |
| #32 | OS route cutover/rollback и физические старые TCP/UDP flows; LAN group adapter/handoff |
| #33 | Реальная UI/системная диагностика full/split, IPv6, outage/control loss на разрешённых устройствах |
| #34 | Sleep/reboot/handoff/crash/outage, rollback cleanup, измерения retry/CPU/energy |
| #35 / tunnel#22 | Активные сессии и физический SLA; legacy/shared migration, LAN groups, QR/renewal physical acceptance, обязательная offline freshness |
| #36 | Exact commit/package hashes, installed update/rollback/vault tests, publisher signatures, 24h soak и budgets |

Новый `PolicyChanged` event отличается от физической смены сети. APK/JNI
собираются парой; старые клиенты не должны получать новый observation kind без
проверки совместимости. Endpoint verifier не подключается к сторонним адресам:
каждый адрес stdin-profile должен быть числовым loopback, TLS остаётся проверенным.
