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

USB Android отклонил side APK установку с INSTALL_FAILED_USER_RESTRICTED;
ожидается подтверждение пользователя на телефоне. Side package:
`org.rtrusttunnel.android.scopetest`; рабочие пакеты и vault сохраняются.

## Оставшаяся приёмка и реализация

| Задача | Что ещё нужно |
| --- | --- |
| #32 | OS route cutover/rollback и физические старые TCP/UDP flows; mobile group-policy adapter |
| #33 | Реальная UI/системная диагностика full/split, IPv6, outage/control loss на разрешённых устройствах |
| #34 | Sleep/reboot/handoff/crash/outage, rollback cleanup, измерения retry/CPU/energy |
| #35 / tunnel#22 | Реальный endpoint H2/H3 rotate/revoke, активные сессии и соседнее устройство; legacy/shared migration, QR/renewal/freshness contracts |
| #36 | Exact commit/package hashes, installed update/rollback/vault tests, publisher signatures, 24h soak и budgets |

Новый `PolicyChanged` event отличается от физической смены сети. APK/JNI
собираются парой; старые клиенты не должны получать новый observation kind без
проверки совместимости. Endpoint verifier не подключается к сторонним адресам:
каждый адрес stdin-profile должен быть числовым loopback, TLS остаётся проверенным.
