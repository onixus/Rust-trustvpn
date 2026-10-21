# Состояние проекта и issue — 21 октября 2026

Основание: GitHub main и тег `v0.6.2` —
`4123160f14969905a68a61395bc5a9d823aaf1f5`; диффы merged PR #77–#108,
открытые PR [#109](https://github.com/onixus/Rust-trustvpn/pull/109) и
[#42](https://github.com/onixus/Rust-trustvpn/pull/42), текущие issue и их комментарии.
Изменения #109 учтены как документационный вход; PR ещё не merged.
Эта сверка не запускает runtime, CI, installed-package, packet capture,
signing или soak заново.

## Исходники и опубликованные пакеты

Workspace **0.6.2**, desktop sequence **12**, Android **0.6.2 / 60202**,
iOS **0.6.2 / 60202**. [v0.6.2](releases/v0.6.2.md) опубликован
21 октября по времени Europe/Istanbul (GitHub: 20 октября 23:21 UTC).
В release assets есть Windows installer, macOS UI Choices DMG с тремя PKG,
Linux Native/WebView/Both Flatpak и `rtrust-host-0.6.2-12`, Android APK,
SHA256SUMS и source identity/manifest. iOS assets остаются в v0.5.0.
Наличие assets сверено; их подписи, содержимое, source binding и
update-channel latest в этой сверке — **NOT RUN**.

## Изменения после состояния на 14 октября

| PR | Что вошло в main и v0.6.2 | Граница доказательств |
| --- | --- | --- |
| [#80](https://github.com/onixus/Rust-trustvpn/pull/80), [#83](https://github.com/onixus/Rust-trustvpn/pull/83), [#94](https://github.com/onixus/Rust-trustvpn/pull/94) | macOS Stop с отдельным cleanup supervisor и route snapshot; bounded Windows Recover; Android start/stop lifecycle; проверка распакованных CI tools; обезличенные Stop/reconnect timings | #71/#75/#76 закрыты. #70 остаётся открытым: split-mode timing и сохранность чужих маршрутов требуют приёмки. |
| [#84](https://github.com/onixus/Rust-trustvpn/pull/84), [#91](https://github.com/onixus/Rust-trustvpn/pull/91), [#96](https://github.com/onixus/Rust-trustvpn/pull/96) | DNS/guard/transport system probes; cancellation fence, TTL 30 с; macOS BPF tap с контрольным кадром | Для `7bfb564` описаны installed guard/DNS positive/negative tests; это не универсальное доказательство отсутствия leaks. [Объём](vpn-observations.md#service-system-probes-issue-81). |
| [#86](https://github.com/onixus/Rust-trustvpn/pull/86), [#89](https://github.com/onixus/Rust-trustvpn/pull/89), [#92](https://github.com/onixus/Rust-trustvpn/pull/92) | Android не пересоздаёт VPN при безвредном добавлении IPv6; sleep recovery и восстановление retry budget | Physical-device upgrade финального APK и overnight acceptance — NOT RUN. |
| [#87](https://github.com/onixus/Rust-trustvpn/pull/87), [#88](https://github.com/onixus/Rust-trustvpn/pull/88) | Linux packet-level failover/Always-on recovery и runtime route-explain lab | Изолированные namespaces/captures; physical-node и exact-package acceptance этим не заменяются. |
| [#95](https://github.com/onixus/Rust-trustvpn/pull/95) | После загрузки своего PF guard служба сбрасывает всю таблицу PF states, включая состояния других VPN | Намеренный системный эффект: существующие PF-tracked соединения могут прерваться. Чужие rules/anchors/tables не удаляются. |
| [#100](https://github.com/onixus/Rust-trustvpn/pull/100), [#103](https://github.com/onixus/Rust-trustvpn/pull/103), [#104](https://github.com/onixus/Rust-trustvpn/pull/104) | Wake backlog/reset-handshake cleanup, quiet-flow liveness и bounded reconnect Native SOCKS на том же профиле/порту | Installed system-VPN wake на двух Mac — PASS для `da92864`, см. ниже. Installed SOCKS wake и handoff через сон — NOT RUN. |
| [#102](https://github.com/onixus/Rust-trustvpn/pull/102) | IPC v7: system probes только при недавнем `viewed` от UI; keepalive один не включает проверки | GUI и служба обновляются вместе. Отдельная app system-path диагностика имеет собственный lifecycle. |
| [#98](https://github.com/onixus/Rust-trustvpn/pull/98), [#101](https://github.com/onixus/Rust-trustvpn/pull/101), [#105](https://github.com/onixus/Rust-trustvpn/pull/105), [#106](https://github.com/onixus/Rust-trustvpn/pull/106), [#108](https://github.com/onixus/Rust-trustvpn/pull/108) | Состав macOS release, lab/paused-clock test fixes, финальная версия 0.6.2 | Test-only исправления #105/#106 не являются изменением production Stop. |

Desktop full-mode теперь имеет service DNS/guard/transport producers; route и
connectivity без отдельного producer остаются Unknown. В split DNS/guard
Unsupported. iOS continuous snapshot по-прежнему не доказывает route/DNS/guard.
Android VPN-bound UI checks доступны с Android 12; route — решение таблицы
Android, guard — настройка Always-on/lockdown, не packet-level attestation.

## Приёмка и открытые задачи

[Финальный отчёт #99](https://github.com/onixus/Rust-trustvpn/issues/99#issuecomment-6291062141)
описывает одинаковый установленный пакет из main `da92864` на двух Mac:
reconnect за 3–4 с, TCP-ответы в пределах 30 с без ручного Stop/Start;
на одном Mac HTTPS 200 за 0,16 с. #99 закрыта. Этот результат относится к
`da92864`, а не к более поздним опубликованным пакетам `4123160`.

| Открытое issue | Текущее состояние | Следующий gate |
| --- | --- | --- |
| [#30](https://github.com/onixus/Rust-trustvpn/issues/30) | Вертикаль реализована частями; #31/#35 закрыты | Координатор: exact-package приёмка и пилот с добровольными локальными метриками. |
| [#32](https://github.com/onixus/Rust-trustvpn/issues/32) | Shared route evaluator и runtime Linux lab (#88) | Routing/test owner: остальные ОС, CNAME/CDN/DoH, реальные split/full IPv4/IPv6 paths. |
| [#33](https://github.com/onixus/Rust-trustvpn/issues/33) | App system-path diagnostics, verdict/actions и service probes реализованы | Platform labs: installed endpoint/control failures, cancellation и сопоставление diagnostics с traffic evidence. |
| [#34](https://github.com/onixus/Rust-trustvpn/issues/34) | Desktop backup recovery; Linux packet captures (#87) | Platform labs: физические DNS/IPv4/IPv6 captures переходов на точных пакетах; Always-on backups только Linux/Windows. |
| [#36](https://github.com/onixus/Rust-trustvpn/issues/36) | Provenance/acceptance tooling и assets v0.6.2 существуют | Publisher/labs: подписи, install/update/rollback, recovery и soak ≥24 ч. [Матрица](package-acceptance.md). |
| [#62](https://github.com/onixus/Rust-trustvpn/issues/62) | #69/#103 расширили liveness; #99 закрыта с installed wake evidence | macOS/network lab: более широкие roam/failure cases и точные release packages; серверная диагностика — onixus/tunnel. |
| [#70](https://github.com/onixus/Rust-trustvpn/issues/70) | #80 устранил синхронный Stop; #94 добавил timings. В whole-computer режиме записаны Stop 0,3–0,5 с и reconnect около 3 с | macOS lab: split с SHA/hash/числом маршрутов, Stop ≤3 с, Status во время Stop, reconnect до TLS ≤5 с, точное восстановление своего OS state и сохранность чужого. |
| [#81](https://github.com/onixus/Rust-trustvpn/issues/81) | System probes и BPF proof реализованы (#84/#91/#96) | Labs: installed Linux/Windows, другие macOS interfaces/drivers, negative guard и stale/cancel cases. |
| [#90](https://github.com/onixus/Rust-trustvpn/issues/90) | Viewed admission реализован в #102, IPC v7 | Labs: installed visibility/cancellation/timing matrix Linux/macOS/Windows; issue остаётся открытым в GitHub. |
| [#107](https://github.com/onixus/Rust-trustvpn/issues/107) | Неудачный первичный Start не записывается; macOS events.log ограничен 256 КиБ и очищается при переполнении | Developer/DevSecOps: bounded redacted failed-connect journal с ротацией и хранением ≤7 дней/15 МБ; это требование, ещё не реализация. |

Закрытые #71/#75/#76 не перечисляются как неисправленные. Открытый macOS
widget PR #42 не входит в main/v0.6.2: desktop widget описан в PR, Control
Center toggle имеет известный незавершённый executor path.

Серверные credentials/enforcement принадлежат [onixus/tunnel](https://github.com/onixus/tunnel).
Клиентский merge или Connected transport не закрывает серверные зависимости
и обязательные network/package gates.

## Результат сверки

- **PASS:** статическая сверка исходников/диффов и актуальных GitHub состояний
  PR, issue, release assets. Существующие результаты привязаны к своим SHA.
- **FAIL:** обнаруженные устаревшие версии и утверждения о неисправленных
  #70/#75/#76, отсутствии service producers и Linux captures исправлены.
- **NOT RUN:** новые runtime/CI/device/network/signing/latest/soak проверки;
  результаты Jenkins и phone test binaries из #109 отдельно приведены в
  [release record](releases/v0.6.2.md#acceptance-status) как перенесённые отчёты.
- **BLOCKED:** полная приёмка опубликованных пакетов без недостающего evidence.

Эта актуализация не меняет состояния issue, не выполняет merge или release.
