# Состояние проекта и issue — 23 ноября 2026

[v0.7.1](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.1)
(`55bc488`) опубликован 23 ноября 2026: workspace **0.7.1** / sequence **14**.
Jenkins этого SHA: native #109, linux #46, android #12, все SUCCESS.
Приёмка установленных пакетов не проводилась. Android TV по-прежнему отдельный
pre-release `v0.7.1-tv.3`. Подписанный канал `latest` не продвигался.

Основание: GitHub `origin/main` `04f0f85729110f5b06c214ff9d5c263f25163146`
(merge [#132](https://github.com/onixus/Rust-trustvpn/pull/132), 23 ноября
01:27 +03), тег [v0.7.0](releases/v0.7.0.md) (`232fd7b`, 28 октября),
pre-release [v0.7.1-tv.3](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.1-tv.3)
и открытые issue/PR на момент сверки. Эта сверка не запускает runtime, CI,
installed-package, packet capture, signing или soak заново.

## Исходники и опубликованные пакеты

На этой ветке workspace в `Cargo.toml` — **0.7.1**, desktop update sequence
**14**, control IPC **v7**. Телефонный Android в исходниках — versionName
**0.7.1** / versionCode **70005** (`org.rtrusttunnel.android`). Отдельный пакет
Android TV собирается только с `-PrtrustTv`: `org.rtrusttunnel.android.tv`,
versionName **0.7.1-tv.3** / versionCode **70004**, ABI `armeabi-v7a` и
`arm64-v8a`; из этого тега его под старым именем не переиздают. iOS в
workspace — 0.7.1 / 70005; отдельных iOS assets после v0.5.0 нет.

Опубликованный Latest — [v0.7.0](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.0)
(28 октября 2026, GitHub 22:37 UTC): Windows installer, macOS UI Choices DMG,
Linux Native/WebView/Both Flatpak и `rtrust-host-0.7.0-6`, Android APK,
SHA256SUMS и source identity/manifest. Android TV опубликован отдельно как
pre-release `v0.7.1-tv.3` (22 ноября 2026). Наличие assets сверено через
GitHub Releases API; их подписи, содержимое, source binding и update-channel
`latest` в этой сверке — **NOT RUN**.

Коммиты `v0.7.0..04f0f85` (44) **не входят** в опубликованный v0.7.0. Скачанный
релиз 0.7.0 их не содержит.

## Что вошло в main после v0.7.0

| PR | Что в main | Граница доказательств |
| --- | --- | --- |
| [#119](https://github.com/onixus/Rust-trustvpn/pull/119), [#120](https://github.com/onixus/Rust-trustvpn/pull/120) | Уточнение приёмки #113; скриншоты 0.7.0 и структура README | Документация. Не новая приёмка пакетов. |
| [#121](https://github.com/onixus/Rust-trustvpn/pull/121) | Linux Flatpak: Route и Connectivity через netlink, без `ip` внутри sandbox | Исправление на установленном Flatpak 0.7.0 (Fedora 43 KDE) описано в PR. Повтор на `04f0f85` — NOT RUN. |
| [#122](https://github.com/onixus/Rust-trustvpn/pull/122) | Простой dataplane Windows/Android не опрашивает TCP-стек каждые 5 мс; индекс Wintun читается один раз до маршрутов | Unit-тесты в PR. Installed idle/reconnect — NOT RUN. |
| [#124](https://github.com/onixus/Rust-trustvpn/pull/124), [#125](https://github.com/onixus/Rust-trustvpn/pull/125), [#128](https://github.com/onixus/Rust-trustvpn/pull/128) | Ротация журнала по `level`; handshake 10 с вместо 4 с; причина остановки транспорта на Windows; последние 10 эпизодов reconnect (`keep=reconnect`) | См. [журнал](diagnostics-journal.md). Installed journal на опубликованном 0.7.0 этой политики не имеет. |
| [#127](https://github.com/onixus/Rust-trustvpn/pull/127) | Сохранённый конфиг портала подключается без живого портала; ещё действующий токен продлевается не чаще раза в сутки. Истёкший токен не отправляется | Поведение клиентов после merge. Device acceptance — NOT RUN. |
| [#129](https://github.com/onixus/Rust-trustvpn/pull/129) | Режим «весь компьютер» может локально отбрасывать IPv6, даже если профиль умеет его релеить. Старая служба без capability не подключается молча | Unit-тесты в PR. Installed full-tunnel IPv6 block — NOT RUN. |
| [#130](https://github.com/onixus/Rust-trustvpn/pull/130), [#132](https://github.com/onixus/Rust-trustvpn/pull/132) | Отдельный Android TV пакет и баннер 320×180 на leanback, в том числе у телефонного APK | TV APK `v0.7.1-tv.3` опубликован. Установка баннера на ТВ и неизменность телефонного лаунчера — NOT RUN (чеклист PR). |
| [#131](https://github.com/onixus/Rust-trustvpn/pull/131) | Проверка GitHub Releases из Native, WebView, TUI, Android и iOS. Скачивание сверяется с `SHA256SUMS` и не ставит пакет само. iOS только открывает страницу релиза | Подписанный канал Ed25519 не заменяется. См. [secure updates](secure-updates.md). Android/iOS сборки в PR не запускались. |

Открытый PR: [#126](https://github.com/onixus/Rust-trustvpn/pull/126) — замена
Wintun на пакет адаптера Rttun. В main не входит; документация по-прежнему
описывает Wintun.

## Приёмка и открытые задачи

[v0.7.0](releases/v0.7.0.md) опубликован. Его installed-package gates остаются
**NOT RUN**, как в записи релиза: подписи, update/rollback этого пакета, VLESS
через настоящий CDN, soak. Результат macOS sleep/wake из #99 относится к пакету
`da92864`, не к `232fd7b` и не к `04f0f85`.

| Открытое issue | Текущее состояние | Следующий gate |
| --- | --- | --- |
| [#30](https://github.com/onixus/Rust-trustvpn/issues/30) | Вертикаль реализована частями; #31/#35 закрыты | Координатор: exact-package приёмка и пилот с добровольными локальными метриками. |
| [#32](https://github.com/onixus/Rust-trustvpn/issues/32) | Shared route evaluator и runtime Linux lab (#88) | Routing/test owner: остальные ОС, CNAME/CDN/DoH, реальные split/full IPv4/IPv6 paths. |
| [#33](https://github.com/onixus/Rust-trustvpn/issues/33) | App system-path diagnostics, verdict/actions и service probes реализованы. Linux Flatpak Route/Connectivity заполняются с #121 | Platform labs: installed endpoint/control failures, cancellation и сопоставление diagnostics с traffic evidence. |
| [#34](https://github.com/onixus/Rust-trustvpn/issues/34) | Desktop backup recovery; Linux packet captures (#87) | Platform labs: физические DNS/IPv4/IPv6 captures переходов на точных пакетах; Always-on backups только Linux/Windows. |
| [#36](https://github.com/onixus/Rust-trustvpn/issues/36) | Provenance/acceptance tooling и assets v0.7.0 существуют | Publisher/labs: подписи, install/update/rollback, recovery и soak ≥24 ч. [Матрица](package-acceptance.md). |
| [#62](https://github.com/onixus/Rust-trustvpn/issues/62) | #69/#103 расширили liveness; #99 закрыта с installed wake evidence для `da92864`. Handshake budget увеличен в #125 | macOS/network lab: более широкие roam/failure cases и точные release packages; серверная диагностика — onixus/tunnel. |
| [#81](https://github.com/onixus/Rust-trustvpn/issues/81) | System probes, BPF proof и Windows WFP drop proof (#116) реализованы | Labs: installed Linux/Windows на точном пакете, другие macOS interfaces/drivers, negative guard и stale/cancel cases. |
| [#110](https://github.com/onixus/Rust-trustvpn/issues/110) | Унификация дизайна по APEX Design System | Дизайн: не начато в main после v0.7.0. |
| [#111](https://github.com/onixus/Rust-trustvpn/issues/111) | VLESS WebSocket+TLS в клиенте (#112); follow-ups (XHTTP, `fp`, CDN acceptance) открыты | Labs: installed VLESS через настоящий CDN. |

Закрытые с прошлой сверки и больше не числящиеся открытыми: #70, #90, #107.
Журнал #107 реализован в v0.7.0 и сужен по уровням в #124/#128; это не
installed acceptance журнала на каждом пакете.

Серверные credentials/enforcement принадлежат [onixus/tunnel](https://github.com/onixus/tunnel).
Клиентский merge или Connected transport не закрывает серверные зависимости
и обязательные network/package gates.

## Результат сверки

- **PASS:** статическая сверка `origin/main` `04f0f85`, тега v0.7.0, списка
  релизов, открытых issue и merged PR #119–#132. Версии сверены с
  `Cargo.toml`, `CURRENT_SEQUENCE` и `apps/android/app/build.gradle`.
- **FAIL:** устаревшие утверждения сверки от 21 октября (workspace 0.6.2,
  открытые #70/#90/#107, «#109 ещё не merged») заменены этим документом.
- **NOT RUN:** новые runtime/CI/device/network/signing/latest/soak проверки.
- **BLOCKED:** полная приёмка опубликованных пакетов v0.7.0 и TV pre-release
  без недостающего evidence.

Эта актуализация не меняет состояния issue, не выполняет merge или release.
