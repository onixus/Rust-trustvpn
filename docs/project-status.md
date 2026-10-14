# Состояние проекта и issue — 14 октября 2026

Сверка: GitHub main `e10cb99d537d6ff9c0e4e69914e286d256a3ff55`.
Это документационная актуализация; новый runtime, installed-package,
packet-capture, signing или soak прогон не выполнялся.

## Исходники и опубликованные пакеты

Workspace 0.6.1, desktop sequence 11, Android 60101 / 0.6.1-preview.1,
iOS 0.6.1 / 60101. [v0.6.1](releases/v0.6.1.md) опубликован 13 октября
из `db8796a89e4bef11c524b514557e0db60d4057ec` (annotated tag).
GitHub assets содержат Android APK, Windows installer, macOS DMG/PKG,
SHA256SUMS и native source identity/manifest. Linux assets остаются в
v0.5.0-rebuild.9, iOS — в v0.5.0. Подписи, содержимое артефактов, binding
source manifest и update-channel latest в этой сверке — **NOT RUN**.

После тега в main вошли:

| PR | Реализация | Границы проверки |
| --- | --- | --- |
| [#69](https://github.com/onixus/Rust-trustvpn/pull/69), head `3511dca` | H3 data-plane liveness, guarded degraded reconnect, Android retry refund после доказанной доставки | GitHub CI Linux/macOS/Windows PASS на PR. Installed macOS sleep/roam NOT RUN; CONNECT 5xx вне heuristic. |
| [#72](https://github.com/onixus/Rust-trustvpn/pull/72), head `fed62a2` | Linux TUI поверх общего desktop Controller | PR описывает unit и disposable-container SOCKS/HTTP evidence. Installed TUI TUN/full, guard и DNS/IPv6 capture NOT RUN. [Объём](tui.md). |
| [#73](https://github.com/onixus/Rust-trustvpn/pull/73), head `a3a3ffe` | Android UI вариант 3, VPN-bound route/DNS/HTTPS checks, темы и foldable layout | GitHub CI Linux/macOS/Windows PASS на PR. В PR описаны точечные physical-device UI observations; это не полная приёмка пакета/lockdown/leaks. Финальный Jenkins gate здесь не перепроверен. |
| [#74](https://github.com/onixus/Rust-trustvpn/pull/74), head `1100820` | Native/WebView/iOS UI вариант 3 | GitHub CI Linux/macOS/Windows PASS на PR. В body checkbox desktop installed acceptance противоречит фразе «не запускалась»: PASS не установлен. Physical iPhone acceptance NOT RUN. |

CI merged PR относится к проверенным PR heads, а не к новому документационному
commit или опубликованному пакету. Текущий desktop/iOS continuous snapshot
имеет только transport producer: route/DNS/guard/connectivity без результатов
не дают зелёный статус. Android UI checks через собственную VPN network доступны
с Android 12; route — решение таблицы Android, не packet-level attestation.
Отдельная system-path диагностика desktop не заменяет continuous producers.

## Открытые задачи и следующий gate

| Issue | Подтверждённое состояние | Следующий шаг / владелец |
| --- | --- | --- |
| [#30](https://github.com/onixus/Rust-trustvpn/issues/30) | Первая вертикаль реализована частями; #31/#35 и server #22 закрыты в GitHub. #32/#33/#34/#36 открыты. | Координатор: exact-package приёмка вертикали и пилот с локальными/добровольными метриками. |
| [#32](https://github.com/onixus/Rust-trustvpn/issues/32) | Shared route decisions/explain, DNS provenance и observed flow decisions существуют. | Routing/test owner: матрица ОС, split/full, IPv4/IPv6, CNAME/CDN/DoH, policy revision и сопоставление объяснения с реальным dataplane. |
| [#33](https://github.com/onixus/Rust-trustvpn/issues/33) | Desktop system-path DNS/route/interface-bound HTTPS, verdict/actions и recheck существуют; Android UI получил отдельные VPN-bound checks. | Diagnostics/platform owners: installed split/full/IPv6, отказ endpoint/control, stale/cancellation и проверка редактированного отчёта. |
| [#34](https://github.com/onixus/Rust-trustvpn/issues/34) | Opt-in desktop backup recovery; Always-on backups только Linux/Windows. Android #63 reconnect текущего профиля не равен backup failover. | Platform/test owners: packet-level отсутствие запрещённого direct DNS/IPv4/IPv6 при переходах, budgets и cancellation на точных пакетах; учитывать #62/#70/#75. |
| [#36](https://github.com/onixus/Rust-trustvpn/issues/36) | Provenance/signature/acceptance tooling и release assets существуют. | Publisher + platform labs: точные hashes/commit/device, подписи, install/update/rollback, recovery и soak ≥24 ч. [Матрица](package-acceptance.md). |
| [#62](https://github.com/onixus/Rust-trustvpn/issues/62) | #69 добавил heuristic liveness; Lost после первого `_check` сохраняется для endpoint 1.1.0. | macOS lab: воспроизвести sleep/roam и автоматическое восстановление на установленном пакете. Server причина: [tunnel#30](https://github.com/onixus/tunnel/issues/30); slow Stop: #70. |
| [#70](https://github.com/onixus/Rust-trustvpn/issues/70) | Stop ещё синхронно вызывает release; повторное измерение 23 с не выполнено. | macOS owner/lab: Stop ≤3 с, responsive Status, reconnect до TLS ≤5 с, точное восстановление своего OS state при записанном числе маршрутов. |
| [#71](https://github.com/onixus/Rust-trustvpn/issues/71) | Windows E2E всё ещё ждёт фиксированные 2 с перед Recover. | Windows test owner: bounded lease-busy retry и 5 повторов с сохранением guard до явного Recover. |
| [#75](https://github.com/onixus/Rust-trustvpn/issues/75) | Android active/stopping early return и stopSelf без startId остаются. Ожидание cleanup в тесте не исправляет продукт. | Android owner: сохранить/явно отклонить новый start, быстрые toggles, lockdown, TUN/callback lifecycle. |
| [#76](https://github.com/onixus/Rust-trustvpn/issues/76) | ci/tools.py проверяет archive SHA-256, но не извлечённый executable. | CI owner: corruption/re-extraction regression, bounded retries, сохранённая pinned archive verification. VirtioFS инцидент здесь не воспроизводился. |

Серверные credentials/enforcement принадлежат
[onixus/tunnel](https://github.com/onixus/tunnel).
Закрытый [tunnel#22](https://github.com/onixus/tunnel/issues/22) не заменяет
приёмку нового клиентского пакета. Merge, release publication и Connected
transport не закрывают обязательные installed/network gates.

## Результат этой сверки

- **PASS:** GitHub состояния issue/PR/tag/assets, статическая сверка затронутых
  implementation paths; независимые architect/DevSecOps проверки документации.
- **FAIL:** в исходной документации найдены устаревшие release/download claims;
  они исправляются этой актуализацией.
- **NOT RUN:** новые runtime/CI/device/network/signing/latest/soak проверки.
- **BLOCKED:** закрытие acceptance criteria без соответствующего evidence;
  доступность устройств и signing credentials заново не инвентаризировалась.

Issue остаются открытыми; чужие изменения основного checkout не включены.
