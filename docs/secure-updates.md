# Signed desktop updates

Windows Settings exposes explicit check, download and install actions. Packages
use an Ed25519 envelope pinned in the application, a monotonically increasing
release sequence, target and IPC bounds, expiry, exact size and SHA-256. HTTPS
fetches are restricted to the deployment origin and release path; redirects are
not followed. Authenticode is separate and is not claimed by this implementation.
The offline signing key is excluded from CI snapshots and stays on the publisher's
machine. Losing that key requires a separately trusted bootstrap installer.

Before install, the client downloads both the new package and the signed package
for its exact current sequence. An expired historical rollback envelope is usable
only for that exact sequence. The helper locks verified package files against
replacement, waits for the GUI to exit, acquires an idle-service maintenance lease
and saves the encrypted profile vault. UAC elevates only the verified installer.
The service refuses maintenance while a tunnel or retained network guard exists.
Older services without the maintenance command require one ordinary bootstrap
installation; unsupported IPC never bypasses the check.

After Setup, the helper launches the installed GUI smoke mode. A failed health
check installs and checks the previous signed package. If the replacement service
is unavailable, active, or retains a guard, automatic rollback stops safely;
the replacement service admits the previous IPC version only for capability
negotiation and the maintenance reservation, and the IPC versions of published
older helpers listed in `RELEASED_UPDATER_VERSIONS` only for the reservation,
answered in that version's wire shape, so an IPC bump alone does not stop the
old helper's rollback;
packages, encrypted backup and logs remain in the transaction directory. The
helper does not clear a network guard or overwrite the user's vault. A successful
update restarts the GUI; after rollback the user can restart the previous version.
No downgrade migration is promised for arbitrary old vault formats.

`prepare-signed-release.py` accepts only artifacts from a completed successful
Jenkins build whose pinned root matches the local root. `publish-signed-release.py`
publishes immutable version directories. Promoting `latest.json` is a separate
explicit step after maintenance validation. Private keys are never published.

`ci/windows_signed_update_e2e.py` runs only with explicit existing-installation
maintenance authorization. It executes a preserved old-version test runner against
real signed new/old installers: upgrade, injected failed health check, rollback,
launch check, then successful upgrade. `maintenance_fixture` preserves existing
profiles or temporarily populates an empty vault and checks encrypted bytes and
OS-keyring decryption afterward. Ordinary CI does not run this invasive test.

macOS system-service installation and Flatpak updates are delivered in their
platform stages; the Windows installer helper is not used on those platforms.

## Verified Windows maintenance, 2026-09-30

Completed Jenkins #36 (0.2.0, sequence 2) and #37 (0.2.1, sequence 3): full
unit/Clippy, native smoke, keyring, Linux network E2E, Gitleaks and Trivy gates.
Installed-client maintenance was run separately on the authorized Windows host.
The preserved sequence-2 test runner passed the actual 2→3→2 rollback→3 cycle
in 16.87 seconds. The encrypted fixture remained byte-identical and decryptable;
the original empty user vault was restored afterward. Installed GUI, updater and
SCM service hashes match build #37, service ownership is unchanged, and autostart
remains disabled. Temporary scheduled tasks were removed.

The surrounding PowerShell wrapper initially reported failure because a null
startup value produced no snapshot file. The actual Rust E2E and vault-retention
checks had passed. A separate final verification confirmed absence of the startup
entry and all installed hashes; the original failed wrapper log was retained.
This was a harness bookkeeping defect, not a rollback success inferred from logs.

Installer SHA-256 for build #37:
`b344a751bb93c231d0a8126cb1064ee711d188692357f7491f5483763a0a1d1e`.
Maintenance used a temporary interactive elevated task; production UAC prompting
was not automated. Ordinary CI continues to skip the invasive Windows installer,
Wintun and whole-host WFP tests unless explicitly enabled.

## Withheld candidate

Sequence 4 (0.3.0, build #46) has immutable versioned artifacts but is **not**
promoted to latest: its authorized Windows always-on SCM restart runtime failed.
Do not use it for delivery. At rejection, latest remained sequence 3. The replacement sequence 6 below
passed runtime and real signed upgrade/rollback verification before promotion.

## Delivered sequence 6

Build #53 completed SUCCESS. Version 0.3.2 / sequence 6 passed authorized
Windows full-tunnel/always-on runtime and genuine signed 3→6 upgrade with an
injected failed health check, verified rollback to 3, and successful retry to 6.
The transaction took 16.98 seconds; encrypted vault retention/decryption, original
empty-vault restoration, autostart, LocalSystem/desktop SID and installed hashes
were verified. Setup was delivered to the Windows user's Downloads directory.

Setup SHA-256: `31202330accd7dc2b34ea0dfbb38964a99ae8acd092007ceaf5f9591703a53c2`.
Sequence 4 was withheld from latest; sequence 5 was prepared locally but not published.

## Delivered sequence 7

Native build #93 completed SUCCESS. Version 0.4.0 / sequence 7 passed the genuine
signed 6→7 upgrade on the authorized Windows host on 2026-10-03 with a sequence-6
test runner: injected failed health check, verified rollback to 6 and successful
retry to 7 in 16.49 seconds. The existing encrypted vault (real profiles, not a
synthetic one) stayed byte-identical and decryptable, autostart was unchanged,
the service runs as LocalSystem, and the installed GUI, updater, service and
wintun.dll hashes match build #93. Sequence 7 was then promoted to latest for
`windows-x86_64`. Afterwards the authorized Windows full-tunnel run passed once
with TrustTunnel and once with AmneziaWG on the service binary of build #93.

Setup SHA-256: `938a957a97e6a244162367a7d8759f7763f07432ec07f507f9d7eda5d2a65e28`.
The `macos-aarch64` manifest of sequence 7 is published under its versioned path
but not promoted; no macOS latest manifest exists yet.

## Delivered sequence 9 — v0.5.0 desktop rebuild

The October 6, 2026 desktop rebuild fixes the 0.5.0 update identity defect. The
original desktop package identified itself as sequence 7, which could repeatedly
offer 0.5.0 and select the 0.4.0 rollback package. Rebuild
`v0.5.0-rebuild.9` identifies as sequence **9** and release signing refuses a
manifest whose version or sequence differs from the archived compiled source.

Real Windows maintenance passed the signed **7 → 9** update, an injected failed
health check, verified rollback to 7 and a successful retry to 9. The encrypted
profile vault remained unchanged and decryptable, installed GUI/service hashes
matched the rebuilt artifacts, and the installed updater rejects sequence 9 as
already current.

The published Windows sequence-9 Setup is 14610519 bytes, SHA-256
`dcb5ee4eb2eac4a3ef7d3c0cebb8209f7a600a0664d0724a57e308e7919b50e8`.

Windows latest is sequence 9. macOS automatic-update promotion remains withheld.
The rebuild release is:
https://github.com/onixus/Rust-trustvpn/releases/tag/v0.5.0-rebuild.9

## Candidate sequence 10 — v0.6.0 (not published)

The source tree compiles as version **0.6.0**, `CURRENT_SEQUENCE = 10`;
`CURRENT_IPC` stays 1. `prepare-signed-release.py` refuses any other sequence for
this source and runs the signing tool with `--offline --locked`. No sequence-10
artifact, signed manifest or rollback envelope has been built or published, and
no target's `latest` points at sequence 10. See [v0.6.0](releases/v0.6.0.md).

Rollback 10 → 9: the installed sequence-9 helper from v0.5.0-rebuild.9 speaks
control IPC **v1**, two or more steps behind the 0.6.0 service (v6), so the
one-step `VERSION - 1` exception alone would refuse its `PrepareUpdate` after a
failed health check. `rtrust_control::RELEASED_UPDATER_VERSIONS = [1]` admits
exactly `PrepareUpdate` from that published helper (v1 has no `Capabilities`),
and the Windows service answers it in the v1 `Response` shape
(`version`/`state`/`message`), which the v1 helper parses with
`deny_unknown_fields`. Every other v1 command still gets an IPC version
mismatch; pipe authentication is unchanged, and a retained guard or active
session still refuses the reservation. Linux and macOS keep strict equality.
Unit tests pin the v1 request JSON and the v1-readable reply. On 2026-10-13 a
lab-signed rehearsal on the Windows lab passed: the published sequence-9 package
and updater installed the 0.6.0 candidate Setup (exact source `974debf`), an
injected health failure made the v1 updater reserve the v6 service and roll
back to 9, and the retry to 10 succeeded with the encrypted vault unchanged.
The manifests used a throwaway lab key, so the production-key sequence-10
metadata is still NOT RUN and is required, with the acceptance matrix, before
Windows `latest` may move to sequence 10. macOS remains withheld.

## Версия IPC и gate приёмки (issues #31/#36)

`CURRENT_IPC = 1` — совместимость транзакции обновления в исторических полях
`min_ipc`/`max_ipc` подписанного манифеста. Она независима от версии IPC GUI/службы:
установщик заменяет оба компонента согласованным комплектом. Строгая проверка
`rtrust_control::VERSION` в службе сохраняется. Подготовка релиза проверяет хеши
архивированных исходников и берёт границы совместимости из скомпилированного
updater. Старый updater принимает новый пакет с границами 1..1; исторический
подписанный пакет установленной версии остаётся доступен для отката.

Перед первым SSH publisher проверяет Ed25519 по закреплённому корню тем же Rust
верификатором, что клиент: схему, платформу, совместимость, срок действия, точный
номер релиза, канонический versioned URL, размер и SHA256 установщика. Загрузка
использует приватную копию проверенных файлов. Gate приёмки сопоставляет версию
и `update_manifest_sha256` с проверенным подписанным envelope; каждый отчёт для
пакета с обновлениями тоже содержит этот хеш. После изменения или повторного
подписания манифеста прежние отчёты не разрешают продвижение latest.

`python3 scripts/release-acceptance.py MATRIX.json` проверяет матрицу,
сохраняя различие passed/failed/not_run/unsupported.
`--production` требует passed для каждого заявленного protocol/mode/Always-on
и каждой обязательной проверки. `publish-signed-release.py --promote` требует
`--acceptance MATRIX.json` и проверяет точный SHA256 устанавливаемого пакета
**до первого обращения к серверу**. Preview не проходит этот gate. Это
не заменяет отдельного решения о публикации и не авторизует публикацию.

Матрица schema 1 содержит массив `packages`. Запись пакета имеет полный
40-символьный `commit`, `version`, `target`, `os`, `device`, `artifact` и
`artifact_sha256`, `source_manifest` и `source_manifest_sha256`, а для targets
с update_metadata — `update_manifest` и `update_manifest_sha256`; boolean
`preview`, массив `claims` и массив `checks`. Пути файлов разрешаются относительно
матрицы. Claim содержит `protocol` (trusttunnel/http3/hysteria2/amneziawg),
`mode` (split/full/proxy) и boolean `always_on`. Нельзя переносить результат
обычного подключения на Always-on или с одного протокола на другой.

Каждый check содержит `scenario`, те же protocol/mode/always_on и `status`.
Список обязательных сценариев находится в `SCENARIOS` проверяющего скрипта:
установка/права/удаление, update/rollback/vault, загрузка/сон/смена сети, аварии,
outage, DNS/HTTPS/egress, отсутствие прямых утечек, восстановление своего
состояния, бюджет и soak. Для непроверенных/неподдерживаемых/проваленных
проверок обязательны `owner` и `dependency`; они не проходят production gate.

Passed содержит `evidence: {"path": "report.json", "sha256": "..."}`.
JSON-отчёт повторяет все поля идентичности пакета, scenario/protocol/mode/always_on,
status и непустой `recorded_at`. Хэш отчёта проверяется; отчёт другого commit,
пакета, ОС или устройства отклоняется. Для recovery_budget/soak нужны
`metrics.limits` и `metrics.measured`: именованные конечные неотрицательные
числа, измерения не превышают заранее определённые верхние пределы. Само
время soak и минимально нужная длительность описываются в исходном отчёте.

Подписи проверяются отдельными scenarios с protocol/mode/always_on=null:
Windows — authenticode/update_metadata; macOS — developer_id/notarization/
update_metadata; Linux — repository_signature/update_metadata; Android —
apk_signature; iOS — apple_distribution. Подпись обновления не доказывает
подпись издателя. Этот скрипт проверяет привязку и полноту записанных evidence,
а не самостоятельно подтверждает истинность сетевых измерений или подписи.
Синтетические fixtures в `ci/test_release_acceptance.py` проверяют отказ gate
и не считаются приёмкой реального пакета.
