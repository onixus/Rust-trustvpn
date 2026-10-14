# Exact-package acceptance (issue #36)

An installed package is accepted only for its tested source commit, artifact
SHA-256/version, OS/device, protocol and operating mode. Existing Linux,
Windows, Android and macOS results are historical evidence for their own
candidates. A successful compilation, simulator build or connected transport
does not supply the installed-package gate for a new candidate.

## Local evidence ledger

`scripts/acceptance-matrix.py` creates a local JSON ledger and validates its
identity/evidence hashes. It never installs a package, signs/publishes a release,
changes networking, reads a vault or uploads a report. This is a **manual evidence
ledger**, not a VPN test runner. A reviewer must confirm the declared commit was
actually compiled from the CI checkout/build source manifest, each artifact was
tested on the declared device, and each evidence file establishes the claimed
result. Hashes do not certify source provenance or the truth of log contents.

Create one ledger per exact package set and device/OS. Include every delivered
component (installer, service/UI pair, APK or IPA as applicable) as an artifact;
never substitute a preview ZIP for the installed package. Select every promoted
protocol and mode, including selected/full and their Always-on variants where
applicable. Use a stable lab device identifier, not a personal device serial.

Before the first test, set recovery and resource budgets against a recorded
baseline on the same lab. The tool enforces finite positive budgets and at least
24 hours of soak, but a human must check measurements against those budgets.
There is no invented universal performance/battery threshold. On a desktop
without a battery, record that resource subcheck's limitation in evidence; any
waiver needs an explicit narrower reviewed acceptance scope.

Example (budget environment variables must be supplied from the reviewed plan):

```sh
python3 scripts/acceptance-matrix.py init \
  --output /private/tmp/candidate-acceptance.json \
  --commit "$CANDIDATE_COMMIT" --version "$CANDIDATE_VERSION" \
  --platform macos-aarch64 --device lab-mac-01 --os-version "$TEST_OS" \
  --owner release-maintainer --artifact "$EXACT_INSTALLER" \
  --protocol h2 --protocol h3 --mode selected --mode full \
  --recovery-seconds "$RECOVERY_BUDGET" --soak-hours 24 \
  --max-rss-mib "$RSS_BUDGET" --max-cpu-percent "$CPU_BUDGET" \
  --max-battery-percent-hour "$BATTERY_BUDGET"

python3 scripts/acceptance-matrix.py record \
  --ledger /private/tmp/candidate-acceptance.json --commit "$CANDIDATE_COMMIT" \
  --case h2/full/endpoint_outage --status passed --owner lab-operator \
  --reason 'Observed guard retention and recovery within predeclared budget' \
  --evidence /private/tmp/reviewed-redacted-outage.json

python3 scripts/acceptance-matrix.py verify \
  --ledger /private/tmp/candidate-acceptance.json --commit "$CANDIDATE_COMMIT" \
  --require-passed
```

Each cell starts `not_run`. `passed` and `failed` require a timestamp and hashed
local evidence. `unsupported` requires an owner and reason and remains distinct
from a pass. `verify` checks all expected cells, artifact and evidence hashes;
`--require-passed` exits 1 for any failed/not-run/unsupported cell and 2 for
invalid identity/evidence. Without that flag it validates an incomplete ledger
for inventory. Even an all-passed ledger outputs
`release_promotion_authorized=false`: promotion remains a separate decision.

Keep artifacts/evidence at their recorded absolute paths until review. Inspect
and redact evidence **before** recording it; logs and captures can contain
credentials, DNS names or visited addresses. The tool stores paths, hashes,
owners and user-written reasons without automatic redaction. Keep local ledgers
in ignored `reports/` or outside Git; publish only a deliberately reviewed,
redacted summary. Rehashing changed evidence means recording a new reviewed
result, not treating altered logs as the original proof.

Regression checks: `python3 scripts/test-acceptance-matrix.py`. These use
explicitly synthetic files and prove ledger rejection behavior, not VPN or
package acceptance.

## Required scenarios and evidence

| Cells | Required evidence |
| --- | --- |
| `build_provenance` | Completed exact-source CI/build checkout log, archived source manifest and artifact receipt; reviewer correlates full commit, compiled tree and package hashes |
| `clean_install`, `permissions_service` | Fresh OS/user install, requested permission dialogs, authenticated service/UI channel, vault accessible only as intended |
| `publisher_signature` | Platform publisher verification: Apple Developer ID **and** notarization, Windows Authenticode, Android signing identity/upgrade continuity, iOS provisioning/distribution identity, or Linux package/repository signature as applicable |
| `signed_update_metadata` | Separate update-root metadata verification, expiry/sequence/target/hash checks and rejection of tampered/replayed metadata; this does not replace OS publisher signing |
| `update_vault_guard`, `rollback_vault_guard` | Genuine previous signed package → candidate and rollback, vault/profile preservation, UI/service IPC compatibility, guard retained during maintenance/failure |
| `uninstall_restore`, `stop_owned_state_restore` | Snapshot before/after routes/DNS/firewall, unrelated rules unchanged, removal of only app-owned state |
| `dns_failure`, `ipv4_ipv6_dns_https` | Real resolver/kernel-route and traffic corroboration through installed system path, split/full and IPv4/IPv6; distinguish unsupported from missing test |
| `cold_boot`, `sleep_wake`, `network_handoff` | Physical-device event timestamps, stale observation invalidation before refreshed results, service/guard ownership through transition |
| `gui_crash`, `service_crash`, `endpoint_outage`, `forbidden_egress` | Independent capture/OS firewall evidence of forbidden direct traffic absence, expected endpoint allowances, fail-closed recovery without weakening policy |
| `recovery_timing` | Event → first verified system DNS/HTTPS availability, sample count, retries, p50/p95/max against predeclared budget |
| `soak_resources_battery` | At least 24 h, repeat counts, bounded RAM/CPU, battery drain where applicable, baseline and candidate on same device/network |

The network/resource cells are generated separately for every declared
protocol × mode. Identifiers are unique lowercase letters/digits/underscore/hyphen,
with no slash. Use `ordinary`/`always_on` on mobile, and selected/full variants
on desktop; names are explicit scope labels and do not enable an unsupported
runtime mode. A partial platform acceptance can be documented, but this strict
ledger must not be used to promote an unsupported combination as fully accepted.

Reuse existing runners rather than treating the ledger as another infrastructure
stack: `ci/linux_system_e2e.py`, `ci/linux_host_package_e2e.py`,
`ci/flatpak_update_e2e.py`, `ci/macos_system_e2e.py`,
`ci/windows_full_e2e.py`, `ci/windows_split_e2e.py`,
`ci/windows_signed_update_e2e.py`, `ci/windows_sleep_e2e.py`,
`ci/android_network_e2e.py`, `ci/android_always_on_e2e.py`,
`ci/android_process_death_e2e.py` and `ci/android_upgrade_e2e.py` cover different
parts of this matrix. Read their authorization/environment requirements first.
Do not launch them against a personal installation as an incidental self-test.

## Candidate 0.6.0 inventory — 2026-10-12

Pre-release candidate **0.6.0** (desktop sequence 10, Android
`0.6.0-preview.1`/60001, iOS 0.6.0/60001) on branch `codex/release-0.6.0`, based
on main at
`dee8b141695a82d011da4d578965d2c9896e8a9e`. It is a preview, not a production or `latest` candidate.
No exact-source artifact has been built yet, so the commit, artifact and
manifest hashes below are intentionally empty; they are filled in only from the
completed build's source identity and artifact receipts, never estimated. A
ledger is created per package set after that build.

| Package / gate | Commit | Artifact SHA-256 | Status | Owner / dependency |
| --- | --- | --- | --- | --- |
| Windows x64 installer + service | — | — | `not_run` | Windows lab; exact-source build pending |
| Windows Authenticode | — | — | `blocked` | Windows publisher |
| Windows signed update 9 → 10 + forced rollback | `974debf` | Setup `6da53333…` | `passed` (lab-signed) | Windows lab 2026-10-13; production-key metadata and Authenticode `not_run` (see [secure updates](secure-updates.md)) |
| macOS system package installed acceptance | — | — | `blocked` | Dedicated test Mac required |
| macOS Developer ID + notarization | — | — | `blocked` | Apple publisher; packages remain ad-hoc sealed |
| Linux host package + Flatpaks, x86_64/ARM64, reboot/sleep | — | — | `not_run` | Linux lab |
| Android signed APK, physical device | — | — | `not_run` | Android lab / publisher |
| iOS signed IPA, physical device | — | — | `blocked` | Apple publisher + iOS lab |
| Independent physical-interface leak capture | — | — | `not_run` | No runner exists; current evidence is active probes in container/emulator |
| Recovery/resource budgets, soak ≥24 h | — | — | `blocked` | Budgets not approved |
| Server contracts (portal 409 limits, profile API) | — | — | `not_run` | onixus/tunnel |
| Sequence-10 signed update metadata | — | — | `not_run` | Release publisher after exact-source build |

Always-on recovery through backup profiles is claimed for Linux/Windows only;
macOS and mobile cells for it are `unsupported`, not passed.

## Inventory and owners — 2026-10-11

Initial read-only environment inventory was collected in the issue-work
checkout at `815458266bc77292d4f6dbfba549771484c33238` on Darwin arm64.
Upstream subsequently advanced to
`a2909340f3d328d6f44b29a699df7d1079e39800`, including desktop network/resume
events, diagnostics verdict/actions and ordinary-session permitted failover.
The issue changes are being integrated on that newer base; neither base SHA
identifies a final compiled candidate for these changes.

At this re-audit no `dist/` exact candidate was present in the issue checkout.
No installed-package test was performed for the integrated changes, so no
candidate ledger or new runtime pass is claimed. The installed Mac app exists,
but its source/package hash has not been correlated to this candidate. Initial
signing/tool/device observations below remain session inventory, not a renewed
claim about other machines or publisher accounts. Historical reports remain
bound to their recorded source, package and environment.

| Platform / dependency | Status for this candidate | Owner / next action |
| --- | --- | --- |
| macOS exact installer + installed test | `not_run` | Release maintainer builds/archive source-bound artifact; lab operator uses a dedicated Mac for install, failure, update/rollback and soak |
| Apple signing/notarization | `not_run` | Publisher supplies Developer ID/notarization access; local `security find-identity` returned zero valid signing identities in this session, not proof of absence elsewhere |
| iOS signed IPA / physical device | `not_run` | Apple publisher + iOS lab; initial default Command Line Tools could not find `simctl`, but installed Xcode/iPhoneOS SDK was subsequently located for typechecking; no device/simulator acceptance run |
| Windows Authenticode + Wintun/WFP device | `not_run` | Windows publisher + Windows lab; no matching candidate/device result collected |
| Linux signed package + physical KDE/ARM64 | `not_run` | Linux package maintainer + lab; dated Linux acceptance cannot be reassigned to current commit |
| Android signed APK + device | `not_run` | Android publisher + lab; `adb` exists but device enumeration failed with sandbox listener denial, so device availability is unknown |
| Signed update metadata + previous artifact | `not_run` | Release publisher provides offline-key operation and genuine previous signed installers; credentials were not read or changed |
| Physical interruption and 24 h soak | `not_run` | Lab operator reserves dedicated devices; reboot/sleep/handoff on personal systems need the user-authorized maintenance scope |

## Remaining acceptance of issues #31–33

The existing implemented-platform matrices remain in
[vpn-observations.md](vpn-observations.md),
[route-explain.md](route-explain.md) and
[system-diagnostics.md](system-diagnostics.md). Those contracts and code tests
do not satisfy all installed-device criteria. The newer upstream implementation
is accounted for explicitly:

- **#31:** desktop services now collect network-change and kernel-clock resume
  events and invalidate earlier observations. This is implemented; physical
  sleep/wake, rapid network handoff, installed-package stale-result/cancellation
  behavior and real system corroboration still require acceptance for the exact
  integrated package. Android selected underlying Network/link-property changes
  and iOS provider path/wake callbacks are now wired to the shared invalidation
  adapter. Android deep-sleep clock differences also invalidate active-session
  observations when existing polling resumes; injected clock/session tests do
  not establish native callback/device latency. Physical-device event evidence remains a separate gate. Lifecycle
  transport/configuration remains distinct from DNS, route, guard and end-to-end
  proof; unknown/unsupported must never be green.
- **#32:** the native IPv4 intent editor now provides validated offline previews,
  fixed priorities/conflicts and managed source locking, with changes saved for
  the next disconnected connection. The shared Router core implements atomic
  conditional local decision-policy revision/rollback with epochs, stale DNS
  rejection, immutable managed sources and opt-in bounded redacted observations
  of real flow-policy selections; see [core boundaries](routing-policy.md).
  Mobile adapters now expose an explicit, bounded local capture of actual flow
  policy decisions from their active router, with session/capture fences, expiry,
  queue-loss counts and no destination history. Desktop adapters do not
  subscribe, and no adapter invokes hot revision apply. Established/pending flow revocation, atomic OS-route/
  guard cutover, explicit managed administrator authentication/provenance and
  installed observed-flow-versus-prediction corroboration remain incomplete.
  Core/editor regression tests cannot establish installed hot desktop rollback
  or real traffic agreement.
- **#33:** exact installed-package diagnostics compared to kernel routes and
  actual IPv4/IPv6 split/full traffic, unavailable control endpoint and
  repeat-after-action freshness. Native verdicts and endpoint/reconnect/recheck
  actions are now implemented and unit-tested; live outage/control-loss and
  reconnect-then-recheck evidence for the integrated package remains required.
  Linux IPC v4 adds a service-owned check of the active pinned HTTP/2 endpoint;
  physical route/interface proof is required for attributable failure.
  Unproven virtual paths, inactive leases and other transports remain
  unsupported/inconclusive. Windows now implements bounded resolver, exact
  live-adapter route and interface-bound verified HTTPS checks. These changes
  require installed traffic evidence; mobile/WebView system-diagnostics UI
  remains unsupported. A timeout cannot distinguish every cause and must not be
  reported as proven blocking.

Ordinary-session permitted failover from upstream and the additional
service-owned Always-on recovery use different lifecycle paths. Their unit or
disposable-namespace evidence does not transfer to the integrated installer.
Include failure, guard retention, cancellation and restoration scenarios for
each promoted path, protocol and mode in the exact-package ledger.

Issues #31–33 and #36 remain open until their missing implementation/device and
publisher gates have evidence. This inventory neither closes issues nor
publishes/promotes a release.

Release source preparation requires Jenkins `SOURCE_PATH` and a full `SOURCE_SHA`.
`ci/snapshot.py DEST --source REPO --sha COMMIT` exports that immutable Git tree
into an empty, separate destination, preserving executable modes and excluding
untracked and dirty working bytes. Symlinks, submodules and Git archive attribute
rewrites fail closed. `source-manifest.json` retains its path-to-SHA256 format;
archived `source-identity.json` binds its digest to the full commit and tree ID.

`prepare-signed-release.py --source-sha COMMIT ...` verifies the complete manifest
against Git and requires a matching clean tracked signing checkout before reading
Jenkins credentials or creating release output. Old archives without identity
must be rebuilt. These checks bind declared source identity; reviewers still
correlate build logs and artifact receipts, publisher signing and device acceptance.
They do not prove a binary was compiled honestly or replace required package gates.
