# Native Jenkins CI

Job: http://localhost:8081/job/rtrust-native/

`Jenkinsfile` targets `macos-arm64` (native macOS host, one executor) and `windows-amd64` (native Windows 11, MSVC). Linux ARM64 native/TUN tests run in disposable Docker containers on the Mac agent, including Weston Wayland, systemd-resolved and nftables. The controller is Linux and is used only to freeze source and run security gates. The job never treats the controller as macOS.

The project is versioned in Git. `ci/snapshot.py` copies an explicit set of project directories into the controller workspace. All nodes receive the same stash; archived `source-manifest.json` contains per-file SHA-256 hashes. Reconfigure the inline job definition after changing `Jenkinsfile`. No controller restart or history deletion is required.

Stages:

1. Frozen source snapshot and fingerprinted manifest.
2. Gitleaks 8.30.1 scans the source tree with redacted JSON output. Trivy 0.74.0 scans dependencies and misconfiguration; HIGH/CRITICAL findings fail the stage. Both tools are fetched from official releases using committed SHA-256 pins in `ci/tools.lock.json`. Scanner/download errors fail the job, not pass it.
3. Native macOS and Windows: Rust 1.98.1, format check, workspace unit/integration tests, self-contained vendored h2 tests, Clippy, release builds, smoke and packaging. The existing upstream HPACK fixture omission is explicit: `--skip hpack::test::fixture` (fixtures are not distributed with that crate).
4. Native GUI smoke starts the actual application with `--ci-smoke`, opens its event loop and exits after three seconds. It does not load the user's vault or connect a VPN. It also checks CLI profile import and rejection. This is a startup smoke test, not a GUI click-through test.
5. E2E on both operating systems uses the real release `rtrust-inspect` client against official endpoint 1.1.0. It exercises HTTP/2 and HTTP/3 HTTP/UDP, SOCKS TCP/UDP including fragment/source rejection, wrong-password and wrong-TLS-identity rejection, and official `tt://` export import. HTTP/3 half-close remains a documented unsupported case; this test does not claim that it works.

The official endpoint does not ship a Windows server binary. A temporary endpoint runs on the macOS agent, bound to its LAN address reachable from the Windows node (`192.168.68.116`). HTTP/UDP targets are loopback-only on the Mac. Each run generates a self-signed certificate valid from 24 hours before fixture creation through 24 hours after it, and a random synthetic password; clients trust only that certificate. Credentials are passed only through the transient fixture stash, never archived as artifacts. The server has a 20-minute upper lifetime and a stop-file cleanup path. No production server/profile is used. A changed Windows node IP requires updating fixture route discovery.

`ci/run.py` records complete command logs and one JUnit case per command group, including failures. JUnit totals describe command groups; Rust test counts are in the accompanying logs. Jenkins archives reports plus native `.app`/`.exe` release artifacts, with fingerprints. Native Windows builds require the existing Visual Studio Build Tools installation; the job does not silently fall back to cross-compilation.

The macOS agent is a user LaunchAgent (`org.rtrust.jenkins-macos`), with EXCLUSIVE scheduling and private credentials under `~/.jenkins-agent/macos`. It executes with the logged-in user's privileges. The agent was explicitly authorized by the user. Other nodes and jobs are not modified.

Register/update the job with the existing private Jenkins API token (the script never prints it):

```sh
python3 ci/register_jenkins.py --token-file "$HOME/jenkins_home/admin-token.txt" --build
```

During initial native E2E validation the Windows node UTC clock was approximately three hours behind macOS. E2E explicitly reports clock differences over five minutes. The fixture certificate validity window tolerates that known lab skew; production TLS checks are unchanged, and the Windows OS clock was not modified. Fixture creation requires OpenSSL with `req -not_before/-not_after` support (available on this Mac).


## Verified run

2026-09-30: [rtrust-native #5](http://localhost:8081/job/rtrust-native/5/) finished with `building=false`, `result=SUCCESS`. All 15 reported command groups passed. Each OS passed 37 workspace tests and 59 self-contained h2 tests (one upstream ignored test and 382 unavailable fixture cases remain explicitly excluded), format, Clippy, native release build, GUI startup smoke and network E2E. Gitleaks: zero findings. Trivy: zero HIGH/CRITICAL findings across both Cargo lockfiles. Fixture keys, credentials and client manifest were removed after the run.

The earlier failures are retained: #1 scanner-distribution README/hash-manifest false positives; #2 Windows exposed unread SOCKS port bytes causing loss of the error reply; #3 Windows clock skew; #4 Windows UDP ICMP close semantics and log encoding. The actual SOCKS implementation was fixed to consume the port before rejecting a malformed hostname, with a malformed UTF-8 regression case. The closed-UDP test accepts Windows `ConnectionResetError` only after the live relay and control-socket closure checks, consistent with [Winsock recvfrom semantics](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recvfrom).

Native Windows release: [R-TrustTunnel.exe](http://localhost:8081/job/rtrust-native/5/artifact/dist/native-preview-windows/R-TrustTunnel.exe), SHA-256 `d99b5e309056e03a1248362b1d97cde2cdc1680615704c48bb19110a77defa42`.

Native macOS executable SHA-256: `431e29dda761676d18b66aa6991b3c0ce91c4a93904e0d45df78c66af84f152d`; `.app` and reports are in the same build's artifacts. These unsigned release binaries are not final installers.

## Windows Wintun / SCM — 30 сентября 2026

[Прогон #12](http://localhost:8081/job/rtrust-native/12/) завершился `SUCCESS`. Помимо прежних native unit/build/smoke и SOCKS E2E, добавлен настоящий Wintun и временный официальный endpoint в Docker. Проверены установка и повторная установка SCM-службы, защищённый pipe, подключение Rust-клиента с отключёнными административными правами и отказ неавторизованному restricted token. Проверены 8 HTTP-передач по 512 KiB, UDP 1/512/1472, удержание маршрута при обрыве endpoint и автоматическое восстановление TCP, Stop ACK, закрытие процесса GUI-клиента и SCM Stop. После удаления тестовой службы вся IPv4-таблица совпала с исходной; существующий пользовательский TrustTunnel не отключался.

В процессе исправлены реальные проблемы: #6 — Linux-only signal handler в Windows diagnostic CLI; #7 — quoting пути службы при регистрации через sc.exe (заменено structured New-Service/CIM); #8 — CA:TRUE в сертификате нового тестового стенда; #9 — отсутствующие read-only SCM-права desktop SID; #10 — Connected до завершения Windows DAD; #11 остановлен после обнаружения нарушения Clippy в snapshot. История не переписывалась.

Новый ZIP содержит GUI, service executable, подписанный официальный Wintun DLL, лицензию, установщик PowerShell и SHA256SUMS. Это preview для выбранных IPv4-сетей; full tunnel/DNS/IPv6 и постоянный WFP kill switch остаются отдельными задачами. Само приложение/служба пока не подписаны. [Инструкция](windows-service.md).

Общий data-plane после выделения из Linux модуля отдельно проверен в Linux ARM64 Docker: `service-interop.py` (две аварии endpoint, SIGKILL/restart/recovery, UID isolation, Stop) и `tun-interop.py` (TCP, half-close, DNS, UDP, параллельные передачи). Это не заменяет KDE/systemd lifecycle проверку.

Финальная версия с возвратом ошибок установки адаптера/маршрутов в GUI: [#13 — SUCCESS](http://localhost:8081/job/rtrust-native/13/), `building=false`, 16 JUnit-групп без падений. macOS: 37 workspace tests; Windows: 43 workspace tests, включая отдельную повторную проверку ACL против установленной службы в E2E; h2: 59 тестов на каждой ОС. Gitleaks: 0; Trivy HIGH/CRITICAL: 0. [Windows ZIP](http://localhost:8081/job/rtrust-native/13/artifact/dist/R-TrustTunnel-Windows-preview.zip).


## Linux full tunnel + Wayland-only: verified #17

2026-09-30: [#17](http://localhost:8081/job/rtrust-native/17/) finished with `building=false`, `result=SUCCESS`. All 17 JUnit command groups passed. Workspace tests: macOS 41, Windows 47, Linux 42. Gitleaks: 0; Trivy HIGH/CRITICAL: 0. macOS/Windows h2 tests and official endpoint SOCKS E2E passed; Windows installed-service ACL, traffic, reconnect and cleanup E2E passed.

The Linux stage runs native build/unit/Clippy, real GUI startup in headless Weston, an assertion that X11 features are absent, and a protocol assertion for `xdg_toplevel.set_app_id("org.rtrusttunnel.Native")`. DISPLAY is unset and XWayland is not enabled. Linux selected-network, TCP/UDP/half-close and full-host VPN tests all passed. The full-host test uses actual systemd-resolved and source-IP observations to verify DNS routing; endpoint loss, GUI crash and service SIGKILL retain protection, with verified explicit recovery and preservation of unrelated nftables state.

History is retained: #14 failed because the then-X11 test image lacked libXcursor; #15 was cancelled after the user's instruction to stop supporting X11; #16 passed the Wayland and VPN suite; #17 adds the separately verified Wayland window app ID and its regression assertion. No X11 support remains in the final Linux build. A separate Linux x86_64 build passed Wayland/app-ID/CLI smoke under Docker amd64 emulation; this is not physical KDE validation.

## Unsigned DMG and portal API tests

2026-09-30: [#19](http://localhost:8081/job/rtrust-native/19/) finished with `building=false`, `result=SUCCESS`; 19 JUnit command groups passed. This includes seven isolated portal API integration tests using the real Rust codec, plus read-only DMG integrity/GUI smoke. Server source and pinned dependencies are now included in the source snapshot and security scans: Gitleaks 0, Trivy HIGH/CRITICAL 0. Existing Linux Wayland/full-tunnel and Windows selected-network Wintun/SCM E2E passed. Windows full-tunnel/WFP is not covered or implemented. The portal overlay has not been deployed and native-client exchange integration remains unfinished.

[Unsigned Apple Silicon DMG](http://localhost:8081/job/rtrust-native/19/artifact/dist/R-TrustTunnel-macOS-arm64-preview.dmg), [SHA-256](http://localhost:8081/job/rtrust-native/19/artifact/dist/R-TrustTunnel-macOS-arm64-preview.dmg.sha256). This macOS preview provides profiles/SOCKS5, not system-wide VPN.

## Windows full tunnel and native Setup

Windows builds now use the static MSVC CRT. `ci/package_windows.py` pins Inno Setup 6.7.1 by official SHA256 and creates `R-TrustTunnel-Windows-x64-Setup.exe` plus checksum. `windows-installer-e2e` exercises install/upgrade/uninstall and the installed GUI event loop. Full-tunnel E2E is executed by a protected SYSTEM scheduled task with a separate four-minute recovery task, because WFP intentionally cuts the Jenkins connection while the tunnel is active. Only the authorized Windows host may run this stage. Temporary credentials, Python runtime, tasks and service are removed afterward; reports retain failures.

Final Windows delivery: [#23 SUCCESS](http://localhost:8081/job/rtrust-native/23/), completed with zero JUnit failures. Windows full-tunnel evidence is in `reports/windows-full-worker.log` and `windows-full-result.json`; installer lifecycle in `windows-installer-e2e.log`. Gitleaks and Trivy HIGH/CRITICAL findings: zero. Build #20 retained the original Setup service-directory failure; #21/#22 were superseded and aborted, not treated as passing evidence. The registration helper now preserves job properties on pipeline updates.

## Preserving installed Windows clients

`WINDOWS_SYSTEM_E2E` defaults to false. Normal CI still runs unit, Clippy, GUI
smoke, packaging and SOCKS network E2E; installer lifecycle and Wintun/full-host
checks are explicitly skipped in JUnit. Enable that parameter only for an idle
Windows test host without a user installation. The installer test retains its
refusal to overwrite an existing application. Build #23 is the prior completed
full system validation; #24 correctly stopped when a user installation appeared.

Build [#25](http://localhost:8081/job/rtrust-native/25/) completed SUCCESS on
2026-09-30: 20 JUnit groups passed, 3 explicit Windows system-test skips.
Gitleaks and Trivy passed; macOS/Windows unit, native smoke and HTTP2/HTTP3 SOCKS
E2E passed; Linux Wayland and full-tunnel tests passed. Real Rust-to-FastAPI HTTPS
profile exchange passed. Setup SHA256:
`e23e1281f2afd3d99cb94debfd8565b58701b39b71e828ae282c4a7d31ef2edf`.
Delivered to `C:\Users\onixu\Downloads\R-TrustTunnel-Windows-x64-Setup.exe`
and verified there; the existing installation was preserved.

## Desktop regression fixes — build 29

[Build #29](http://localhost:8081/job/rtrust-native/29/) finished SUCCESS on
2026-09-30 (22 JUnit groups passed, 3 explicit invasive Windows checks skipped).
Validated encrypted persistence via a new process and the actual OS key store on
Windows/macOS/Linux. Windows desktop/keyring checks run in a temporary limited
interactive task because SSH network logons cannot use Credential Manager.
Temporary tasks and synthetic credentials are removed after each check.

GUI smoke covers tray initialization, hide/restore; Linux additionally uses a
real session bus and a test StatusNotifierWatcher, verifies DBusMenu and invokes
Activate externally. The application remains alive with no Wayland window.
Wayland runs with DISPLAY unset, no XWayland. Linux full-tunnel and macOS/Windows
HTTP2/HTTP3 SOCKS E2E also passed; Gitleaks and Trivy report zero findings.

Build 26 exposed the SSH credential-store restriction; 27 caught a Linux-only
Clippy issue; 28 passed desktop/Linux checks but failed when the Windows SSH
agent disconnected before network E2E. Its failed result is retained. The node
was reconnected and the full pipeline rerun successfully without changing hosts.

Installer delivered and hash-verified at
`C:\Users\onixu\Downloads\R-TrustTunnel-Windows-x64-Setup.exe`:
`d26cbb12d5970ca4da57abe4c9694d13cf1c9eadf3cdbb030278aa70ac3a1f8f`.
The user's installed application/service were not overwritten by CI. Full
Windows Wintun/WFP and installer lifecycle were not repeated on that installation;
the transport-selection regression is covered by native tests on Windows/Linux.

## Opt-in login startup — build 32

[Build #32](http://localhost:8081/job/rtrust-native/32/) finished SUCCESS on
2026-09-30: 22 JUnit command groups passed, 3 invasive Windows groups explicitly
skipped. Gitleaks and Trivy reported zero findings. Native unit/Clippy, Settings
GUI smoke, actual OS-keyring restart persistence, Linux Wayland tray/full-tunnel,
and macOS/Windows official-endpoint SOCKS E2E passed.

Login startup tests cover isolated Windows registry enable/read/remove, private
Unix entry replacement and symlink rejection, macOS plutil validation, and real
Linux gio launch with spaces/quotes/backslash/dollar/backtick in the executable
path. Build 30 retained a Windows Clippy failure; build 31 exposed GLib's percent
path incompatibility. Production now rejects percent paths with an actionable
message. A separate regression failed before the fix and now verifies that a
locked vault at login keeps its error window visible instead of hiding it.

No real user login entry was enabled, no logout/login was performed, and Windows
uninstall cleanup was compiled but not exercised against the user's installed
client. Existing Wintun/WFP and installer lifecycle evidence remains build 23.
The code matches the build's frozen source manifest; post-build changes are docs.

Delivered and SHA256-verified at
`C:\Users\onixu\Downloads\R-TrustTunnel-Windows-x64-Setup.exe`:
`4c2f9a30fccdde83915eb70d1c47423e178e0a97b4170bc5667fcebadfde11c2`.
Local dist contains this Setup and the unsigned Apple Silicon DMG from build 32.

## Authorized existing-client upgrade / reinstall — 2026-09-30

The user explicitly authorized installer checks on the installed Windows client.
A manual run of `ci/windows_user_upgrade_e2e.py --allow-existing-installation`
completed PASS using build 32 Setup. It verified upgrade over the old binary,
repeat installation, uninstall (SCM/application removal), clean reinstall, and
installed EXE GUI/settings/tray smoke with a limited interactive user token.
The original application/data were backed up before the first mutation. The
final client is installed and RTrustTunnel service is Running for the same SID.
Startup preference and data-file hashes were preserved. There was no encrypted
profile vault on this machine, only profiles.lock: this run does not establish
preservation/decryption of real saved profiles across reinstall.

Original executable SHA256:
`8918dda618d74b58e21eefe06dc7b51aa6545e68b5b16309f302b46574da60f6`.
Final executable SHA256:
`0ed130a1765614f93a66a222caab4e820d0fb5502b20f3b8769f055b58c165e9`.
Original backup: `C:\Users\onixu\Downloads\RTrustTunnel-maintenance-20260930-182014`.
Successful logs/result: `C:\Users\onixu\Downloads\RTrustTunnel-maintenance-20260930-182204`.
Earlier failed test reports remain available. They exposed test harness issues:
PowerShell direct GUI invocation did not yield an exit code, and the test assumed
unins000.exe rather than reading the registered uninstall path. The final test
waits through Python subprocess and uses the registered executable. Desktop task
results are now published by a rename to avoid observing an empty in-progress file.
No VPN traffic or full-tunnel/WFP E2E was run in this installer-only maintenance.
This is a separate manual test result, not a new complete Jenkins pipeline build.

## Optional startup connection — build 33

[Build #33](http://localhost:8081/job/rtrust-native/33/) finished SUCCESS on
2026-09-30. Native tests cover default-off migration, encrypted preference
roundtrip, initial-load-only connection, cancellation without retrigger, missing
profiles/locked vault, visible connection failures, and refusal to substitute
SOCKS for unsupported macOS system VPN. GUI/settings/tray smoke, real keyring
restart checks on three OSes, Linux Wayland/full tunnel and Windows/macOS SOCKS
network E2E passed. Gitleaks/Trivy: zero findings. 22 JUnit groups passed; three
invasive Windows groups skipped. The run does not exercise actual OS login or
an automatic system VPN connection on the user's machine.

Windows Setup delivered and hash-verified in the user's Downloads:
`b243890c8b2d98c51e2b551e0b3185af0f7c0847894ab9d30639ce53db55659b`.
The installed build 32 was preserved; build 33 is available for installation.
Windows Setup and unsigned macOS DMG are also copied to local dist. Source files
matched the frozen build manifest before delivery; this evidence paragraph was
added afterward.

## Profile synchronization / conflict recovery — build 34

[Build #34](http://localhost:8081/job/rtrust-native/34/) finished SUCCESS on
2026-09-30: 22 JUnit groups passed, three invasive Windows groups skipped.
Gitleaks/Trivy: zero findings. macOS/Windows/Linux native unit/Clippy/GUI and actual
keyring restart tests passed. Linux Wayland/tray/full-tunnel and Windows/macOS
SOCKS network E2E passed. Rust-to-FastAPI HTTPS E2E additionally replaced an external
profile, replayed the same commit idempotently and rejected a stale write without
changing the newer profile. Sync merge decisions, origin binding, deleted/revoked
profile retention, explicit recovery of corrupt storage, repeated save conflicts,
and keep-both/default preservation have regression coverage. Background polling
was not exercised during a real user login; tests use synthetic profiles.

Delivered Windows Setup SHA256:
`d35bebfbeff62d6a53be354f1330935a62d36def54d22270d49693251bc9dbe8`.
Installer is in `C:\Users\onixu\Downloads\R-TrustTunnel-Windows-x64-Setup.exe`;
the installed application was not replaced. Code matches the frozen source
manifest; subsequent changes before delivery were documentation only.

## Native Linux x86_64 acceptance (2026-10-01)

`Jenkinsfile.linux` / `rtrust-linux` use the `gaming-amd64` Linux node without
waiting for the dual-boot Windows agent. Build #5 completed SUCCESS: Gitleaks,
Trivy, unit, Clippy, Wayland/tray, packet and full-tunnel E2E, Flatpak and Arch
host-package builds. Builds #2–#4 retain the reconnect failures; the fix keeps
strict reverse-path filtering enabled and restores exact routing state.

The packaging stage also runs `ci/flatpak_update_e2e.py` with a private Flatpak
installation and a temporary GPG key: signed install/update/rollback, unsigned
commit rejection, uninstall. The test key is destroyed and never published.

Physical KDE tests (`ci/kde_flatpak_smoke.py`, document/background portal probes,
`--ci-storage-smoke`) run in the authorized desktop session. Package lifecycle
and `ci/linux_system_e2e.py` are separate, explicitly invasive acceptance tools;
they must not run as ordinary CI. The host-network driver requires a separate
systemd restore timer and restores the original VPNs in its cleanup path.
See [Linux acceptance](linux-acceptance.md) for evidence and remaining checks.

## Android on the Linux agent

`Jenkinsfile.android` defines the separate `rtrust-android` job. It runs security
checks on the controller and `ci/android.py` on the Linux/KVM node. Provision
SDK 36, build-tools 36.0.0, NDK 28.2.13676358, JDK 17+, Gradle 8.13 and the
API 36 Google APIs x86_64 emulator. The configured emulator serial must belong
to an isolated test device: the tests replace the app installation.

The job checks Rust/JNI, both ABIs, Android lint, Keystore/tamper smoke, real
TrustTunnel IPv4/IPv6/DNS/reconnect/Activity lifecycle, and reinstall/version
upgrade. The fixture binds only host loopback, runs as the source-file owner
without capabilities and cleans up its own Docker network. No host VPN switch
is required. Release APKs leave CI unsigned; the persistent release key stays
outside Jenkins. See [Android details](android.md).
