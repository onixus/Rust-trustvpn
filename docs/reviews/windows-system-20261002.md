# Windows system acceptance — 2026-10-02

Overall result: **issues found; not a clean release gate**. The final isolated
full-tunnel worker passed, but earlier always-on restarts timed out, and the
production TrustTunnel profile failed with automatic address-family selection.
The Wintun recovery candidate described below has local checks only; neither
finding is claimed resolved on the Windows machine.

## Wintun recovery candidate (not yet accepted)

The original recovery code called PnP removal once, then only polled the
interface table for 30 seconds. A temporarily unreadable driver registry key
was skipped, leaving no further removal attempt inside that wait. The candidate
re-enumerates present Wintun devices every 500 ms within the existing deadline,
matching only the network GUID from the protected journal. It checks all
matching instances, and still requires the interface table to become clear
before deleting endpoint routes, lifting WFP protection, or deleting the journal.
Removal/inspection failures retain protection. The PnP race is a code-level
failure case, **not yet the confirmed cause of the observed crash timeout**.

Follow-up review of the candidate (same day) weakened the PnP-race hypothesis
and corrected two defects:

- The original code was not truly one-shot in the observed failure: the
  always-on loop re-runs `full::recover()` roughly every 33 seconds, so the
  120-second timeout already included about four removal attempts while
  interface 43 stayed listed with operational status 2 (Down). A faster retry
  alone is therefore unlikely to be the fix; the actual cause is still unknown.
- The candidate had added `DIGCF_PRESENT`. A device left in surprise removal by
  a killed owner can be non-present while its interface is still listed, and
  would then never be removed. Enumeration is back to all Wintun devices.
- Removal used to return success silently when no device matched or a driver
  key was unreadable. Each attempt now reports `matched`, `unreadable` and
  whether PnP flagged `DI_NEEDREBOOT`/`DI_NEEDRESTART`; the timeout message
  (visible in `AlwaysOnStatus`) includes the last summary. On the next field
  failure this separates "journal GUID matches nothing", "registry unreadable"
  and "removed but Windows keeps the interface until reboot".

Checks performed for this candidate:

- Three recovery unit tests passed, including delayed device identity,
  remaining/unknown interfaces, and deletion failure.
- The delayed-identity test failed when run with the former one-shot-removal
  algorithm in an isolated copy; it passed with repeated removal. This is an
  algorithm regression test, not a reproduction using a Windows driver.
- All 19 `rtrust-tun` library tests available on macOS passed.
- Windows GNU target `cargo check` and `cargo clippy -D warnings` passed for
  the library and tests. This does not execute Windows tests or produce an
  accepted native release.
- The full-tunnel E2E worker now captures service PID, adapter GUID/index,
  PnP state and journal adapter identity if reconnect remains blocked for
  10 seconds. Profiles, policy contents and keys are excluded.
- The authorized existing-installation runner accepts `--crash-cycles 3` for
  three consecutive always-on service crashes, with WFP and real traffic
  checks on every cycle and recovery latency in the log. Its worker timeout
  and independent rollback timer grow together (11 and 12 minutes for three
  cycles); use a freshly started 15-minute fixture. Default remains one cycle.
  Python syntax and CLI parsing were checked locally; the repeated Windows
  scenario has not yet been executed.

On re-check (2026-10-02, after the follow-up changes) the Windows node
192.168.68.116 was still unreachable (ping and SSH time out; Jenkins reconnects
every 5 minutes and fails). The Windows GNU `cargo check`/`clippy -D warnings`
and all 19 macOS library tests pass with the follow-up changes.

The Windows node was offline during this work: Jenkins reported SSH connection
refused, and subsequent direct SSH/RDP probes timed out. The candidate has not
been installed. Required next gate: native Windows build and repeated service
crash/always-on recovery, full WFP/Wintun traffic and cleanup tests. Keep the
independent scheduled rollback enabled. Preserve the earlier timeout evidence.

The user explicitly authorized testing the existing Windows installation,
changing its agent and temporarily disrupting its network. Tests ran on the
Windows 11 Jenkins node. Application/service artifacts were from completed
Jenkins `rtrust-native/78`, revision
`c49fb4e3a14b730dd0bd963c8c427260063a6f8e`.

Verified SHA-256:

| Artifact | SHA-256 |
| --- | --- |
| Setup.exe | `d41f429bfc0206fd1ea4e044c7bc52501698a04eb5c5daef2fdecf2031b54429` |
| rtrust-service.exe | `fd79462c88b5ea9bed752220afbf9097133de1943d8f959eeba99d99577bf8a3` |

## Results

| Check | Result |
| --- | --- |
| Gitleaks, Trivy, workspace unit tests, clippy, Native smoke, keyring restart, packaged installer and HTTP/2 + HTTP/3 interop | Passed in Jenkins #78; system tests supplemented that build |
| WebView assets/IPC, hide and restore | Passed in the interactive desktop session |
| Existing installation: upgrade, reinstall, uninstall, clean reinstall, GUI/settings/tray, startup and user-data preservation | Passed; latest tested client remains installed |
| Installed IPC under a limited desktop token; unauthorized token denied | Passed against the actual SCM service |
| Partial Wintun: wrong IPC version/network/password, exclusive lease, 8 × 512 KiB TCP, UDP, outage/reconnect, Stop, IPC death, SCM Stop | Passed; exact original route table restored before the physical handoff |
| Full WFP/Wintun: system DNS, TCP/UDP, IPv6 fragmentation, IPv4/IPv6 ICMP, direct/preexisting-flow blocking, endpoint outage/reconnect, Stop while down, IPC death, service SIGKILL/restart, explicit recovery | Passed in the final isolated worker |
| Always-on encrypted policy, restart without UI, physical Ethernet loss/restore, explicit disable | Final isolated worker passed; earlier restart timeout remains an unresolved intermittent finding |
| Production Hysteria 2: Google/example HTTPS with certificate verification, public egress, system DNS, UDP DNS, WFP guard and IPC-death recovery | Passed with normal address-family selection |
| Production TrustTunnel with normal address-family selection | Failed: HTTPS reset (`WinError 10054`) |
| Same production TrustTunnel profile with process-local IPv4-only sockets | Passed HTTPS/DNS/UDP, WFP guard and IPC-death recovery; diagnostic result only |

Production checks used disposable accounts on the existing server. They never
paused production endpoints, switched server routes, or sent notifications.
Both temporary accounts and their TrustTunnel keys were removed afterward.
Endpoint outage/cycling was exercised only on a disposable Docker fixture.
Production TrustTunnel Wintun checks used HTTP/2. HTTP/3 interoperability in #78
uses the inspection/SOCKS client; TrustTunnel HTTP/3 in Wintun remains wave-3 debt.
Hysteria 2 uses its own QUIC transport.

## Findings still open

1. **Always-on restart reliability.** After the longer crash sequence, recovery
   sometimes remained `Blocked` beyond the test's 120-second wait:
   `Wintun adapter removal is still pending ... interface 43 ... refusing reuse`.
   The guard remained fail-closed. A shorter focused restart passed, and the
   last full run eventually recovered and passed the physical handoff. This is
   evidence of an intermittent recovery delay, not proof that it is fixed.
2. **IPv4-only profile compatibility.** The production TrustTunnel profile
   explicitly declares `has_ipv6=false`, but full-tunnel setup still installs
   IPv6 addressing/routes. Normal-family HTTPS failed twice; forcing only the
   diagnostic application's sockets to IPv4 made the same profile pass.
   This supports investigating enforcement of the profile's IPv6 restriction;
   it does not establish that every HTTPS reset has the same cause.

## Test-harness corrections

Two local changes were required to reach the actual system checks:

- The shared DNS fixture answered `.example` only, while the Windows full test
  queries `.fixture.test`. It now recognizes both synthetic suffixes and still
  rejects unrelated names.
- After endpoint resume, Docker's published port could accept TCP before the
  endpoint was ready. The test now waits for a certificate-verified TLS handshake
  with HTTP/2 ALPN instead of considering an open TCP port sufficient.

The original failing runs were retained. The first TLS-readiness attempt omitted
ALPN and was corrected before the final run. Installer and agent binaries were
not rebuilt or altered for these fixture changes.

## Recovery and evidence

Independent SYSTEM recovery tasks were armed before changing the service/network.
Ethernet loss interrupted Jenkins remoting; the SYSTEM test worker continued and
saved `success=true`. Recovery was finalized separately, verifying original
service/DLL hashes, SCM identity, running state, WFP self-test, idle authenticated
IPC, removal of test policy/journal/key and removal of scheduled tasks.

After the handoff, Windows also populated four routes on the existing inactive
Wi-Fi interface. All original routes remained. These physical-interface additions
were recorded and retained; the post-test physical table is **not byte-for-byte
equal** to the pre-test table. No test-owned Wintun route/guard remains. The
strict route assertion in the original full worker was not weakened.

Local logs are under `reports/windows-system-20261002/` (ignored by Git):
`windows-user-lifecycle.log`, `windows-ipc-access.log`,
`windows-existing-service.log`, `windows-full-handoff-final.log`,
`windows-always-on-timeout.log`, `windows-production-dual-stack-failed.log` and
`windows-production-ipv4.log`. Recovery evidence also remains in protected
`C:\ProgramData\RTrustTunnel-E2E-*` directories; secret fixture files were removed.

The supplemental checks were run manually through Jenkins remoting against the
verified #78 artifacts. Jenkins #78's green result alone does **not** include
these later production failures or the intermittent always-on failure.
