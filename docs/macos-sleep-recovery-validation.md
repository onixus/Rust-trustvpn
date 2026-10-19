# macOS sleep recovery investigation (2026-10-07)


Current follow-up (2026-10-14): these are historical observations, not acceptance
of the latest package. [#62](https://github.com/onixus/Rust-trustvpn/issues/62)
still needs installed sleep/roam verification after #69's data-plane liveness
change; [#70](https://github.com/onixus/Rust-trustvpn/issues/70) tracks slow Stop
and route operations. [Current status](project-status.md).

## Evidence and limits

The installed helper and GUI both started after the previous package installation.
The helper PID remained 17696 across clamshell sleep at 14:18:29 and Deep Idle wake
at 14:26:55 (+03:00). No service restart occurred. Neither unified logging nor
legacy syslog retained an IPC-exit explanation for this episode. The currently
connected GUI cannot establish automatic recovery because manual reconnect was
reported previously. The specific latest user-visible failure is not yet proven.

The previous implementation synchronously awaited `Workers::stop()` in its wake
select branch. An aborted `block_in_place` route refresh keeps running until its
synchronous operation returns. The supervisor therefore stopped answering Status
while waiting. The extracted **production supervisor**, not a separate mock IPC
server, reproduces the failure in
`wake_during_route_refresh_keeps_real_supervisor_responsive`: the old code fails
with `wake blocked Status IPC`; the fixed code responds while retaining the lease
and starts no new mutation before the old worker has drained.

## Implementation

- Register a dedicated CFRunLoop with IORegisterForSystemPower.
- Acknowledge CanSystemSleep and SystemWillSleep immediately, without vetoing or
  waiting for network cleanup. Cancel workers on sleep, retain PF and routes.
- Wait for SystemHasPoweredOn before scheduling reconnect. Ignore early
  SystemWillPowerOn: Apple documents that hardware/network access can still block.
- Drain cancelled workers as select events, leaving Status/EOF processing active.
  Ignore any successful result from a worker invalidated by a power event.
- Keep bounded, redacted lifecycle diagnostics at
  `/private/var/run/rtrust/events.log` (root-owned, desktop-readable, 256 KiB cap).
  Never record profiles, credentials, request bodies or packet content.

References: Apple's [QA1340](https://developer.apple.com/library/archive/qa/qa1340/_index.html)
and the SDK IOPMLib.h IORegisterForSystemPower contract. The service no longer uses
wall-clock/Instant gaps as a substitute for OS power events. The client's existing
suspend-tolerant framed exchange is unchanged.

## Completed validation

- Rust 1.98.1, locked dependencies: control 10 tests + TUN 30 tests passed.
- Strict clippy (`-D warnings`) passed for both packages/all targets.
- Native IOKit registration and cleanup passed outside the sandbox on this Mac.
- Supervisor regression: fails before the fix, passes after.
- Sleep test: no retry until powered-on event; Status and Stop remain available.
- Release helper compiled; package payload extraction and ad-hoc signature verified.
- Packaged GUI is the unchanged, already installed IPC-fix GUI; helper is rebuilt.

## Required installed acceptance (not yet completed)

1. Disconnect and quit the old app, install the candidate, then reconnect.
2. Verify `service_started native_power_monitor=registered` in events.log.
3. Close the lid for at least one minute, wake, and do not reconnect manually.
4. Record sleep/awake generation, reconnect attempts and reconnect_complete.
5. Check uncached system DNS, HTTPS, tunnel egress, LAN exclusion and route ownership.
6. Repeat a sleep while reconnecting; verify no IPC loss or foreign route cleanup.

Do not label the incident resolved based only on unit tests or connected UI.

## Installed observation and user confirmation

The candidate was installed and its helper SHA-256 matched the extracted package:
`15522d129ec266c5836239629df32898939d11031b35d2f78ed5dae803e1039c`.
The native power monitor registered successfully. During the 2026-10-07
16:28:54–16:31:32 (+03:00) clamshell sleep, the service PID remained 25518.
It received sleep and powered-on events and reconnected automatically 15.281
seconds after powered-on. DNS resolution and HTTPS to Apple and Cloudflare worked.

This first recovery was not fully stable: 105.583 seconds later the transport
reported `Tunnel protocol negotiation failed`, then recovered automatically again
in 15.794 seconds. No manual reconnect, service restart, DNS change or firewall
change was performed during that diagnostic interval. Ordinary DNS for example.com
also differed from Google DoH; HTTPS succeeded with the DoH address. The cause of
that DNS difference was not established and must not be attributed to macOS sleep.

The user subsequently confirmed that networking worked and the blocking symptom
was gone, then requested pushing this macOS update to Git. This is confirmation of
the installed recovery behavior, not proof that the intermittent HTTP/3 failure or
DNS discrepancy has been fixed. Repeated sleep-during-reconnect acceptance remains
outstanding.

## Integration re-audit — 2026-10-12

The four historical recovery commits are integrated with main `e849ac4`. The
merged implementation retains IPC v4/capability negotiation, observation epochs,
permitted candidate pinning and jittered burst/cooldown recovery. Native power
events invalidate observations without resetting the retry budget. The client
uses kernel clocks and permits at most one deadline extension per exchange.
Raw transport/IPC error payloads are excluded from lifecycle logs.

New regressions cover repeated power events reaching the original cooldown,
stale evidence after wake, repeated resume notifications against a dead service,
and rejection of per-domain/supplemental/mDNS resolver mirroring. Native IOKit
registration/cleanup has passed on the development Mac without changing its VPN,
routes, DNS or installed package. Exact integrated-package physical/network
acceptance has not been performed. The earlier installed helper hash, timings
and user confirmation above remain evidence only for that historical candidate.

Local validation of the integrated tree: 293 workspace tests passed, 10 ignored;
strict workspace/all-target Clippy passed. Native IOKit registration/cleanup was
also run separately and passed. Current-head CI and package evidence must remain
bound to their own commit and artifacts.

## Wake reconnect proxies nothing (issue #99, 2026-10-16)

Three wake reconnects on 2026-10-16 (12:24, 13:14, 17:48) reported
`reconnect_complete` while almost every TCP connection through utun5254 received
no bytes, DNS through the tunnel retransmitted, and UDP returned nothing until a
manual Stop/Start. Reconnects after `VPN transport stopped` (04:07, 13:47) worked.
One episode without manual intervention recovered by itself exactly 300 seconds
later. The mechanism is in the local TCP stack, not in QUIC, PF or routes:

- Sleep cancels the data plane, so nobody reads utun until `reconnect_complete`;
  the kernel keeps the SYNs queued meanwhile, and host sockets give up.
- The new data plane answers each stale SYN with SYN-ACK; the host replies RST.
  smoltcp returns a listening socket to LISTEN on RST in SYN-RECEIVED, the stack
  skipped LISTEN sockets and removed only Closed ones, so each reset handshake
  held a flow slot for the 300-second idle timeout.
- With all 128 slots held, new SYNs were dropped silently: no SYN-ACK, no RST.

Changes: a handshake reset by the host frees its slot immediately; a handshake
without progress for `stack::HANDSHAKE` (10 s) is aborted; the UDP relay evicts
its least recently used mapping instead of refusing new datagrams at 256; and the
data plane discards packets queued on the device before the session started
(one awaited read bounded by `dataplane::PRIME_WAIT`, then a non-blocking sweep
bounded by `dataplane::BACKLOG_LIMIT`), so TCP and DNS retransmit instead of
opening upstream streams for sockets that are already gone. The sweep is
best-effort and Unix-only (`try_recv`; Windows and iOS discard at most the one
packet the awaited read consumed); correctness
after wake rests on the stack changes, the discard only spares the fresh
session a burst of upstream opens.

Diagnostics: 30 seconds after `tunnel_connected` and after `reconnect_complete`
the service records `dataplane_summary after=<connect|reconnect> window_s=30`
with process-wide counters only (`syn_accepted`, `syn_refused`,
`handshake_reset`, `handshake_timeout`, `backlog_discarded`, `udp_evicted`); no
addresses, hosts or profile data. Sleep or a transport failure cancels a pending
summary. Regressions: `stack::tests::host_reset_after_syn_ack_frees_the_flow_slot`,
`stale_backlog_resets_do_not_exhaust_the_flow_table`,
`unanswered_handshakes_expire_before_the_idle_timeout`,
`dataplane::backlog_tests::backlog_discard_is_bounded_and_counted`.

Installed-package observation 2026-10-16/17 (four wake reconnects without manual
intervention, handshakes within seconds) confirmed the stack change. Two follow-up
defects showed on 2026-10-18/19:

- After long sleeps the first 30 seconds saw `syn_refused` of 563 and 149: the
  wake burst of application reconnects, not stale backlog, exceeded 128 flows.
  `stack::MAX_FLOWS` is now 512 on desktop (128 stays on Android/iOS; buffers are
  allocated per flow).
- Power events never restored the retry budget: eight wake attempts across a
  day, two of them cancelled by an immediate second sleep, reached the 300 s
  cooldown, so a failed reconnect at 14:15 left the user without a tunnel. Sleep
  after a stable session now restores the budget (`Budget::disconnected`), and a
  pending attempt that sleep cancels is refunded (`Budget::interrupted`); a
  cooldown already entered is kept. Wake-to-wake flapping still keeps the
  backoff (`repeated_power_events_preserve_retry_budget_and_stale_evidence`).
  `VPN reconnect failed` now carries its fixed reason string.

Installed-package sleep/wake acceptance on a real Mac remains required before
the issue is closed.
