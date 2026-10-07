# macOS sleep recovery investigation (2026-10-07)

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
