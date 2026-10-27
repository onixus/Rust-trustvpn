# macOS system VPN — development preview

## Sleep recovery integration

The service listens to native IOKit sleep/powered-on notifications. Sleep cancels
old transport work while retaining the existing utun/PF guard. Powered-on permits
a retry; early wake does not. Cancelled synchronous route mutations are drained
without blocking Status IPC, and Stop drains them before releasing owned state.
Each retry restores owned endpoint/tunnel routes and DNS before and after connecting.
Conflicting routes or DNS entries retain protection instead of overwriting another
owner. Dataplane health checks have a ten-second outer deadline.

Recovery preserves the permitted backup candidates and the shared jittered retry
budget: power events do not replenish a burst or skip its five-minute cooldown.
Sleep invalidates previous observations, and late pre-wake transport completions
cannot start a session. Transport liveness still does not prove DNS/routes/guard
or end-to-end availability.

Since v0.6.2 (#69/#103), session liveness includes both silent and predominantly
quiet TCP flows, even when a few other flows still work. A degraded session fails its health
check and is reconnected. If it never delivered an inbound byte, its exit does not
restore the retry budget, however long it lasted, so an endpoint handing out dead
sessions reaches the five-minute cooldown instead of a fast loop. The service event
log records `transport_degraded proven=<bool> kind=silent|quiet` without destinations or addresses.
See [dead-session detection](http3.md#dead-session-detection).

Installed sleep/wake after #100/#103/#104 is recorded for main `da92864`
on two Macs in [#99 acceptance](https://github.com/onixus/Rust-trustvpn/issues/99#issuecomment-6291062141):
reconnect 3–4 s and data within 30 s without manual Stop/Start. #99 is closed.
This does not accept the later v0.6.2 artifacts (`4123160`), network handoff
across sleep or installed SOCKS wake; those remain untested.

The desktop client keeps a partially read IPC response through sleep and never
resends the command. Kernel clocks detect suspension without wall-clock assumptions.
macOS status polls allow 30 seconds, with at most one further 30-second extension
for an observed sleep. Dead services cannot extend the exchange indefinitely.

Selected-network mode mirrors the primary configured IPv4 DNS server without
physical-interface scoping only when its address belongs to the tunnel networks.
Per-domain, supplemental and mDNS resolvers are excluded. Persistent network-service
preferences remain unchanged; Stop/recovery remove the owned temporary DNS entry.
Lifecycle logs contain only bounded, redacted events.

The integrated source has supervisor/IPC/DNS regression tests and native IOKit
registration checks. Historical installed acceptance is recorded separately in
[macOS sleep investigation](macos-sleep-recovery-validation.md). Those results do
not accept the new package: physical sleep during reconnect, changed-gateway
handoff and signed installer/update/rollback still require exact-package evidence.

## Published Flow branding: v0.3.2-ui.2

macOS Jenkins **#73 completed SUCCESS**. The selected Flow icon is declared in
Info.plist and sealed in every Native/WebView/Both app payload; package icon hashes
and codesign verification passed. This branding package has not been installed on
the host Mac. The preceding UI upgrade acceptance below belongs to v0.3.2-ui.1.

[Download the UI Choices DMG](https://github.com/onixus/Rust-trustvpn/releases/download/v0.3.2-ui.2/R-TrustTunnel-macOS-arm64-UI-Choices.dmg)
and choose exactly one Native, WebView or Both PKG. The preceding v0.3.2-ui.1
passed macOS Jenkins **#69 completed SUCCESS**. Its Native package was installed over the existing app; its executable
and helper matched the PKG payload, GUI/service smoke passed, and the encrypted
vault remained byte-for-byte unchanged. This is an Apple Silicon preview, without
Developer ID/notarization. It does not close boot always-on, sleep/handoff,
clean-install-on-another-Mac or automatic rollback acceptance.

Disconnect/recover an active session and quit both frontends before installing.
Use the standard macOS administrator prompt. Preserve application data and the
Keychain entry. If macOS requests approval, use the per-app Privacy & Security
flow; do not disable Gatekeeper globally. See [release evidence](releases/v0.3.2-ui.2.md)
and [actual UI screenshots](screenshots/README.md).

## Implementation

The working tree now includes a root LaunchDaemon, reserved `utun5254`, authenticated
Unix IPC restricted to the configured desktop UID, selected IPv4 networks and
full IPv4/IPv6 tunnel modes. The native UI uses the same IPC contract as Windows
and Linux and uses the profile's transport, HTTP/2 or HTTP/3 ([HTTP/3](http3.md)).

The service adds only its own PF anchor, routes tagged with `RTF_PROTO2`, and a
SystemConfiguration DNS entry. Recovery verifies ownership before deletion.
Foreign VPN routes or PF rules cause preflight refusal. Existing PF states
(for example left by Cisco Secure Client / AnyConnect) do not: once the guard
rules are loaded and PF is enabled, the service flushes the global state table
(`pfctl -F states`), because pre-existing states would bypass the guard. PF
cannot flush per owner, so every PF-tracked connection, including other
components', is dropped and re-established under the guard; the guard's own
rules are `no state`, so the tunnel transport is unaffected.
Transport reconnect retains the utun device. GUI/service failure retains the
session guard until explicit recovery. macOS boot always-on is not implemented.
Network handoff to a different physical gateway is not yet accepted.

`scripts/package-macos-system.py` creates a package inside a DMG, without
Developer ID signing or notarization. The root helper is nested inside
`R-TrustTunnel.app/Contents/Library/LaunchServices` and the complete application
is ad-hoc sealed. Installation requires normal macOS administrator authorization.
The preinstall refuses an active GUI, active/recovery journal or desktop-owner
change. A race with Start is detected after stopping the old daemon, which is
then restored before refusing the package.

## Earlier live network acceptance (#61)

Jenkins #61 finished SUCCESS and its system candidate was installed on October 1.
The package's desktop-UID IPC probe passed again after the service crash test.
The helper runs inside the ad-hoc sealed application; this supersedes the old
standalone-helper Gatekeeper failure in `reports/macos-runtime/gatekeeper-56.json`.
Installed package SHA-256:
`c726b95e002e35f83cc4e81846bf81a4c911a40d3d7baff7c924e90ae203d792`.
DMG SHA-256:
`1c2ff3d01fe42e3edfa1bcec54b6a44eeb624efae5680700730834217079575a`.

Live acceptance passed IPv4/IPv6 TCP 512 KiB, UDP payloads up to 60 KB,
ICMP echo with 5000-byte fragmentation, system DNS, blocking a physical-bound
bypass, endpoint outage, automatic reconnect and explicit Stop. GUI/IPC crash
and an actual service SIGKILL followed by launchd restart retained the guard;
explicit authorized recovery restored physical access and removed the utun.
Evidence: `reports/macos-runtime/acceptance-61.json` and
`reports/macos-runtime/live-61-service-crash.log`.
The preceding run also passed data/outage/GUI checks but timed out waiting for
an external SIGKILL trigger; it is preserved as `live-61-crash.log`, not a pass.

The intermittent transfer failure observed in #58–60 was traced to endpoint
1.1.0 closing `_udp2` after an ICMP port-unreachable. Previously the dataplane
reset the entire transport, aborting unrelated TCP downloads. It now reopens
only UDP with bounded backoff while retaining TCP/ICMP and the independent
endpoint health check. The deterministic Linux regression fails on the old
binary and passes on the fix (`udp-regression-before.log`,
`udp-regression-after.log`); build #61 includes this regression in CI.

The Mac UDP probe enlarges only its own socket buffers; Darwin's default
9216-byte buffer otherwise rejects the 60 KB test locally. Global buffer
settings are unchanged. The driver recovers the service and original VPN on
failure as well as success. Hiddify connection and on-demand were restored.

Pending: sleep/network handoff, boot always-on, clean install on another Mac,
and automatic signed update/rollback. The tested artifact remains a candidate
with these explicit limits, without Developer ID signing or notarization.

## Native window glass

The iced Native frontend uses a transparent Metal/wgpu surface on macOS and places
public AppKit `NSGlassEffectView` behind its content on macOS 26+.
Older macOS versions use `NSVisualEffectView` under-window material. The window
keeps its existing input handlers and delegate. “Reduce transparency” makes the
foreground background opaque; AppKit handles the material's accessibility behavior.
Other platforms retain their existing software renderer. This changes the Native
frontend only; the optional WebView frontend retains its current appearance.

The Native Settings screen includes “Стекло — прозрачный фон окна”. It updates the window immediately and persists in NSUserDefaults, separately from VPN profiles. `--appearance-preview` opens this screen without accessing the vault or connecting VPN.

## IPC attachment lifetime (#55)

The running service owns the active tunnel, utun device, guard, reconnect
budget and native power/network supervision. Once guard installation commits
Start, closing or crashing the GUI, a malformed IPC attachment or a failed/frozen
response writer only detaches that control connection. Traffic and reconnect
continue under the existing guard. Before installation, an abandoned Start is
cancelled; it cannot create a late tunnel after its caller disappears.

A fresh authenticated Status request observes the current session once and
does not acquire mutation rights. Its IPC 7 `viewed` flag is ignored: only the
lease connection can keep the service's system probes running
([observations](vpn-observations.md#service-system-probes-issue-81)). The original Start connection keeps its
particular session sender, so a late Stop cannot affect a replacement session.
There is no automatic GUI adoption. A GUI which loses IPC reports
ControlLost; reopening it does not prove control was recovered.
Use explicit Recover to stop and drain the current service-owned session,
release its guard, then Start again (owner rules below). Recover and Stop acknowledge Idle only
after session cleanup and lease release. Start and PrepareUpdate cannot run
concurrently with the current tunnel. If the session supervisor ends
unexpectedly (including a panic or cancellation), its registration and lease
are dropped but the network guard is retained; Status and Recover then answer
from the no-session path, so Recover can still release the retained guard.

Normal service termination uses a durable signal outside the bounded IPC
queue. An actor queued before termination observes the signal on its first
poll; pending preparation is cancelled and committed worker route mutations
are drained while retaining the fail-closed journal/guard for explicit recovery.
Shutdown takes priority over queued requests and reconnect; if it arrives
while explicit Stop drains workers, the Stop response is Blocked and the guard
is retained. Service crash and launchd
restart continue to require recovery as before. None of these lifecycle
observations establish DNS/IPv6 leak freedom or kill-switch enforcement.

Deterministic synthetic actor/IPC tests cover attachment loss, failed writes,
power events, stale senders and cancellation. The opt-in live driver
`ci/macos_system_e2e.py` additionally checks at least 65 seconds of repeated
fixture traffic after dropping IPC in full and selected IPv4 split mode,
with route checks, fresh read-only Status and explicit Recover cleanup.
This issue's installed-package/device acceptance has NOT RUN; earlier #61
evidence does not validate the new binary.

## Managed access freshness (local source change)

Managed TUN/full Start carries a finite portal lease. The macOS service now
accepts `StartLeased` and advertises `managed_access_freshness` only together
with service-side enforcement; the client still rejects an incompatible helper
without retrying plain Start. Reinstalling an older package that lacks this
capability cannot resolve `Service freshness capability required`.

The same sticky deadline covers DNS/transport preparation, guard installation,
active dataplane and every reconnect. Darwin `CLOCK_MONOTONIC_RAW` includes
suspended time (`clock_gettime(3)`); observed wall-clock rollback or clock failure
invalidates access. Wake, GUI detachment and retry do not renew it. Checks fence
worker polls and synchronous OS-operation boundaries in addition to a 100 ms
polling timer; this is not a hard real-time termination guarantee.

Expiry stops and joins tunnel/reconnect workers, reports Blocked, and retains
PF/routes/DNS plus the recovery journal. Status remains available while an
already-started OS mutation drains. Expiry never releases the guard: explicit
Stop or authorized owner Recover performs cleanup under the existing ownership
contract. A new portal synchronization and connection are required for fresh
access; an existing lease is not silently extended.

Synthetic regressions exercise lease validation, expiry, GUI detachment,
sleep/wake events, clock rollback, stale-result fences and blocked OS mutations.
Native installed-package acceptance (real sleep/wake and clock behavior,
IPv4/IPv6/DNS packet enforcement and cleanup in full/selected mode) is **NOT RUN**.
This describes the local source patch, not a published or installed package;
managed SOCKS and permanent Always-on remain unsupported.

## Session owner for Recover (IPC v6)

Peer-uid authentication alone let any process of the desktop user stop a live
session with Recover and drop the guard. Since IPC v6 an admitted Start gets a
256-bit service-generated owner (`OsRng`; Start is refused if it is
unavailable). It is returned once, in the Connected reply to that Start, and
lives only in the service registry and the caller.

- Recover from a new connection while a session is live must carry the matching
  `owner` (constant-time comparison). A missing or wrong owner gets `Blocked`;
  the session, lease, workers and guard stay. A new connection cannot Stop: the
  live session holds the lease. Status remains read-only and needs no owner.
- The original Start connection keeps Stop fenced to its own actor, as before.
- With no live session (ended, panicked or cancelled actor, or after a service
  crash/restart) Recover takes the unchanged journal path without an owner.
- The desktop client keeps the owner in the login Keychain
  (`org.rtrusttunnel.desktop` / `service-session-owner-v1`, the same keyring
  mechanism as the vault master key), so a restarted GUI can still Recover its
  session; it clears the item after a confirmed Stop or Recover. `rtrust-inspect
  --recover-service` reads the same item (macOS may ask to allow access).
  The GUI uses the owner of its own live session from memory first; if its
  Stop is not confirmed (e.g. IPC lost), it keeps that owner in memory until
  Recover succeeds or a new session starts. If the
  service refuses the owner, the GUI explains the exit (disconnect in the
  starting app, or restart the Mac / have an administrator restart the
  service, then Recover). A failed Keychain write is shown as a warning while
  connected. The owner is redacted in `Debug`, is
  never logged, never in events, diagnostics or errors, and is dropped from the
  client status snapshot.
- Version 5 clients get `IPC version mismatch` before any action, so an old GUI
  cannot release a live session's guard.

Residual limits: if the GUI exits after the service sent Connected but before
the owner reached the Keychain (or the Keychain write failed), only the original
connection can Stop that session; otherwise an administrator restart of the
service (journal path) is required. A same-uid process able to read the GUI's
memory or approved for its Keychain item is outside this boundary. Linux and
Windows services accept the same wire format (`owner` since IPC v6, current v7) and ignore `owner`: their Recover
runs only when no session holds the lease, so it never stops a live session.
Deterministic synthetic tests cover rejection, owner Recover and the journal
path; installed-package/device acceptance of this change has NOT RUN.
