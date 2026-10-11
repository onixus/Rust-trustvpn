# Allowed backup profiles and automatic recovery (issue #34)

A desktop TUN or whole-host connection can recover through profiles the user
allowed in advance. This is off by default. Without allowed backups the fixed
profile behaves as before: the same profile is retried and no transport is ever
substituted.

## Enabling it

Native → Settings → **Automatic recovery** lists every profile except the
default one. Up to three can be allowed. The order you tick them in is the
preference order, shown as "backup 1..3". The vault stores profile names
(`connection.fallback_profiles`); renaming keeps the selection, and a deleted
profile drops out. Older vaults without the field mean "no backups". WebView
uses the same vault setting but has no editor for it. SOCKS mode and Always-on
do not use backups: Always-on keeps its single boot profile.

## What the service does

The client sends the allowed backups with `Start` / `StartFull` (IPC field
`fallbacks`; the service advertises `capabilities.failover`). A UI never sends
backups to a service that does not advertise the capability.

1. **Pinning.** At Start the service resolves the endpoint of the requested
   profile and of every backup concurrently, each within its own 10 s limit
   (`failover::pin_endpoint`, shared by all three services). The requested
   profile must resolve; a backup that fails or is slow is left out and the
   start message says how many were skipped. macOS and Windows whole-host mode
   pin IPv4 answers only, because their guards pin IPv4 endpoint exceptions;
   an IPv6-only endpoint is therefore unusable there.
2. **One guard for all candidates.** The firewall, routes and DNS are installed
   once with each candidate's pinned endpoint address, transport protocol and
   own Hysteria hop ports. TCP and UDP exceptions coexist, and hopping ranges
   are never applied to another candidate. Switching between candidates
   therefore never touches the guard:
   there is no moment when it is lifted or rebuilt, and no direct bypass. The
   cost is that the endpoint addresses of the allowed backups have the same
   exception as the requested endpoint for the whole session. That exception
   exists for the service's own transport. Applications still cannot reach
   those addresses directly; the Linux test checks this.
3. **Choosing a candidate.** Startup tries each allowed candidate in order,
   up to two attempts each, within one shared 30 s handshake budget. A single
   candidate retains its original one-attempt, 30 s budget. Stop/EOF cancels
   the pending attempt. Protection is installed before reporting Connected;
   no startup attempt is reported as protected before the guard is installed.
   The transport worker uses the active candidate.
   A failed reconnect counts as a failure, and so does a session that ends
   within 30 s of connecting, so a flapping endpoint is not mistaken for a
   working one. After **two** consecutive failures the next allowed candidate
   is tried, wrapping around to the requested profile. Switches are at least
   **20 s** apart. Backoff (2→30 s) is unchanged except that it restarts at
   2 s after a switch. The service does not move back to the requested profile
   while a backup works; it returns on the backup's failure or on the user's
   reconnect.
4. **Confirmation.** A candidate counts as connected only after its transport
   session is established and the guard refresh succeeds, as for any
   reconnect. Until then the host stays in the blocked state.
5. **Visibility.** `Response.active_profile` is the active index (0 is the
   requested profile, preserving the original request indices even when a
   backup was skipped during DNS pinning). The observation journal records
   `failed_over`. Native
   shows "via backup profile «name»" and the desktop summary mentions the
   switch for a minute.
6. **Stop.** Stop cancels the pending attempt; an endpoint that returns later
   cannot revive the tunnel.

## Limits

- Open TCP/UDP flows break when the transport changes: the server-side exit
  differs, so sessions must reconnect.
- Choice is based on transport establishment and session lifetime, not on
  per-site availability. A backup that connects but cannot reach a given site
  is still "working"; destination diagnostics (#33) show that case.
- A captive portal does not trigger a bypass: with every candidate failing, the
  host stays blocked.
- Each switch costs one connection attempt per backoff step; with every
  endpoint down the service attempts at most one connection per 30 s once the
  backoff is at its cap.

## Validation

`scripts/failover-interop.py` runs a real whole-host Linux VPN in a disposable
Docker namespace with two endpoints on different addresses. While an
application keeps sending HTTP and DNS:

- the requested endpoint is killed;
- the service switches to the backup and the session is confirmed on the
  backup's address;
- the backup is killed and the service returns to the requested profile no
  sooner than the cooldown;
- with both endpoints down the host stays blocked;
- Stop restores the baseline routes and firewall, and a returning endpoint
  cannot revive the tunnel.

Host-side nftables counters must stay at zero for every client packet sent to
anything other than an endpoint port, IPv6 included. The script records
switch and recovery times.

Unit tests cover the selection policy (fixed profile, threshold, cooldown,
flapping, wrap-around), pinning (a backup is dropped, the requested profile is
required, the limit is enforced), vault validation, and the Native setting.
macOS and Windows compile with the same union-guard path; their packet-level
behavior has not been tested here (issue #36).

### Recorded on 2026-10-11 (Docker `rust:1-bookworm`, linux/arm64, endpoint v1.1.0)

| Scenario | Result |
| --- | --- |
| Positive control: a direct request before the VPN is counted | Passed |
| Requested endpoint killed under continuous HTTP+DNS load | Switched after 6.9 s, connected on the backup after 8.9 s; 0 leaked packets |
| Backup killed immediately afterwards | Returned to the requested profile 36 s after the previous switch (cooldown 20 s); 0 leaked packets |
| Both endpoints down for 30 s | Host blocked, candidates retried; 0 leaked packets |
| Stop, then an endpoint returns | Baseline routes and firewall restored; the tunnel is not revived |
| macOS / Windows | Compiled with strict clippy; no packet-level run |
