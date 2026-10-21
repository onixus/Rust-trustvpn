# TrustTunnel HTTP/3 in the system VPN

A TrustTunnel profile with `upstream_protocol = "http3"` now uses HTTP/3 for
SOCKS5 **and** for the system tunnel (Linux TUN/full tunnel, Windows Wintun,
macOS utun, Android VpnService). The native UI, always-on and the Android bridge
no longer replace it with HTTP/2 at runtime. This closes
[W3-HTTP3](technical-debt.md).

## Transport selection

There is no automatic fallback. The profile's protocol is the transport:
`http2` uses TLS over TCP, `http3` uses QUIC over UDP. If QUIC is blocked, the
connection fails and the kill switch keeps blocking traffic; it does not silently
switch to HTTP/2. A user who needs HTTP/2 imports or edits the profile. TLS
verification, hostname, credentials and the endpoint addresses are unchanged.

## Endpoint 1.1.0 half-close

The official endpoint 1.1.0 (quiche) wakes a CONNECT stream's reader only on h3
DATA events. A client FIN that arrives without new DATA raises only `Finished`,
which the endpoint handles by shutting down the QUIC read side without waking
the reader, so the destination TCP server never receives EOF. Large uploads
usually carried FIN in the last data frame and passed; a request followed by a
separate `shutdown(SHUT_WR)` hung until the destination timed out.

The client now ends every CONNECT body with an empty DATA frame written
immediately before FIN, so both leave in one STREAM frame. The resulting DATA
event wakes the reader, which observes the finished stream. h3 GREASE frames are
disabled: a GREASE frame + FIN would be another unknown-frame-only FIN. The
change is harmless for a conforming HTTP/3 server.

## Endpoint 1.1.0 lost responses

The endpoint answers `_check` and failed CONNECT requests with
`send_response(eof)` and drops the stream at once. When the QUIC stream is
blocked (a large download in flight, a slow path), the response is queued and
the drop finishes the stream without it. RFC 9114 makes a request stream that
ends before response HEADERS a connection error, so h3 closed the connection
and with it every tunnelled flow. The dataplane's 5 s health check made this
frequent: on the Android emulator 5 of 10 network acceptance runs over HTTP/3
failed (truncated downloads, resets, UDP timeouts) against 0 of 10 over
HTTP/2; a Linux netem reproduction (10 ms ±5 ms delay, 25 % reordering, 1 %
loss) broke 2 of 100 downloads.

A vendored h3 0.0.8 ([patch notes](../vendor/h3/RTRUST-PATCH.md)) fails only
that request. A health check whose response is lost counts as healthy once the
same connection's first check returned 200, which also proves the credentials.
Lost checks are therefore no evidence of a dead session; the next section
describes what is.

## Dead-session detection

Since v0.6.2, `Session::health` (`crates/engine/src/lib.rs`) evaluates two
independent liveness verdicts. Both are session-level and apply across engine
transports, not only HTTP/3. Idle sessions are not degraded merely for being idle.

- **Silent (A, #69):** outbound demand stays unanswered for 20 s, and within
  60 s and since the last inbound byte, at least five TCP opens failed in
  transport or at least five accepted opens stayed silent, across at least
  three destination buckets. The two kinds are counted separately. Any inbound
  byte clears this verdict's demand.
- **Quiet (B, #103):** TCP flows to ports 443/853/8443/80 that wrote first
  receive no reply after a 10 s grace, or their opens fail with Timeout/Credit.
  A fixed ring of 5 s slots judges 60 s of mature flows. Degraded requires at
  least 24 unanswered/failed flows, at least 80% unanswered among judged flows,
  and six unanswered host buckets not shared with answered buckets. A few
  successful flows, shared UDP relay traffic or ICMP do not clear this evidence.

Lost `_check` responses, endpoint rejections, authentication errors, server-first
flows and an application retrying only one or two dead hosts do not by themselves
establish either verdict. An endpoint that answers `_check` but rejects CONNECT
with 5xx remains outside this heuristic's coverage. Quiet watches TCP only;
UDP/QUIC/DNS stalls are left to silent detection. Many plain-HTTP long polls
across several hosts can trigger a transient quiet verdict.

The exit is `Degraded { proven, kind: Silent | Quiet }`. For silent detection,
`proven` means any inbound delivery in that session. Quiet requires a watched
TCP answer at least 70 s before the verdict (grace plus judged window); a few
answers just after reconnect do not restore its budget. Desktop and iOS keep
the existing retry budget: an unproven degraded exit never replenishes it,
however long the session lasted; a proven session lasting at least 30 s can.
Android similarly restores its finite per-session budget after 30 s of real
time unless the session ended degraded and unproven. A long session can still
replenish the budget on repeated quiet exits; this is not a global lifetime
retry cap.

macOS logs `transport_degraded proven=<bool> kind=silent|quiet`. Numeric
`dataplane_summary` counters include `tcp_opened`, `tcp_answered`, `tcp_quiet`,
`tcp_open_failed` and `credit_timeout`. H3 request credit and Hysteria stream
credit have a 10 s deadline and return `Credit`; H2 readiness and response
share one 10 s deadline and exhaustion can appear as `Timeout`.

Liveness keeps only fixed-size in-memory counters, timestamps and per-session
keyed host-hash bitsets; no destination/address or host hash is logged or exposed.
Each new session has its own evidence, so old flows cannot prove a new session.

System VPN uses its guarded reconnect path without direct fallback. The Native
app also reconnects degraded SOCKS sessions on the same profile/port (#104),
stopping its listener before waiting; other SOCKS health errors still disconnect.
See [Native SOCKS recovery](desktop-lifecycle.md#native-socks-recovery).

Unit tests and in-process H3 fixtures cover both verdicts, thresholds, proof age
and budget behavior. [Installed acceptance in #99](https://github.com/onixus/Rust-trustvpn/issues/99#issuecomment-6291062141)
records system-VPN sleep/wake on two Macs at main `da92864`: data within 30 s,
reconnect in 3–4 s, no manual Stop/Start. #99 is closed. Network handoff across
sleep, installed SOCKS wake and acceptance of the later v0.6.2 artifacts
(`4123160`) remain NOT RUN. #62 and slow-Stop #70 remain open; server behavior
belongs to [onixus/tunnel](https://github.com/onixus/tunnel).

This is a heuristic, not a VPN-bound HTTPS or DNS/IPv6/guard acceptance check.
Independent remote failures can also trigger reconnect. No new runtime tests
were run for this documentation refresh.

## Transport bypass

The QUIC socket is routed around the tunnel before its first packet, exactly as
for Hysteria 2:

- Linux full tunnel: `SO_MARK 0x5254`; nftables already admits only marked output
  to the endpoint, the fwmark rule sends it through the main table.
- Android: `VpnService.protect()` on the UDP socket; the endpoint must be a numeric,
  pre-resolved address. A failing protect rejects the attempt, never a plain socket.
- Windows: the endpoint host route is pinned as before; the WFP permit for the
  service application switches from TCP to UDP for HTTP/3 profiles.
- macOS: the endpoint route via the physical interface is unchanged; the PF rule
  for root switches from `proto tcp` to `proto udp`.

`Profile::udp_transport()` selects UDP for Hysteria 2, AmneziaWG and TrustTunnel
HTTP/3. QUIC keepalive is 10 s with a 30 s idle timeout; the dataplane health
check (every 5 s, 10 s timeout) detects a dead endpoint and, since #62, a
session that carries no traffic ([dead-session detection](#dead-session-detection)).

## Verification

- `crates/engine/tests/h3_transport.rs`: in-process HTTP/3 endpoint; half-close
  with empty, 1-byte and 300 KB bodies; wrong password; protect hook runs once per
  fresh socket before the first packet, denial fails closed, hostnames rejected; a
  response finished without HEADERS fails only its request while another tunnel
  and later health checks continue.
- `scripts/interop.py` (macOS, official endpoint 1.1.0): SOCKS5 half-close with
  empty, 1-byte, short and 512 KiB bodies over HTTP/2 and HTTP/3. 320 additional
  half-close connections (sequential with a random delay before FIN, and 8 in
  parallel) passed during development.
- `scripts/tun-interop.py` (Linux, isolated namespace, endpoint 1.1.0): the full
  TUN suite — TCP 512 KiB, 12 concurrent downloads, half-close 512 KiB and
  13 bytes, DNS, UDP up to 60000 bytes, IPv6, ICMP/ICMPv6, refused UDP
  destination, SIGTERM cleanup and endpoint failure — runs for HTTP/2 and HTTP/3.
- `scripts/full-tunnel-interop.py --http3` (Linux, in `ci/linux.py`): whole-host
  IPv4/IPv6, DNS, endpoint loss and reconnect, GUI and service crashes, always-on,
  physical network handoff, early boot guard and an endpoint without IPv6.
- Windows: `ci/windows_fixture.py --protocol http3` (Jenkins parameter
  `WINDOWS_TRANSPORT=http3`) runs the Wintun service and full-tunnel E2E against
  a QUIC-listening endpoint. On 4 October 2026 the authorized run
  (`ci/windows_authorized_full.py`, timed rollback to the installed service)
  passed: Wintun TCP/UDP/ICMP, endpoint outage and reconnect, GUI and service
  crashes, always-on with a crash cycle, and a physical network loss. It passed
  again with the final service build, including the lost-response fix.
- Android: `ci/android.py` runs the network acceptance for TrustTunnel over
  HTTP/2 and HTTP/3 (`ci/android_fixture.py --protocol http3`). On the emulator
  HTTP/3 passed 10 of 10 interleaved runs after the lost-response fix.

Not yet verified for HTTP/3: the macOS system service, a physical Android device,
Windows sleep/wake, a production server and networks that throttle or block UDP.
