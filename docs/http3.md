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

Before #62 a session could stay "Connected" after a reconnect while no flow got a
reply, because `_check` alone kept passing. Since main after 0.6.1 (PR #69),
`Session::health` (`crates/engine/src/lib.rs`) also fails with `Degraded` when the
session carries no traffic. The check is session-level, so it applies to every
transport, not only HTTP/3. A session is degraded only when both hold:

- outbound data has stayed unanswered for 20 s;
- within the last 60 s and since the last inbound byte, at least 5 TCP opens
  failed in transport, or at least 5 were accepted but stayed silent, across at
  least 3 distinct destinations. The two kinds are counted separately
  (`crates/engine/src/liveness.rs`).

These do not count as evidence: an idle tunnel, lost `_check` responses, endpoint
rejections and authentication or destination errors, shared UDP/ICMP relay
streams, and one application retrying one or two dead hosts. A failed health
check ends the data plane and the normal supervisor reconnects.

The exit carries `proven`: whether the session ever delivered an inbound byte.

- Desktop and iOS: an unproven degraded session never restores the reconnect
  budget, however long it lasted, so an endpoint that hands out dead sessions
  reaches the normal blocked cooldown instead of a fast loop
  (`crates/control/src/recovery.rs`). A proven session connected for at least
  30 s restores it as before.
- Android: any session that ended after 30 s of real time restores the
  finite per-session budget unless it ended degraded without delivering data
  (`crates/mobile/src/reserves.rs`), so exits over days cannot block the VPN
  permanently. Unproven or short exits still count.
- macOS records `transport_degraded proven=<bool>` in the service event log.

Liveness keeps only in-memory counters and a per-session keyed 64-bit host-hash
set. No destination or address is stored, logged or exposed.

Degradation enters the existing guarded reconnect path without direct fallback.
Verified by unit tests and `crates/engine/tests/h3_transport.rs`; no installed
package or device acceptance has been run for it.

This is a heuristic, not a VPN-bound HTTPS acceptance check. An endpoint that
returns 200 for `_check` but rejects CONNECT with 5xx remains outside its
coverage; independent remote failures can also trigger reconnect. Installed
macOS sleep/wake and roam reproduction remains open in
[#62](https://github.com/onixus/Rust-trustvpn/issues/62), slow Stop in
[#70](https://github.com/onixus/Rust-trustvpn/issues/70), and the server cause in
[onixus/tunnel#30](https://github.com/onixus/tunnel/issues/30).
These changes were merged after the published v0.6.1 tag.

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
