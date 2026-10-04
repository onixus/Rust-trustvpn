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
check (every 5 s, 10 s timeout) detects a dead endpoint.

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
  a QUIC-listening endpoint.

Not yet verified for HTTP/3: Android VpnService on the emulator, the macOS system
service, Windows sleep/wake, a production server and networks that throttle or
block UDP.
