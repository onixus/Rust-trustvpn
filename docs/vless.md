# VLESS over a CDN (WebSocket + TLS) preview

The shared Rust engine imports `vless://` links issued by the CDN panel of the
server ([onixus/tunnel](https://github.com/onixus/tunnel), `cdn.py`
`render_client`) and connects through Xray-core behind a CDN with VLESS over
WebSocket and TLS. The saved profile carries the explicit `vless` protocol
discriminator; TrustTunnel, Hysteria 2 and AmneziaWG profiles are unaffected.
The client runs no Xray binary: the WebSocket and VLESS layers are in-process
(`crates/engine/src/vless`).

## Link and profile

The server issues:

```text
vless://<uuid>@<address>:<port>?encryption=none&security=tls&sni=<domain>&host=<domain>&fp=chrome&type=ws&path=<path>&alpn=http%2F1.1#<name>
```

XHTTP links carry `type=xhttp&mode=auto` instead of `alpn`. The profile stores:

| Link | Profile |
| --- | --- |
| `<uuid>` | `endpoint.password` (canonical lower-case UUID; `endpoint.username` is `vless`) |
| `<address>:<port>` | `endpoint.addresses` (one entry; IPv6 in brackets; the port is required) |
| `sni`, `host` | `endpoint.hostname` (a DNS name, never an IP; `host` must be empty or equal to `sni`) |
| `type`, `path`, `fp`, `mode` | `vless.transport`, `vless.path` (secret), `vless.fingerprint`, `vless.xhttp_mode` |
| `#<name>` | `name` (control and bidi characters removed; the SNI when empty) |

`endpoint.has_ipv6` is `false`: the CDN origin container has no IPv6 egress, so
IPv6 flows fail locally instead of disappearing in the tunnel. The field is
not forced: setting `has_ipv6: true` in R-TrustTunnel JSON makes sense only
when the server does have IPv6 egress.

Import fails closed: only `encryption=none` and `security=tls` are accepted, and
unknown options, duplicates, REALITY (`pbk`, `sid`, `spx`, `pqv`), `flow`,
`allowInsecure`/`insecure`, `headerType`, `serviceName`, `authority`, `ech`,
`extra`, `fp` other than `chrome`, a non-canonical UUID and paths with
controls, spaces, `%`, `?` or `#` (including `?ed=`) are rejected. Errors name
the field, never its value.

Export: R-TrustTunnel JSON and the link, in the server's own field order, so a
server link round-trips byte for byte. Policy, a custom CA, DNS upstreams and
other JSON-only fields are reported as losses.

## What connects

| Supported | Not supported |
| --- | --- |
| WebSocket over TLS (ALPN `http/1.1`) | XHTTP: imports and exports, connecting reports `VLESS XHTTP transport` as unsupported |
| TCP flows to IPv4, IPv6 and domain targets | mux / XUDP, early data (`ed`), uTLS / browser fingerprints |
| UDP up to 8190 bytes per datagram | ICMP relay |

- **Fingerprint.** `fp=chrome` is kept for export, but the TLS handshake is the
  client's own (rustls). The profile details say "Browser TLS fingerprint is not
  emulated".
- **One connection per flow.** Each TCP flow and each UDP source/destination
  pair is its own TLS connection and WebSocket upgrade (at most 256 TCP flows
  per session; 64 UDP flows per tunnel and 1024 per session). There is no
  shared multiplexed session. Every flow socket is marked or protected before
  connect; the endpoint name is resolved once when the session starts, never
  per flow.
- **UDP flow table.** A full table evicts the least recently active flow
  (DNS flows that already got their answer first) instead of dropping new
  datagrams, so a resolver that takes a new source port per query cannot lock
  UDP out. DNS flows (destination port 53) close 5 s after their last packet;
  any UDP flow the server has not answered for 60 s is closed, and the next
  datagram opens a new one. Only answers count: outgoing datagrams do not
  keep a flow alive.
- **Dead paths.** After 30 s without anything from the server a flow sends a
  WebSocket ping. Xray answers it only when it reads the frame, after all data
  sent before it, so a slow target can delay the answer for as long as its
  buffers take to drain. The flow is therefore closed as dead only when the
  ping is unanswered for 15 s **and** nothing was written to the server in the
  last 120 s; a single frame write that cannot complete for 45 s also ends the
  flow. An idle path that died without FIN or RST ends a TCP flow within about
  45 s, and a blocked upload within 45 s. A flow that keeps writing small
  amounts into a dead path is left to TCP's own retransmission timeout; a UDP
  flow in that state is replaced after 60 s without answers (see above).
- **Refused flows back off.** A UDP flow whose handshake fails, or which the
  server closes without sending a byte, waits 2 s before the same pair may
  dial again. Xray closes a flow to an unreachable or refusing target the same
  way as a flow with a revoked UUID, so the session reacts only to a varied
  run: at least 8 flows in a row (TCP or UDP) closed without a byte, covering
  at least 4 TCP destinations or 8 UDP source/destination pairs (a resolver
  with a new source port per query counts as many pairs). Then new flows are
  not dialed for 2 s, doubling up to 30 s with each further such flow; the
  first flow that receives data resets this. One host that keeps refusing, or
  a few dead hosts, never delays the session.
- **UDP size.** Xray's buffers carry 8190 payload bytes with the 2-byte length
  prefix. Larger downlink packets are dropped silently and larger uplink ones
  are split, which breaks datagram boundaries, so the client drops datagrams
  above 8190 bytes in both directions and counts them; the rest of the tunnel
  is unaffected.
- **Half-close.** When the application finishes sending, the client keeps the
  flow open for the answer until the server closes or 10 s pass without data.
  Xray's outbound closes 1 s after the uplink ends.
- **No open confirmation.** VLESS has no CONNECT answer: the response header
  arrives only with the first downlink data. A wrong path is an HTTP 404 at
  upgrade time; redirects are not followed. A wrong or revoked UUID gives a
  successful WebSocket upgrade followed by a close, so connecting succeeds
  and the status can show "connected" while new flows close empty. After the
  varied run above the session backs off, and health reports "Endpoint closed
  recent streams without data" rather than an authentication error, because
  the client cannot tell a revoked UUID from unreachable targets.
- **Health.** That varied run fails health. Otherwise a WebSocket upgrade in the
  last 30 s (by both the monotonic and the wall clock, so device sleep counts)
  proves the endpoint; without one, one probe upgrade without a VLESS request
  is made.

## Privacy

TLS terminates at the CDN. The CDN sees the WebSocket path, the VLESS UUID and
all tunneled traffic that is not itself encrypted end to end. The path and the
UUID are secrets of the profile: they are redacted from logs, `Debug`, errors
and summaries, and kept in the encrypted vault.

## Known limitations

- The kill switch admits TCP to the endpoint addresses, and CDN addresses are
  shared with other sites (follow-up). On macOS (PF `pass … user root`) and
  Windows (WFP filter by the service's `ALE_APP_ID`) only the tunnel service
  may reach those addresses, so other sites on the same CDN addresses are
  unreachable while the full guard is on. On Linux, unmarked traffic to those
  addresses is routed into the tunnel, and such sites stay reachable.
- Older client versions cannot read a vault that contains a VLESS profile.
- Android and iOS do not register the `vless` URL scheme yet; pasted text,
  files and Android QR codes go through the shared parser.
- Interop against Xray-core 26.10.21 is a separate loopback fixture;
  installed-package acceptance through a real CDN is not done.
