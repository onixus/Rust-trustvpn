# Hysteria 2 preview

The shared Rust engine detects the protocol during import. `tt://`, TrustTunnel
TOML and existing profile JSON select TrustTunnel. `hy2://`, `hysteria2://` and
Hysteria client YAML/JSON select Hysteria 2. The saved profile carries an explicit
protocol discriminator; connecting never guesses from a port or retries another
protocol after authentication failure. Existing TrustTunnel profiles remain
compatible.

The Hysteria implementation uses QUIC, HTTP/3 authentication, multiplexed TCP
streams and UDP datagrams, with optional Salamander obfuscation. It does not run
an external client process. Android protects and binds the QUIC socket before
sending traffic; desktop system services use the corresponding endpoint bypass
and firewall rules. Hysteria 2 is separate from the deferred TrustTunnel HTTP/3
system-tunnel work.

## Import and export

Supported client configuration fields:

- `server`, including a port-hopping set (`vpn.example:443,20000-30000`), `auth`, `name`;
- `tls.sni`; `tls.pinSHA256` and `tls.insecure` are preserved for round trip but
  rejected at connection time (see below);
- `obfs` of type `salamander` or `gecko` (`password`, `minPacketSize`, `maxPacketSize`);
- `transport.udp.hopInterval`, or `minHopInterval` with `maxHopInterval` (at least 5 s;
  Go durations such as `7.5s` or `1m30s`, kept to the millisecond);
- `bandwidth.up`/`down` (`bps`/`kbps`/`mbps`/`gbps`/`tbps`, decimal bits per second);
- `congestion.type` (`bbr` or `reno`; only the `standard` BBR profile);
- `quic` receive windows (at least 16 KiB, no upper limit as upstream),
  `maxIdleTimeout` (4–120 s), `keepAlivePeriod` (2–60 s, independent of the idle timeout)
  and `disablePathMTUDiscovery` (always in effect: the transport uses a fixed
  1200-byte QUIC MTU).

Local listener sections of the official client (`socks5`, `http`, forwarding,
TProxy, redirect, `tun`) are ignored: they carry no transport or security
settings. R-TrustTunnel JSON can additionally embed a custom CA certificate and a
mutual-TLS client certificate and key (`client_certificate`, `client_key`). The
YAML `tls.clientCertificate`/`clientKey` file paths are rejected, because file
references are never loaded implicitly.

```yaml
server: vpn.example:443,20000-30000
auth: EXAMPLE-NOT-A-REAL-PASSWORD
tls:
  sni: vpn.example
obfs:
  type: salamander
  salamander:
    password: EXAMPLE-OBFUSCATION-KEY
transport:
  udp:
    hopInterval: 30s
bandwidth:
  up: 50 mbps
  down: 200 mbps
```

Export as R-TrustTunnel JSON to preserve all routing, DNS, certificate,
hop-interval, bandwidth, QUIC and Gecko size settings. A `hy2://` link carries the
server port set, SNI, obfuscation type and password, and reports every other
field it cannot represent. Endpoint/CLI TrustTunnel TOML export is unavailable
for Hysteria profiles. YAML aliases, excessive nesting and unknown security or
transport options are rejected.

### Port hopping

Every hop picks a random port of the set and opens a fresh local UDP socket; the
previous socket keeps receiving for one more interval, as in the official
client. A port given as a range of one (`443-443`) rotates only the local
socket. QUIC sees one fixed server address. On Linux and Android each new socket
is marked or protected before its first packet, and a failure skips the hop
instead of sending unprotected. macOS PF and Windows WFP bypass rules allow the
whole port set for the endpoint address only.

### Bandwidth and Brutal

`bandwidth.down` is announced in `Hysteria-CC-RX`. With `bandwidth.up` set, the
client switches to Brutal after authentication at the upload rate, capped by the
server's announced receive rate (`auto` keeps regular congestion control).
Brutal ignores loss for its rate and compensates up to 25% observed loss.
Quinn derives pacing from the congestion window, so the window is one smoothed
RTT at the target rate (at least ten datagrams), which paces about 25% above the
target; the official client keeps two RTTs and paces exactly at the rate. Without
`bandwidth.up` the selected `bbr`/`reno` controller (default: Cubic) is used.

### Gecko

Gecko fragments QUIC long-header (handshake) packets into 2–8 randomly padded
fragments on top of Salamander with the same password (at least 4 bytes);
short-header packets are plain Salamander. Fragments are reassembled with the
upstream limits (8 s, 8 messages per source). Gecko and Salamander servers are
not interchangeable.

### Not supported

Insecure TLS and certificate pin overrides (see below), ECH, Hysteria Realms,
Chrome QUIC fingerprint parroting, mimic, `fastOpen`/`lazy`, and the
`conservative`/`aggressive` BBR profiles are rejected rather than silently
ignored. There is no ICMP relay in Hysteria 2.

- **Certificate pin.** `pinSHA256` would be an additional check on top of
  normal CA validation; enabling it changes the TLS verification path and is
  pending an explicit decision. `insecure`, alone or with a pin, stays rejected.
- **ECH** needs HPKE, which the `ring` crypto provider lacks; rustls offers it
  only through aws-lc-rs, a new native build dependency on every platform.

## Verification and peer limits

`python3 ci/hysteria_interop.py` runs checksum-pinned official Hysteria 2.12.3
servers on loopback with temporary credentials and certificates. It checks TCP
payload integrity, independent UDP sessions, fragmentation, and credential/TLS/
obfuscation rejection. A second server uses Gecko with required mutual TLS and
rejects a missing client certificate and a Salamander client. Port hopping runs
through a userspace relay on 16 ports with 20 ms delay each way, standing in for
the server's Linux port-range redirect: one stream survives several 5-second
hops, every hop must use a new client socket, and a 5 MB upload at a 20 Mbit/s
Brutal rate must take over 1.2 s (about 0.3 s without Brutal). It does not change
host routes or an existing VPN.

The official server's UDP reply buffer is 4096 bytes. The fixture checks large
outgoing requests using a small response containing their size and SHA-256;
it checks full echo replies separately up to 4000 bytes. macOS's default UDP
socket limit also prevents a local official server from sending 60 KB datagrams;
the Mac fixture stops at 8192 bytes, while Linux checks through 65507 bytes.
UDP remains an unreliable transport: fragmentation does not provide retransmission.
The official server closes both TCP directions when either reaches EOF, so
half-close-dependent exchanges are not claimed as supported.

Production opt-in verification uses `RTRUST_HYSTERIA_TEST_PROFILE` with an
owner-only local configuration file and the ignored `hysteria_live` test. Never
commit the configuration or include its contents in CI artifacts. Current
production transport checks cover TCP, UDP DNS, encrypted DNS through the tunnel
and rejection of a wrong password. Linux Jenkins #18 additionally passed system full-tunnel, dual-stack DNS/TCP,
endpoint loss/reconnect, process crash, Always-on and network handoff for both
protocols. Android #26 passed emulator VpnService and reinstall/upgrade tests.
Huawei passed production Hysteria 2 and encrypted DNS from a separate app UID.
macOS #66 passed transport/build/package/UI checks; installed macOS Hysteria
full-tunnel and Windows runtime acceptance remain unverified.

Protocol references: [URI scheme](https://v2.hysteria.network/docs/developers/URI-Scheme/),
[wire protocol](https://v2.hysteria.network/docs/developers/Protocol/),
[official UDP implementation](https://github.com/HyNetworks/hysteria/blob/app/v2.12.3/core/server/udp.go).
