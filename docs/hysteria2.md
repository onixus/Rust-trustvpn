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

Supported client configuration fields are `server`, `auth`, `name`,
`tls.sni`, `tls.insecure`, `tls.pinSHA256`, and
`obfs: {type: salamander, salamander: {password: ...}}`.
The last two TLS overrides are preserved for round-trip compatibility but are
currently rejected at connection time. Normal connections require certificate
validation. R-TrustTunnel JSON can embed a custom CA certificate.

```yaml
server: vpn.example:443
auth: EXAMPLE-NOT-A-REAL-PASSWORD
tls:
  sni: vpn.example
obfs:
  type: salamander
  salamander:
    password: EXAMPLE-OBFUSCATION-KEY
```

Export as R-TrustTunnel JSON to preserve all routing, DNS and certificate
settings. Link export reports fields that the Hysteria URI cannot represent.
Endpoint/CLI TrustTunnel TOML export is unavailable for Hysteria profiles.
YAML aliases, excessive nesting and unknown security/transport options are
rejected. File references are not loaded implicitly.

Unsupported features include port hopping, Gecko, Realms, ECH, mTLS, custom
congestion/bandwidth settings, fingerprint imitation, insecure TLS and certificate
pin overrides. Unsupported configuration is rejected rather than silently ignored.
There is no ICMP relay in Hysteria 2.

## Verification and peer limits

`python3 ci/hysteria_interop.py` runs a checksum-pinned official Hysteria 2.12.3
server on loopback with temporary credentials and certificates. It checks TCP
payload integrity, independent UDP sessions, fragmentation, and credential/TLS/
obfuscation rejection. It does not change host routes or an existing VPN.

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
