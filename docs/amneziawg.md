# AmneziaWG 3 preview

The shared Rust engine detects an `awg-quick` configuration (`[Interface]` /
`[Peer]`) during import and selects AmneziaWG. The saved profile carries the
explicit `amneziawg` protocol discriminator; TrustTunnel and Hysteria 2 profiles
are unaffected. The implementation is in-process: it runs no `awg`/`amneziawg-go`
binary and needs no kernel module. With no obfuscation options the wire format
is unmodified WireGuard, so a plain WireGuard configuration connects as well.

WireGuard carries IP packets, while the engine exposes TCP streams and UDP
messages to the SOCKS listener and the TUN/VpnService data planes. The session
therefore terminates flows in a userspace TCP/IP stack bound to the `Address`
of the profile and sends the resulting IP packets through the tunnel. Android
protects the UDP socket before its first packet; desktop system services use the
existing endpoint bypass, with the firewall rule opened for UDP.

## Import and export

Supported `awg-quick` keys (case-insensitive):

- `[Interface]`: `PrivateKey`, `Address` (the first IPv4 and the first IPv6
  address are used), `DNS` (IP addresses; search domains are dropped), `MTU`
  (default 1280);
- AmneziaWG 1.x/2.0: `Jc`, `Jmin`, `Jmax` (junk packets), `S1`–`S4` (random
  prefixes of initiation, response, cookie and transport messages), `H1`–`H4`
  (message type value or range), `I1`–`I5` (signature packets with the `<b 0x..>`,
  `<r N>`, `<rc N>`, `<rd N>`, `<t>` tags);
- AmneziaWG 3.x: `HeaderProtectionKey` (requires `S1`–`S4` of at least 12),
  `ContentPaddingAddition`, `RandomTrailers`, `DisableCookies`, `RekeyAfterTime`,
  `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts`
  and a ranged `PersistentKeepalive` (`a`, `a-b` or `(off)`);
- `[Peer]` (exactly one): `PublicKey`, `PresharedKey`, `Endpoint`, `AllowedIPs`
  (an entry without a prefix is a single host), `PersistentKeepalive`.

A `#` comment may follow a value, as in `awg-quick`. Up to three resolved
addresses of the endpoint are tried in order.

`ListenPort`, `FwMark`, `Table` and `SaveConfig` are ignored. `PreUp`/`PostUp`/
`PreDown`/`PostDown` are rejected: shell hooks are never executed. Unknown keys,
overlapping `H1`–`H4` ranges and malformed signature tags are rejected rather
than silently dropped. A leading `# name` comment becomes the profile name.

Export as R-TrustTunnel JSON keeps everything, including the routing policy.
Export as an AmneziaWG config writes the `awg-quick` text; the application
routing policy has no representation there. The private key is the profile
credential; like every profile it is kept in the encrypted profile store.

```ini
[Interface]
PrivateKey = EXAMPLE-NOT-A-REAL-KEY
Address = 10.8.1.2/32
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 33
S2 = 12
S3 = 40
S4 = 17
H1 = 1163027011-1163027074
H2 = 2948113920-2948113983
H3 = 377210880-377210911
H4 = 3731148800-3731149055
I1 = <b 0x16030100><r 48><t>
HeaderProtectionKey = EXAMPLE-NOT-A-REAL-KEY
ContentPaddingAddition = 16-96
RandomTrailers = on

[Peer]
PublicKey = EXAMPLE-NOT-A-REAL-KEY
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = vpn.example:51820
PersistentKeepalive = 22-30
```

## Protocol behaviour

- **Cryptography** is WireGuard's Noise_IKpsk2 (Curve25519, ChaCha20-Poly1305,
  BLAKE2s) with the reference's 8128-packet replay window; both the initiator and the
  responder role are implemented, so a server-initiated rekey works.
- **Header protection** XORs the handshake messages and the 16-byte transport
  header with ChaCha20 keyed by `HeaderProtectionKey`; the nonce is the first 12
  bytes of the random `S` prefix of that datagram.
- **Padding.** `ContentPaddingAddition`, or `RandomTrailers` without it, appends
  zero bytes inside the encrypted payload; handshake messages get a random
  trailer. Both stay within the largest datagram already seen on the path, as in
  the reference. The receiver recovers the packet from its IP length.
- **Timers** follow the reference state machine with the configured ranges:
  retransmission with jitter, rekey on send and before rejection, passive and
  persistent keepalive, key expiry and zeroing.
- **Health.** Four initiations without an answer (about 15 s with the default
  timeout) mark the session unhealthy so the caller can reconnect, e.g. after a
  network change. The count is independent of new traffic, which restarts the
  reference's own attempt counter.
- With `RandomTrailers` the reference classifies a datagram by its type range
  alone, so wide `H1`–`H3` ranges claim transport packets as handshake messages
  and drop them. This client mirrors that rule; keep those ranges narrow.

- **UDP larger than the tunnel MTU** is fragmented at the IP layer inside the
  tunnel and reassembled on receipt (IPv4 and IPv6), so the 1500-byte outer TUN
  and the 1280-byte default tunnel MTU need no agreement. Reassembly state is
  bounded (64 datagrams, 2 MiB, 10 s); overlapping fragments discard the datagram.

## Not supported

- Amnezia `vpn://` share links and the Amnezia application's JSON container;
  export the native AmneziaWG `.conf` instead.
- Several peers, roaming to a new peer address, and `ListenPort`.
- ICMP relay (ping through the tunnel), as for Hysteria 2.
- `AllowedIPs` does not program routes: the application routing policy decides
  what enters the tunnel. It is kept for export and filters the source address
  of received packets.
- Host names as destinations (SOCKS mode) need a `DNS` address in the profile;
  they are resolved inside the tunnel.

## Verification and limits

`python3 ci/amneziawg_interop.py` builds a reference peer from the official
`amneziawg-go` v3.1.20260828 device on a userspace network stack (Go modules
pinned by `ci/amneziawg_fixture/go.sum`) and runs it on loopback in three modes:
unmodified WireGuard; junk, signature packets, prefixes and type ranges; and the
3.x header protection, content padding, random trailers and configured timers.
Each mode checks TCP payload integrity over IPv4 and IPv6, eight parallel
streams, a destination resolved by DNS inside the tunnel, a refused port, UDP
echo on independent streams from 1 to 20000 bytes (fragmented above 1252), and rejection of a wrong preshared key. The third
mode also holds a stream open across several key rotations. The fixture creates
no TUN device and changes no routes or an existing VPN; it needs Go 1.26.

The same script runs the forwarding peer of the Android fixture against local
targets: TCP, a refused port and fragmented UDP.

**Android.** `ci/android.py` runs the emulator network acceptance with a third
protocol, `amneziawg`, next to TrustTunnel and Hysteria 2. The fixture container
runs the official device with header protection, content padding and random
trailers as a forwarding peer: a userspace stack terminates the tunnel's flows
and relays them to the test targets, so the container has no TUN device and no
capabilities. CI nodes without Go build it in a digest-pinned `golang` image
(`ci/amneziawg_server.py`). The test covers VpnService over IPv4 and IPv6 (TCP
512 KiB, UDP 1 to 60000 bytes), system DNS, a 60-second peer outage with the
blocking TUN retained and reconnect, per-app and per-flow routing, an IPv4-only
endpoint and an unavailable endpoint at start. WireGuard has no connection to
lose, so the app notices a silent peer only through unanswered traffic; the test
keeps probing while it waits.

Not established: a system full tunnel on Windows, Linux or macOS with an
AmneziaWG profile, a physical Android device, a production server, cookie
replies of a loaded server, and throughput. Flows are terminated twice (TUN stack and tunnel
stack), which costs CPU compared with a packet-level WireGuard client.
