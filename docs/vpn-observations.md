# VPN observations (issue #31)

`State::Connected` is a lifecycle state, not a network availability verdict.
The shared model lives in `rtrust-control::observations`; desktop, Android and
iOS use that contract. No observation contains a hostname, URL, credential,
profile content or free-text error. Nothing is sent to a server.

## Contract and compatibility

IPC version 6 requires observation schema 2 and an explicit capability response.
Version 6 adds the macOS session owner (Start reply, `Recover.owner`); see
`docs/macos-system.md`.
Schema 2 adds native network-change/resume events; schema 1 peers are rejected
during capability negotiation, and the Android/iOS adapters accept only schema 2.
Version 3 also adds opt-in persistent Linux/Windows recovery; observation schema remains 2.
The desktop client negotiates through a separate authenticated, read-only
`Capabilities` connection **before** sending a profile or issuing a mutation.
Negotiation is available while another lease or Always-on owns the service.
Version 1–5 clients/services are incompatible with version 6: upgrade the UI and service
together. A mismatch fails before a new Start, Recover or update reservation;
an existing service-owned VPN/guard is not disabled to achieve compatibility.
Profile, routing-journal and boot-policy schema versions are unchanged.
The Python IPC acceptance clients must use the same negotiated IPC version.
Legacy evidence produced with IPC v2 remains evidence for that earlier build.
See [recovery.md](recovery.md) for recovery semantics and
[system-diagnostics.md](system-diagnostics.md) for the IPC v4 endpoint probe.

Every observation carries outcome, source, applicable mode, timestamp,
freshness interval and stable reason. Results are `passed`, `failed`,
`configured`, `unknown`, `stale` or `unsupported`. Configuration/lifecycle
observations never become `passed` just because a worker exists. A UI may show
verified availability only while all five observations are fresh passes.
`Blocked` alone does not attest to a functioning firewall, nor prove that
internet access is unavailable. Guard and connectivity observations are separate.

Snapshots are scoped to a lease/worker. Reconnect, control loss and Stop
invalidate its generation. A result captured under an old generation is
rejected. Successful/configured observations expire after six seconds;
clock reversal invalidates them as well. A polling gap above six seconds is a
`lifecycle_gap`, not proof of sleep or a particular network failure. Transport
stays stale after that gap until a real worker transition.

## Native network-change and resume events

Desktop services (`apps/tun/src/netwatch.rs`) record two OS-attested events per
lease, `network_changed` and `resumed`, with matching stale reasons:

- **Resume** is measured by the kernel, not by a polling gap: the growth of
  suspended time between a clock that counts sleep and one that does not
  (Linux `CLOCK_BOOTTIME − CLOCK_MONOTONIC`, macOS
  `CLOCK_MONOTONIC − CLOCK_UPTIME_RAW`, Windows `GetTickCount64 −
  QueryUnbiasedInterruptTime`). Two seconds or more is reported. Like a gap,
  transport stays stale until a real worker transition, because the worker may
  not yet have noticed a dead session.
- **Network change** is a change in link state or unicast addresses of any
  interface except loopback and the service's own TUN (`rtrust0`, `utun5254`,
  `RTrustTunnel`). Route edits, including the guard's own, are ignored. Linux
  wakes on rtnetlink link/address groups and macOS on the routing socket; both
  settle bursts for 500 ms and confirm by re-reading the interface list, so a
  renewed lease with unchanged addresses is not a change. Windows polls the
  adapter list every two seconds; Linux/macOS also re-check every ten seconds
  in case a notification is lost.
  A change bumps the generation: a probe started earlier cannot be applied, and
  earlier passes become stale. The running worker's lifecycle status is not
  proof either way and is reported again on the next poll.

With allowed backup profiles (docs/failover.md), the service also records
`failed_over` when it moves to another candidate.

Events are advisory: they do not reconnect, change routes/DNS or the guard
(automatic recovery is issue #34). Desktop summaries show the latest such event
for one minute. Capabilities advertise `network_events=true` for the desktop
services. Android now invalidates observations when ConnectivityManager
changes the selected non-VPN underlying Network or reports changed link
properties for that network. Repeated callbacks for another network or identical
properties are not events. Android now also samples
[SystemClock](https://developer.android.com/reference/android/os/SystemClock):
`elapsedRealtime` includes deep sleep and `uptimeMillis` excludes it. An increase
of at least two seconds in their difference invalidates the active session on
the first existing widget poll after CPU execution resumes. Clock reads are
bracketed by uptime samples; the new lower bound is compared with the old
upper bound so read skew cannot inflate a short sleep past the threshold.
A sampling span over 50 ms, invalid/reversed clocks or a new session only reset
the baseline. Cleanup revokes the session before
native Stop. Screen unlock and an awake polling delay are not resume evidence;
this is kernel-clock evidence, not a native wake callback or measured device latency.

iOS PacketTunnel now uses an
[NWPathMonitor](https://developer.apple.com/documentation/network/nwpathmonitor):
the first path establishes a baseline and subsequent OS path updates invalidate
observations. The provider forwards the native
[wake callback](https://developer.apple.com/documentation/networkextension/neprovider/wake%28%29)
as `resumed`. The monitor runs on the provider's existing serial queue, is
cancelled on Stop/start failure, and late callbacks from an old provider
generation are ignored. These are advisory path events, not independent proof
of physical-interface traffic or DNS/guard health. No network identifiers cross
the JNI/C boundary or enter the observation journal.
No successful DNS/route/guard evidence is invented in their absence.

The local in-memory journal contains at most 64 timestamped event enums and
generations. It covers lease start, worker failure/recovery, polling gaps,
desktop network changes and resumes, control loss and cooperative Stop. It is
not durable across process restart. Observations are advisory and do not change routing, DNS or guard.

## Implemented observation matrix

| Platform / mode | Transport | Route / DNS / guard | End-to-end connectivity | UI |
| --- | --- | --- | --- | --- |
| Linux selected / full / Always-on | Service worker lifecycle; failure/reconnect/gap; netlink network change, kernel-clock resume; full: `passed` while a service DNS answer through the tunnel is fresh | Full: service probe (see below), route Unknown; selected: DNS/guard `unsupported` | Unknown | Native and WebView share the Rust verdict |
| Windows selected / full / Always-on | Service worker lifecycle; failure/reconnect/gap; polled adapter change, kernel-clock resume; full: `passed` while a service DNS answer through the tunnel is fresh | Full: service probe (see below), route Unknown; selected: DNS/guard `unsupported` | Unknown | Native and WebView share the Rust verdict |
| macOS selected / full | Service worker lifecycle; failure/reconnect/gap; routing-socket network change, kernel-clock resume; full: `passed` while a service DNS answer through the tunnel is fresh | Full: service probe (see below), route Unknown; selected: DNS/guard `unsupported` | Unknown | Native and WebView share the Rust verdict |
| Desktop SOCKS | Proxy lifecycle only | Unsupported for the system path | Unknown | Explicit proxy scope |
| Android | Shared mobile worker lifecycle; failure/recovery/gap; selected underlying Network/link-property changes; kernel deep-sleep clock evidence | Unknown; VpnService setup is not a live audit of DNS or lockdown | Unknown | JNI JSON, localized summary of checks that have a result, no green lifecycle badge |
| iOS | Shared mobile worker lifecycle; failure/recovery/gap; provider path updates and native wake callback | Unknown; NetworkExtension status is not a live audit | Unknown | Redacted provider message; generation/age checked; localized summary |

Desktop services advertise `system_probes=true` (issue #81, see below);
Android and iOS do not. The desktop GUI may
fold its own path check of one user-chosen destination into the snapshot it
displays, as `source: app_probe` for route and connectivity only; a service
never sends that source, and it replaces only open or expired service results,
never a current `system_probe` row.
The adapters retain
existing platform differences; this change does not make unsupported checks
available or constitute packet-level leak acceptance.

Since 0.6.1 (#67) every client lists only checks that produced a result. Route
and connectivity have no service producer, so while they are
Unknown they are omitted instead of shown as "unchecked": a running transport
reads "Transport: running" (iOS/Android widgets: "Transport running"). The amber
colour still means that nothing is verified. Failed, stale and unsupported
results are always shown. Desktop system-path diagnostics are reported separately;
see [system diagnostics](system-diagnostics.md).

## Service system probes (issue #81)

In whole-computer mode the Linux, macOS and Windows services probe their own
DNS, guard and transport, read-only, and publish `source: system_probe` rows.
Wire shape is unchanged (IPC 6, schema 2): verdicts use existing enums,
`passed`/`failed` with `configuration_applied`, an inconclusive or timed-out
check `unknown` with `check_unavailable`.

- **Schedule.** One run at a time per lease, on the lease loop's own timer:
  2 s after Connected or any invalidation, then 15 s after the previous run
  ended (`PROBE_INTERVAL_MS`), for as long as the session is Connected.
  Status never starts a probe; but the client holding the lease polls Status
  as a keepalive (see known limitations), so in practice probes run every
  15 s throughout a Connected session whether or not a window shows them.
  Outside Connected a due tick is not re-armed on a short timer: the next
  lifecycle change (reconnect, network change, resume) re-arms it; Windows
  defers a run whose permit list is unavailable by a full interval.
  Each run has a 5 s hard deadline; its parts (own rules, bypass attempts,
  DNS) each have 4 s (`PART`), so a slow part (e.g. `pfctl`) reports only its
  own checks `unknown` and keeps the tunnel DNS reply gathered beside it; each
  tool has 2 s. A run is dropped (its sockets closed, children killed) on
  reconnect, worker failure, network change, resume, sleep, access expiry and
  Stop. A result is applied only to the running generation it started in and
  is stamped with the run's start, not its completion. Blocking OS calls
  (Windows IP Helper/WFP/registry, macOS SCDynamicStore) cannot be
  cancelled; at most one stays alive per backend, and while it is stuck later
  runs report those checks `unknown` instead of stacking threads. On Windows
  the rules read, the bypass datagrams and the DNS read share one blocking
  call; it checks a flag cleared when its run is dropped before every
  datagram and before the DNS read, so after Stop (the run is dropped before
  WFP teardown) it sends nothing. Rows carry `valid_for_ms = PROBE_TTL_MS`
  (30 s: interval plus two deadlines plus 5 s, since evidence is stamped with
  its run start); readers cap `system_probe` rows at 30 s and every other
  service row at 6 s. Without a repeat, green falls back to blue after 30 s.
  A probe failure expires with its TTL; on a new generation every probe row
  is stale.
- **Guard** is `passed` only if the service's own objects read back exactly as
  the installer's generator produces them (Linux `nft -j list table inet
  rtrust_full` against `guard_rules()`; macOS PF enabled, standard root, no
  other non-empty `com.apple` anchor, our anchor equal to `pfctl -n` of
  `policy()`; Windows every filter of our provider and every filter of any
  provider in our sublayer, read per layer, equal to `filter_specs()`: a
  foreign filter placed in our sublayer is a mismatch, `failed`), **and** one unmarked UDP datagram to `192.0.2.1:9` and
  one to `[2001:db8::1]:9`, bound to every physical default-route interface,
  are refused locally. Where the interface has an IPv6 default route, the IPv6
  datagram must be refused too (an unreachable errno or socket setup failure
  is `unknown`); only without one does IPv6 count as absent. Any missing/changed
  rule or a datagram that leaves is `failed`; everything else is `unknown`.
  The probe socket never carries the transport mark or an endpoint address.
  **macOS differs** (installed package, macOS 26.5.2, full mode): PF drops
  output silently, so `sendto` returns success while nothing leaves (tcpdump
  on en0 empty, our block rule's packet counter up), and with the tunnel up an
  unscoped physical default no longer serves interface-scoped lookups for far
  targets, so `192.0.2.1` fails with `ENETUNREACH` in routing before PF. The
  macOS probe therefore sends to the interface's own default gateway (port 9;
  IPv6 only a link-local gateway of that interface, without one IPv6 is
  absent and nothing is sent) after `route -n get -ifscope` confirms the
  scoped route, and watches the interface on a read-only BPF tap (`/dev/bpf*`,
  SEESENT verified, Ethernet only, a UDP-to-port-9 filter). The datagram on the
  wire is `failed`; silence with no BPF drops **and** our final `block drop out`
  rule counting more packets (`pfctl -vsr`) is a refusal; anything else
  (no route, `link#N` gateway, an endpoint gateway, no tap) is `unknown`. If the
  guard is broken, that one byte reaches the LAN gateway's discard port.
- **DNS** is `passed` only if the tunnel resolver configuration is the
  service's own (Linux resolved link `rtrust0`: that server, `~.`,
  default-route; macOS our SCDynamicStore entry, compared not installed, and
  present in `scutil --dns`; Windows Wintun interface settings), the route to
  the resolver uses the VPN interface, a `. IN NS` query bound to that
  interface gets a matching NOERROR reply with a well-formed answer record, and every other resolver the OS
  may select (other links/adapters, IPv6, resolv.conf, NRPT, scoped
  resolvers) is contained by a `passed` guard of the same run. A foreign
  resolver with an unproven guard, a changed configuration or a resolver
  route outside the tunnel is `failed`.
- **Transport** becomes `passed` while a reply from the tunnel resolver over
  the tunnel interface in the current generation is fresh and the worker
  runs; otherwise lifecycle `configured` as before. After a polling gap or
  resume, only such a reply from a run started after it restores transport;
  lifecycle `configured` still waits for a worker transition.
- **Selected networks (split).** DNS and guard are `unsupported` from the
  start and never `passed`: there is no kill switch, and system DNS is not
  probed. A selection that carries the resolver gets the VPN resolver (and on
  Windows a DNS lock), one that does not keeps the system resolver; neither is
  verified. UIs show "not checked" and "off" without claiming a leak; the
  status stays blue. No probe runs.
- **Privacy.** Results are enums and timestamps only. Tool output, argv,
  addresses, resolvers and interface names are parsed in memory and dropped;
  nothing is logged.

Known limitations of the probes (accepted, fail-closed: each reads as
`unknown`, never `passed`):

- **Probes run without a reader.** The desktop client's lease connection
  polls Status every 2 s and the always-on supervisor every 1 s as a
  keepalive, whether or not a window shows the rows, so the service cannot
  tell a reader from a keepalive. It probes every 15 s for the whole
  Connected session (on macOS about a dozen short-lived tool processes and
  one DNS query through the tunnel per run). A result is shown only if a
  later read finds it fresh in the same generation; internal paths also
  sample the monitor, so an unread result is not guaranteed to be discarded.
  Reducing this needs an IPC flag meaning
  "a UI is reading" (capability-gated, sent only by clients whose UI polls);
  that is a follow-up, not done here.
- **Large macOS route tables.** `netstat -rn` output over 64 KiB, or more than
  eight physical default-route interfaces, makes the bypass check
  `unknown`; such hosts never reach a `passed` guard.
- **Refusal errnos are unverified.** `EPERM` (Linux) and `WSAEACCES` (Windows
  ALE) are the expected local refusals but have no installed-package capture
  yet (lab gate below). Another errno is `unknown`. macOS uses no errno (see
  Guard above).
- **macOS block counter is shared.** Other traffic our guard drops also counts;
  the counter only shows PF dropped something meanwhile. The proof of no leak
  is the empty tap; the counter guards against a tap that silently misses.
- **A send already in progress.** On Windows a datagram whose send call had
  started when its run was dropped can still complete; every later one is
  suppressed. Other platforms run no send outside the polled run.
- **WFP enumeration rights.** The read-back sees only filters the service may
  enumerate; a filter hidden by its security descriptor is not compared.
  More than 65 536 enumerated or 4 096 kept filters reads `unknown`.
- **Defensive-branch tests.** Some unit tests cover branches no production
  input reaches (an empty expected rule set, an endpoint equal to a
  documentation probe target). They pin the parser and classifier contracts,
  not runtime behaviour, and are no evidence for an installed package.

Lab-unconfirmed (no installed-package run yet): the local refusal errno
(Linux `EPERM` with the kernel's bound-interface on-link fallback; for IPv6
the unreachable policy route may answer first, which would keep dual-stack
Linux guard `unknown`; Windows `WSAEACCES` at ALE; on macOS that the BPF tap
sees an unguarded probe datagram, the `tap_sees_an_unguarded_datagram` lab
test); nft JSON rendering across
nftables versions; `resolvectl` output format; `pfctl -sr` versus `pfctl -nv`
rendering (a same-count, own-label difference is `unknown`, not `failed`);
`scutil --dns` rendering of the supplemental entry; WFP enumeration of the
conditions as installed. A mismatch in any of these reads as `unknown` or, for
a changed rule set, `failed` (yellow) on a healthy host and needs a lab
capture to correct.

## Validation and remaining acceptance

Code validation for this PR: Rust regression tests for incompatible schemas,
legacy responses, timeout, occupied-lease capability negotiation, failed
transport with unobserved DNS/guard, expiry/clock reversal, lifecycle gaps,
stale generation rejection, Stop and bounded secret-free journal. Native UI
regressions and both desktop UI compilation are also included. Separate Linux
container tests, Windows target compilation, Android Java/lint and the iOS
simulator build are recorded in the PR with their actual outcomes.

An iOS simulator build does not provide a functioning system VPN on an iPhone.
Windows target compilation does not prove installed WFP/Wintun behavior. Linux
container unit tests do not establish a physical-node or installed-package gate.
Existing historical acceptance reports apply to their own commits and packages.

Issue #31 remains open: durable event history if required, installed-package timing/cancellation and
actual DNS/route/guard/system-connectivity evidence still need acceptance.
Issue #33 supplies the real-path probe; issue #36 tracks package/device evidence.
No release is published or promoted by this PR.

### Validation recorded on 2026-10-10

| Check | Result | Boundary |
| --- | --- | --- |
| macOS Rust suites: control, tun, desktop, mobile, iOS, Android codec, native UI | Passed: 83 tests, no failures | Host tests; Android JNI module needs a target build |
| Native + WebView macOS compilation | Passed | No installed VPN session was altered |
| Linux ARM64 container control/tun/mobile suites | Passed: 37 tests on implementation commit 9a382aa | Container units, not installed x86_64 or packet-level acceptance |
| Windows x86_64 service target check | Passed | Cross-compilation only |
| iOS simulator app + PacketTunnel + widget build | Passed | Local ad-hoc simulator signing, no device VPN acceptance |
| Android Java compilation + lintDebug | Passed | No Android JNI target build or emulator acceptance |
| Physical Linux node 192.168.68.116 | Not run: SSH connection reset | Node was not restarted and its network was not altered |
| Exact-head Jenkins, Windows/iPhone/Android installed-package failure scenarios | Not run | Required before accepting the broader issue/release |

### Network-change and resume events, recorded on 2026-10-11

| Check | Result | Boundary |
| --- | --- | --- |
| macOS: control, tun, desktop, Native suites; strict clippy incl. WebView | Passed | Routing socket opened unprivileged; no interface was changed on the host |
| Linux (Docker `rust:1-bookworm`): control/tun suites, strict clippy | Passed | Container units |
| Linux live netlink: dummy link + address in a `NET_ADMIN` container | Passed: change reported before the 10 s poll; own TUN name ignored | Disposable namespace, not an installed package |
| Windows x86_64 tun strict clippy | Passed | Cross-compilation only; adapter polling not run on Windows |
| Real sleep/wake, Wi-Fi handoff on installed packages | Not run | Issue #36 |

### Mobile callback validation — 2026-10-11

- Host Rust tests: mobile adapter, Android codec and iOS core pass. The shared
  adapter regression checks rapid network-change generation invalidation,
  rejection of an old result, native resume staleness, unknown DNS/guard and
  ignored events after Stop. Host Android codec tests do not compile Android JNI.
- Injected pure Java clock/session regression checks a long awake polling gap,
  subthreshold and two-second deep sleep, one event per change, clock reversal,
  invalid/skewed reads, Stop and stale-session rejection. The standalone runner
  uses an existing JDK and is required by the three-platform GitHub check and
  Android build script; missing Java fails rather than skipping.
- Modified Android NativeCore/TunnelService Java boundary compiles against the
  existing Android 36 SDK and previously generated app classes/resources in a
  disposable networkless compiler container. This is not a fresh full APK build,
  JNI target check, emulator run or physical-device acceptance. No Android Rust
  target is installed in the inspected local toolchains; none was installed.
- iOS provider/shared Swift sources typecheck against the installed iPhoneOS
  27 SDK using the existing Xcode path; the modified Rust core also passes
  `cargo check --target aarch64-apple-ios`. These checks do not launch an
  iPhone/simulator or supply signing/install evidence. Native callback timing, cancellation and
  path/wake behavior still require exact-package/device validation.

## Service-owned endpoint checks (Linux)

IPC4 adds `endpoint_probes`, `ProbeEndpoint { token }` and a structured timed
endpoint result. The token contains a random per-lease identity and a worker
observation generation; no caller-selected profile, destination or URL is
accepted. A separate channel retains the active connection's authenticated UID
boundary and cancels its check on EOF. Stop, lease retirement, network changes,
resume and profile switching invalidate pending work. A failed worker exposes
no active probe token. Only one check can run, with a 30-second cooldown and
10-second overall budget.

The current implementation checks the first numeric address of the active
TrustTunnel HTTP/2 profile. It requires a hardware-backed physical interface,
TCP destination-port route evidence for the service UID and existing full-mode
mark where applicable, and verifies interface identity before/after binding and
again after the check. Every diagnostic socket uses that interface; neither the
active transport nor routes, DNS or firewall rules are changed. A successful
result proves this independent endpoint TLS/authenticated `_check` attempt,
not tunneled egress or OS guard enforcement. Typed connection/TLS/authentication,
protocol and timeout failures describe this one address attempt only. Missing
pins, virtual interfaces, unsupported transports and stale/cancelled work stay
unsupported/inconclusive; they do not establish endpoint unavailability.
Interface identifiers and secrets are excluded from returned facts. macOS and
Windows advertise this endpoint capability as unavailable until equivalent
socket-path proof exists. These unit/compile gates do not replace installed
service/device acceptance.
