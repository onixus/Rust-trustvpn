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
| Linux selected / full / Always-on | Service worker lifecycle; failure/reconnect/gap; netlink network change, kernel-clock resume | Unknown; no live system probe | Unknown | Native and WebView share the Rust verdict |
| Windows selected / full / Always-on | Service worker lifecycle; failure/reconnect/gap; polled adapter change, kernel-clock resume | Unknown; no live system probe | Unknown | Native and WebView share the Rust verdict |
| macOS selected / full | Service worker lifecycle; failure/reconnect/gap; routing-socket network change, kernel-clock resume | Unknown; no live system probe | Unknown | Native and WebView share the Rust verdict |
| Desktop SOCKS | Proxy lifecycle only | Unsupported for the system path | Unknown | Explicit proxy scope |
| Android | Shared mobile worker lifecycle; failure/recovery/gap; selected underlying Network/link-property changes; kernel deep-sleep clock evidence | Unknown; VpnService setup is not a live audit of DNS or lockdown | Unknown | JNI JSON, localized summary of checks that have a result, no green lifecycle badge |
| iOS | Shared mobile worker lifecycle; failure/recovery/gap; provider path updates and native wake callback | Unknown; NetworkExtension status is not a live audit | Unknown | Redacted provider message; generation/age checked; localized summary |

Capabilities explicitly advertise `system_probes=false`. The desktop GUI may
fold its own path check of one user-chosen destination into the snapshot it
displays, as `source: app_probe` for route and connectivity only; a service
never sends that source, and it replaces only open or expired service results.
The adapters retain
existing platform differences; this change does not make unsupported checks
available or constitute packet-level leak acceptance.

Since 0.6.1 (#67) every client lists only checks that produced a result. Route,
DNS, guard and connectivity have no runtime producer yet, so while they are
Unknown they are omitted instead of shown as "unchecked": a running transport
reads "Transport: running" (iOS/Android widgets: "Transport running"). The amber
colour still means that nothing is verified. Failed, stale and unsupported
results are always shown. Desktop system-path diagnostics are reported separately;
see [system diagnostics](system-diagnostics.md).

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
