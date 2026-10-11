# Destination diagnostics (issue #33)

Native Diagnostics now offers a separate **current system path** operation, alongside the explicitly labelled independent TCP transport test and the offline route explain from #32. In TUN/full mode, checks start automatically on connection and repeat every 30 seconds against the destination shown in Diagnostics (default `example.com`). Enter a hostname or numeric IP without URL/port to change it; the repeat button remains available. Checks run in the background without blocking disconnect, navigation or other operations. The UI discloses system name resolution and one HTTPS:443 HEAD request to `/`. It does not compare with a direct request, change routes/firewall, start another transport, or claim global Internet/guard verification.

## Evidence and bounds

- macOS uses the system resolver (`dscacheutil`) and numeric kernel route lookup. Linux uses the system NSS resolver (`getent ahosts`) and JSON kernel route lookup with the calling effective UID, TCP and destination port 443; this matters for the desktop UID policy rule. Windows isolates its synchronous OS resolver (`System.Net.Dns.GetHostAddresses`) in a cancellable PowerShell child; the hostname is passed as environment data, never interpolated into commands. Windows checks `GetBestRoute2` against the live service adapter alias `RTrustTunnel`, LUID and interface index.
- Resolver/route subprocesses have three-second limits, 8 KiB output caps and kill-on-drop cancellation. At most eight distinct answers are accepted. Only the first answer is tested; there is no automatic fallback to another address/family. Numeric inputs do not count as a DNS test. Resolver success means an answer was obtained, including system cache/NSS; it does not prove that the DNS request was tunneled.
- The kernel route must name the service's exact interface (`utun5254` / `rtrust0` / `RTrustTunnel`). Unknown, malformed, ambiguous and outside routes never trigger HTTPS. This is a per-destination lookup, not packet/guard attestation.
- HTTPS sockets are bound to that interface to prevent a route change/removal from falling back to physical egress. Environment proxies are disabled. The selected answer is pinned, TLS verification remains enabled, redirects are disabled, and only HEAD headers are requested. The body is not consumed. macOS/Linux HTTP/1 parser buffering is bounded by Hyper's default 417792 bytes and header count, rather than an unbounded response download. Windows sets `IP_UNICAST_IF`/`IPV6_UNICAST_IF` before bind/connect, checks the same interface identity before and after network operations, uses verified rustls TLS and accepts only complete final HTTP headers, capped at 8 KiB and 64 fields. HTTPS has a five-second total limit (macOS/Linux also cap connect at three seconds); the whole operation has a 15-second deadline. One request per run, no retries or fallback endpoint; UI starts are limited to one per five seconds and cannot overlap.
- Structured facts distinguish resolver, route, known TLS, connection and timeout outcomes. Wrapped `rustls::Error` is inspected through both `source` and `io::Error::get_ref`; unknown failures remain connection failure. A timeout is not proof of blocking, general loss of Internet, or endpoint failure. HTTP 4xx/5xx still prove that a certified server responded, not that the desired site function works.
- The existing shared observation snapshot describes the service lifecycle separately. The resolved numeric destination also receives a policy prediction from the shared selection evaluator. Missing endpoint/LAN inputs, full-system predictions and unspecified managed admin/user ownership remain unknown. An opaque revision is exported as a SHA-256 fingerprint.
- Report timestamps, connection epoch and control generation prevent old session results from becoming current proof. The UI labels reports older than six seconds or from another connection epoch as historical. Stop/close and destination edits cancel an active diagnostic. Service-generation changes also invalidate results even when the UI connection epoch is unchanged. Lifecycle polling preserves the last diagnostic summary with its age rather than replacing it with unverified service observations; repeat uses the same ordinary connection lifecycle.

## Verdict and proposed actions

Each report now carries a typed verdict (`Report::verdict`): one `cause`, its
`basis` (`observed` or `inferred`) and the actions that may help. The UI
localizes it; machine consumers use the enums.

| Facts | Cause | Basis | Actions |
| --- | --- | --- | --- |
| Control IPC lost | `service_unavailable` | observed | reconnect, recheck |
| Transport worker failed | `transport_down` (or endpoint cause once checked) | observed | check endpoint, reconnect, recheck |
| HTTPS response | `responded` | observed | recheck |
| TLS verification failed | `certificate_rejected` | observed | recheck |
| Kernel route outside VPN | `route_outside_vpn` | observed | review rules, recheck |
| Resolver returned nothing | `name_resolution` | observed | check endpoint, recheck |
| Timeout / connection failure, endpoint not checked | `undetermined` | inferred | check endpoint, recheck |
| Same, endpoint answered | `destination_unreachable` | inferred | reconnect, recheck |
| Same, endpoint unreachable / refused | `endpoint_unreachable` / `endpoint_rejected` | inferred | reconnect, recheck |

A timeout is never reported as blocking. **Check endpoint** asks the authenticated
service to check only its current pinned profile through a fresh IPC channel.
The request contains an opaque lease token and generation, never a caller-selected
profile, hostname or URL. Linux IPC v4 currently supports this for verified
TrustTunnel HTTP/2 numeric endpoints. Up to eight distinct configured endpoint
addresses share the same total budget: any independently verified successful
health exchange is sufficient, but a failure is attributable only after every
configured address failed on a proven physical path. A partial, unpinned or
expired address set remains inconclusive; a failed first address cannot declare
a profile down while its later address works. The service proves a hardware-backed
physical interface and kernel route for its UID, transport mark and endpoint TCP
port, then binds every probe socket to that interface and rechecks identity and
route after TLS, authentication and the health exchange. No destination is contacted
and no route/firewall is changed. There is one in-flight probe, a 30-second cooldown,
and a ten-second service budget; the IPC exchange is bounded at 15 seconds.
Stop, EOF, network changes and profile transitions cancel or invalidate old results.
Unsupported transports, unproven physical paths and inactive leases remain
unsupported/inconclusive. Windows/macOS do not advertise this service capability;
there is no substitute desktop connection that could confuse local guard refusal
with endpoint failure. A result can refine only a report that started before it,
in the same connection epoch. Lease tokens, candidate indices and interface names
are excluded from the diagnostic export.

**Reconnect** is the ordinary Stop then Start of the current connection; when
Always-on owns the connection it is not offered from diagnostics. After Start,
the same destination is checked again automatically. **Review rules** shows the
policy prediction already in the report and points to the selection settings;
nothing is applied. **Recheck** repeats the check. A repeat after any action
records `follows`: the action, the earlier cause and the earlier finish time.
Actions are disabled for a historical result, except Recheck.

Diagnostics are now allowed while the running worker's transport observation is
`stale` (after sleep, a network change or a polling gap): the check is the new
evidence. A failed worker or changed generation still refuses or invalidates it.

## Preview and export

The report excludes the hostname, addresses, URLs, headers, response payload, raw errors and profile credentials. Policy revisions are hashed. Native displays an editable JSON preview, then saves only when the user explicitly chooses a file. Nothing is uploaded or automatically sent. User edits replace the default preview; users should redact any information they add themselves.

## Validation and remaining acceptance

Unit/regression coverage includes DNS and route refusal without HTTPS, changed-session rejection, redacted export, exact route identity, bounded command output, actual child cancellation, localhost TLS certificate rejection, a trusted localhost redirect response without following it or consuming its advertised large body, and a missing bound interface with no fallback connection. Native requires a current TUN and refuses export without a completed report.

Windows now performs system-path checks through the exact live VPN adapter; route mismatch, missing adapter, unavailable resolver or socket binding never trigger an unbound HTTPS retry. Windows unit tests and cross-compilation do not establish installed-device acceptance. Android/iOS and WebView system-diagnostic UI are not added here. Linux interface binding may require privilege on older kernels; failure remains an explicit connection failure and never causes an unbound retry. Flatpak may not expose host resolver/route tools; that is unsupported, not an empty successful result.

This is a draft implementation, not completion of #33's installed acceptance. The verdict layer now models unavailable control/endpoint cases and separates endpoint from destination failure with an independent endpoint check; these are unit-tested, not yet exercised on installed packages. Still required: installed macOS/Linux/Windows package traffic correlation for split/full and IPv6, live endpoint-outage and control-loss runs of the verdict and the reconnect-then-recheck flow, WebView/mobile diagnostic UI, package cancellation/timing tests, and exact-head Jenkins/package/device acceptance. Existing transport-only tests do not cover these criteria. No historical release is treated as evidence for this source, and no release is promoted.
