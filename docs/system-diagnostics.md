# Destination diagnostics (issue #33)

Native Diagnostics now offers a separate **current system path** operation, alongside the explicitly labelled independent TCP transport test and the offline route explain from #32. Connect TUN/full mode, enter a hostname or numeric IP without URL/port, then press the system-path button. The UI discloses system name resolution and one HTTPS:443 HEAD request to `/`. It does not compare with a direct request, change routes/firewall, start another transport, or claim global Internet/guard verification.

## Evidence and bounds

- macOS uses the system resolver (`dscacheutil`) and numeric kernel route lookup. Linux uses the system NSS resolver (`getent ahosts`) and JSON kernel route lookup with the calling effective UID, TCP and destination port 443; this matters for the desktop UID policy rule.
- Resolver/route subprocesses have three-second limits, 8 KiB output caps and kill-on-drop cancellation. At most eight distinct answers are accepted. Only the first answer is tested; there is no automatic fallback to another address/family. Numeric inputs do not count as a DNS test. Resolver success means an answer was obtained, including system cache/NSS; it does not prove that the DNS request was tunneled.
- The kernel route must name the service's exact interface (`utun5254` / `rtrust0`). Unknown, malformed, ambiguous and outside routes never trigger HTTPS. This is a per-destination lookup, not packet/guard attestation.
- HTTPS sockets are bound to that interface to prevent a route change/removal from falling back to physical egress. Environment proxies are disabled. The selected answer is pinned, TLS verification remains enabled, redirects are disabled, and only HEAD headers are requested. The body is not consumed. HTTP/1 parser buffering is bounded by Hyper's default 417792 bytes and header count, rather than an unbounded response download. HTTPS has a five-second total/three-second connect limit; the whole operation has a 15-second deadline. One request per run, no retries or fallback endpoint; UI starts are limited to one per five seconds and cannot overlap.
- Structured facts distinguish resolver, route, known TLS, connection and timeout outcomes. Wrapped `rustls::Error` is inspected through both `source` and `io::Error::get_ref`; unknown failures remain connection failure. A timeout is not proof of blocking, general loss of Internet, or endpoint failure. HTTP 4xx/5xx still prove that a certified server responded, not that the desired site function works.
- The existing shared observation snapshot describes the service lifecycle separately. The resolved numeric destination also receives a policy prediction from the shared selection evaluator. Missing endpoint/LAN inputs, full-system predictions and unspecified managed admin/user ownership remain unknown. An opaque revision is exported as a SHA-256 fingerprint.
- Report timestamps, connection epoch and control generation prevent old session results from becoming current proof. The UI labels reports older than six seconds or from another connection epoch as historical. Stop/close cancel an active diagnostic; repeat uses the same ordinary connection lifecycle.

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

A timeout is never reported as blocking. **Check endpoint** opens one separate
authenticated session to the profile's endpoint and exchanges a health check,
like the transport test, with a ten-second limit. It contacts no destination and
changes no route. It may refine only a report that started before it, in the
same connection epoch. On Linux the desktop UID policy may carry that session
through the tunnel, so a failure there is not attributed to the endpoint
(`endpoint_independent=false`); a pass, or an authentication refusal, is.

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

Windows currently reports unavailable checks and makes no external diagnostic request. Android/iOS and WebView system-diagnostic UI are not added here. Linux interface binding may require privilege on older kernels; failure remains an explicit connection failure and never causes an unbound retry. Flatpak may not expose host resolver/route tools; that is unsupported, not an empty successful result.

This is a draft implementation, not completion of #33's installed acceptance. The verdict layer now models unavailable control/endpoint cases and separates endpoint from destination failure with an independent endpoint check; these are unit-tested, not yet exercised on installed packages. Still required: installed macOS/Linux/Windows package traffic correlation for split/full and IPv6, live endpoint-outage and control-loss runs of the verdict and the reconnect-then-recheck flow, WebView/mobile diagnostic UI, package cancellation/timing tests, and exact-head Jenkins/package/device acceptance. Existing transport-only tests do not cover these criteria. No historical release is treated as evidence for this source, and no release is promoted.
