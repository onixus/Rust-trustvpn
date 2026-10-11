# Local mobile flow observations

Android Settings offers **Observe local flow decisions**; iOS Settings offers an
explicit local capture control. Capture uses the same `Arc<Router>` handed to the
active mobile dataplane worker. It reports selections actually published by
`route_flow`, with `prediction=false`; this does not establish packet delivery,
OS guard enforcement, or agreement with an offline prediction.

The default has no subscriber. Explicit enable requires the current session and
capture token. Each poll consumes at most 32 bounded broadcast reads and serializes at most
60 KiB including metadata and rule IDs. Events omitted to stay within the byte
budget have an explicit counter. Lagged reads
and discarded old-policy events are counted explicitly. The screen displays only
the current bounded batch, with decision action/reason/source, policy epoch,
revision digest and event age. No destination addresses, names, ports, visited
history, disk persistence, report export or automatic telemetry are added.

Both the policy revision and decision-context revision are SHA-256 digests at
the mobile serialization boundary, including identity responses. They identify
revision equality; they are not signatures or administrator authentication, and
hashing is not anonymization of a known low-entropy identifier. Raw revisions
remain internal for exact current-version comparison. The UI abbreviates these
fixed 64-character digests.

Capture stays unavailable until transport connection, health and UDP setup succeed.
Each transport failure/reconnect or fatal-error wait clears the queue and opt-in
and invalidates the capture token before reporting loss. A recovered transport
requires a new explicit opt-in. Stop, replacement session and worker exit detach capture. Session and capture
tokens reject late polls, enable and close from older sessions/captures. Closing
Android's dialog, leaving its activity, leaving iOS Settings or backgrounding the
iOS app disables capture and clears the visible batch. An unrenewed capture
expires after 30 seconds through normal native status sampling. Reading status
never opts in, drains observations or renews the lease.

The shared adapter regressions cover default-off/no retrospective history,
bounded loss reporting, cancellation and session replacement, late old-worker
exit/close, lease expiry, old-policy discard, and free-text revision redaction.
Host mobile/iOS/Android codec tests and mobile Clippy pass. Current Android Java
sources compile against SDK 36 and real generated resources; iOS app/provider
Swift typechecking and the `aarch64-apple-ios` Rust check validate source/ABI
boundaries. These checks do not constitute an APK install, signed device run or
physical packet-capture acceptance.

This adapter does not invoke atomic hot policy revision, revoke established or
pending flows, perform scoped OS-route/guard cutover, or correlate mobile
observations with an entered address. Those issue #32 acceptance items remain
open, together with installed actual-system corroboration in issue #33.
