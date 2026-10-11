# Runtime routing revisions and local flow observations

`rtrust-engine::routing::Router` is shared by policy explain, mobile routing and
TCP/UDP/ICMP dataplane decisions. The existing fixed-profile startup behavior
remains: compiling a policy creates a router and neither explain nor compilation
opens sockets. This core API adds revision replacement inside an existing
`Arc<Router>`; the desktop IPC and mobile adapters do not expose hot policy apply
yet. Desktop policy edits still require their existing connection lifecycle.

## Atomic decisions, apply and rollback

`Router::version()` returns a `PolicyVersion { revision, epoch }`. The revision
identifies the compiled policy; epoch increases on every successful update and
rollback. `apply_local(expected, policy, context)` compiles and validates the
entire replacement before taking the publication lock, compares the exact
expected token, then replaces compiled rules/source/revision together. Existing
readers finish using the prior complete policy; subsequent readers see the new
complete policy. An invalid rule, stale token, reused current revision, source
change or unsupported new direct-routing capability leaves the old policy and
its DNS evidence intact.

Only local/user/embedded-profile policies can use this API. Admin,
managed-unknown and unknown-source policies reject local apply and rollback,
even when the caller repeats the old source label. Source metadata itself does
not authenticate an administrator: the adapter that imports it must establish
its provenance and authorization. A source change requires a new authorized
session rather than a caller relabeling the active router. A router initially
prepared for tunnel-only operation cannot enable direct routing through an
update; that also requires a new protected session with appropriate routes and
socket protection.

One immutable previous compiled snapshot is retained. `rollback_local(expected,
previous_revision)` requires both the current token and the exact retained
previous revision. Rollback restores rules/source/revision as a unit and advances
the epoch; a stale update from before A → B → A cannot succeed because its
original A epoch differs. Older unretained revisions are unavailable. These are
in-memory decision snapshots, not a persistent policy approval/history store.

For example, a lifecycle owner already holding the shared router may obtain its
version, call `apply_local` with that token and a validated replacement, then use
the returned token to request rollback to the retained previous revision. It
must also coordinate termination of established/in-flight flows and any required
OS route changes before claiming that all traffic uses the replacement. This
API alone does **not** revoke sockets created by a prior decision, reconfigure
system DNS/routes/firewall, perform device acceptance, or guarantee atomic
cutover of established flows. A TCP decision made before publication can still
be waiting for socket protection/connect; that pending connection belongs to
the prior-flow boundary too and is not cancelled by the swap. A caller requiring
full cutover must cancel and join these pending flow tasks before acknowledging
an apply. There is no intermediate empty policy or default
direct bypass in the decision evaluator itself.

## DNS evidence belongs to a policy epoch

Successful apply and rollback clear cached DNS names while holding the same
policy→DNS lock order as the evaluator. DNS query paths capture the version
before awaiting the answer and use `learn_for(version, query, answer)` to attach
validated DNS provenance. Late answers from an obsolete epoch are rejected,
including after rollback to the same revision. Both encrypted DNS and forwarded
TCP/UDP DNS paths carry this token. Existing synchronous `learn` remains a
compatibility helper for immediate evidence; asynchronous callers must capture
the version before sending the query. Matching question/ID, CNAME-chain TTL,
shared-IP ambiguity and protected unknown-name behavior remain unchanged.

## Prediction and a real dataplane selection

`decide(destination)` remains an offline prediction. The dataplane uses
`route_flow(destination)`, which runs the same evaluator and returns its typed
action. TCP and UDP branches admit direct traffic only for explicit `Direct`;
future unknown/block actions do not fall through to direct sockets. Android
unprivileged direct ICMP remains unavailable.

An explicit local caller can subscribe with `observe_flows()`. At most four
subscribers share a bounded queue of 32 observations. Slow consumers receive
`Lagged`, not a silent claim of complete history. No observations are sent or
retrospectively replayed while unsubscribed. Each item contains the policy
version, monotonic observation time and the existing redacted `Decision` with
`prediction=false`. It contains no destination, DNS name, application identity,
payload or credentials and performs no export or network request. Consumers
should compare the event version with the active router version and use the
monotonic time when discussing freshness.

This observes a policy selection for a real flow/datagram reaching the
dataplane. It is not proof of packet delivery, DNS correctness, current system
routes or guard enforcement: later transport failure, DNS synthesis or an
unsupported ICMP path can still prevent forwarding. Current desktop explain
remains a prediction and does not subscribe to these flow observations. The
unsubscribed packet path avoids cloning revision strings and allocating
rule-ID lists; only explicit diagnostic subscriptions construct these objects.

Regression coverage includes invalid/stale updates, ABA-safe rollback,
managed-source rejection, DNS cache clearing and late-answer rejection,
concurrent action/revision consistency, real-flow vs prediction distinction,
redaction, subscription limits and queue overflow. Packet-level OS cutover,
established-flow cancellation and real-device routing acceptance remain
separate work.
