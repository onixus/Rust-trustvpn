# Route decisions and offline explain (issue #32)

The shared contract in `rtrust-profile::routing` describes tunnel/direct/block/
unknown, rule IDs, policy source/revision, reason, input basis, scope and whether
this is a prediction. It contains no destination or learned DNS name. `Block`
is representable but neither existing flow routing nor desktop CIDR selection
implements an independent block rule; unsupported features are not advertised.

## One evaluator per actual routing backend

`Router::tunneled`, `Router::decide` and `Router::route_flow` use the same
evaluator. The dataplane calls `route_flow`, which returns the action and can
publish a redacted observed decision; the full explanation remains a separate
request. Rules retain their existing semantics:

- Port 53 is always tunneled.
- General-mode exclusions choose direct; selective-mode exclusions choose VPN.
- IPv4/IPv6, CIDRs, exact IP/port and wildcard-port rules retain their behavior.
- With domain rules, unknown DNS provenance remains protected.
- Conflicting observed names on a shared CDN IP remain tunneled in general mode,
  unless an explicit numeric rule independently permits direct.
- DNS cache names are evidence of resolver answers, not the application's actual
  hostname or proof that application DoH used this resolver. Manually entered
  hostnames return unknown without any external DNS lookup.

The revision hashes length-delimited policy inputs (or uses an explicitly
provided bounded opaque revision). Rule IDs are zero-based positions within
that revision. A new Router is fully validated before use and starts with an
empty DNS cache; an old cache must not be reused across policy revisions.

One intentional safety correction: learned destination provenance expires at
the shortest TTL in its related CNAME chain, capped at 300 seconds, rather than
outliving a CNAME via the A/AAAA record TTL. Unrelated records are not provenance.
The regression fails with the old TTL calculation and passes with this fix.

`Selection::explain` uses the same `Selection::routes` subtraction as installation.
Reserved space, exclusions, endpoint exceptions and requested LAN exclusions
retain priority over included prefixes. Known runtime inputs are validated as
a complete installable prefix set before a prediction is returned. Missing
endpoint or requested LAN inputs produce unknown; IPv6 is unsupported in this
selected-IPv4 backend. The actual OS route/guard can still differ from intent.

Linux's UID-scoped policy does not exclude the root service's endpoint from the
user prefix set. Native preview passes an empty endpoint set for that backend;
macOS/Windows require their endpoint exceptions. This difference is explicit.

## User-visible entry points and ownership

Native Diagnostics has **Explain route · no network request**. It uses the
current mode and effective managed/local selection. It shows path, reason,
source, revision and rule IDs, and labels the result as a prediction. Missing
runtime inputs are visible. Full-system and proxy paths remain unknown in this
offline tool; an unrelated mobile flow policy is not used to guess them.

Managed route groups continue to override local selection in `tun_selection`.
Their actual revision is displayed. The current portal contract does not attest
to admin versus user ownership, so that role is marked unknown rather than
invented. The source enum is descriptive metadata, not an authorization grant.

Native selected-IPv4 settings now provide **Намерения и предпросмотр правил**.
“Work through VPN” takes explicit IPv4 CIDRs, “networks directly” takes explicit
exclusion CIDRs, and “LAN directly” uses the local networks discovered at the
next connection. These labels edit the existing Selection fields without
changing embedded profile data or inventing a domain/per-app policy adapter.
The preview shows fixed precedence, zero-based rule references, overlaps where
the direct exclusion wins, source, and a deterministic policy revision. It uses
the same Selection evaluator and endpoint inputs as Diagnostics offline explain;
unknown endpoint/LAN inputs stay unknown. Domain, port and IPv6 inputs are
rejected by this editor rather than silently reduced to an IPv4 rule.

Preview does not modify the vault, call the portal, resolve DNS or install routes.
A successful preview is required before accepting the entire local draft for the
next connection. Changing the draft invalidates that preview; changes to its
base settings, endpoint inputs or managed source require opening it again.
Accept is disabled while connecting, connected or under always-on control.
Existing vault conflict/save handling remains authoritative. A managed group's
policy is read-only here, retains its actual revision and unknown admin/user
role, and cannot be overridden by accepting local intentions. This editor does
not replace an active desktop policy or claim hot system-route rollback.

The CLI can inspect the mobile flow policy without a resolver/socket request:

```
rtrust-inspect FILE --explain-mobile-flow 192.0.2.1:443
```

It uses `rtrust_mobile::prepare` to preserve the existing strict policy adapter.
This evaluates `flow_policy` only for packets delivered to the mobile core; it
is not an OS inclusion/per-app/guard audit. Unsupported mobile profile fields
are rejected by the same adapter used at runtime. The decision JSON contains
rule references and a policy revision, never the visited address/name. It does
not apply an Android managed prefix selection (`with_prefix_selection`) and has
no DNS cache, so an address covered only by a domain rule is explained as the
protective `tunnel`/`unknown_name_protected`, never as direct.

The desktop selected-IPv4 prediction is available without a profile:

```
rtrust-inspect --explain-selected 192.0.2.1 --include 192.0.2.0/24 \
  [--exclude CIDRS] [--exclude-lan | --lan CIDRS] [--endpoints IPS]
```

It calls `Selection::explain` and prints two lines: the decision JSON and
`{"routes": [...]}`, the prefix set `Selection::routes` would install, or `null`
when a runtime input is unknown. `--lan` supplies observed local networks (the
Linux service reads them from the main table and interface subnets before
Start); `--exclude-lan` alone requests LAN exclusion without that observation,
so included addresses are `unknown`/`local_networks_unobserved`. Endpoints
default to an empty set on Linux, as in Native, and are unknown elsewhere unless
given. Nothing is resolved, connected or installed, and the destination is not
printed.

## Capability matrix by operating system

Derived from the current code; “explain” is the offline prediction above.

| Path | Linux | macOS | Windows | Android | iOS |
| --- | --- | --- | --- | --- | --- |
| Selected IPv4 prefixes | UID-scoped `ip rule … uidrange` to table 51830; endpoint needs no exception; LAN from main table + interface subnets | Endpoint exceptions required | Endpoint exceptions required | Managed groups only, applied as `with_prefix_selection` before the flow policy | Not offered |
| Selected IPv6 | Not routed by this backend (system path); explain `unknown`/`unsupported_family` | Same | Same | Managed prefix scope; IPv6 outside it is blocked when not selected | — |
| Ports in selected mode | Ignored; port 53 follows the prefixes | Same | Same | — | — |
| Flow policy (IP/CIDR/port) | Lab harness only (`flow-lab`) | — | — | Dataplane `route_flow` | Dataplane `route_flow` |
| Domain rules | Lab harness only | — | — | VPN-DNS provenance, CNAME/TTL bound, conflicts protected | Same |
| Hot local revision | Lab harness only | — | — | `flowPolicy` native call → `policy::Controller` (prepare, drain, commit) | Not wired |
| Observed decisions | Lab harness only | — | — | Explicit capture (`flows::Capture`) | Explicit capture |
| Full system / SOCKS | Explain `unknown` (system path / proxy scope) | Same | Same | — | — |
| Per-app | Unsupported | Unsupported | Unsupported | VpnService exclusions, outside this evaluator | Unsupported |

Documented differences between explain and the dataplane:

- Native Diagnostics passes `local = None` (`apps/native/src/main.rs`,
  `Message::ExplainRoute`), so with “LAN directly” enabled every included address is
  explained as `unknown`/`local_networks_unobserved`, although the connected
  service subtracts the observed LAN. The CLI accepts `--lan` for that input.
- `--explain-mobile-flow` neither applies an Android managed prefix selection
  nor has the runtime DNS cache: domain-covered addresses stay protective
  `tunnel`/`unknown_name_protected` offline while the dataplane may choose
  direct after a correlated VPN DNS answer.
- Desktop selected mode ignores ports: DNS to an included resolver is tunneled,
  to an excluded or non-included one it is direct. Only the mobile flow policy
  always tunnels port 53.
- Linux selected mode scopes rules to the desktop UID: other local users and the
  root service are not routed by it, which explain does not model.

## Validation

`scripts/route-explain-interop.py` (lane `explain` of
[`ci/linux_lab.py`](linux-lab.md)) compares explain with packets in a disposable
Docker network namespace. The oracle is the `X-Peer` reported by an HTTP server
behind the endpoint (the client veth address means direct) and nftables output
counters in the client namespace (`oifname rtrust0` versus the veth, per
destination, port and UID).

- **P1** Desktop selected via raw IPC `Start` (include `198.18.0.0/16`,
  `10.0.0.0/8`, exclude `198.18.2.0/24`, LAN on): selected, excluded, LAN,
  second included prefix and outside addresses match on ports 80 and 8081;
  UID 1001 stays direct; IPv6 is explained `unknown` and leaves the veth; the
  CLI `routes` equal the installed UID rules and table 51830 routes. Without
  `--lan` the prediction is `unknown`.
- **P2** `Stop`, then `Start` with include `0.0.0.0/0` (the client subnet is
  excluded because preflight rejects a selection containing a local address):
  new revision, reserved space direct, only the new prefix set installed, and no
  table 51830 or UID rule after `Stop`.
- **P3/P6** `apps/tun/examples/flow-lab.rs` runs `rtrust_mobile::prepare`, the
  Android dataplane `run_with_policy` with SO_BINDTODEVICE socket protection and
  `flows::Capture`. Excluded CIDR and `IP:port` are direct, other ports and
  addresses tunnel, UDP 53 to an excluded resolver tunnels with zero port-53
  packets on the veth. Offline decision, observed event (`prediction=false`,
  SHA-256 of the CLI revision) and packets agree. IPv6 runs when the container
  provides IPv6 addressing, otherwise the lane prints `BLOCKED`.
- **P4** A synthetic DNS server behind the endpoint: TTL expiry, CNAME-chain
  TTL, CNAME into a wildcard rule (matched by the queried name only), shared-IP
  conflict, the same with a numeric rule, and a rule address without a query.
- **P5** `apply-local` through `policy::Controller`: new revision and epoch,
  DNS evidence cleared, and a DNS answer of the old revision that arrives after
  the commit is not applied.

Every run asserts that unknown, unobserved and conflict decisions are never
direct, that decision/event JSON contains none of the tested addresses or names,
and that no events are recorded without a subscriber. This is laboratory
evidence in Linux namespaces, not installed-package, Android/iOS device or
macOS/Windows acceptance; flow-lab is not shipped. Admin/managed provenance,
established-flow behaviour across an OS-route change and actual-system
corroboration (#33) remain open.

No history is transmitted, no policy is changed by explain, and no direct
comparison request is made. The native editor and CLI remain offline previews.
The shared core also provides conditional atomic local policy revision/
rollback and explicitly subscribed, bounded redacted observations of actual
flow-policy selections; see [runtime routing revisions](routing-policy.md).
Admin/managed/unknown-source policies reject local mutation. Neither the source
label nor a flow-policy selection establishes administrator authentication,
packet delivery or OS guard/route enforcement.

Android/iOS offer [explicit local flow capture](mobile-flow-observations.md)
from their active router; desktop explain remains a prediction. Android's
`flowPolicy` bridge invokes the hot revision API; iOS does not. Capture is
bounded, session-fenced and has no address correlation or packet-delivery proof.
Full hot OS-route/guard cutover and explicit managed administrator provenance
remain separate work. Existing vault conflict handling remains in force.
