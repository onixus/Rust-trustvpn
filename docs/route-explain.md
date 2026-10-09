# Route decisions and offline explain (issue #32)

The shared contract in `rtrust-profile::routing` describes tunnel/direct/block/
unknown, rule IDs, policy source/revision, reason, input basis, scope and whether
this is a prediction. It contains no destination or learned DNS name. `Block`
is representable but neither existing flow routing nor desktop CIDR selection
implements an independent block rule; unsupported features are not advertised.

## One evaluator per actual routing backend

`Router::tunneled` and `Router::decide` call the same evaluator. The dataplane
continues to call `tunneled`; explanation serialization and revision string
cloning are kept off that hot path. Rules retain their existing semantics:

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

The CLI can inspect the mobile flow policy without a resolver/socket request:

```
rtrust-inspect FILE --explain-mobile-flow 192.0.2.1:443
```

It uses `rtrust_mobile::prepare` to preserve the existing strict policy adapter.
This evaluates `flow_policy` only for packets delivered to the mobile core; it
is not an OS inclusion/per-app/guard audit. Unsupported mobile profile fields
are rejected by the same adapter used at runtime. The decision JSON contains
rule references and a policy revision, never the visited address/name.

## Capability matrix and remaining acceptance

| Path | IP / port | Domain | Per-app | Evidence boundary |
| --- | --- | --- | --- | --- |
| Desktop selected IPv4 | IPv4 CIDRs; port ignored by this backend | Unsupported | Unsupported | Offline prediction; actual LAN/endpoint inputs required |
| Desktop full system | Actual OS rules remain authoritative | No offline claim | Unsupported | Unknown without system observation |
| Desktop SOCKS | Proxy requests are a separate scope | No system-route claim | Apps must opt into proxy | Unknown for system route |
| Android/iOS delivered mobile flows | IPv4/IPv6, CIDRs and ports | Correlated VPN DNS, bounded CNAME/TTL; missing provenance protected | No universal per-app claim | Flow policy evaluation, not packet capture |
| Android OS excluded apps | Existing VpnService capability | Not this evaluator | Existing platform exclusion | No cross-platform guarantee |

No history is transmitted, no policy is changed by explain, and no direct
comparison request is made. This PR supplies the decision contract/evaluator
and offline preview. It does not implement hot system-policy replacement or
rollback, flow telemetry, an intent-rule editor, a managed admin/user ownership
extension, or installed package/packet-level acceptance. Existing immutable
policy installation and vault conflict handling remain in force. Issue #32
stays open for those acceptance items and the actual-system diagnostics in #33.
