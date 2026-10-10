//! Bounded destination routing with DNS provenance; no resolver or socket side effects.
use crate::{Error, Result};
use hickory_proto::{
    op::{Message, MessageType},
    rr::RData,
};
use ipnet::IpNet;
pub use rtrust_profile::routing::{Action, Basis, Context, Decision, Reason, RuleId, RuleKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub mode: String,
    pub exclusions: Vec<String>,
}
#[derive(Clone)]
enum Host {
    Any,
    Net(IpNet),
    Domain(String, bool),
}
#[derive(Clone)]
struct Rule {
    host: Host,
    port: Option<u16>,
}
pub struct Router {
    selective: bool,
    context: Context,
    rules: Vec<Rule>,
    learned: Mutex<HashMap<(IpAddr, String), Instant>>,
}
fn rule(text: &str) -> Result<Rule> {
    if text.len() > 512 || text.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Unsupported("routing exclusion"));
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        return Ok(Rule {
            host: Host::Net(ip.into()),
            port: None,
        });
    }
    if let Ok(net) = text.parse::<IpNet>() {
        if net != net.trunc() {
            return Err(Error::Unsupported("non-canonical route"));
        }
        return Ok(Rule {
            host: Host::Net(net),
            port: None,
        });
    }
    if let Ok(address) = text.parse::<SocketAddr>() {
        if address.port() == 0 {
            return Err(Error::Unsupported("routing port"));
        }
        return Ok(Rule {
            host: Host::Net(address.ip().into()),
            port: Some(address.port()),
        });
    }
    let (host, port) = if let Some((host, port)) = text.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or(Error::Unsupported("routing port"))?;
        (host, Some(port))
    } else {
        (text, None)
    };
    let host = if host == "*" && port.is_some() {
        Host::Any
    } else {
        let (domain, wildcard) = host
            .strip_prefix("*.")
            .map(|s| (s, true))
            .unwrap_or((host, false));
        if domain.is_empty()
            || domain.len() > 253
            || !domain.split('.').all(|part| {
                !part.is_empty()
                    && part.len() <= 63
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(Error::Unsupported("routing domain"));
        }
        Host::Domain(domain.to_ascii_lowercase(), wildcard)
    };
    Ok(Rule { host, port })
}
impl Policy {
    pub fn compile(&self) -> Result<Router> {
        self.compile_with_context(Context::default())
    }
    pub fn compile_with_context(&self, mut context: Context) -> Result<Router> {
        if context
            .revision
            .as_ref()
            .is_some_and(|r| r.is_empty() || r.len() > 256 || r.chars().any(char::is_control))
        {
            return Err(Error::Unsupported("routing revision"));
        }
        if context.revision.is_none() {
            let mut hash = Sha256::new();
            for value in std::iter::once(&self.mode).chain(&self.exclusions) {
                hash.update((value.len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
            context.revision = Some(format!("{:x}", hash.finalize()));
        }
        if !matches!(self.mode.as_str(), "general" | "selective")
            || self.exclusions.len() > 64
            || (self.mode == "selective" && self.exclusions.is_empty())
        {
            return Err(Error::Unsupported("routing policy"));
        }
        Ok(Router {
            selective: self.mode == "selective",
            context,
            rules: self
                .exclusions
                .iter()
                .map(|s| rule(s))
                .collect::<Result<_>>()?,
            learned: Mutex::new(HashMap::new()),
        })
    }
}
impl Router {
    pub fn needs_direct(&self) -> bool {
        self.selective || !self.rules.is_empty()
    }
    pub fn tunneled(&self, destination: SocketAddr) -> bool {
        self.evaluate(destination).0 == Action::Tunnel
    }
    /// Same evaluator used by the dataplane. DNS cache names are evidence of
    /// resolver answers, not proof of the application/hostname of this flow.
    pub fn decide(&self, destination: SocketAddr) -> Decision {
        let (action, mask, reason, basis) = self.evaluate(destination);
        let rules = (0..self.rules.len())
            .filter(|index| mask & (1u64 << index) != 0)
            .map(|index| RuleId {
                kind: RuleKind::Flow,
                index: index as u8,
            })
            .collect();
        Decision {
            action,
            scope: rtrust_profile::routing::Scope::FlowPolicy,
            rules,
            context: self.context.clone(),
            reason,
            basis,
            prediction: true,
        }
    }
    fn evaluate(&self, destination: SocketAddr) -> (Action, u64, Reason, Basis) {
        let make = |action, rules, reason, basis| (action, rules, reason, basis);
        if destination.port() == 53 {
            return make(
                Action::Tunnel,
                0,
                Reason::DnsAlwaysTunneled,
                Basis::NumericDestination,
            );
        }
        let mut names = self.learned.lock().unwrap_or_else(|p| p.into_inner());
        names.retain(|_, expiry| *expiry > Instant::now());
        let matching = |name: Option<&str>| {
            self.rules
                .iter()
                .enumerate()
                .fold(0u64, |mask, (index, r)| {
                    if r.port.is_some_and(|p| p != destination.port()) {
                        return mask;
                    }
                    let matched = match &r.host {
                        Host::Any => true,
                        Host::Net(net) => net.contains(&destination.ip()),
                        Host::Domain(domain, wildcard) => name.is_some_and(|name| {
                            name == domain || (*wildcard && name.ends_with(&format!(".{domain}")))
                        }),
                    };
                    if matched {
                        mask | (1u64 << index)
                    } else {
                        mask
                    }
                })
        };
        let known: Vec<_> = names
            .keys()
            .filter(|(ip, _)| *ip == destination.ip())
            .map(|(_, name)| name.as_str())
            .collect();
        let numeric = matching(None);
        let mut rules = numeric;
        for name in &known {
            rules |= matching(Some(name));
        }
        let matched = rules != 0;
        let has_domains = self
            .rules
            .iter()
            .any(|r| matches!(r.host, Host::Domain(..)));
        let basis = if numeric != 0 || !has_domains {
            Basis::NumericDestination
        } else if known.is_empty() {
            Basis::MissingDnsName
        } else {
            Basis::ObservedDnsCache
        };
        if self.selective {
            if matched {
                make(Action::Tunnel, rules, Reason::MatchedRule, basis)
            } else if known.is_empty() && has_domains {
                make(
                    Action::Tunnel,
                    rules,
                    Reason::UnknownNameProtected,
                    Basis::MissingDnsName,
                )
            } else {
                make(Action::Direct, rules, Reason::DefaultDirect, basis)
            }
        } else if !known.is_empty()
            && numeric == 0
            && matched
            && known.iter().any(|name| matching(Some(name)) == 0)
        {
            make(
                Action::Tunnel,
                rules,
                Reason::SharedIpConflictProtected,
                Basis::SharedDnsNames,
            )
        } else if matched {
            make(Action::Direct, rules, Reason::MatchedRule, basis)
        } else {
            make(
                Action::Tunnel,
                rules,
                if basis == Basis::MissingDnsName {
                    Reason::UnknownNameProtected
                } else {
                    Reason::DefaultTunnel
                },
                basis,
            )
        }
    }
    /// A user-entered hostname is not authenticated DNS provenance. This offline
    /// preview deliberately makes no resolver request and no direct connection.
    pub fn preview_hostname(&self) -> Decision {
        let mut decision = Decision::unknown(self.context.clone(), Reason::SystemPathUnobserved);
        decision.scope = rtrust_profile::routing::Scope::FlowPolicy;
        decision
    }
    pub fn learn(&self, query: &[u8], answer: &[u8]) {
        let (Ok(query), Ok(answer)) = (Message::from_vec(query), Message::from_vec(answer)) else {
            return;
        };
        if query.metadata.message_type != MessageType::Query
            || answer.metadata.message_type != MessageType::Response
            || query.metadata.id != answer.metadata.id
            || query.queries.len() != 1
            || query.queries != answer.queries
            || answer.metadata.truncation
            || answer.metadata.response_code != hickory_proto::op::ResponseCode::NoError
        {
            return;
        }
        let domain = query.queries[0]
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        // Follow only the queried name's CNAME chain, not unrelated additional records.
        let mut allowed = vec![query.queries[0].name().clone()];
        for _ in 0..8 {
            let mut added = false;
            for record in &answer.answers {
                if allowed.contains(&record.name)
                    && let RData::CNAME(cname) = &record.data
                    && !allowed.contains(&cname.0)
                {
                    allowed.push(cname.0.clone());
                    added = true;
                }
            }
            if !added {
                break;
            }
        }
        // DNS provenance cannot outlive any CNAME link used to establish it.
        // Bound conservatively across the queried chain; unrelated additions
        // neither shorten nor supply evidence for this destination.
        let chain_ttl = answer
            .answers
            .iter()
            .filter(|record| {
                allowed.contains(&record.name) && matches!(record.data, RData::CNAME(_))
            })
            .map(|record| record.ttl)
            .min()
            .unwrap_or(300);
        let mut learned = self.learned.lock().unwrap_or_else(|p| p.into_inner());
        learned.retain(|_, expiry| *expiry > Instant::now());
        for record in &answer.answers {
            if !allowed.contains(&record.name) || record.ttl == 0 || chain_ttl == 0 {
                continue;
            }
            let ip = match &record.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(a) => IpAddr::V6(a.0),
                _ => continue,
            };
            let key = (ip, domain.clone());
            if learned.len() >= 2048 && !learned.contains_key(&key) {
                continue;
            }
            learned.insert(
                key,
                Instant::now() + Duration::from_secs(record.ttl.min(chain_ttl).min(300) as u64),
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cname_evidence_is_bounded_by_chain_ttl_and_ignores_unrelated_records() {
        use hickory_proto::{
            op::Query,
            rr::{
                Name, Record, RecordType,
                rdata::{A, CNAME},
            },
        };
        let router = Policy {
            mode: "general".into(),
            exclusions: vec!["allowed.test".into()],
        }
        .compile()
        .unwrap();
        let name = Name::from_ascii("allowed.test.").unwrap();
        let cname = Name::from_ascii("cdn.test.").unwrap();
        let mut query = Message::query();
        query.metadata.id = 41;
        query.add_query(Query::query(name.clone(), RecordType::A));
        let mut answer = query.clone();
        answer.metadata.message_type = MessageType::Response;
        answer.add_answer(Record::from_rdata(
            name,
            1,
            RData::CNAME(CNAME(cname.clone())),
        ));
        answer.add_answer(Record::from_rdata(
            cname,
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        answer.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.test.").unwrap(),
            0,
            RData::A(A("192.0.2.2".parse().unwrap())),
        ));
        router.learn(&query.to_vec().unwrap(), &answer.to_vec().unwrap());
        assert_eq!(
            router.decide("192.0.2.1:443".parse().unwrap()).action,
            Action::Direct
        );
        let learned = router.learned.lock().unwrap();
        assert_eq!(learned.len(), 1);
        assert!(*learned.values().next().unwrap() <= Instant::now() + Duration::from_secs(1));
    }
    #[test]
    fn explanation_keeps_dns_unknown_name_ipv6_and_port_semantics() {
        let cases = [
            (
                "general",
                vec!["192.0.2.0/24"],
                "192.0.2.1:443",
                Action::Direct,
                Reason::MatchedRule,
            ),
            (
                "general",
                vec!["*:53"],
                "192.0.2.1:53",
                Action::Tunnel,
                Reason::DnsAlwaysTunneled,
            ),
            (
                "selective",
                vec!["*.example.test:443"],
                "192.0.2.1:80",
                Action::Tunnel,
                Reason::UnknownNameProtected,
            ),
            (
                "selective",
                vec!["192.0.2.1:443"],
                "192.0.2.1:80",
                Action::Direct,
                Reason::DefaultDirect,
            ),
            (
                "general",
                vec!["[2001:db8::1]:443"],
                "[2001:db8::1]:443",
                Action::Direct,
                Reason::MatchedRule,
            ),
            (
                "general",
                vec!["2001:db8::/32"],
                "[2001:db8::1]:80",
                Action::Direct,
                Reason::MatchedRule,
            ),
        ];
        for (mode, rules, target, action, reason) in cases {
            let router = Policy {
                mode: mode.into(),
                exclusions: rules.into_iter().map(str::to_owned).collect(),
            }
            .compile()
            .unwrap();
            let destination = target.parse().unwrap();
            let decision = router.decide(destination);
            assert_eq!(decision.action, action);
            assert_eq!(decision.reason, reason);
            assert_eq!(router.tunneled(destination), action == Action::Tunnel);
        }
    }
    #[test]
    fn cdn_conflict_and_expired_dns_are_explained_and_policy_swaps_clear_names() {
        let policy = Policy {
            mode: "general".into(),
            exclusions: vec!["allowed.example.test".into()],
        };
        let router = policy.compile().unwrap();
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let expiry = Instant::now() + Duration::from_secs(60);
        router
            .learned
            .lock()
            .unwrap()
            .insert((target.ip(), "allowed.example.test".into()), expiry);
        assert_eq!(router.decide(target).action, Action::Direct);
        router
            .learned
            .lock()
            .unwrap()
            .insert((target.ip(), "protected.example.test".into()), expiry);
        let conflict = router.decide(target);
        assert_eq!(conflict.action, Action::Tunnel);
        assert_eq!(conflict.reason, Reason::SharedIpConflictProtected);
        assert_eq!(conflict.basis, Basis::SharedDnsNames);
        assert_eq!(
            conflict.rules,
            [RuleId {
                kind: RuleKind::Flow,
                index: 0
            }]
        );
        router
            .learned
            .lock()
            .unwrap()
            .retain(|(_, name), _| name == "allowed.example.test");
        *router
            .learned
            .lock()
            .unwrap()
            .get_mut(&(target.ip(), "allowed.example.test".into()))
            .unwrap() = Instant::now() - Duration::from_secs(1);
        assert_eq!(router.decide(target).reason, Reason::UnknownNameProtected);
        assert_eq!(
            policy.compile().unwrap().decide(target).basis,
            Basis::MissingDnsName
        );
    }
    #[test]
    fn numeric_override_and_revision_boundaries_remain_explicit() {
        let policy = Policy {
            mode: "general".into(),
            exclusions: vec!["allowed.test".into(), "192.0.2.0/24".into()],
        };
        let router = policy.compile().unwrap();
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        router.learned.lock().unwrap().insert(
            (target.ip(), "protected.test".into()),
            Instant::now() + Duration::from_secs(60),
        );
        assert_eq!(router.decide(target).action, Action::Direct);
        assert_eq!(router.decide(target).basis, Basis::NumericDestination);
        assert_eq!(
            router.context.revision,
            policy.compile().unwrap().context.revision
        );
        assert_ne!(
            router.context.revision,
            Policy {
                mode: "selective".into(),
                ..policy.clone()
            }
            .compile()
            .unwrap()
            .context
            .revision
        );
        assert!(
            policy
                .compile_with_context(Context {
                    source: rtrust_profile::routing::Source::Admin,
                    revision: Some("x".repeat(257))
                })
                .is_err()
        );
        assert_eq!(router.preview_hostname().action, Action::Unknown);
        let serialized = serde_json::to_string(&router.decide(target)).unwrap();
        assert!(!serialized.contains("allowed.test") && !serialized.contains("192.0.2.1"));
    }
    #[test]
    fn numeric_and_port_rules_have_explicit_general_selective_semantics() {
        let general = Policy {
            mode: "general".into(),
            exclusions: vec!["192.0.2.0/24".into(), "*:8080".into()],
        }
        .compile()
        .unwrap();
        assert!(!general.tunneled("192.0.2.1:443".parse().unwrap()));
        assert!(!general.tunneled("198.51.100.1:8080".parse().unwrap()));
        assert!(general.tunneled("192.0.2.1:53".parse().unwrap()));
        let selective = Policy {
            mode: "selective".into(),
            exclusions: vec!["192.0.2.1:443".into()],
        }
        .compile()
        .unwrap();
        assert!(selective.tunneled("192.0.2.1:443".parse().unwrap()));
        assert!(!selective.tunneled("192.0.2.1:80".parse().unwrap()));
    }
    #[test]
    fn malformed_rules_are_not_silently_ignored() {
        for s in [
            "*:0",
            "*",
            "a..example",
            "http://x",
            "192.0.2.1/24",
            "x:65536",
        ] {
            assert!(rule(s).is_err(), "{s}");
        }
    }
    #[test]
    fn domain_mapping_requires_matching_dns_question_and_id() {
        use hickory_proto::{
            op::Query,
            rr::{Name, Record, RecordType, rdata::A},
        };
        let router = Policy {
            mode: "general".into(),
            exclusions: vec!["*.example.com".into()],
        }
        .compile()
        .unwrap();
        let name = Name::from_ascii("www.example.com.").unwrap();
        let mut query = Message::query();
        query.metadata.id = 42;
        query.add_query(Query::query(name.clone(), RecordType::A));
        let mut answer = query.clone();
        answer.metadata.message_type = MessageType::Response;
        answer.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        answer.metadata.id = 43;
        router.learn(&query.to_vec().unwrap(), &answer.to_vec().unwrap());
        assert!(router.tunneled("192.0.2.1:443".parse().unwrap()));
        answer.metadata.id = 42;
        router.learn(&query.to_vec().unwrap(), &answer.to_vec().unwrap());
        assert!(!router.tunneled("192.0.2.1:443".parse().unwrap()));
        let other = Name::from_ascii("protected.invalid.").unwrap();
        let mut query = Message::query();
        query.metadata.id = 44;
        query.add_query(Query::query(other.clone(), RecordType::A));
        let mut answer = query.clone();
        answer.metadata.message_type = MessageType::Response;
        answer.add_answer(Record::from_rdata(
            other,
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        router.learn(&query.to_vec().unwrap(), &answer.to_vec().unwrap());
        assert!(
            router.tunneled("192.0.2.1:443".parse().unwrap()),
            "Shared-IP name conflict must remain protected"
        );
    }
}
