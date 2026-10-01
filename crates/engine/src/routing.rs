//! Bounded destination routing with DNS provenance; no resolver or socket side effects.
use crate::{Error, Result};
use hickory_proto::{
    op::{Message, MessageType},
    rr::RData,
};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
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
        if !matches!(self.mode.as_str(), "general" | "selective")
            || self.exclusions.len() > 64
            || (self.mode == "selective" && self.exclusions.is_empty())
        {
            return Err(Error::Unsupported("routing policy"));
        }
        Ok(Router {
            selective: self.mode == "selective",
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
        // DNS is always resolved inside VPN; it also supplies authenticated provenance for domain rules.
        if destination.port() == 53 {
            return true;
        }
        let mut names = self.learned.lock().unwrap_or_else(|p| p.into_inner());
        names.retain(|_, expiry| *expiry > Instant::now());
        let matches = |name: Option<&str>| {
            self.rules.iter().any(|r| {
                if r.port.is_some_and(|p| p != destination.port()) {
                    return false;
                }
                match &r.host {
                    Host::Any => true,
                    Host::Net(net) => net.contains(&destination.ip()),
                    Host::Domain(domain, wildcard) => name.is_some_and(|name| {
                        name == domain || (*wildcard && name.ends_with(&format!(".{domain}")))
                    }),
                }
            })
        };
        let known: Vec<_> = names
            .keys()
            .filter(|(ip, _)| *ip == destination.ip())
            .map(|(_, name)| name.as_str())
            .collect();
        let matched = matches(None) || known.iter().any(|name| matches(Some(name)));
        if self.selective {
            // Cached application DNS / external encrypted resolvers may hide the name.
            // Unknown destinations remain tunneled when domain rules are present.
            matched
                || (known.is_empty()
                    && self
                        .rules
                        .iter()
                        .any(|r| matches!(r.host, Host::Domain(..))))
        } else {
            // Shared CDN IPs with conflicting observed names stay protected.
            !matched
                || (!known.is_empty()
                    && !matches(None)
                    && known.iter().any(|name| !matches(Some(name))))
        }
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
        let mut learned = self.learned.lock().unwrap_or_else(|p| p.into_inner());
        learned.retain(|_, expiry| *expiry > Instant::now());
        for record in &answer.answers {
            if !allowed.contains(&record.name) || record.ttl == 0 {
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
                Instant::now() + Duration::from_secs(record.ttl.min(300) as u64),
            );
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
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
