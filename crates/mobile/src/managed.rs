//! Device-assigned IPv4 groups use the desktop route subtraction contract.
use crate::{Plan, prepare};
use rtrust_control::Selection;
use rtrust_profile::Profile;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub group: String,
    pub revision: String,
    pub include: Vec<ipnet::Ipv4Net>,
    pub exclude: Vec<ipnet::Ipv4Net>,
    pub exclude_lan: bool,
}
impl Group {
    pub fn validate(&self) -> Result<Selection, String> {
        if !(1..=80).contains(&self.group.chars().count())
            || self.group.chars().any(char::is_control)
            || !(1..=64).contains(&self.revision.len())
            || !self.revision.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err("Invalid managed routing identity".into());
        }
        // LAN subtraction depends on live local prefixes and their handoff.
        // Refuse that capability until Android owns its route refresh lifecycle.
        if self.exclude_lan {
            return Err("Managed LAN exclusion is not supported on Android".into());
        }
        let selection = Selection {
            include: self.include.clone(),
            exclude: self.exclude.clone(),
            exclude_lan: false,
        };
        selection.validate()?;
        Ok(selection)
    }
}
pub fn prepare_group(profile: Profile, group: &Group) -> Result<(Profile, Plan), String> {
    let selection = group.validate()?;
    // Preserve and validate the embedded flow/DNS/guard policy first. The device
    // group's selected IPv4 prefixes override only OS route selection.
    let (profile, mut plan) = prepare(profile)?;
    let endpoints = profile
        .endpoint
        .addresses
        .iter()
        .filter_map(
            |value| match value.parse::<std::net::SocketAddr>().ok()?.ip() {
                std::net::IpAddr::V4(ip) => Some(ip),
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    let mut routes = selection.routes(&endpoints, &[])?;
    for dns in &plan.dns {
        let ip: std::net::Ipv4Addr = dns
            .parse()
            .map_err(|_| "Managed IPv4 group requires IPv4 VPN DNS")?;
        if !routes.iter().any(|route| route.contains(&ip)) {
            routes.push(ip.into());
        }
    }
    routes.sort();
    routes.dedup();
    if routes.len() > 256 {
        return Err("Mobile route limit exceeded".into());
    }
    plan.routes = routes.iter().map(ToString::to_string).collect();
    plan.ipv6 = false;
    Ok((profile, plan))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn device_group_preserves_flow_dns_and_guard_but_selects_ipv4() {
        let mut profile = Profile::import("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n").unwrap();
        profile.policy = serde_json::json!({"mode":"selective","exclusions":["*.example:443"],"kill_switch":"always_on","dns_upstreams":["tls://dns.example"]});
        let group: Group = serde_json::from_value(serde_json::json!({"group":"Team","revision":"admin:1:2","include":["10.0.0.0/8"],"exclude":["10.2.0.0/16"],"exclude_lan":false})).unwrap();
        let (_, plan) = prepare_group(profile, &group).unwrap();
        assert_eq!(plan.flow.mode, "selective");
        assert_eq!(plan.flow.exclusions, ["*.example:443"]);
        assert!(plan.require_lockdown);
        assert!(!plan.ipv6);
        let routes = plan
            .routes
            .iter()
            .map(|s| s.parse::<ipnet::Ipv4Net>().unwrap())
            .collect::<Vec<_>>();
        assert!(
            routes
                .iter()
                .any(|r| r.contains(&"10.1.0.1".parse::<std::net::Ipv4Addr>().unwrap()))
        );
        assert!(
            !routes
                .iter()
                .any(|r| r.contains(&"10.2.0.1".parse::<std::net::Ipv4Addr>().unwrap()))
        );
        assert!(
            routes
                .iter()
                .any(|r| r.contains(&"198.18.0.53".parse::<std::net::Ipv4Addr>().unwrap()))
        );
        let mut unsupported = group;
        unsupported.exclude_lan = true;
        assert!(unsupported.validate().is_err());
    }
}
