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
        let selection = Selection {
            include: self.include.clone(),
            exclude: self.exclude.clone(),
            exclude_lan: self.exclude_lan,
        };
        selection.validate()?;
        Ok(selection)
    }
}
pub fn prepare_group(profile: Profile, group: &Group) -> Result<(Profile, Plan), String> {
    prepare_group_on_network(profile, group, Some(&[]))
}
pub fn prepare_group_on_network(
    profile: Profile,
    group: &Group,
    local: Option<&[ipnet::Ipv4Net]>,
) -> Result<(Profile, Plan), String> {
    let selection = group.validate()?;
    if group.exclude_lan && local.is_none() {
        return Err("Local network prefixes not observed".into());
    }
    let local = local.unwrap_or_default();
    if local.len() > 64 {
        return Err("Local prefix limit exceeded".into());
    }
    // Preserve and validate the embedded flow/DNS/guard policy first. The device
    // group's selected IPv4 prefixes override only OS route selection.
    let (mut profile, mut plan) = prepare(profile)?;
    let local = local.iter().map(|n| n.trunc()).collect::<Vec<_>>();
    // Endpoint sockets use VpnService.protect + underlying-network binding;
    // application flows to those IPs still follow the assigned selection.
    let mut routes = selection.routes(&[], &local)?;
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
    // The runtime copy also drives transport capability/status; do not announce
    // IPv6 when this selected-IPv4 group blocks the family in VpnService.
    profile.endpoint.has_ipv6 = false;
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
        let (runtime, plan) = prepare_group(profile, &group).unwrap();
        assert!(!runtime.endpoint.has_ipv6);
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
        assert!(unsupported.validate().is_ok());
        assert!(prepare_group_on_network(runtime.clone(), &unsupported, None).is_err());
        let (_, lan) = prepare_group_on_network(
            runtime,
            &unsupported,
            Some(&["10.1.0.4/24".parse().unwrap()]),
        )
        .unwrap();
        assert!(!lan.routes.iter().any(|r| {
            r.parse::<ipnet::Ipv4Net>()
                .unwrap()
                .contains(&"10.1.0.3".parse::<std::net::Ipv4Addr>().unwrap())
        }));
    }
}
