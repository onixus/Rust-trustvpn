//! Explicit mobile adaptation of portable desktop route/DNS policy.
use ipnet::IpNet;
use rtrust_profile::Profile;
use serde::Serialize;
use serde_json::Value;
#[cfg(test)]
use serde_json::json;

#[derive(Serialize)]
pub struct Plan {
    pub flow: rtrust_engine::routing::Policy,
    pub mtu: u16,
    pub routes: Vec<String>,
    pub dns: Vec<String>,
    pub ipv6: bool,
    pub require_lockdown: bool,
}
fn bad() -> String {
    "Unsupported mobile policy field or value; no routing settings were discarded".into()
}
fn strings(v: Option<&Value>) -> Result<Vec<String>, String> {
    match v {
        None => Ok(vec![]),
        Some(Value::Array(a)) if a.len() <= 64 => a
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(bad))
            .collect(),
        _ => Err(bad()),
    }
}
fn networks(values: &[String]) -> Result<Vec<IpNet>, String> {
    values.iter().map(|s| {
        let net = s.parse::<IpNet>().or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from)).map_err(|_| "Domain/port exclusions require a flow-routing policy and cannot be mapped to Android IP routes".to_owned())?;
        if net != net.trunc() { return Err(bad()); }
        Ok(net)
    }).collect()
}
fn subtract(route: IpNet, excluded: IpNet, out: &mut Vec<IpNet>) -> Result<(), String> {
    if out.len() >= 256 {
        return Err("Mobile route limit exceeded".into());
    }
    if excluded.contains(&route) {
        return Ok(());
    }
    if !route.contains(&excluded) {
        out.push(route);
        return Ok(());
    }
    for child in route.subnets(route.prefix_len() + 1).map_err(|_| bad())? {
        subtract(child, excluded, out)?;
    }
    Ok(())
}
pub fn prepare(mut profile: Profile) -> Result<(Profile, Plan), String> {
    profile.validate().map_err(|e| e.to_string())?;
    let mut mode = "general".to_owned();
    let mut include: Vec<String> = vec!["0.0.0.0/0".into(), "::/0".into()];
    let mut exclude = vec![];
    let mut special = vec![];
    let mut require_lockdown = false;
    let mut mtu = 1500;
    if let Some(cli) = &profile.original_cli {
        let value = serde_json::to_value(cli).map_err(|_| bad())?;
        let root = value.as_object().ok_or_else(bad)?;
        for (key, value) in root {
            match key.as_str() {
                "endpoint" | "listener" => {}
                "vpn_mode" => mode = value.as_str().ok_or_else(bad)?.into(),
                "exclusions" => special = strings(Some(value))?,
                "dns_upstreams" if profile.endpoint.dns_upstreams.is_empty() => {
                    profile.endpoint.dns_upstreams = strings(Some(value))?
                }
                "dns_upstreams" if strings(Some(value))?.is_empty() => {}
                "killswitch_enabled" if value.as_bool() == Some(true) => {}
                "killswitch_allow_ports" if value.as_array().is_some_and(Vec::is_empty) => {}
                "loglevel"
                    if matches!(
                        value.as_str(),
                        Some("info" | "warn" | "error" | "debug" | "trace")
                    ) => {}
                _ => return Err(bad()),
            }
        }
        if let Some(listener) = root.get("listener") {
            let listener = listener.as_object().ok_or_else(bad)?;
            if listener.len() != 1 || !listener.contains_key("tun") {
                return Err(bad());
            }
            for (key, value) in listener["tun"].as_object().ok_or_else(bad)? {
                match key.as_str() {
                    "included_routes" => include = strings(Some(value))?,
                    "excluded_routes" => exclude = strings(Some(value))?,
                    "change_system_dns" if value.as_bool() == Some(true) => {}
                    "mtu_size" if matches!(value.as_u64(), Some(1280 | 1500)) => {
                        mtu = value.as_u64().unwrap() as u16;
                    }
                    "bound_if" if value.as_str() == Some("") => {}
                    _ => return Err(bad()),
                }
            }
        }
    }
    if !profile.policy.is_null() {
        let policy = profile.policy.as_object().ok_or_else(bad)?;
        if profile.original_cli.is_some() && !policy.is_empty() {
            return Err("Conflicting CLI and application policy".into());
        }
        for (key, value) in policy {
            match key.as_str() {
                "mode" => mode = value.as_str().ok_or_else(bad)?.into(),
                "exclusions" => special = strings(Some(value))?,
                "included_routes" => include = strings(Some(value))?,
                "excluded_routes" => exclude = strings(Some(value))?,
                "dns_upstreams" => profile.endpoint.dns_upstreams = strings(Some(value))?,
                "ipv6" if value.as_str() == Some("block") => profile.endpoint.has_ipv6 = false,
                "ipv6" if value.as_str() == Some("tunnel") && profile.endpoint.has_ipv6 => {}
                "kill_switch" if value.as_str() == Some("always_on") => require_lockdown = true,
                "kill_switch" if value.as_str() == Some("during_session") => {}
                "allow_lan" if value.as_bool() == Some(false) => {}
                "fallback" if value.as_str() == Some("disabled") => {}
                _ => return Err(bad()),
            }
        }
    }
    let mut routes = networks(&include)?;
    let flow = rtrust_engine::routing::Policy {
        mode,
        exclusions: special,
    };
    flow.compile().map_err(|e| e.to_string())?;
    for excluded in networks(&exclude)? {
        let mut kept = vec![];
        for route in routes {
            subtract(route, excluded, &mut kept)?;
        }
        routes = kept;
    }
    routes.retain(|r| profile.endpoint.has_ipv6 || matches!(r, IpNet::V4(_)));
    if routes.is_empty() || routes.len() > 256 {
        return Err("Mobile policy has no usable routes or exceeds route limit".into());
    }
    let encrypted = rtrust_engine::dns::encrypted(&profile.endpoint.dns_upstreams)
        .map_err(|e| e.to_string())?
        .is_some();
    let dns = if encrypted {
        vec!["198.18.0.53".into()]
    } else if profile.endpoint.dns_upstreams.is_empty() {
        vec!["1.1.1.1".into()]
    } else {
        profile.endpoint.dns_upstreams.clone()
    };
    for server in &dns {
        let ip: std::net::IpAddr = server.parse().map_err(|_| bad())?;
        if ip.is_ipv6() && !profile.endpoint.has_ipv6 {
            return Err("IPv6 DNS requires IPv6 support".into());
        }
        // DNS always goes through the VPN, including selective mode.
        if !routes.iter().any(|r| r.contains(&ip)) {
            routes.push(ip.into());
        }
    }
    routes.sort();
    routes.dedup();
    profile.policy = serde_json::to_value(&flow).map_err(|_| bad())?;
    let plan = Plan {
        flow,
        mtu,
        routes: routes.iter().map(ToString::to_string).collect(),
        dns,
        ipv6: profile.endpoint.has_ipv6,
        require_lockdown,
    };
    // Only this validated runtime copy is adapted; original imports/exports stay unchanged.
    profile.original_cli = None;
    Ok((profile, plan))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        Profile::import("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\nhas_ipv6=false\n").unwrap()
    }
    #[test]
    fn selective_routes_intersect_inclusions_and_keep_dns_inside_vpn() {
        let mut p = profile();
        p.policy = json!({"mode":"selective","included_routes":["10.0.0.0/8"],"exclusions":["10.2.0.0/16","192.0.2.0/24"],"dns_upstreams":["tls://dns.example"]});
        let (runtime, plan) = prepare(p).unwrap();
        assert_eq!(plan.routes, ["10.0.0.0/8", "198.18.0.53/32"]);
        assert!(
            plan.flow
                .compile()
                .unwrap()
                .tunneled("10.2.0.1:443".parse().unwrap())
        );
        assert!(
            !plan
                .flow
                .compile()
                .unwrap()
                .tunneled("10.3.0.1:443".parse().unwrap())
        );
        assert_eq!(runtime.policy["mode"], "selective");
    }
    #[test]
    fn exclusions_are_subtracted_without_broadening_or_losing_adjacent_addresses() {
        let mut p = profile();
        p.policy = json!({"included_routes":["10.0.0.0/24"],"excluded_routes":["10.0.0.128/25"]});
        let (_, plan) = prepare(p).unwrap();
        assert!(plan.routes.contains(&"10.0.0.0/25".into()));
        assert!(!plan.routes.contains(&"10.0.0.0/24".into()));
    }
    #[test]
    fn unsafe_or_unrepresentable_policies_never_degrade_to_full_tunnel() {
        for policy in [
            json!({"exclusions":["*invalid.example.com"]}),
            json!({"mode":"selective","exclusions":[]}),
            json!({"kill_switch":"off"}),
            json!({"unknown":true}),
            json!({"included_routes":["10.0.0.1/24"]}),
        ] {
            let mut p = profile();
            p.policy = policy;
            assert!(prepare(p).is_err());
        }
    }
}
