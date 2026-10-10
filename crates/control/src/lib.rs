use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;
#[cfg(not(target_os = "macos"))]
pub const SOCKET: &str = "/run/rtrust/control.sock";
#[cfg(target_os = "macos")]
pub const SOCKET: &str = "/private/var/run/rtrust/control.sock";
pub const LIMIT: usize = 2 * rtrust_profile::MAX_INPUT;
pub const VERSION: u32 = 2;
pub mod observations;
pub use ipnet::Ipv4Net;
use std::net::Ipv4Addr;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub command: Command,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Command {
    Start {
        profile: Box<rtrust_profile::Profile>,
        networks: Vec<Ipv4Net>,
        // Omitted when unused, so a plain selection keeps the old wire format.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude: Vec<Ipv4Net>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        exclude_lan: bool,
        /// Resolver for the system; a service uses it only when the
        /// selection routes it through the VPN.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dns: Option<std::net::Ipv4Addr>,
    },
    StartFull {
        profile: Box<rtrust_profile::Profile>,
        dns: std::net::Ipv4Addr,
    },
    Capabilities,
    Status,
    PrepareUpdate,
    EnableAlwaysOn {
        profile: Box<rtrust_profile::Profile>,
        dns: std::net::Ipv4Addr,
    },
    DisableAlwaysOn,
    AlwaysOnStatus,
    Stop,
    Recover,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum State {
    Connected,
    Blocked,
    Idle,
    Error,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub state: State,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_on: Option<bool>,
    pub observations: observations::Snapshot,
    pub capabilities: Capabilities,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    pub observations_schema: u32,
    pub lifecycle_observations: bool,
    pub system_probes: bool,
}
impl Capabilities {
    pub fn current() -> Self {
        Self {
            observations_schema: observations::SCHEMA,
            lifecycle_observations: true,
            system_probes: false,
        }
    }
}
impl Response {
    pub fn new(state: State, message: &str) -> Self {
        Self {
            version: VERSION,
            state,
            message: message.into(),
            always_on: None,
            observations: observations::Snapshot::unknown(observations::Mode::Unknown),
            capabilities: Capabilities::current(),
        }
    }
}
/// Never routed through the selected-network TUN: unspecified, loopback,
/// link-local (the TUN source address lives there) and multicast/reserved space.
const RESERVED: [&str; 4] = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"];
pub const MAX_INCLUDE: usize = 16;
pub const MAX_EXCLUDE: usize = 64;
/// Upper bound for the installed prefix set after subtraction.
pub const MAX_ROUTES: usize = 512;

/// IPv4 split tunnel: `include` goes through the VPN except `exclude`, the
/// VPN endpoint and, with `exclude_lan`, networks already routed locally.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub include: Vec<Ipv4Net>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<Ipv4Net>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclude_lan: bool,
}
impl Selection {
    pub fn parse(include: &str, exclude: &str, exclude_lan: bool) -> Result<Self, String> {
        let selection = Self {
            include: parse_networks(include)?,
            exclude: parse_networks(exclude)?,
            exclude_lan,
        };
        selection.validate()?;
        Ok(selection)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.include.is_empty() || self.include.len() > MAX_INCLUDE {
            return Err(format!("Укажите от 1 до {MAX_INCLUDE} IPv4-сетей"));
        }
        if self.exclude.len() > MAX_EXCLUDE {
            return Err(format!("Не больше {MAX_EXCLUDE} сетей-исключений"));
        }
        if let Some(net) = self
            .include
            .iter()
            .chain(&self.exclude)
            .find(|n| n.addr() != n.network())
        {
            return Err(format!("{net}: адрес не совпадает с началом сети"));
        }
        self.routes(&[], &[]).map(|_| ())
    }
    /// Offline prediction using the same subtraction as route installation.
    /// None means missing evidence; an empty slice means the runtime inspected it.
    pub fn explain(
        &self,
        destination: std::net::IpAddr,
        endpoints: Option<&[Ipv4Addr]>,
        local: Option<&[Ipv4Net]>,
        mut context: rtrust_profile::routing::Context,
    ) -> Result<rtrust_profile::routing::Decision, String> {
        use rtrust_profile::routing::{Action, Basis, Decision, Reason, RuleId, RuleKind};
        self.validate()?;
        if context
            .revision
            .as_ref()
            .is_some_and(|r| r.is_empty() || r.len() > 256 || r.chars().any(char::is_control))
        {
            return Err("Недопустимая ревизия политики".into());
        }
        if context.revision.is_none() {
            use sha2::Digest;
            context.revision = Some(format!(
                "{:x}",
                sha2::Sha256::digest(serde_json::to_vec(self).map_err(|_| "Invalid selection")?)
            ));
        }
        // Validate the final runtime prefix set before describing a configuration
        // that could not be installed at all.
        if let Some(endpoints) = endpoints
            && (!self.exclude_lan || local.is_some())
        {
            self.routes(endpoints, local.unwrap_or_default())?;
        }
        let std::net::IpAddr::V4(ip) = destination else {
            return Ok(Decision::unknown(context, Reason::UnsupportedFamily));
        };
        let make = |action, rules, reason| Decision {
            action,
            scope: rtrust_profile::routing::Scope::SelectedIpv4,
            rules,
            context: context.clone(),
            reason,
            basis: Basis::NumericDestination,
            prediction: true,
        };
        if let Some(index) = RESERVED
            .iter()
            .position(|s| s.parse::<Ipv4Net>().unwrap().contains(&ip))
        {
            return Ok(make(
                Action::Direct,
                vec![RuleId {
                    kind: RuleKind::Reserved,
                    index: index as u8,
                }],
                Reason::ReservedAddress,
            ));
        }
        let rules: Vec<_> = self
            .exclude
            .iter()
            .enumerate()
            .filter(|(_, n)| n.contains(&ip))
            .map(|(index, _)| RuleId {
                kind: RuleKind::Exclude,
                index: index as u8,
            })
            .collect();
        if !rules.is_empty() {
            return Ok(make(Action::Direct, rules, Reason::ExcludedPrefix));
        }
        let rules: Vec<_> = self
            .include
            .iter()
            .enumerate()
            .filter(|(_, n)| n.contains(&ip))
            .map(|(index, _)| RuleId {
                kind: RuleKind::Include,
                index: index as u8,
            })
            .collect();
        if rules.is_empty() {
            return Ok(make(Action::Direct, rules, Reason::OutsideSelection));
        }
        let Some(endpoints) = endpoints else {
            return Ok(Decision::unknown(context, Reason::EndpointUnresolved));
        };
        if endpoints.contains(&ip) {
            return Ok(make(Action::Direct, vec![], Reason::EndpointBypass));
        }
        if self.exclude_lan {
            let Some(local) = local else {
                return Ok(Decision::unknown(context, Reason::LocalNetworksUnobserved));
            };
            if local.iter().any(|n| n.contains(&ip)) {
                return Ok(make(Action::Direct, vec![], Reason::LocalNetworkBypass));
            }
        }
        let installed = self.routes(endpoints, local.unwrap_or_default())?;
        Ok(make(
            if installed.iter().any(|n| n.contains(&ip)) {
                Action::Tunnel
            } else {
                Action::Direct
            },
            rules,
            Reason::SelectedPrefix,
        ))
    }
    /// Prefixes to install. `local` is subtracted only with `exclude_lan`.
    pub fn routes(
        &self,
        endpoints: &[Ipv4Addr],
        local: &[Ipv4Net],
    ) -> Result<Vec<Ipv4Net>, String> {
        let mut removed: Vec<Ipv4Net> = RESERVED.iter().map(|s| s.parse().unwrap()).collect();
        removed.extend(&self.exclude);
        removed.extend(endpoints.iter().map(|ip| Ipv4Net::from(*ip)));
        if self.exclude_lan {
            removed.extend(local);
        }
        let routes = cidrs(&subtract(&ranges(&self.include), &ranges(&removed)));
        if routes.is_empty() {
            return Err("После исключений не осталось сетей для VPN".into());
        }
        if routes.len() > MAX_ROUTES {
            return Err(format!(
                "Исключения дробят выбор на {} маршрутов (максимум {MAX_ROUTES})",
                routes.len()
            ));
        }
        Ok(routes)
    }
}
fn parse_networks(text: &str) -> Result<Vec<Ipv4Net>, String> {
    text.split([',', ' ', '\n', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Ipv4Net>()
                .map_err(|_| format!("{s}: ожидается IPv4 CIDR, например 198.18.0.0/24"))
        })
        .collect()
}
/// Included networks without exclusions (the original TUN selection).
pub fn networks(text: &str) -> Result<Vec<Ipv4Net>, String> {
    Ok(Selection::parse(text, "", false)?.include)
}
/// Checks an installed or journaled prefix set produced by [`Selection::routes`].
pub fn validate_routes(nets: &[Ipv4Net]) -> Result<(), String> {
    let reserved: Vec<Ipv4Net> = RESERVED.iter().map(|s| s.parse().unwrap()).collect();
    if nets.is_empty() || nets.len() > MAX_ROUTES {
        return Err("Недопустимое число IPv4-маршрутов".into());
    }
    let mut sorted = nets.to_vec();
    sorted.sort();
    for (i, net) in sorted.iter().enumerate() {
        if net.prefix_len() == 0
            || net.addr() != net.network()
            || reserved
                .iter()
                .any(|n| n.contains(net) || net.contains(n) || n.contains(&net.network()))
            || i > 0 && u32::from(sorted[i - 1].broadcast()) >= u32::from(net.network())
        {
            return Err("Недопустимый или перекрывающийся IPv4-маршрут".into());
        }
    }
    Ok(())
}
/// Sorted, merged half-open ranges [start, end).
fn ranges(nets: &[Ipv4Net]) -> Vec<(u64, u64)> {
    let mut all: Vec<(u64, u64)> = nets
        .iter()
        .map(|n| {
            (
                u32::from(n.network()) as u64,
                u32::from(n.broadcast()) as u64 + 1,
            )
        })
        .collect();
    all.sort();
    let mut merged: Vec<(u64, u64)> = Vec::new();
    for (start, end) in all {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
}
fn subtract(from: &[(u64, u64)], removed: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut result = Vec::new();
    for &(mut start, end) in from {
        for &(a, b) in removed {
            if b <= start || a >= end {
                continue;
            }
            if a > start {
                result.push((start, a));
            }
            start = start.max(b);
            if start >= end {
                break;
            }
        }
        if start < end {
            result.push((start, end));
        }
    }
    result
}
fn cidrs(ranges: &[(u64, u64)]) -> Vec<Ipv4Net> {
    let mut nets = Vec::new();
    for &(mut start, end) in ranges {
        while start < end {
            let align = if start == 0 {
                32
            } else {
                start.trailing_zeros().min(32)
            };
            let fit = 63 - (end - start).leading_zeros();
            let bits = align.min(fit);
            nets.push(Ipv4Net::new(Ipv4Addr::from(start as u32), (32 - bits) as u8).unwrap());
            start += 1 << bits;
        }
    }
    nets
}
pub async fn read<T: serde::de::DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<T, String> {
    let len = stream.read_u32().await.map_err(|_| "IPC closed")? as usize;
    if len == 0 || len > LIMIT {
        return Err("IPC frame limit exceeded".into());
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "IPC closed")?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid IPC message (redacted)".into())
}
pub async fn write<T: Serialize>(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> Result<(), String> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| "IPC serialization failed")?);
    if bytes.len() > LIMIT {
        return Err("IPC frame limit exceeded".into());
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| "IPC closed")?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| "IPC closed".into())
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod client;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub use client::Client;

/// DNS must be a routable IPv4 host, including private VPN resolvers.
pub fn validate_dns(ip: std::net::Ipv4Addr) -> Result<(), String> {
    let first = ip.octets()[0];
    if first == 0 || ip.is_loopback() || ip.is_link_local() || first >= 224 {
        return Err("DNS должен быть IPv4-адресом сервера, доступного через VPN".into());
    }
    Ok(())
}

/// The split-mode resolver: `dns`, if valid and routed by `networks`.
/// Services then point the system at it so names do not leak to the LAN.
pub fn tunneled_resolver(
    networks: &[Ipv4Net],
    dns: Option<std::net::Ipv4Addr>,
) -> Option<std::net::Ipv4Addr> {
    dns.filter(|ip| validate_dns(*ip).is_ok() && networks.iter().any(|n| n.contains(ip)))
}

#[cfg(test)]
mod tests {
    #[test]
    fn selection_explain_matches_the_prefixes_installed_with_runtime_inputs() {
        use rtrust_profile::routing::{Action, Context, Reason};
        let selection = Selection::parse("0.0.0.0/0", "10.0.0.0/8", true).unwrap();
        let endpoints: [Ipv4Addr; 1] = ["203.0.113.1".parse().unwrap()];
        let local = ["192.168.1.0/24".parse().unwrap()];
        let routes = selection.routes(&endpoints, &local).unwrap();
        for text in [
            "1.1.1.1",
            "10.1.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "192.168.1.1",
            "203.0.113.1",
            "203.0.113.2",
            "224.0.0.1",
        ] {
            let ip: Ipv4Addr = text.parse().unwrap();
            let explanation = selection
                .explain(
                    ip.into(),
                    Some(&endpoints),
                    Some(&local),
                    Context::default(),
                )
                .unwrap();
            assert_eq!(
                explanation.action == Action::Tunnel,
                routes.iter().any(|n| n.contains(&ip)),
                "{text}"
            );
            assert!(explanation.prediction);
            assert!(explanation.context.revision.is_some());
        }
        let unknown = selection
            .explain("8.8.8.8".parse().unwrap(), None, None, Context::default())
            .unwrap();
        assert_eq!(unknown.action, Action::Unknown);
        assert_eq!(unknown.reason, Reason::EndpointUnresolved);
        let lan = selection
            .explain(
                "8.8.8.8".parse().unwrap(),
                Some(&[]),
                None,
                Context::default(),
            )
            .unwrap();
        assert_eq!(lan.reason, Reason::LocalNetworksUnobserved);
        assert_eq!(
            selection
                .explain(
                    "2001:db8::1".parse().unwrap(),
                    Some(&[]),
                    Some(&[]),
                    Context::default()
                )
                .unwrap()
                .action,
            Action::Unknown
        );
    }
    #[test]
    fn selection_explain_rejects_an_uninstallable_final_policy() {
        let selection = Selection::parse("203.0.113.1/32", "", false).unwrap();
        let endpoints: [Ipv4Addr; 1] = ["203.0.113.1".parse().unwrap()];
        assert!(
            selection
                .explain(
                    endpoints[0].into(),
                    Some(&endpoints),
                    Some(&[]),
                    rtrust_profile::routing::Context::default()
                )
                .is_err()
        );
    }
    #[test]
    fn full_dns_rejects_local_and_non_unicast_destinations() {
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.53",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                super::validate_dns(address.parse().unwrap()).is_err(),
                "{address}"
            );
        }
        for address in ["1.1.1.1", "10.0.0.53", "198.18.0.1"] {
            assert!(super::validate_dns(address.parse().unwrap()).is_ok());
        }
    }

    use super::*;
    #[test]
    fn bounded_network_selection() {
        assert!(networks("198.18.0.0/24,10.20.0.0/16").is_ok());
        for value in [
            "",
            "127.0.0.0/8",
            "198.18.0.1/24",
            "::/0",
            "224.0.0.1/32",
            "169.254.0.0/16",
        ] {
            assert!(networks(value).is_err(), "{value}");
        }
        let all = (0..17)
            .map(|i| format!("10.{i}.0.0/16"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(networks(&all).is_err());
    }
    #[test]
    fn whole_ipv4_minus_reserved_lan_and_endpoint() {
        let selection = Selection::parse(
            "0.0.0.0/0",
            "10.0.0.0/8, 172.16.0.0/12\n192.168.0.0/16",
            false,
        )
        .unwrap();
        let endpoint: Ipv4Addr = "203.0.113.7".parse().unwrap();
        let routes = selection.routes(&[endpoint], &[]).unwrap();
        validate_routes(&routes).unwrap();
        let routed = |ip: &str| {
            let ip: Ipv4Addr = ip.parse().unwrap();
            routes.iter().any(|n| n.contains(&ip))
        };
        for ip in [
            "1.1.1.1",
            "8.8.8.8",
            "203.0.113.6",
            "203.0.113.8",
            "223.255.255.255",
            "100.64.0.1",
        ] {
            assert!(routed(ip), "{ip}");
        }
        for ip in [
            "203.0.113.7",
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.68.1",
            "127.0.0.1",
            "169.254.254.2",
            "0.1.2.3",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!routed(ip), "{ip}");
        }
        assert!(routes.len() < 100, "{}", routes.len());
    }
    #[test]
    fn local_networks_are_subtracted_only_on_request() {
        let local: Vec<Ipv4Net> = vec!["100.64.1.0/24".parse().unwrap()];
        let keep = Selection::parse("100.64.0.0/10", "", false).unwrap();
        assert_eq!(
            keep.routes(&[], &local).unwrap(),
            vec!["100.64.0.0/10".parse::<Ipv4Net>().unwrap()]
        );
        let lan = Selection {
            exclude_lan: true,
            ..keep
        };
        let routes = lan.routes(&[], &local).unwrap();
        assert!(
            !routes
                .iter()
                .any(|n| n.contains(&"100.64.1.9".parse::<Ipv4Addr>().unwrap()))
        );
        assert!(
            routes
                .iter()
                .any(|n| n.contains(&"100.64.2.9".parse::<Ipv4Addr>().unwrap()))
        );
        assert!(Selection::parse("192.168.0.0/16", "192.168.0.0/16", false).is_err());
        assert!(Selection::parse("10.0.0.0/8", "10.0.0.1/8", false).is_err());
    }
    #[test]
    fn route_set_validation_rejects_overlap_and_reserved() {
        let parse = |v: &str| {
            v.split(',')
                .map(|s| s.parse().unwrap())
                .collect::<Vec<Ipv4Net>>()
        };
        validate_routes(&parse("1.0.0.0/8,2.0.0.0/7")).unwrap();
        for bad in [
            "0.0.0.0/1",
            "10.0.0.0/8,10.1.0.0/16",
            "126.0.0.0/7",
            "169.254.1.0/24",
            "224.0.0.0/4",
        ] {
            assert!(validate_routes(&parse(bad)).is_err(), "{bad}");
        }
        assert!(validate_routes(&[]).is_err());
    }
    #[test]
    fn plain_start_keeps_the_old_wire_format() {
        let profile = rtrust_profile::Profile::import(
            "hostname='vpn.example'\naddresses=['192.0.2.1:443']\nusername='u'\npassword='p'\n",
        )
        .unwrap();
        let command = |exclude: Vec<Ipv4Net>, exclude_lan, dns| {
            serde_json::to_value(Command::Start {
                profile: Box::new(profile.clone()),
                networks: vec!["10.0.0.0/8".parse().unwrap()],
                exclude,
                exclude_lan,
                dns,
            })
            .unwrap()
        };
        let plain = command(vec![], false, None);
        assert!(
            plain.get("exclude").is_none()
                && plain.get("exclude_lan").is_none()
                && plain.get("dns").is_none()
        );
        let split = command(
            vec!["10.1.0.0/16".parse().unwrap()],
            true,
            Some("1.1.1.1".parse().unwrap()),
        );
        assert_eq!(split["exclude"][0], "10.1.0.0/16");
        assert_eq!(split["exclude_lan"], true);
        assert_eq!(split["dns"], "1.1.1.1");
        let old: Command = serde_json::from_value(plain).unwrap();
        assert!(matches!(old, Command::Start { dns: None, .. }));
    }
    #[test]
    fn tunneled_resolver_requires_a_routed_valid_address() {
        let networks: Vec<Ipv4Net> = vec!["0.0.0.0/1".parse().unwrap()];
        let ip = |s: &str| Some(s.parse().unwrap());
        assert_eq!(tunneled_resolver(&networks, ip("1.1.1.1")), ip("1.1.1.1"));
        assert_eq!(tunneled_resolver(&networks, ip("192.168.1.1")), None);
        assert_eq!(tunneled_resolver(&networks, ip("127.0.0.1")), None);
        assert_eq!(tunneled_resolver(&networks, None), None);
    }
    #[tokio::test]
    async fn oversized_frame_rejected_before_body_and_secrets_redacted() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_u32(u32::MAX).await.unwrap();
        assert!(read::<Request>(&mut reader).await.is_err());
        let malformed = b"secret-password";
        writer.write_u32(malformed.len() as u32).await.unwrap();
        writer.write_all(malformed).await.unwrap();
        assert!(
            !read::<Request>(&mut reader)
                .await
                .err()
                .unwrap()
                .contains("secret-password")
        );
    }
}

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
mod broker;
