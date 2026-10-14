//! The service's own read-only DNS, guard and transport probes (issue #81).
//!
//! One run at a time per lease, on the lease loop's own timer, never on
//! Status. Each run is tagged with the snapshot generation it started in and
//! bounded by a hard deadline; dropping it cancels it and kills its children.
//! Nothing here changes routes, DNS, marks or firewall rules. Facts are reduced
//! to the enums below at once: no address, interface or tool output survives.
use rtrust_control::observations::{
    Mode, Observation, Outcome, PROBE_DEADLINE_MS, PROBE_INTERVAL_MS, SystemProbe, now_ms,
};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    time::Duration,
};

/// Wait after Connected or an invalidation before the first run.
const SETTLE: Duration = Duration::from_secs(2);
/// Per external tool.
#[cfg(unix)]
const STEP: Duration = Duration::from_secs(2);
const ATTEMPT: Duration = Duration::from_millis(1_500);
/// Neutral documentation destinations (RFC 5737/3849), discard port. Never
/// an endpoint, DHCP or ND port, never multicast.
pub const TARGET_V4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 9);
pub const TARGET_V6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    9,
);

type Task = Pin<Box<dyn Future<Output = SystemProbe> + Send>>;
pub enum Tick {
    Due,
    Done(u64, SystemProbe),
}
/// Single flight, no queue: a due tick while a run is pending cannot exist.
pub struct Runner {
    task: Option<(u64, Task)>,
    due: Pin<Box<tokio::time::Sleep>>,
}
impl Default for Runner {
    fn default() -> Self {
        Self {
            task: None,
            due: Box::pin(tokio::time::sleep(SETTLE)),
        }
    }
}
impl Runner {
    #[cfg(test)]
    fn busy(&self) -> bool {
        self.task.is_some()
    }
    pub fn start(
        &mut self,
        generation: u64,
        collect: impl Future<Output = SystemProbe> + Send + 'static,
    ) {
        if self.task.is_some() {
            return;
        }
        let deadline = Duration::from_millis(PROBE_DEADLINE_MS);
        self.task = Some((
            generation,
            Box::pin(async move {
                tokio::time::timeout(deadline, collect)
                    .await
                    .unwrap_or_else(|_| SystemProbe::unknown(now_ms()))
            }),
        ));
    }
    /// Drop a pending run (its sockets and children go with it) and settle.
    pub fn cancel(&mut self) {
        self.task = None;
        self.reschedule(SETTLE);
    }
    fn reschedule(&mut self, after: Duration) {
        self.due.as_mut().reset(tokio::time::Instant::now() + after);
    }
    /// Cancel-safe in `select!`: the run and the timer live in `self`.
    pub async fn next(&mut self) -> Tick {
        if let Some((generation, task)) = &mut self.task {
            let probe = task.await;
            let generation = *generation;
            self.task = None;
            self.reschedule(Duration::from_millis(PROBE_INTERVAL_MS));
            return Tick::Done(generation, probe);
        }
        self.due.as_mut().await;
        // A due tick the caller does not use must not fire again at once.
        self.reschedule(SETTLE);
        Tick::Due
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Audit {
    Match,
    Mismatch,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Path {
    Tunnel,
    Outside,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// NOERROR with at least one answer.
    Answered,
    /// A matching reply with an error or no answer: still carried by the tunnel.
    Responded,
    None,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Foreign {
    None,
    Present,
    Unknown,
}
/// One unmarked datagram bound to a physical interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    Blocked,
    Leaked,
    /// This family has no path on that interface; proves nothing either way.
    Absent,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dns {
    pub config: Audit,
    pub path: Path,
    pub reply: Reply,
    pub foreign: Foreign,
}
#[cfg(test)]
impl Dns {
    const UNKNOWN: Self = Self {
        config: Audit::Unknown,
        path: Path::Unknown,
        reply: Reply::None,
        foreign: Foreign::Unknown,
    };
}

pub fn attempt(sent: Result<(), i32>, blocked: &[i32], absent: &[i32]) -> Attempt {
    match sent {
        Ok(()) => Attempt::Leaked,
        Err(code) if blocked.contains(&code) => Attempt::Blocked,
        Err(code) if absent.contains(&code) => Attempt::Absent,
        Err(_) => Attempt::Unknown,
    }
}
/// Passed needs the exact own rule set and a local refusal on every probed
/// interface; any leak or missing/changed rule is a failure.
pub fn guard(audit: Audit, attempts: &[Attempt]) -> Outcome {
    if audit == Audit::Mismatch || attempts.contains(&Attempt::Leaked) {
        Outcome::Failed
    } else if audit == Audit::Match
        && attempts.contains(&Attempt::Blocked)
        && attempts
            .iter()
            .all(|a| matches!(a, Attempt::Blocked | Attempt::Absent))
    {
        Outcome::Passed
    } else {
        Outcome::Unknown
    }
}
/// Another resolver the OS may pick is contained only by a proven guard.
pub fn dns(facts: Dns, guard: Outcome) -> Outcome {
    let contained = match facts.foreign {
        Foreign::None => Some(true),
        Foreign::Present => Some(guard == Outcome::Passed),
        Foreign::Unknown => (guard == Outcome::Passed).then_some(true),
    };
    if facts.config == Audit::Mismatch || facts.path == Path::Outside || contained == Some(false) {
        Outcome::Failed
    } else if facts.config == Audit::Match
        && facts.path == Path::Tunnel
        && facts.reply == Reply::Answered
        && contained == Some(true)
    {
        Outcome::Passed
    } else {
        Outcome::Unknown
    }
}
pub fn result(facts: Dns, audit: Audit, attempts: &[Attempt], at: u64) -> SystemProbe {
    let guard = guard(audit, attempts);
    SystemProbe {
        transport_proven_at: matches!(facts.reply, Reply::Answered | Reply::Responded)
            .then_some(at),
        dns: Observation::system(dns(facts, guard), Mode::Full, at),
        guard: Observation::system(guard, Mode::Full, at),
    }
}
/// A probe target that is also an endpoint would test an exemption.
pub fn collides(endpoints: &[IpAddr]) -> bool {
    endpoints
        .iter()
        .any(|ip| *ip == TARGET_V4.ip() || *ip == TARGET_V6.ip())
}

/// `.` IN NS, recursion desired: no user, profile or destination data.
pub fn query(id: u16) -> [u8; 17] {
    let [a, b] = id.to_be_bytes();
    [a, b, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
}
pub fn reply(id: u16, bytes: &[u8]) -> Reply {
    if bytes.len() < 17
        || bytes[..2] != id.to_be_bytes()
        || bytes[2] & 0x80 == 0
        || bytes[2] & 0x78 != 0
        || bytes[4..6] != [0, 1]
        || bytes[12..17] != [0, 0, 2, 0, 1]
    {
        return Reply::None;
    }
    if bytes[3] & 0x0f == 0 && bytes[6..8] != [0, 0] {
        Reply::Answered
    } else {
        Reply::Responded
    }
}
/// Two attempts with fresh IDs over a socket the caller bound to the tunnel.
pub async fn exchange(socket: std::net::UdpSocket, server: SocketAddr) -> Reply {
    if socket.set_nonblocking(true).is_err() {
        return Reply::None;
    }
    let Ok(socket) = tokio::net::UdpSocket::from_std(socket) else {
        return Reply::None;
    };
    for _ in 0..2 {
        let id = rand::random::<u16>();
        if socket.send_to(&query(id), server).await.is_err() {
            return Reply::None;
        }
        let answer = tokio::time::timeout(ATTEMPT, async {
            let mut buffer = [0u8; 512];
            loop {
                let (len, from) = socket.recv_from(&mut buffer).await.ok()?;
                if from == server {
                    match reply(id, &buffer[..len]) {
                        Reply::None => {}
                        found => return Some(found),
                    }
                }
            }
        })
        .await;
        if let Ok(Some(found)) = answer {
            return found;
        }
    }
    Reply::None
}
pub fn send(socket: &std::net::UdpSocket, target: SocketAddr) -> Result<(), i32> {
    socket
        .send_to(&[0], target)
        .map(drop)
        .map_err(|e| e.raw_os_error().unwrap_or(-1))
}
#[cfg(any(unix, test))]
pub fn interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}

/// One fixed read-only tool: absolute path, no shell, cleared environment,
/// bounded output and time; the child dies with the dropped future.
#[cfg(unix)]
pub async fn run(path: &'static str, args: &[&str], max: usize) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut child = tokio::process::Command::new(path)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let output = child.stdout.take()?;
    let mut bytes = Vec::new();
    let status = tokio::time::timeout(STEP, async {
        output
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        if bytes.len() > max {
            return None;
        }
        child.wait().await.ok()
    })
    .await
    .ok()??;
    status.success().then_some(bytes)
}

/// Read-back parsers for the Linux service's own objects; host-tested.
#[cfg(any(target_os = "linux", test))]
pub mod linux {
    use super::Audit;
    use serde_json::Value;
    pub fn has_table(bytes: &[u8], name: &str) -> Option<bool> {
        let value: Value = serde_json::from_slice(bytes).ok()?;
        Some(
            value["nftables"]
                .as_array()?
                .iter()
                .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == name),
        )
    }
    fn operand(value: &Value) -> Option<String> {
        match value {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Object(o) => {
                let mut items = o
                    .get("set")?
                    .as_array()?
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => Some(s.clone()),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    })
                    .collect::<Option<Vec<_>>>()?;
                items.sort();
                Some(items.join(","))
            }
            _ => None,
        }
    }
    /// Known shapes render canonically; an unknown shape proves nothing.
    fn expression(value: &Value) -> Option<String> {
        let (kind, body) = value.as_object()?.iter().next()?;
        if kind != "match" {
            return Some(kind.clone());
        }
        let op = body["op"].as_str()?;
        let left = &body["left"];
        let left = match (left["meta"]["key"].as_str(), &left["payload"]) {
            (Some(key), _) => format!("meta.{key}"),
            (None, payload) => format!(
                "{}.{}",
                payload["protocol"].as_str()?,
                payload["field"].as_str()?
            ),
        };
        let op = if matches!(op, "==" | "in") { "==" } else { op };
        Some(format!("{left}{op}{}", operand(&body["right"])?))
    }
    /// `nft -j list table`: the exact chains and rules of `expected`, in any order.
    pub fn audit(bytes: &[u8], expected: &[String]) -> Audit {
        let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
            return Audit::Unknown;
        };
        let Some(items) = value["nftables"].as_array() else {
            return Audit::Unknown;
        };
        let mut actual = Vec::new();
        for item in items {
            let Some((kind, body)) = item.as_object().and_then(|o| o.iter().next()) else {
                return Audit::Unknown;
            };
            let token = match kind.as_str() {
                "metainfo" | "table" => continue,
                "chain" => match (
                    body["name"].as_str(),
                    body["type"].as_str(),
                    body["hook"].as_str(),
                    body["prio"].as_i64(),
                    body["policy"].as_str(),
                ) {
                    (Some(name), Some(kind), Some(hook), Some(prio), Some(policy)) => {
                        format!("chain {name} {kind} {hook} {prio} {policy}")
                    }
                    (Some(name), ..) => format!("chain {name}"),
                    _ => return Audit::Unknown,
                },
                "rule" => {
                    let (Some(chain), Some(exprs)) =
                        (body["chain"].as_str(), body["expr"].as_array())
                    else {
                        return Audit::Unknown;
                    };
                    let Some(exprs) = exprs.iter().map(expression).collect::<Option<Vec<_>>>()
                    else {
                        return Audit::Unknown;
                    };
                    format!("{chain} {}", exprs.join(" "))
                }
                other => format!("object {other}"),
            };
            actual.push(token);
        }
        let mut expected = expected.to_vec();
        actual.sort();
        expected.sort();
        if actual == expected {
            Audit::Match
        } else {
            Audit::Mismatch
        }
    }
    /// `resolvectl <setting> [link]`: values listed for `device`.
    pub fn link_values(text: &str, device: &str) -> Option<Vec<String>> {
        let tag = format!("({device}):");
        let line = text.lines().find(|line| line.contains(&tag))?;
        Some(
            line.split_once(&tag)?
                .1
                .split_whitespace()
                .map(|v| v.split(['#', '%']).next().unwrap_or(v).to_owned())
                .collect(),
        )
    }
    /// `resolvectl dns`: any global or other link's server can be selected.
    pub fn foreign_links(text: &str, device: &str) -> Option<bool> {
        let tag = format!("({device})");
        let mut seen = false;
        let mut foreign = false;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (head, values) = line.split_once(':')?;
            seen = true;
            foreign |= !head.contains(&tag) && !values.trim().is_empty();
        }
        seen.then_some(foreign)
    }
    /// Programs reading resolv.conf directly bypass resolved's routing.
    pub fn resolv_conf_foreign(text: &str, dns: std::net::Ipv4Addr) -> bool {
        text.lines().any(|line| {
            let mut words = line.split_whitespace();
            words.next() == Some("nameserver")
                && words
                    .next()
                    .is_some_and(|server| server != "127.0.0.53" && server != dns.to_string())
        })
    }
    pub fn route_device(bytes: &[u8]) -> Option<String> {
        let routes: Vec<Value> = serde_json::from_slice(bytes).ok()?;
        let [route] = routes.as_slice() else {
            return None;
        };
        let dev = route["dev"].as_str()?;
        super::interface_name(dev).then(|| dev.into())
    }
    pub fn default_devices(bytes: &[u8], exclude: &str) -> Option<Vec<String>> {
        let routes: Vec<Value> = serde_json::from_slice(bytes).ok()?;
        let mut devices = Vec::new();
        for route in &routes {
            let hops = match route["nexthops"].as_array() {
                Some(hops) => hops.iter().collect(),
                None => vec![route],
            };
            for hop in hops {
                let dev = hop["dev"].as_str()?;
                if !super::interface_name(dev) {
                    return None;
                }
                if dev != exclude && !devices.iter().any(|d| d == dev) {
                    devices.push(dev.to_owned());
                }
            }
        }
        (devices.len() <= 8).then_some(devices)
    }
}

/// Read-back parsers for the macOS service's own objects; host-tested.
#[cfg(any(target_os = "macos", test))]
pub mod macos {
    use super::Audit;
    /// `pfctl -s info`.
    pub fn pf_enabled(text: &str) -> Option<bool> {
        let status = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("Status:"))?;
        match status.split_whitespace().next()? {
            "Enabled" => Some(true),
            "Disabled" => Some(false),
            _ => None,
        }
    }
    fn lines(text: &str) -> Vec<&str> {
        let mut lines: Vec<_> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        lines.sort_unstable();
        lines
    }
    /// The loaded anchor against pfctl's own parse (`-n`) of the policy the
    /// service would install. A missing, extra or foreign rule is a mismatch;
    /// our own rules rendered differently prove nothing either way.
    pub fn same_rules(loaded: &str, expected: &str, label: &str) -> Audit {
        let (loaded, expected) = (lines(loaded), lines(expected));
        if expected.is_empty() {
            Audit::Unknown
        } else if loaded == expected {
            Audit::Match
        } else if loaded.len() != expected.len() || loaded.iter().any(|l| !l.contains(label)) {
            Audit::Mismatch
        } else {
            Audit::Unknown
        }
    }
    /// `route -n get`.
    pub fn route_interface(text: &str) -> Option<String> {
        let name = text
            .lines()
            .find_map(|line| line.trim().strip_prefix("interface:"))?
            .trim();
        super::interface_name(name).then(|| name.into())
    }
    /// `scutil --dns`: each resolver address the system may select, with the
    /// interface its resolver block is scoped to.
    pub fn resolvers(text: &str) -> Option<Vec<(String, Option<String>)>> {
        let mut found = Vec::new();
        let mut seen = false;
        for block in text.split("resolver #").skip(1) {
            seen = true;
            let mut servers = Vec::new();
            let mut scope = None;
            for line in block.lines() {
                let Some((key, value)) = line.trim().split_once(':') else {
                    continue;
                };
                let (key, value) = (key.trim(), value.trim());
                if key.starts_with("nameserver[") && key.ends_with(']') {
                    servers.push(value.to_owned());
                } else if key == "if_index" {
                    let name = value.split_once('(')?.1.strip_suffix(')')?;
                    scope = Some(name.to_owned());
                }
            }
            found.extend(servers.into_iter().map(|s| (s, scope.clone())));
        }
        seen.then_some(found)
    }
}

/// The Windows full-tunnel WFP policy as data: the installer adds exactly
/// these filters and the probe's audit reads them back; host-tested.
#[cfg(any(target_os = "windows", test))]
pub mod wfp {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Layer {
        ConnectV4,
        ConnectV6,
        PacketV4,
        PacketV6,
        ForwardV4,
        ForwardV6,
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Condition {
        Loopback,
        LocalInterface(u64),
        RemoteAddress(u32),
        /// The service executable's own app id.
        AppId,
        Protocol(u8),
        RemotePort(u16),
        RemotePorts(u16, u16),
        LocalPort(u16),
        /// Read back but not part of this policy.
        Other,
    }
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Spec {
        pub layer: Layer,
        pub boottime: bool,
        pub permit: bool,
        pub conditions: Vec<Condition>,
    }
    pub fn filter_specs(luid: u64, permits: &[crate::failover::Permit], boot: bool) -> Vec<Spec> {
        use Condition::*;
        let mut specs = Vec::new();
        let mut add = |layer, permit, conditions: Vec<Condition>| {
            specs.push(Spec {
                layer,
                boottime: false,
                permit,
                conditions,
            })
        };
        // Packet filters cover existing flows and raw packets as well as new connects.
        for (layer, v4, ale) in [
            (Layer::ConnectV4, true, true),
            (Layer::ConnectV6, false, true),
            (Layer::PacketV4, true, false),
            (Layer::PacketV6, false, false),
        ] {
            add(layer, true, vec![Loopback]);
            if luid != 0 {
                add(layer, true, vec![LocalInterface(luid)]);
            }
            if v4 {
                for permit in permits {
                    let mut conditions = vec![RemoteAddress(u32::from(*permit.address.ip()))];
                    if ale {
                        // QUIC (HTTP/3, Hysteria 2) and AmneziaWG use UDP.
                        conditions.extend([AppId, Protocol(if permit.udp { 17 } else { 6 })]);
                        if !permit.ports.is_empty() {
                            for &(low, high) in &permit.ports {
                                let mut ranged = conditions.clone();
                                ranged.push(RemotePorts(low, high));
                                add(layer, true, ranged);
                            }
                            continue;
                        }
                        conditions.push(RemotePort(permit.address.port()));
                    }
                    add(layer, true, conditions);
                }
                let mut dhcp = vec![RemoteAddress(u32::from(std::net::Ipv4Addr::BROADCAST))];
                if ale {
                    dhcp.extend([Protocol(17), LocalPort(68), RemotePort(67)]);
                }
                add(layer, true, dhcp);
            }
            add(layer, false, vec![]);
        }
        for layer in [Layer::ForwardV4, Layer::ForwardV6] {
            add(layer, false, vec![]);
        }
        if boot {
            // Separate flags on the SAME provider: WFP transitions atomically at BFE startup.
            for layer in [
                Layer::PacketV4,
                Layer::PacketV6,
                Layer::ForwardV4,
                Layer::ForwardV6,
            ] {
                specs.push(Spec {
                    layer,
                    boottime: true,
                    permit: false,
                    conditions: vec![],
                });
            }
        }
        specs
    }
    /// Read-back multiset against the expected policy, conditions in any order.
    pub fn audit(mut found: Vec<Spec>, mut expected: Vec<Spec>) -> super::Audit {
        for spec in found.iter_mut().chain(expected.iter_mut()) {
            spec.conditions.sort();
        }
        found.sort();
        expected.sort();
        if !expected.is_empty() && found == expected {
            super::Audit::Match
        } else {
            super::Audit::Mismatch
        }
    }
    /// `DNS_INTERFACE_SETTINGS.NameServer`: comma or space separated.
    pub fn servers(text: &str) -> Vec<&str> {
        text.split([',', ' '])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_control::observations::{Monitor, Source};
    const LEAK: &[Attempt] = &[Attempt::Leaked];
    #[test]
    fn guard_passes_only_on_exact_rules_and_local_refusal_everywhere() {
        use Attempt::*;
        assert_eq!(guard(Audit::Match, &[Blocked, Absent]), Outcome::Passed);
        assert_eq!(guard(Audit::Match, &[Blocked, Blocked]), Outcome::Passed);
        assert_eq!(guard(Audit::Match, &[]), Outcome::Unknown);
        assert_eq!(guard(Audit::Match, &[Absent]), Outcome::Unknown);
        assert_eq!(guard(Audit::Match, &[Blocked, Unknown]), Outcome::Unknown);
        assert_eq!(guard(Audit::Unknown, &[Blocked]), Outcome::Unknown);
        assert_eq!(guard(Audit::Mismatch, &[Blocked]), Outcome::Failed);
        assert_eq!(guard(Audit::Match, &[Blocked, Leaked]), Outcome::Failed);
        assert_eq!(guard(Audit::Unknown, LEAK), Outcome::Failed);
    }
    #[test]
    fn errno_classification_is_fail_closed() {
        const EPERM: i32 = 1;
        const ENETUNREACH: i32 = 101;
        assert_eq!(attempt(Ok(()), &[EPERM], &[]), Attempt::Leaked);
        assert_eq!(attempt(Err(EPERM), &[EPERM], &[]), Attempt::Blocked);
        assert_eq!(attempt(Err(ENETUNREACH), &[EPERM], &[]), Attempt::Unknown);
        assert_eq!(
            attempt(Err(ENETUNREACH), &[EPERM], &[ENETUNREACH]),
            Attempt::Absent
        );
        assert_eq!(attempt(Err(-1), &[EPERM], &[]), Attempt::Unknown);
        // macOS without a scoped route passes no blocked errno at all.
        assert_eq!(attempt(Err(65), &[], &[]), Attempt::Unknown);
    }
    #[test]
    fn dns_needs_own_config_tunnel_path_answer_and_contained_resolvers() {
        let good = Dns {
            config: Audit::Match,
            path: Path::Tunnel,
            reply: Reply::Answered,
            foreign: Foreign::None,
        };
        assert_eq!(dns(good, Outcome::Unknown), Outcome::Passed);
        let other = Dns {
            foreign: Foreign::Present,
            ..good
        };
        assert_eq!(dns(other, Outcome::Passed), Outcome::Passed);
        assert_eq!(dns(other, Outcome::Unknown), Outcome::Failed);
        assert_eq!(dns(other, Outcome::Failed), Outcome::Failed);
        let unread = Dns {
            foreign: Foreign::Unknown,
            ..good
        };
        assert_eq!(dns(unread, Outcome::Passed), Outcome::Passed);
        assert_eq!(dns(unread, Outcome::Unknown), Outcome::Unknown);
        for (facts, outcome) in [
            (
                Dns {
                    config: Audit::Mismatch,
                    ..good
                },
                Outcome::Failed,
            ),
            (
                Dns {
                    path: Path::Outside,
                    ..good
                },
                Outcome::Failed,
            ),
            (
                Dns {
                    reply: Reply::Responded,
                    ..good
                },
                Outcome::Unknown,
            ),
            (
                Dns {
                    reply: Reply::None,
                    ..good
                },
                Outcome::Unknown,
            ),
            (
                Dns {
                    config: Audit::Unknown,
                    ..good
                },
                Outcome::Unknown,
            ),
            (Dns::UNKNOWN, Outcome::Unknown),
        ] {
            assert_eq!(dns(facts, Outcome::Passed), outcome, "{facts:?}");
        }
        // Any reply through the tunnel proves the transport, not DNS.
        let served = result(
            Dns {
                reply: Reply::Responded,
                ..good
            },
            Audit::Match,
            &[Attempt::Blocked],
            7,
        );
        assert_eq!(served.transport_proven_at, Some(7));
        assert_eq!(served.dns.outcome, Outcome::Unknown);
        assert_eq!(served.guard.outcome, Outcome::Passed);
        assert_eq!(
            result(Dns::UNKNOWN, Audit::Unknown, &[], 7).transport_proven_at,
            None
        );
    }
    #[test]
    fn root_ns_query_and_reply_matching() {
        let q = query(0xbeef);
        assert_eq!(&q[..4], &[0xbe, 0xef, 0x01, 0x00]);
        let mut r = q.to_vec();
        r[2] |= 0x80;
        assert_eq!(reply(0xbeef, &r), Reply::Responded);
        r[7] = 1;
        assert_eq!(reply(0xbeef, &r), Reply::Answered);
        assert_eq!(reply(0xbeee, &r), Reply::None);
        let mut servfail = r.clone();
        servfail[3] |= 2;
        assert_eq!(reply(0xbeef, &servfail), Reply::Responded);
        assert_eq!(reply(0xbeef, &q), Reply::None, "a query is not a reply");
        let mut other = r.clone();
        other[14] = 1;
        assert_eq!(reply(0xbeef, &other), Reply::None);
        assert_eq!(reply(0xbeef, &r[..16]), Reply::None);
    }
    #[test]
    fn neutral_targets_never_collide_silently() {
        assert!(collides(&["192.0.2.1".parse().unwrap()]));
        assert!(collides(&["2001:db8::1".parse().unwrap()]));
        assert!(!collides(&["203.0.113.7".parse().unwrap()]));
        for target in [TARGET_V4, TARGET_V6] {
            assert!(!matches!(target.port(), 53 | 67 | 68 | 546 | 547));
            assert!(!target.ip().is_multicast());
        }
    }
    fn passing(at: u64) -> SystemProbe {
        result(
            Dns {
                config: Audit::Match,
                path: Path::Tunnel,
                reply: Reply::Answered,
                foreign: Foreign::None,
            },
            Audit::Match,
            &[Attempt::Blocked],
            at,
        )
    }
    #[tokio::test(start_paused = true)]
    async fn runner_is_single_flight_bounded_and_cancellable() {
        let started = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut runner = Runner::default();
        assert!(matches!(runner.next().await, Tick::Due));
        for _ in 0..3 {
            let started = started.clone();
            runner.start(4, async move {
                started.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                std::future::pending().await
            });
        }
        assert!(runner.busy());
        // A collector that never ends times out into an unknown, unproven run.
        let Tick::Done(generation, probe) = runner.next().await else {
            panic!("expected a finished run");
        };
        assert_eq!(started.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(generation, 4);
        assert_eq!(probe.transport_proven_at, None);
        assert_eq!(probe.guard.outcome, Outcome::Unknown);
        assert!(!runner.busy());
        // The next run waits a full interval; nothing queued meanwhile.
        let before = tokio::time::Instant::now();
        assert!(matches!(runner.next().await, Tick::Due));
        assert!(before.elapsed() >= Duration::from_millis(PROBE_INTERVAL_MS));
        // Cancel drops the run and its result.
        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Flag(dropped.clone());
        runner.start(5, async move {
            let _flag = flag;
            tokio::time::sleep(Duration::from_secs(1)).await;
            passing(now_ms())
        });
        runner.cancel();
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(runner.next().await, Tick::Due));
    }
    #[tokio::test(start_paused = true)]
    async fn a_late_result_after_invalidation_is_rejected() {
        let now = now_ms();
        let mut monitor = Monitor::new(Mode::Full, Source::ServiceLifecycle, now);
        let mut runner = Runner::default();
        runner.start(monitor.generation(), async move { passing(now) });
        monitor.network_changed(now);
        let Tick::Done(generation, probe) = runner.next().await else {
            panic!("expected a finished run");
        };
        assert!(!monitor.apply_system(generation, probe, now));
        let s = monitor.sample(now);
        assert_eq!(s.dns.outcome, Outcome::Unknown);
        assert_eq!(s.transport.outcome, Outcome::Configured);
        runner.start(monitor.generation(), async move { passing(now) });
        let Tick::Done(generation, probe) = runner.next().await else {
            panic!("expected a finished run");
        };
        assert!(monitor.apply_system(generation, probe, now));
        assert_eq!(monitor.sample(now).transport.outcome, Outcome::Passed);
    }
    #[test]
    fn probe_results_carry_no_fixture_identifiers() {
        let probe = passing(1);
        let text = format!(
            "{probe:?}{}{}",
            serde_json::to_string(&probe.dns).unwrap(),
            serde_json::to_string(&probe.guard).unwrap()
        );
        for canary in [
            "198.51.100",
            "203.0.113",
            "192.0.2",
            "2001:db8",
            "rtcanary",
            "eth0",
            "en0",
            "utun",
            "rtrust0",
            "Wintun",
        ] {
            assert!(!text.contains(canary), "{canary}");
        }
    }
    fn nft_fixture(extra: &str) -> String {
        let m = |left: &str, right: &str| {
            format!(r#"{{"match":{{"op":"==","left":{left},"right":{right}}}}}"#)
        };
        let meta = |k: &str| format!(r#"{{"meta":{{"key":"{k}"}}}}"#);
        let pay = |p: &str, f: &str| format!(r#"{{"payload":{{"protocol":"{p}","field":"{f}"}}}}"#);
        let rule = |exprs: Vec<String>| {
            format!(
                r#"{{"rule":{{"family":"inet","table":"rtrust_full","chain":"output","handle":3,"expr":[{},{{"accept":null}}]}}}}"#,
                exprs.join(",")
            )
        };
        let rules = [
            rule(vec![m(&meta("oifname"), "\"lo\"")]),
            rule(vec![m(&meta("mark"), "21076")]),
            rule(vec![m(&meta("oifname"), "\"rtrust0\"")]),
            rule(vec![
                m(&pay("ip", "daddr"), "\"255.255.255.255\""),
                m(&pay("udp", "sport"), "68"),
                m(&pay("udp", "dport"), "67"),
            ]),
            rule(vec![
                m(&pay("ip6", "hoplimit"), "255"),
                m(
                    &pay("icmpv6", "type"),
                    r#"{"set":["nd-router-solicit","nd-neighbor-solicit","nd-neighbor-advert"]}"#,
                ),
            ]),
            rule(vec![
                m(&pay("ip6", "daddr"), "\"ff02::1:2\""),
                m(&pay("udp", "sport"), "546"),
                m(&pay("udp", "dport"), "547"),
            ]),
        ];
        format!(
            r#"{{"nftables":[{{"metainfo":{{"version":"1.0.6","json_schema_version":1}}}},{{"table":{{"family":"inet","name":"rtrust_full","handle":7}}}},{{"chain":{{"family":"inet","table":"rtrust_full","name":"output","handle":1,"type":"filter","hook":"output","prio":-10,"policy":"drop"}}}},{},{{"chain":{{"family":"inet","table":"rtrust_full","name":"forward","handle":2,"type":"filter","hook":"forward","prio":-10,"policy":"drop"}}}}{extra}]}}"#,
            rules.join(",")
        )
    }
    fn nft_expected() -> Vec<String> {
        let mut expected: Vec<String> = [
            "chain output filter output -10 drop",
            "chain forward filter forward -10 drop",
        ]
        .map(str::to_owned)
        .to_vec();
        for rule in [
            "meta.oifname==lo accept",
            "meta.mark==21076 accept",
            "meta.oifname==rtrust0 accept",
            "ip.daddr==255.255.255.255 udp.sport==68 udp.dport==67 accept",
            "ip6.hoplimit==255 icmpv6.type==nd-neighbor-advert,nd-neighbor-solicit,nd-router-solicit accept",
            "ip6.daddr==ff02::1:2 udp.sport==546 udp.dport==547 accept",
        ] {
            expected.push(format!("output {rule}"));
        }
        expected
    }
    #[test]
    fn nft_read_back_matches_only_the_exact_own_table() {
        let expected = nft_expected();
        assert_eq!(
            linux::audit(nft_fixture("").as_bytes(), &expected),
            Audit::Match
        );
        let accept = r#",{"rule":{"family":"inet","table":"rtrust_full","chain":"output","handle":9,"expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"203.0.113.7"}},{"accept":null}]}}"#;
        assert_eq!(
            linux::audit(nft_fixture(accept).as_bytes(), &expected),
            Audit::Mismatch
        );
        let accepting = nft_fixture("").replace(
            r#""policy":"drop"}},{"rule""#,
            r#""policy":"accept"}},{"rule""#,
        );
        assert_eq!(
            linux::audit(accepting.as_bytes(), &expected),
            Audit::Mismatch
        );
        let missing = nft_fixture("").replace(r#""right":21076"#, r#""right":1"#);
        assert_eq!(linux::audit(missing.as_bytes(), &expected), Audit::Mismatch);
        let negated = nft_fixture("").replace(
            r#"{"op":"==","left":{"meta":{"key":"mark"}}"#,
            r#"{"op":"!=","left":{"meta":{"key":"mark"}}"#,
        );
        assert_eq!(linux::audit(negated.as_bytes(), &expected), Audit::Mismatch);
        let set = r#",{"set":{"family":"inet","table":"rtrust_full","name":"x"}}"#;
        assert_eq!(
            linux::audit(nft_fixture(set).as_bytes(), &expected),
            Audit::Mismatch
        );
        // Unknown expression shapes and malformed output are not a verdict.
        let odd = nft_fixture("").replace(r#"{"meta":{"key":"mark"}}"#, r#"{"ct":{"key":"mark"}}"#);
        assert_eq!(linux::audit(odd.as_bytes(), &expected), Audit::Unknown);
        for bad in ["", "{", r#"{"nftables":{}}"#, "\u{0}"] {
            assert_eq!(linux::audit(bad.as_bytes(), &expected), Audit::Unknown);
        }
        let truncated = nft_fixture("");
        assert_eq!(
            linux::audit(&truncated.as_bytes()[..truncated.len() / 2], &expected),
            Audit::Unknown
        );
        let tables = br#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"rtrust_full"}},{"table":{"family":"ip","name":"other"}}]}"#;
        assert_eq!(linux::has_table(tables, "rtrust_full"), Some(true));
        assert_eq!(linux::has_table(tables, "absent"), Some(false));
        assert_eq!(linux::has_table(b"[]", "rtrust_full"), None);
    }
    #[test]
    fn resolved_and_route_read_back() {
        let dns: Ipv4Addr = "198.51.100.53".parse().unwrap();
        assert_eq!(
            linux::link_values("Link 9 (rtcanary0): 198.51.100.53\n", "rtcanary0"),
            Some(vec!["198.51.100.53".to_owned()])
        );
        assert_eq!(
            linux::link_values("Link 9 (rtcanary0):\n", "rtcanary0"),
            Some(vec![])
        );
        assert_eq!(linux::link_values("Global: 1.1.1.1\n", "rtcanary0"), None);
        let all = "Global:\nLink 2 (eth0):\nLink 9 (rtcanary0): 198.51.100.53\n";
        assert_eq!(linux::foreign_links(all, "rtcanary0"), Some(false));
        let leak =
            "Global:\nLink 2 (eth0): 192.0.2.53 2001:db8::53\nLink 9 (rtcanary0): 198.51.100.53\n";
        assert_eq!(linux::foreign_links(leak, "rtcanary0"), Some(true));
        assert_eq!(
            linux::foreign_links(
                "Global: 9.9.9.9\nLink 9 (rtcanary0): 198.51.100.53",
                "rtcanary0"
            ),
            Some(true)
        );
        assert_eq!(linux::foreign_links("", "rtcanary0"), None);
        assert!(!linux::resolv_conf_foreign(
            "# stub\nnameserver 127.0.0.53\noptions edns0\n",
            dns
        ));
        assert!(!linux::resolv_conf_foreign(
            "nameserver 198.51.100.53\n",
            dns
        ));
        assert!(linux::resolv_conf_foreign(
            "nameserver 127.0.0.53\nnameserver 192.0.2.53\n",
            dns
        ));
        assert_eq!(
            linux::route_device(br#"[{"dst":"198.51.100.53","dev":"rtcanary0","table":"51830"}]"#),
            Some("rtcanary0".into())
        );
        assert_eq!(linux::route_device(br#"[]"#), None);
        assert_eq!(linux::route_device(br#"[{"dev":"bad name"}]"#), None);
        assert_eq!(
            linux::default_devices(
                br#"[{"dst":"default","gateway":"192.0.2.1","dev":"eth0"},{"dst":"default","nexthops":[{"dev":"wlan0"},{"dev":"eth0"}]},{"dst":"default","dev":"rtcanary0"}]"#,
                "rtcanary0"
            ),
            Some(vec!["eth0".into(), "wlan0".into()])
        );
        assert_eq!(linux::default_devices(br#"[{"dst":"default"}]"#, "x"), None);
    }
    #[test]
    fn pf_and_resolver_read_back() {
        assert_eq!(
            macos::pf_enabled("Status: Enabled for 0 days 00:01:02           Debug: Urgent\n"),
            Some(true)
        );
        assert_eq!(macos::pf_enabled("Status: Disabled\n"), Some(false));
        assert_eq!(macos::pf_enabled("pfctl: Permission denied\n"), None);
        let ours = "pass out quick on lo0 all no state label \"rtrust-501\"\nblock drop out quick all label \"rtrust-501\"\n";
        let label = "label \"rtrust-501\"";
        assert_eq!(macos::same_rules(ours, ours, label), Audit::Match);
        assert_eq!(
            macos::same_rules(
                &format!("\n{}", ours.lines().rev().collect::<Vec<_>>().join("\n")),
                ours,
                label
            ),
            Audit::Match
        );
        assert_eq!(macos::same_rules("", ours, label), Audit::Mismatch);
        assert_eq!(
            macos::same_rules(&format!("pass out quick all\n{ours}"), ours, label),
            Audit::Mismatch
        );
        let foreign = ours.replace(
            "pass out quick on lo0 all no state label \"rtrust-501\"",
            "pass out quick all",
        );
        assert_eq!(macos::same_rules(&foreign, ours, label), Audit::Mismatch);
        let rendered = ours.replace("on lo0 all", "on lo0 from any to any");
        assert_eq!(macos::same_rules(&rendered, ours, label), Audit::Unknown);
        assert_eq!(macos::same_rules(ours, "", label), Audit::Unknown);
        assert_eq!(
            macos::route_interface(
                "   route to: 198.51.100.53\n  interface: utun5254\n      flags: <UP,DONE>\n"
            ),
            Some("utun5254".into())
        );
        assert_eq!(
            macos::route_interface("route: writing to routing socket: not in table"),
            None
        );
        let config = "DNS configuration\n\nresolver #1\n  nameserver[0] : 198.51.100.53\n  flags    : Supplemental\n\nresolver #2\n  nameserver[0] : 192.0.2.53\n  if_index : 15 (en0)\n";
        assert_eq!(
            macos::resolvers(config),
            Some(vec![
                ("198.51.100.53".into(), None),
                ("192.0.2.53".into(), Some("en0".into()))
            ])
        );
        assert_eq!(macos::resolvers("No DNS configuration available"), None);
    }
    #[test]
    fn wfp_policy_specs_and_read_back() {
        use wfp::{Condition::*, Layer, Spec, audit, filter_specs};
        let permits = [
            crate::failover::Permit {
                address: "203.0.113.7:443".parse().unwrap(),
                udp: false,
                ports: vec![],
            },
            crate::failover::Permit {
                address: "203.0.113.8:443".parse().unwrap(),
                udp: true,
                ports: vec![(443, 443), (20000, 20010)],
            },
        ];
        let specs = filter_specs(42, &permits, false);
        // Per v4 layer: loopback, LUID, 1 + 2 ranged endpoint permits (ALE) or
        // 2 address permits (packet), DHCP, block; v6: loopback, LUID, block.
        assert_eq!(specs.len(), (2 + 3 + 2) + 3 + (2 + 2 + 2) + 3 + 2);
        let ale: Vec<_> = specs
            .iter()
            .filter(|s| s.layer == Layer::ConnectV4 && s.conditions.contains(&AppId))
            .collect();
        assert_eq!(ale.len(), 3);
        assert!(
            ale.iter()
                .any(|s| s.conditions.contains(&RemotePorts(20000, 20010))
                    && s.conditions.contains(&Protocol(17)))
        );
        assert!(ale.iter().any(
            |s| s.conditions.contains(&RemotePort(443)) && s.conditions.contains(&Protocol(6))
        ));
        assert!(
            !specs
                .iter()
                .any(|s| s.layer == Layer::PacketV4 && s.conditions.contains(&AppId))
        );
        assert_eq!(filter_specs(0, &permits, false).len(), specs.len() - 4);
        assert_eq!(filter_specs(42, &permits, true).len(), specs.len() + 4);
        let mut shuffled = specs.clone();
        shuffled.reverse();
        for spec in &mut shuffled {
            spec.conditions.reverse();
        }
        assert_eq!(audit(shuffled.clone(), specs.clone()), Audit::Match);
        let mut extra = shuffled.clone();
        extra.push(Spec {
            layer: Layer::ConnectV4,
            boottime: false,
            permit: true,
            conditions: vec![RemoteAddress(1)],
        });
        assert_eq!(audit(extra, specs.clone()), Audit::Mismatch);
        let mut missing = shuffled.clone();
        missing.retain(|s| s.permit || s.layer != Layer::PacketV6);
        assert_eq!(audit(missing, specs.clone()), Audit::Mismatch);
        let mut stale = shuffled.clone();
        for spec in &mut stale {
            for c in &mut spec.conditions {
                if *c == LocalInterface(42) {
                    *c = LocalInterface(43);
                }
            }
        }
        assert_eq!(audit(stale, specs.clone()), Audit::Mismatch);
        let mut foreign = shuffled;
        foreign[0].conditions.push(Other);
        assert_eq!(audit(foreign, specs.clone()), Audit::Mismatch);
        assert_eq!(audit(vec![], vec![]), Audit::Mismatch);
        assert_eq!(wfp::servers("198.51.100.53"), ["198.51.100.53"]);
        assert_eq!(
            wfp::servers("198.51.100.53, 192.0.2.53"),
            ["198.51.100.53", "192.0.2.53"]
        );
        assert!(wfp::servers("").is_empty());
    }
}
