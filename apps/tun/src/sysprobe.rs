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
/// Each part of a run (own rules, bypass attempts, DNS) has its own budget
/// inside the run deadline: a slow part loses only its own facts.
pub const PART: Duration = Duration::from_millis(PROBE_DEADLINE_MS - 1_000);
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
///
/// After a due tick the caller did not use (not Connected), the runner sleeps
/// instead of re-arming a short timer; `next` is re-created by every
/// `select!` iteration, so a later `cancel`/`defer` is seen at once.
pub struct Runner {
    task: Option<(u64, Task)>,
    due: Pin<Box<tokio::time::Sleep>>,
    /// False after a due tick the caller did not use; `cancel` (every
    /// lifecycle change) or `defer` re-arms it.
    armed: bool,
}
impl Default for Runner {
    fn default() -> Self {
        Self {
            task: None,
            due: Box::pin(tokio::time::sleep(SETTLE)),
            armed: true,
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
        self.armed = true;
        self.reschedule(SETTLE);
    }
    /// A due run could not start now (its inputs are unavailable): retry
    /// after a full interval rather than on every loop iteration.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub fn defer(&mut self) {
        self.armed = true;
        self.reschedule(Duration::from_millis(PROBE_INTERVAL_MS));
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
            self.armed = true;
            self.reschedule(Duration::from_millis(PROBE_INTERVAL_MS));
            return Tick::Done(generation, probe);
        }
        if self.armed {
            self.due.as_mut().await;
            // A due tick the caller does not use must not fire again.
            self.armed = false;
            return Tick::Due;
        }
        std::future::pending().await
    }
}

/// Blocking work outlives a dropped run. The run holds the `Fence`; its drop
/// (cancel, Stop, EOF, deadline) clears `Live`, which detached blocking work
/// checks before anything that sends. Teardown happens after the drop, so
/// no datagram starts once the guard may be gone; one already inside the
/// send call when the run is dropped can still complete.
#[cfg(any(target_os = "windows", test))]
pub struct Fence(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[cfg(any(target_os = "windows", test))]
#[derive(Clone)]
pub struct Live(std::sync::Arc<std::sync::atomic::AtomicBool>);
#[cfg(any(target_os = "windows", test))]
pub fn fence() -> (Fence, Live) {
    let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    (Fence(flag.clone()), Live(flag))
}
#[cfg(any(target_os = "windows", test))]
impl Drop for Fence {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}
#[cfg(any(target_os = "windows", test))]
impl Live {
    pub fn get(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}
/// Bound one part of a run; a part over its budget reports `fallback`.
pub async fn part<T>(fallback: T, work: impl Future<Output = T>) -> T {
    tokio::time::timeout(PART, work).await.unwrap_or(fallback)
}

/// Blocking OS calls cannot be cancelled: a dropped run detaches them. One
/// lane per backend keeps at most one alive across runs; while it is busy a
/// new run reports those checks Unknown instead of stacking threads/handles.
/// Linux probes have no blocking calls: tools are async children, sockets
/// are non-blocking.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
pub struct Lane(std::sync::atomic::AtomicBool);
#[cfg(any(target_os = "macos", target_os = "windows", test))]
impl Lane {
    pub const fn new() -> Self {
        Self(std::sync::atomic::AtomicBool::new(false))
    }
    pub fn spawn<T: Send + 'static>(
        &'static self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> Option<tokio::task::JoinHandle<T>> {
        use std::sync::atomic::Ordering;
        if self.0.swap(true, Ordering::AcqRel) {
            return None;
        }
        struct Free(&'static Lane);
        impl Drop for Free {
            fn drop(&mut self) {
                self.0.0.store(false, Ordering::Release);
            }
        }
        let free = Free(self);
        Some(tokio::task::spawn_blocking(move || {
            let _free = free;
            work()
        }))
    }
    #[cfg(test)]
    fn busy(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Acquire)
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
impl Dns {
    pub const UNKNOWN: Self = Self {
        config: Audit::Unknown,
        path: Path::Unknown,
        reply: Reply::None,
        foreign: Foreign::Unknown,
    };
}

/// Linux and Windows refuse with an errno; macOS PF drops silently (see `macos::verdict`).
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub fn attempt(sent: Result<(), i32>, blocked: &[i32], absent: &[i32]) -> Attempt {
    match sent {
        Ok(()) => Attempt::Leaked,
        Err(code) if blocked.contains(&code) => Attempt::Blocked,
        Err(code) if absent.contains(&code) => Attempt::Absent,
        Err(_) => Attempt::Unknown,
    }
}
/// IPv6 proves nothing either way only where the interface has no IPv6
/// default route; with one, a failed setup or an unreachable errno is Unknown.
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub fn v6_attempt(
    default: bool,
    sent: Option<Result<(), i32>>,
    blocked: &[i32],
    absent: &[i32],
) -> Attempt {
    match (sent, default) {
        (None, true) => Attempt::Unknown,
        (None, false) => Attempt::Absent,
        (Some(sent), true) => attempt(sent, blocked, &[]),
        (Some(sent), false) => attempt(sent, blocked, absent),
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
/// Stamp a run with its start: evidence is as old as the run, not its end.
pub async fn evidence(facts: impl Future<Output = (Dns, Audit, Vec<Attempt>)>) -> SystemProbe {
    let started = now_ms();
    let (dns, audit, attempts) = facts.await;
    result(dns, audit, &attempts, started)
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
    if bytes[3] & 0x0f != 0 || bytes[6..8] == [0, 0] {
        return Reply::Responded;
    }
    // ANCOUNT alone is not an answer: the first record must be well formed.
    if answer_record(bytes, 17) {
        Reply::Answered
    } else {
        Reply::None
    }
}
fn answer_record(bytes: &[u8], mut at: usize) -> bool {
    for _ in 0..128 {
        let Some(&len) = bytes.get(at) else {
            return false;
        };
        match len & 0xc0 {
            0 if len == 0 => {
                at += 1;
                break;
            }
            0 => at += 1 + usize::from(len),
            0xc0 if at + 1 < bytes.len() => {
                at += 2;
                break;
            }
            _ => return false,
        }
    }
    let Some(header) = bytes.get(at..at + 10) else {
        return false;
    };
    let data = usize::from(u16::from_be_bytes([header[8], header[9]]));
    at + 10 + data <= bytes.len()
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
        if expected.is_empty() {
            Audit::Unknown
        } else if actual == expected {
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
    use super::{Attempt, Audit};
    /// What the interface's BPF tap saw of one probe datagram.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Seen {
        /// The datagram left on the wire.
        Captured,
        /// Armed tap, no drops, nothing seen; with the send result.
        Silent(Result<(), i32>),
        /// Tap unavailable, wrong link type, SEESENT off or drops.
        Unknown,
    }
    /// PF drops output silently: `sendto` returns success and nothing leaves
    /// (macOS 26.5.2, installed package: tcpdump on en0 empty, block counter
    /// up). So a refusal is proven by absence on the tap plus our block
    /// rule counting packets meanwhile, never by the errno; a datagram on
    /// the wire is a leak.
    pub fn verdict(seen: Seen, before: Option<u64>, after: Option<u64>) -> Attempt {
        match (seen, before, after) {
            (Seen::Captured, _, _) => Attempt::Leaked,
            (Seen::Silent(Ok(()) | Err(libc::EHOSTUNREACH)), Some(before), Some(after))
                if after > before =>
            {
                Attempt::Blocked
            }
            _ => Attempt::Unknown,
        }
    }
    /// Classic BPF over DLT_EN10MB: UDP (IPv4 unfragmented or IPv6 without
    /// extension headers) to port 9. `captured` re-checks every field.
    pub const FILTER: [(u16, u8, u8, u32); 16] = [
        (0x28, 0, 0, 12),     // 0  ldh [12]
        (0x15, 0, 4, 0x86dd), // 1  jeq IPv6 ? 2 : 6
        (0x30, 0, 0, 20),     // 2  ldb [20] next header
        (0x15, 0, 11, 17),    // 3  jeq UDP ? 4 : reject
        (0x28, 0, 0, 56),     // 4  ldh [56] destination port
        (0x15, 8, 9, 9),      // 5  jeq 9 ? accept : reject
        (0x15, 0, 8, 0x0800), // 6  jeq IPv4 ? 7 : reject
        (0x30, 0, 0, 23),     // 7  ldb [23] protocol
        (0x15, 0, 6, 17),     // 8  jeq UDP ? 9 : reject
        (0x28, 0, 0, 20),     // 9  ldh [20] flags/fragment
        (0x45, 4, 0, 0x1fff), // 10 jset offset ? reject : 11
        (0xb1, 0, 0, 14),     // 11 ldxb 4*([14]&0xf)
        (0x48, 0, 0, 16),     // 12 ldh [x+16] destination port
        (0x15, 0, 1, 9),      // 13 jeq 9 ? accept : reject
        (0x06, 0, 0, 0xffff), // 14 accept
        (0x06, 0, 0, 0),      // 15 reject
    ];
    /// One Ethernet frame: UDP from `port` to port 9.
    fn probe_frame(frame: &[u8], port: u16) -> bool {
        let u16_at = |at: usize| {
            frame
                .get(at..at + 2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]))
        };
        let udp = match u16_at(12) {
            Some(0x0800) => {
                let Some(&first) = frame.get(14) else {
                    return false;
                };
                let header = usize::from(first & 0x0f) * 4;
                if first >> 4 != 4 || header < 20 || frame.get(23) != Some(&17) {
                    return false;
                }
                14 + header
            }
            Some(0x86dd) if frame.get(20) == Some(&17) => 54,
            _ => return false,
        };
        u16_at(udp) == Some(port) && u16_at(udp + 2) == Some(9)
    }
    /// A BPF read buffer (Darwin `bpf_hdr`: 8-byte timeval32, caplen at 8,
    /// hdrlen at 16, records 4-byte aligned) holding our datagram.
    pub fn captured(buffer: &[u8], port: u16) -> bool {
        let mut at = 0;
        while let Some(header) = buffer.get(at..at + 18) {
            let caplen =
                u32::from_ne_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let hdrlen = usize::from(u16::from_ne_bytes([header[16], header[17]]));
            if hdrlen < 18 {
                return false;
            }
            let Some(frame) = buffer.get(at + hdrlen..at + hdrlen + caplen) else {
                return false;
            };
            if probe_frame(frame, port) {
                return true;
            }
            at += (hdrlen + caplen + 3) & !3;
        }
        false
    }
    /// `pfctl -a <anchor> -vsr`: packets counted by our final block rule.
    pub fn block_packets(text: &str, label: &str) -> Option<u64> {
        let mut lines = text.lines().map(str::trim);
        lines.find(|l| l.starts_with("block drop out quick all") && l.contains(label))?;
        let counters = lines.next()?.strip_prefix('[')?;
        let value = counters
            .split("Packets:")
            .nth(1)?
            .split_whitespace()
            .next()?;
        value.parse().ok()
    }
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
    /// `netstat -rn` gateway of a default route on `interface`: a unicast
    /// address, IPv6 only link-local scoped to that same interface. `link#N`,
    /// a foreign scope or anything else is None.
    pub fn gateway(value: &str, interface: &str) -> Option<std::net::IpAddr> {
        use std::net::IpAddr;
        if let Ok(IpAddr::V4(ip)) = value.parse::<IpAddr>() {
            let usable = !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_link_local());
            return usable.then_some(IpAddr::V4(ip));
        }
        let (address, scope) = value.split_once('%')?;
        let ip: std::net::Ipv6Addr = address.parse().ok()?;
        (scope == interface && ip.is_unicast_link_local()).then_some(IpAddr::V6(ip))
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
    /// How the read-back treats one enumerated filter.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Read {
        /// Neither our provider nor our sublayer.
        Skip,
        /// Ours: our provider, our sublayer, a plain permit or block.
        Own,
        /// Our provider elsewhere, another provider (or none) inside our
        /// sublayer, or another action: read, but never equal to a spec.
        Foreign,
    }
    /// Every filter of our provider and every filter in our sublayer is read:
    /// a foreign permit placed in our sublayer is arbitrated with our block.
    pub fn classify(our_provider: bool, our_sublayer: bool, plain_action: bool) -> Read {
        match (our_provider, our_sublayer, plain_action) {
            (false, false, _) => Read::Skip,
            (true, true, true) => Read::Own,
            _ => Read::Foreign,
        }
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
        // ANCOUNT without a record is not an answer.
        assert_eq!(reply(0xbeef, &r), Reply::None);
        let record = [0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 0x0e, 0x10, 0, 2, 0xc0, 0x0c];
        let header_only = r.clone();
        r.extend(record);
        assert_eq!(reply(0xbeef, &r), Reply::Answered);
        assert_eq!(reply(0xbeee, &r), Reply::None);
        // Uncompressed owner name, then a record whose data overruns the datagram.
        let mut plain = header_only.clone();
        plain.extend([0, 0, 2, 0, 1, 0, 0, 0, 1, 0, 1, 7]);
        assert_eq!(reply(0xbeef, &plain), Reply::Answered);
        let mut overrun = header_only.clone();
        overrun.extend([0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 0, 1, 0, 9, 1]);
        assert_eq!(reply(0xbeef, &overrun), Reply::None);
        let mut label = header_only.clone();
        label.extend([0x3f, 1, 2]);
        assert_eq!(reply(0xbeef, &label), Reply::None);
        let mut reserved = header_only;
        reserved.extend([0x80, 0, 0, 2, 0, 1, 0, 0, 0, 1, 0, 0]);
        assert_eq!(reply(0xbeef, &reserved), Reply::None);
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
    async fn an_unused_due_tick_waits_for_a_lifecycle_change_not_a_short_timer() {
        let mut runner = Runner::default();
        // Not connected: the caller ignores the tick.
        assert!(matches!(runner.next().await, Tick::Due));
        let again = tokio::time::timeout(Duration::from_secs(120), runner.next()).await;
        assert!(again.is_err(), "an ignored due tick must not re-fire");
        // Reconnected (every lifecycle change cancels): due after the settle.
        runner.cancel();
        let before = tokio::time::Instant::now();
        assert!(matches!(runner.next().await, Tick::Due));
        assert!(before.elapsed() >= SETTLE);
        // Inputs unavailable: deferred by a full interval, not 2 s.
        runner.defer();
        let before = tokio::time::Instant::now();
        assert!(matches!(runner.next().await, Tick::Due));
        assert!(before.elapsed() >= Duration::from_millis(PROBE_INTERVAL_MS));
    }
    #[tokio::test(start_paused = true)]
    async fn a_dropped_run_stops_its_detached_blocking_work_before_any_send() {
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        // Shaped like the Windows collector: rules read, then sends, in one
        // blocking call that a dropped run cannot stop.
        let lane: &'static Lane = Box::leak(Box::new(Lane::new()));
        let sends = Arc::new(AtomicUsize::new(0));
        let reached = Arc::new(AtomicBool::new(false));
        let collect = |release: std::sync::mpsc::Receiver<()>| {
            let (sends, reached) = (sends.clone(), reached.clone());
            let release = Mutex::new(release);
            async move {
                let (_fence, live) = fence();
                let work = lane.spawn(move || {
                    reached.store(true, Ordering::SeqCst);
                    let _ = release.lock().unwrap().recv();
                    for _ in 0..4 {
                        if !live.get() {
                            return;
                        }
                        sends.fetch_add(1, Ordering::SeqCst);
                    }
                });
                if let Some(work) = work {
                    let _ = work.await;
                }
                passing(now_ms())
            }
        };
        let wait_free = || async {
            while lane.busy() {
                tokio::task::yield_now().await;
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        // Cancelled (Stop, EOF, network change) while the rules were read.
        let (release, wait) = std::sync::mpsc::channel();
        let mut runner = Runner::default();
        runner.start(1, collect(wait));
        while !reached.load(Ordering::SeqCst) {
            tokio::select! {
                _ = runner.next() => panic!("a stalled run cannot finish"),
                _ = tokio::task::yield_now() => {}
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        runner.cancel();
        // The guard is torn down here; the detached call then resumes.
        release.send(()).unwrap();
        wait_free().await;
        assert_eq!(
            sends.load(Ordering::SeqCst),
            0,
            "sent after the run was dropped"
        );
        // Control: a live run does send.
        reached.store(false, Ordering::SeqCst);
        let (release, wait) = std::sync::mpsc::channel();
        release.send(()).unwrap();
        runner.start(2, collect(wait));
        assert!(matches!(runner.next().await, Tick::Done(2, _)));
        assert_eq!(sends.load(Ordering::SeqCst), 4);
        wait_free().await;
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
        assert_eq!(
            macos::gateway("198.51.100.1", "en0"),
            Some("198.51.100.1".parse().unwrap())
        );
        assert_eq!(
            macos::gateway("fe80::1%en0", "en0"),
            Some("fe80::1".parse().unwrap())
        );
        for value in [
            "link#11",
            "fe80::1%en1",
            "fe80::1",
            "2001:db8::1%en0",
            "0.0.0.0",
            "127.0.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "",
        ] {
            assert_eq!(macos::gateway(value, "en0"), None, "{value}");
        }
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

    // ---- tester (issue #81): independent fail-closed tables ----
    const ALL_ATTEMPTS: [Attempt; 4] = [
        Attempt::Blocked,
        Attempt::Leaked,
        Attempt::Absent,
        Attempt::Unknown,
    ];
    const ALL_AUDITS: [Audit; 3] = [Audit::Match, Audit::Mismatch, Audit::Unknown];
    #[test]
    fn a_foreign_filter_in_our_sublayer_is_a_mismatch() {
        use wfp::{Read, classify};
        assert_eq!(classify(false, false, true), Read::Skip);
        assert_eq!(classify(true, true, true), Read::Own);
        // Another vendor's (or provider-less) filter inside our sublayer.
        assert_eq!(classify(false, true, true), Read::Foreign);
        // Ours outside our sublayer, or with another action.
        assert_eq!(classify(true, false, true), Read::Foreign);
        assert_eq!(classify(true, true, false), Read::Foreign);
        let expected = wfp::filter_specs(7, &[], false);
        // A foreign permit is read back with an Other condition, as read_back does.
        let mut found = expected.clone();
        found.push(wfp::Spec {
            layer: wfp::Layer::ConnectV4,
            boottime: false,
            permit: true,
            conditions: vec![wfp::Condition::Other],
        });
        assert_eq!(wfp::audit(found, expected.clone()), Audit::Mismatch);
        // Even one that copies one of our permits exactly.
        let mut copy = expected[0].clone();
        copy.conditions.push(wfp::Condition::Other);
        let mut found = expected.clone();
        found.push(copy);
        assert_eq!(wfp::audit(found, expected.clone()), Audit::Mismatch);
        assert_eq!(wfp::audit(expected.clone(), expected), Audit::Match);
    }
    #[test]
    fn tester_guard_verdict_invariants_over_every_combination() {
        let mut sets: Vec<Vec<Attempt>> = vec![vec![]];
        for _ in 0..3 {
            let mut next = sets.clone();
            for set in &sets {
                if set.len() == 2 || set.is_empty() {
                    for a in ALL_ATTEMPTS {
                        let mut s = set.clone();
                        s.push(a);
                        next.push(s);
                    }
                }
            }
            sets = next;
        }
        for audit in ALL_AUDITS {
            for attempts in &sets {
                let outcome = guard(audit, attempts);
                let leaked = attempts.contains(&Attempt::Leaked);
                // A send that got out or a mismatched rule set is never hidden.
                if leaked || audit == Audit::Mismatch {
                    assert_eq!(outcome, Outcome::Failed, "{audit:?} {attempts:?}");
                    continue;
                }
                if outcome == Outcome::Passed {
                    assert_eq!(audit, Audit::Match, "{attempts:?}");
                    assert!(attempts.contains(&Attempt::Blocked), "{attempts:?}");
                    assert!(!attempts.contains(&Attempt::Unknown), "{attempts:?}");
                } else {
                    assert_eq!(outcome, Outcome::Unknown, "{audit:?} {attempts:?}");
                }
            }
        }
        // IPv4 refused, IPv6 inconclusive (either order): not Passed.
        use Attempt::*;
        for attempts in [[Blocked, Unknown], [Unknown, Blocked]] {
            assert_ne!(guard(Audit::Match, &attempts), Outcome::Passed);
        }
        // Several interfaces: one inconclusive or leaking interface spoils all.
        assert_eq!(
            guard(Audit::Match, &[Blocked, Absent, Blocked, Unknown]),
            Outcome::Unknown
        );
        assert_eq!(
            guard(Audit::Match, &[Blocked, Absent, Absent, Leaked]),
            Outcome::Failed
        );
    }
    #[test]
    fn tester_dns_verdict_invariants_over_every_combination() {
        let paths = [Path::Tunnel, Path::Outside, Path::Unknown];
        let replies = [Reply::Answered, Reply::Responded, Reply::None];
        let foreigns = [Foreign::None, Foreign::Present, Foreign::Unknown];
        let guards = [
            Outcome::Passed,
            Outcome::Failed,
            Outcome::Unknown,
            Outcome::Stale,
        ];
        for config in ALL_AUDITS {
            for path in paths {
                for reply in replies {
                    for foreign in foreigns {
                        for g in guards {
                            let facts = Dns {
                                config,
                                path,
                                reply,
                                foreign,
                            };
                            let outcome = dns(facts, g);
                            let leak = config == Audit::Mismatch
                                || path == Path::Outside
                                || (foreign == Foreign::Present && g != Outcome::Passed);
                            if leak {
                                assert_eq!(outcome, Outcome::Failed, "{facts:?} {g:?}");
                            } else if outcome == Outcome::Passed {
                                assert_eq!(config, Audit::Match);
                                assert_eq!(path, Path::Tunnel);
                                assert_eq!(reply, Reply::Answered, "{facts:?}");
                                assert!(
                                    foreign == Foreign::None || g == Outcome::Passed,
                                    "{facts:?} {g:?}"
                                );
                            } else {
                                assert_eq!(outcome, Outcome::Unknown, "{facts:?} {g:?}");
                            }
                        }
                    }
                }
            }
        }
    }
    #[test]
    fn tester_errno_tables_per_platform_are_fail_closed() {
        // (blocked, absent) lists as used by each backend; every other result is Unknown.
        const EPERM: i32 = 1;
        const EAGAIN_LINUX: i32 = 11;
        const EACCES: i32 = 13;
        const ENETUNREACH_LINUX: i32 = 101;
        const ETIMEDOUT_LINUX: i32 = 110;
        const EHOSTUNREACH_LINUX: i32 = 113;
        const EADDRNOTAVAIL_LINUX: i32 = 99;
        const EHOSTUNREACH_MAC: i32 = 65;
        const ENETUNREACH_MAC: i32 = 51;
        const ETIMEDOUT_MAC: i32 = 60;
        const WSAEACCES: i32 = 10013;
        const WSAENETUNREACH: i32 = 10051;
        const WSAETIMEDOUT: i32 = 10060;
        const WSAEHOSTUNREACH: i32 = 10065;
        let linux_v4: (&[i32], &[i32]) = (&[EPERM], &[]);
        for code in [
            EAGAIN_LINUX,
            EACCES,
            ENETUNREACH_LINUX,
            ETIMEDOUT_LINUX,
            EHOSTUNREACH_LINUX,
            -1,
        ] {
            assert_eq!(
                attempt(Err(code), linux_v4.0, linux_v4.1),
                Attempt::Unknown,
                "linux v4 {code}"
            );
        }
        assert_eq!(
            attempt(Err(EPERM), linux_v4.0, linux_v4.1),
            Attempt::Blocked
        );
        let linux_v6: (&[i32], &[i32]) = (
            &[EPERM],
            &[ENETUNREACH_LINUX, EHOSTUNREACH_LINUX, EADDRNOTAVAIL_LINUX],
        );
        assert_eq!(
            attempt(Err(ETIMEDOUT_LINUX), linux_v6.0, linux_v6.1),
            Attempt::Unknown
        );
        let mac_v4: (&[i32], &[i32]) = (&[EHOSTUNREACH_MAC], &[]);
        for code in [ENETUNREACH_MAC, ETIMEDOUT_MAC, EPERM, -1] {
            assert_eq!(
                attempt(Err(code), mac_v4.0, mac_v4.1),
                Attempt::Unknown,
                "mac {code}"
            );
        }
        let windows: (&[i32], &[i32]) = (&[WSAEACCES], &[]);
        for code in [WSAENETUNREACH, WSAETIMEDOUT, WSAEHOSTUNREACH, -1] {
            assert_eq!(
                attempt(Err(code), windows.0, windows.1),
                Attempt::Unknown,
                "windows {code}"
            );
        }
        // A send that succeeded is a leak whatever the lists say.
        for (blocked, absent) in [linux_v4, linux_v6, mac_v4, windows] {
            assert_eq!(attempt(Ok(()), blocked, absent), Attempt::Leaked);
            assert_eq!(
                guard(Audit::Match, &[attempt(Ok(()), blocked, absent)]),
                Outcome::Failed
            );
        }
    }
    fn tester_reply(id: u16, flags: [u8; 2], counts: [u16; 4], question: &[u8]) -> Vec<u8> {
        let mut r = id.to_be_bytes().to_vec();
        r.extend(flags);
        for c in counts {
            r.extend(c.to_be_bytes());
        }
        r.extend(question);
        r
    }
    const ROOT_NS_IN: [u8; 5] = [0, 0, 2, 0, 1];
    /// `.` NS answer: compressed owner, TTL 3600, two bytes of data.
    const TESTER_RECORD: [u8; 14] = [0xc0, 0x0c, 0, 2, 0, 1, 0, 0, 0x0e, 0x10, 0, 2, 0xc0, 0x0c];
    #[test]
    fn tester_dns_reply_matching_table() {
        let id = 0x5a5a;
        let mut ok = tester_reply(id, [0x81, 0x80], [1, 1, 0, 0], &ROOT_NS_IN);
        ok.extend(TESTER_RECORD);
        assert_eq!(reply(id, &ok), Reply::Answered);
        let cases: [(&str, Vec<u8>, Reply); 13] = [
            (
                "answer count without a record (F1)",
                tester_reply(id, [0x81, 0x80], [1, 1, 0, 0], &ROOT_NS_IN),
                Reply::None,
            ),
            (
                "wrong id",
                tester_reply(id ^ 1, [0x81, 0x80], [1, 1, 0, 0], &ROOT_NS_IN),
                Reply::None,
            ),
            (
                "not a response",
                tester_reply(id, [0x01, 0x80], [1, 1, 0, 0], &ROOT_NS_IN),
                Reply::None,
            ),
            (
                "opcode status",
                tester_reply(id, [0x91, 0x80], [1, 1, 0, 0], &ROOT_NS_IN),
                Reply::None,
            ),
            (
                "two questions",
                tester_reply(id, [0x81, 0x80], [2, 1, 0, 0], &ROOT_NS_IN),
                Reply::None,
            ),
            (
                "no question",
                tester_reply(id, [0x81, 0x80], [0, 1, 0, 0], &[]),
                Reply::None,
            ),
            (
                "type A",
                tester_reply(id, [0x81, 0x80], [1, 1, 0, 0], &[0, 0, 1, 0, 1]),
                Reply::None,
            ),
            (
                "class CH",
                tester_reply(id, [0x81, 0x80], [1, 1, 0, 0], &[0, 0, 2, 0, 3]),
                Reply::None,
            ),
            (
                "other name",
                tester_reply(
                    id,
                    [0x81, 0x80],
                    [1, 1, 0, 0],
                    b"\x06canary\x07example\x04test\x00\x00\x02\x00\x01",
                ),
                Reply::None,
            ),
            (
                "no answers",
                tester_reply(id, [0x81, 0x80], [1, 0, 0, 0], &ROOT_NS_IN),
                Reply::Responded,
            ),
            (
                "nxdomain",
                tester_reply(id, [0x81, 0x83], [1, 1, 0, 0], &ROOT_NS_IN),
                Reply::Responded,
            ),
            (
                "refused",
                tester_reply(id, [0x81, 0x85], [1, 0, 0, 0], &ROOT_NS_IN),
                Reply::Responded,
            ),
            ("garbage", vec![0xff; 600], Reply::None),
        ];
        for (name, bytes, expected) in cases {
            assert_eq!(reply(id, &bytes), expected, "{name}");
            // Only an answered NOERROR reply can make DNS Passed.
            let facts = Dns {
                config: Audit::Match,
                path: Path::Tunnel,
                reply: reply(id, &bytes),
                foreign: Foreign::None,
            };
            assert_ne!(dns(facts, Outcome::Passed), Outcome::Passed, "{name}");
        }
        for len in 0..ok.len() {
            assert_eq!(reply(id, &ok[..len]), Reply::None, "truncated to {len}");
        }
    }
    /// Loopback-only fake resolver: synthetic, no system state touched.
    #[tokio::test]
    async fn tester_exchange_ignores_spoofed_and_mismatched_replies() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let spoof = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0u8; 512];
            let (_, from) = server.recv_from(&mut buffer).await.unwrap();
            let id = u16::from_be_bytes([buffer[0], buffer[1]]);
            // A full answer from the wrong source port, then a wrong ID, then
            // the real (empty) reply: only the last may count.
            let mut full = tester_reply(id, [0x81, 0x80], [1, 1, 0, 0], &ROOT_NS_IN);
            full.extend(TESTER_RECORD);
            spoof.send_to(&full, from).await.unwrap();
            let wrong = tester_reply(id ^ 0xffff, [0x81, 0x80], [1, 1, 0, 0], &ROOT_NS_IN);
            server.send_to(&wrong, from).await.unwrap();
            let empty = tester_reply(id, [0x81, 0x80], [1, 0, 0, 0], &ROOT_NS_IN);
            server.send_to(&empty, from).await.unwrap();
        });
        assert_eq!(exchange(client, address).await, Reply::Responded);
        task.await.unwrap();
    }
    #[tokio::test]
    async fn tester_exchange_retries_once_then_gives_up() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let task = tokio::spawn(async move {
            let mut ids = Vec::new();
            let mut buffer = [0u8; 512];
            for _ in 0..2 {
                let (len, _) = server.recv_from(&mut buffer).await.unwrap();
                assert_eq!(len, 17);
                assert_eq!(&buffer[12..17], &ROOT_NS_IN, "root NS query only");
                ids.push(u16::from_be_bytes([buffer[0], buffer[1]]));
            }
            ids
        });
        let started = std::time::Instant::now();
        assert_eq!(exchange(client, address).await, Reply::None);
        // Two bounded attempts, well inside the per-run deadline.
        assert!(started.elapsed() < Duration::from_millis(PROBE_DEADLINE_MS));
        let _ids = task.await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn tester_runner_due_ticks_do_not_queue_and_drop_aborts() {
        let mut runner = Runner::default();
        // A long silence yields one due tick, not a burst.
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(matches!(runner.next().await, Tick::Due));
        // An unused due tick does not refire while the state is unchanged.
        assert!(
            tokio::time::timeout(Duration::from_secs(60), runner.next())
                .await
                .is_err(),
            "an unused due tick must not refire"
        );
        // Dropping the runner (lease EOF/Stop) drops the pending run.
        struct Flag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Flag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = Flag(dropped.clone());
        runner.start(9, async move {
            let _flag = flag;
            std::future::pending::<()>().await;
            unreachable!()
        });
        drop(runner);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        // A run that ends after cancel never surfaces: the next tick is Due.
        let mut runner = Runner::default();
        runner.start(1, async { passing(1) });
        runner.cancel();
        assert!(matches!(runner.next().await, Tick::Due));
    }
    #[test]
    fn tester_nft_audit_fail_closed_table() {
        let expected = nft_expected();
        let base = nft_fixture("");
        let empty = r#"{"nftables":[{"metainfo":{"version":"1.0.6","json_schema_version":1}},{"table":{"family":"inet","name":"rtrust_full","handle":7}}]}"#;
        let duplicate = r#",{"rule":{"family":"inet","table":"rtrust_full","chain":"output","handle":11,"expr":[{"match":{"op":"==","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"accept":null}]}}"#;
        let counter = base.replacen(
            r#"{"accept":null}"#,
            r#"{"counter":{"packets":0,"bytes":0}},{"accept":null}"#,
            1,
        );
        let mangle = r#",{"rule":{"family":"inet","table":"rtrust_full","chain":"output","handle":12,"expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":21076}}]}}"#;
        let jump = r#",{"chain":{"family":"inet","table":"rtrust_full","name":"canary","handle":13}},{"rule":{"family":"inet","table":"rtrust_full","chain":"output","handle":14,"expr":[{"jump":{"target":"canary"}}]}}"#;
        let forward_accept = r#",{"rule":{"family":"inet","table":"rtrust_full","chain":"forward","handle":15,"expr":[{"accept":null}]}}"#;
        let mismatches: [(&str, String); 9] = [
            ("empty own table", empty.to_owned()),
            ("duplicate rule", nft_fixture(duplicate)),
            ("counter added", counter),
            ("mark set", nft_fixture(mangle)),
            ("jump to extra chain", nft_fixture(jump)),
            ("forward accept", nft_fixture(forward_accept)),
            (
                "priority",
                base.replacen(r#""prio":-10"#, r#""prio":100"#, 1),
            ),
            (
                "hook",
                base.replacen(r#""hook":"output""#, r#""hook":"postrouting""#, 1),
            ),
            (
                "device",
                base.replace(r#""right":"rtrust0""#, r#""right":"rtcanary0""#),
            ),
        ];
        for (name, text) in mismatches {
            assert_eq!(
                linux::audit(text.as_bytes(), &expected),
                Audit::Mismatch,
                "{name}"
            );
            assert_eq!(
                guard(
                    linux::audit(text.as_bytes(), &expected),
                    &[Attempt::Blocked]
                ),
                Outcome::Failed,
                "{name}"
            );
        }
        let unknowns: [(&str, Vec<u8>); 5] = [
            ("non-utf8", b"\xff\xfe\x00{\"nftables\":[]}".to_vec()),
            ("garbage", b"Error: No such file or directory".to_vec()),
            ("array root", b"[]".to_vec()),
            ("empty entry", br#"{"nftables":[{}]}"#.to_vec()),
            (
                "rule without expr",
                br#"{"nftables":[{"rule":{"chain":"output"}}]}"#.to_vec(),
            ),
        ];
        for (name, bytes) in unknowns {
            assert_eq!(linux::audit(&bytes, &expected), Audit::Unknown, "{name}");
        }
        for bytes in [&b"\xff\xfe"[..], b"", b"{\"nftables\":{}}"] {
            assert_eq!(linux::has_table(bytes, "rtrust_full"), None);
        }
    }
    #[test]
    fn tester_resolver_and_route_parsers_on_garbage_are_unknown() {
        assert_eq!(linux::foreign_links("no colon here\n", "rtcanary0"), None);
        assert_eq!(linux::link_values("", "rtcanary0"), None);
        assert_eq!(linux::route_device(b"\xff\xfe"), None);
        assert_eq!(
            linux::route_device(br#"[{"dev":"rtcanary0"},{"dev":"rtcanary0"}]"#),
            None,
            "an ambiguous route is not a path"
        );
        assert_eq!(linux::route_device(br#"[{"dev":"Ethernet CANARY"}]"#), None);
        assert_eq!(linux::default_devices(b"garbage", "rtcanary0"), None);
        let many: Vec<String> = (0..9)
            .map(|i| format!(r#"{{"dst":"default","dev":"eth{i}"}}"#))
            .collect();
        assert_eq!(
            linux::default_devices(format!("[{}]", many.join(",")).as_bytes(), "x"),
            None
        );
        assert_eq!(
            linux::default_devices(
                br#"[{"dst":"default","dev":"Ethernet-CANARY-name-too-long"}]"#,
                "x"
            ),
            None
        );
        let dns: Ipv4Addr = "198.51.100.53".parse().unwrap();
        assert!(linux::resolv_conf_foreign("nameserver 2001:db8::53\n", dns));
        assert!(!macos::pf_enabled("garbage").is_some_and(|v| v));
        assert_eq!(macos::pf_enabled("Status: Unknown\n"), None);
        assert_eq!(macos::route_interface("interface: Ethernet CANARY\n"), None);
        assert_eq!(
            macos::resolvers("resolver #1\n  nameserver[0] : 198.51.100.53\n  if_index : 15 en0\n"),
            None
        );
        let ours = "pass out quick on lo0 all no state label \"rtrust-501\"\nblock drop out quick all label \"rtrust-501\"\n";
        let label = "label \"rtrust-501\"";
        let extra_own = format!("pass out quick all label \"rtrust-501\"\n{ours}");
        assert_eq!(macos::same_rules(&extra_own, ours, label), Audit::Mismatch);
        assert_eq!(macos::same_rules("", "", label), Audit::Unknown);
    }
    #[test]
    fn tester_wfp_audit_rejects_duplicates_flags_and_actions() {
        use wfp::{Layer, audit, filter_specs};
        let permits = [crate::failover::Permit {
            address: "203.0.113.7:443".parse().unwrap(),
            udp: false,
            ports: vec![],
        }];
        let specs = filter_specs(42, &permits, false);
        let mut duplicate = specs.clone();
        duplicate.push(specs[0].clone());
        assert_eq!(audit(duplicate, specs.clone()), Audit::Mismatch);
        let mut boot = specs.clone();
        boot[0].boottime = true;
        assert_eq!(audit(boot, specs.clone()), Audit::Mismatch);
        let mut permitted = specs.clone();
        let block = permitted
            .iter_mut()
            .find(|s| !s.permit && s.layer == Layer::ConnectV4)
            .unwrap();
        block.permit = true;
        assert_eq!(audit(permitted, specs.clone()), Audit::Mismatch);
        assert_eq!(audit(vec![], specs.clone()), Audit::Mismatch);
        // The neutral probe target is never a permitted destination.
        for spec in &specs {
            assert!(
                !spec
                    .conditions
                    .contains(&wfp::Condition::RemoteAddress(u32::from(Ipv4Addr::new(
                        192, 0, 2, 1
                    ))))
            );
        }
    }
    #[test]
    fn tester_probe_result_debug_and_json_carry_no_canaries() {
        for facts in [
            Dns {
                config: Audit::Match,
                path: Path::Tunnel,
                reply: Reply::Answered,
                foreign: Foreign::Present,
            },
            Dns::UNKNOWN,
        ] {
            for audit in ALL_AUDITS {
                let probe = result(facts, audit, &[Attempt::Blocked, Attempt::Leaked], 7);
                let text = format!(
                    "{probe:?}{}{}",
                    serde_json::to_string(&probe.dns).unwrap(),
                    serde_json::to_string(&probe.guard).unwrap()
                );
                for canary in [
                    "198.51.100.53",
                    "203.0.113.7",
                    "2001:db8::53",
                    "rtcanary0",
                    "Ethernet-CANARY",
                    "canary.example.test",
                ] {
                    assert!(!text.contains(canary), "{canary}");
                }
            }
        }
    }
    #[cfg(unix)]
    mod tester_run {
        use super::super::run;
        use std::time::{Duration, Instant};
        #[tokio::test]
        async fn bounded_exec_is_fail_closed() {
            // Oversized output is refused, not truncated into a verdict.
            assert_eq!(run("/usr/bin/yes", &[], 1024).await, None);
            // A failing tool proves nothing.
            assert_eq!(run("/usr/bin/false", &[], 1024).await, None);
            // A missing tool is not an error to surface, only None.
            assert_eq!(run("/nonexistent/rtcanary0", &[], 1024).await, None);
            // A hanging tool is cut at the step budget.
            let started = Instant::now();
            assert_eq!(run("/bin/sleep", &["30"], 1024).await, None);
            assert!(started.elapsed() < Duration::from_secs(4));
            // Exactly the cap is fine; one byte over is not.
            assert_eq!(
                run("/bin/echo", &["abc"], 4).await.as_deref(),
                Some(&b"abc\n"[..])
            );
            assert_eq!(run("/bin/echo", &["abcd"], 4).await, None);
        }
        #[tokio::test]
        async fn bounded_exec_clears_the_environment() {
            // The test process always has HOME/USER-like variables; none may pass through.
            assert!(std::env::vars().count() > 2);
            let env = run("/usr/bin/env", &[], 64 * 1024).await.unwrap();
            let env = String::from_utf8(env).unwrap();
            let mut keys: Vec<_> = env
                .lines()
                .filter_map(|l| l.split_once('='))
                .map(|(k, _)| k)
                .collect();
            keys.sort_unstable();
            assert_eq!(keys, ["LC_ALL", "PATH"], "{env}");
        }
        #[tokio::test]
        async fn dropping_a_run_kills_the_child() {
            let dir = tempfile::tempdir().unwrap();
            let pidfile = dir.path().join("pid");
            let script = format!("echo $$ > {}; exec /bin/sleep 30", pidfile.display());
            let args = ["-c", script.as_str()];
            let _ =
                tokio::time::timeout(Duration::from_millis(500), run("/bin/sh", &args, 1024)).await;
            let pid: i32 = std::fs::read_to_string(&pidfile)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            // Killed: gone, or a zombie awaiting the reaper; never still sleeping.
            let deadline = Instant::now() + Duration::from_secs(3);
            loop {
                let alive = unsafe { libc::kill(pid, 0) } == 0;
                let state = std::process::Command::new("/bin/ps")
                    .args(["-o", "stat=", "-p", &pid.to_string()])
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
                    .unwrap_or_default();
                if !alive || state.is_empty() || state.starts_with('Z') {
                    break;
                }
                assert!(Instant::now() < deadline, "child {pid} still {state}");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    #[test]
    fn an_empty_expected_nft_set_is_never_a_match() {
        assert_eq!(linux::audit(br#"{"nftables":[]}"#, &[]), Audit::Unknown);
        assert_eq!(
            linux::audit(br#"{"nftables":[{"metainfo":{}}]}"#, &[]),
            Audit::Unknown
        );
    }
    #[test]
    fn ipv6_is_absent_only_without_an_ipv6_default_route() {
        const BLOCKED: i32 = 1;
        const UNREACHABLE: i32 = 101;
        let absent = &[UNREACHABLE];
        // With an IPv6 default the family must be proven.
        assert_eq!(
            v6_attempt(true, Some(Err(UNREACHABLE)), &[BLOCKED], absent),
            Attempt::Unknown
        );
        assert_eq!(v6_attempt(true, None, &[BLOCKED], absent), Attempt::Unknown);
        assert_eq!(
            v6_attempt(true, Some(Err(BLOCKED)), &[BLOCKED], absent),
            Attempt::Blocked
        );
        assert_eq!(
            v6_attempt(true, Some(Ok(())), &[BLOCKED], absent),
            Attempt::Leaked
        );
        // Without one it proves nothing either way, but a leak is still a leak.
        assert_eq!(
            v6_attempt(false, Some(Err(UNREACHABLE)), &[BLOCKED], absent),
            Attempt::Absent
        );
        assert_eq!(v6_attempt(false, None, &[BLOCKED], absent), Attempt::Absent);
        assert_eq!(
            v6_attempt(false, Some(Ok(())), &[BLOCKED], absent),
            Attempt::Leaked
        );
        assert_eq!(
            v6_attempt(false, Some(Err(-1)), &[BLOCKED], absent),
            Attempt::Unknown
        );
        // Dual stack: IPv4 refused but IPv6 unproven is not a pass.
        let v6 = v6_attempt(true, Some(Err(UNREACHABLE)), &[BLOCKED], absent);
        assert_eq!(
            guard(Audit::Match, &[Attempt::Blocked, v6]),
            Outcome::Unknown
        );
    }
    #[tokio::test(start_paused = true)]
    async fn a_stalled_blocking_collector_is_never_started_twice() {
        use std::sync::{Arc, Mutex, atomic::AtomicUsize, atomic::Ordering};
        let lane: &'static Lane = Box::leak(Box::new(Lane::new()));
        let starts = Arc::new(AtomicUsize::new(0));
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(Mutex::new(wait));
        let collect = |starts: Arc<AtomicUsize>,
                       wait: Arc<Mutex<std::sync::mpsc::Receiver<()>>>| async move {
            match lane.spawn(move || {
                let _ = wait.lock().unwrap().recv();
            }) {
                Some(work) => {
                    starts.fetch_add(1, Ordering::SeqCst);
                    let _ = work.await;
                    passing(now_ms())
                }
                None => SystemProbe::unknown(now_ms()),
            }
        };
        let mut runner = Runner::default();
        runner.start(1, collect(starts.clone(), wait.clone()));
        // Drive the run until its blocking part has been spawned.
        tokio::select! {
            _ = runner.next() => panic!("a stalled run cannot finish"),
            _ = tokio::task::yield_now() => {}
        }
        assert_eq!(starts.load(Ordering::SeqCst), 1);
        assert!(lane.busy());
        // Cancel detaches the blocking call; the next due run must not stack another.
        runner.cancel();
        tokio::time::advance(SETTLE).await;
        assert!(matches!(runner.next().await, Tick::Due));
        runner.start(2, collect(starts.clone(), wait.clone()));
        let Tick::Done(generation, probe) = runner.next().await else {
            panic!("expected a finished run");
        };
        assert_eq!(generation, 2);
        assert_eq!(starts.load(Ordering::SeqCst), 1, "second blocking start");
        assert_eq!(probe.guard.outcome, Outcome::Unknown);
        assert_eq!(probe.transport_proven_at, None);
        // Once the stalled call returns the lane is free again.
        release.send(()).unwrap();
        while lane.busy() {
            std::thread::sleep(Duration::from_millis(1));
        }
        let free = lane.spawn(|| 7).expect("lane free");
        assert_eq!(free.await.unwrap(), 7);
    }
    #[tokio::test]
    async fn evidence_is_stamped_with_the_run_start() {
        let before = now_ms();
        let probe = evidence(async {
            tokio::time::sleep(Duration::from_millis(60)).await;
            (
                Dns {
                    config: Audit::Match,
                    path: Path::Tunnel,
                    reply: Reply::Answered,
                    foreign: Foreign::None,
                },
                Audit::Match,
                vec![Attempt::Blocked],
            )
        })
        .await;
        let after = now_ms();
        for at in [
            probe.transport_proven_at,
            probe.dns.observed_at_ms,
            probe.guard.observed_at_ms,
        ] {
            let at = at.unwrap();
            assert!(at >= before && at + 40 <= after, "{before} {at} {after}");
        }
    }

    /// Classic BPF subset used by `macos::FILTER`.
    fn run_filter(frame: &[u8]) -> u32 {
        let (mut a, mut x, mut pc) = (0u32, 0u32, 0usize);
        let half = |at: usize| {
            frame
                .get(at..at + 2)
                .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
        };
        loop {
            let (code, jt, jf, k) = macos::FILTER[pc];
            let k_at = k as usize;
            pc += 1;
            match code {
                0x28 => match half(k_at) {
                    Some(v) => a = v,
                    None => return 0,
                },
                0x30 => match frame.get(k_at) {
                    Some(&v) => a = u32::from(v),
                    None => return 0,
                },
                0x48 => match half(x as usize + k_at) {
                    Some(v) => a = v,
                    None => return 0,
                },
                0xb1 => match frame.get(k_at) {
                    Some(&v) => x = 4 * u32::from(v & 0x0f),
                    None => return 0,
                },
                0x15 => pc += usize::from(if a == k { jt } else { jf }),
                0x45 => pc += usize::from(if a & k != 0 { jt } else { jf }),
                0x06 => return k,
                _ => panic!("opcode {code:#x}"),
            }
        }
    }
    fn udp_frame(v6: bool, source: u16, destination: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        if v6 {
            frame.extend([0x86, 0xdd, 0x60, 0, 0, 0, 0, 9, 17, 64]);
            frame.extend([0u8; 32]);
        } else {
            frame.extend([0x08, 0x00, 0x45, 0, 0, 29, 0, 0, 0, 0, 64, 17, 0, 0]);
            frame.extend([198, 51, 100, 2, 198, 51, 100, 1]);
        }
        frame.extend(source.to_be_bytes());
        frame.extend(destination.to_be_bytes());
        frame.extend([0, 9, 0, 0, 0]);
        frame
    }
    fn bpf_record(frame: &[u8]) -> Vec<u8> {
        let mut record = vec![0u8; 8];
        record.extend((frame.len() as u32).to_ne_bytes());
        record.extend((frame.len() as u32).to_ne_bytes());
        record.extend(20u16.to_ne_bytes());
        record.extend([0, 0]);
        record.extend(frame);
        while !record.len().is_multiple_of(4) {
            record.push(0);
        }
        record
    }
    #[test]
    fn macos_filter_keeps_only_udp_to_the_discard_port() {
        for v6 in [false, true] {
            assert_ne!(run_filter(&udp_frame(v6, 50_000, 9)), 0, "v6={v6}");
            assert_eq!(run_filter(&udp_frame(v6, 50_000, 53)), 0, "v6={v6}");
        }
        let mut tcp = udp_frame(false, 50_000, 9);
        tcp[23] = 6;
        assert_eq!(run_filter(&tcp), 0);
        let mut fragment = udp_frame(false, 50_000, 9);
        fragment[21] = 1;
        assert_eq!(run_filter(&fragment), 0);
        let mut options = udp_frame(false, 50_000, 9);
        options[14] = 0x46;
        options.splice(34..34, [1, 1, 1, 1]);
        assert_ne!(run_filter(&options), 0);
        let mut arp = udp_frame(false, 50_000, 9);
        arp[12..14].copy_from_slice(&[0x08, 0x06]);
        assert_eq!(run_filter(&arp), 0);
        assert_eq!(run_filter(&[0u8; 10]), 0);
    }
    #[test]
    fn macos_capture_matches_only_our_datagram_in_bpf_records() {
        let mut buffer = bpf_record(&udp_frame(false, 40_000, 9));
        buffer.extend(bpf_record(&udp_frame(true, 50_000, 9)));
        assert!(macos::captured(&buffer, 50_000));
        assert!(macos::captured(&buffer, 40_000));
        assert!(!macos::captured(&buffer, 50_001));
        assert!(!macos::captured(
            &bpf_record(&udp_frame(false, 50_000, 53)),
            50_000
        ));
        // Truncated or malformed buffers never count as a capture.
        assert!(!macos::captured(&buffer[..10], 40_000));
        let mut short = bpf_record(&udp_frame(false, 50_000, 9));
        short[16..18].copy_from_slice(&4u16.to_ne_bytes());
        assert!(!macos::captured(&short, 50_000));
        let mut long = bpf_record(&udp_frame(false, 50_000, 9));
        long[8..12].copy_from_slice(&4096u32.to_ne_bytes());
        assert!(!macos::captured(&long, 50_000));
        assert!(!macos::captured(&[], 50_000));
    }
    #[test]
    fn macos_block_counter_reads_only_our_final_rule() {
        let label = "label \"rtrust-501\"";
        let text = "pass out quick on lo0 all no state label \"rtrust-501\"\n  [ Evaluations: 90        Packets: 80        Bytes: 800         States: 0     ]\n  [ Inserted: uid 0 pid 1 State Creations: 0     ]\nblock drop out quick all label \"rtrust-501\"\n  [ Evaluations: 12        Packets: 7         Bytes: 420         States: 0     ]\n  [ Inserted: uid 0 pid 1 State Creations: 0     ]\n";
        assert_eq!(macos::block_packets(text, label), Some(7));
        assert_eq!(macos::block_packets(text, "label \"rtrust-502\""), None);
        assert_eq!(
            macos::block_packets("block drop out quick all label \"rtrust-501\"\n", label),
            None
        );
        assert_eq!(macos::block_packets("", label), None);
    }
    #[test]
    fn macos_refusal_needs_silence_on_the_wire_and_our_block_counting() {
        use Attempt::*;
        use macos::Seen::*;
        assert_eq!(macos::verdict(Captured, Some(1), Some(2)), Leaked);
        assert_eq!(macos::verdict(Captured, None, None), Leaked);
        assert_eq!(macos::verdict(Silent(Ok(())), Some(1), Some(2)), Blocked);
        assert_eq!(
            macos::verdict(Silent(Err(libc::EHOSTUNREACH)), Some(1), Some(2)),
            Blocked
        );
        for (seen, before, after) in [
            (Silent(Ok(())), Some(2), Some(2)),
            (Silent(Ok(())), None, Some(2)),
            (Silent(Ok(())), Some(1), None),
            (Silent(Ok(())), Some(3), Some(2)),
            (Silent(Err(libc::ENETUNREACH)), Some(1), Some(2)),
            (macos::Seen::Unknown, Some(1), Some(2)),
        ] {
            assert_eq!(
                macos::verdict(seen, before, after),
                Attempt::Unknown,
                "{seen:?}"
            );
        }
    }
}
