//! One bounded check of the service's active profile. No route/firewall mutation.
use rtrust_control::endpoint::{Outcome, Reason, Result as ProbeResult, Token};
use rtrust_profile::Profile;
use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{Semaphore, watch};
const COOLDOWN: Duration = Duration::from_secs(30);
const BUDGET: Duration = Duration::from_secs(10);
struct Active {
    owner: u32,
    token: Token,
    profile: Profile,
    full: bool,
    index: Option<u8>,
    available: bool,
}
#[derive(Default)]
struct State {
    active: Option<Active>,
    last: Option<Instant>,
}
pub(super) struct Registry {
    state: Mutex<State>,
    changed: watch::Sender<u64>,
    slots: Arc<Semaphore>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            state: Mutex::new(State::default()),
            changed: watch::channel(0).0,
            slots: Arc::new(Semaphore::new(1)),
        }
    }
}
pub(super) fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}
pub(super) struct Lease<'a> {
    registry: &'a Registry,
    id: [u8; 16],
}
impl Registry {
    pub(super) fn current_token(&self) -> Option<Token> {
        self.state
            .lock()
            .unwrap()
            .active
            .as_ref()
            .filter(|active| active.available)
            .map(|active| active.token)
    }
    pub(super) fn publish(
        &self,
        profile: &Profile,
        owner: u32,
        full: bool,
        generation: u64,
        index: Option<u8>,
    ) -> Lease<'_> {
        let mut state = self.state.lock().unwrap();
        let id = rand::random::<[u8; 16]>();
        state.active = Some(Active {
            owner,
            token: Token {
                lease: id,
                generation,
            },
            profile: profile.clone(),
            full,
            index,
            available: true,
        });
        self.changed.send_modify(|revision| *revision += 1);
        Lease { registry: self, id }
    }
    async fn probe(&self, token: Token, owner: u32) -> ProbeResult {
        self.probe_with(token, owner, physical_check).await
    }
    async fn probe_with<F, Fut>(&self, token: Token, owner: u32, check: F) -> ProbeResult
    where
        F: FnOnce(Profile, bool, Token) -> Fut,
        Fut: std::future::Future<Output = ProbeResult>,
    {
        let mut changes = self.changed.subscribe();
        let (profile, full, index, _permit) = {
            let mut state = self.state.lock().unwrap();
            let Some(active) = &state.active else {
                return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::StaleLease);
            };
            if active.token != token || active.owner != owner || !active.available {
                return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::StaleLease);
            }
            if state.last.is_some_and(|last| last.elapsed() < COOLDOWN) {
                let mut result =
                    ProbeResult::unknown(token, Outcome::RateLimited, Reason::Cooldown);
                result.active_profile = active.index;
                return result;
            }
            let Ok(permit) = self.slots.clone().try_acquire_owned() else {
                let mut result =
                    ProbeResult::unknown(token, Outcome::RateLimited, Reason::Cooldown);
                result.active_profile = active.index;
                return result;
            };
            let details = (active.profile.clone(), active.full, active.index, permit);
            state.last = Some(Instant::now());
            details
        };
        let started = rtrust_control::observations::now_ms();
        let mut result = tokio::select! {
            _ = changes.changed() => ProbeResult::unknown(token, Outcome::Inconclusive, Reason::Cancelled),
            checked = tokio::time::timeout(BUDGET, check(profile, full, token)) => checked.unwrap_or_else(|_| ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven)),
        };
        result.started_at_ms = started;
        result.completed_at_ms = rtrust_control::observations::now_ms();
        result.active_profile = index;
        // A completed I/O future can race invalidation; never publish a stale fact.
        if self
            .state
            .lock()
            .unwrap()
            .active
            .as_ref()
            .is_none_or(|active| active.token != token || !active.available)
        {
            result.outcome = Outcome::Inconclusive;
            result.reason = Reason::Cancelled;
            result.independent = false;
        }
        result
    }
}
impl Lease<'_> {
    #[cfg(test)]
    pub(super) fn token(&self) -> Option<Token> {
        self.registry
            .state
            .lock()
            .unwrap()
            .active
            .as_ref()
            .filter(|a| a.token.lease == self.id && a.available)
            .map(|a| a.token)
    }
    pub(super) fn suspend(&self) {
        let mut state = self.registry.state.lock().unwrap();
        if let Some(active) = &mut state.active
            && active.token.lease == self.id
        {
            active.available = false;
            self.registry.changed.send_modify(|revision| *revision += 1);
        }
    }
    pub(super) fn resume(&self) {
        let mut state = self.registry.state.lock().unwrap();
        if let Some(active) = &mut state.active
            && active.token.lease == self.id
        {
            active.available = true;
            self.registry.changed.send_modify(|revision| *revision += 1);
        }
    }
    pub(super) fn update(&self, profile: &Profile, generation: u64, index: Option<u8>) {
        let mut state = self.registry.state.lock().unwrap();
        if let Some(active) = &mut state.active
            && active.token.lease == self.id
        {
            if active.token.generation != generation || active.profile != *profile {
                self.registry.changed.send_modify(|revision| *revision += 1);
            }
            active.token.generation = generation;
            active.profile = profile.clone();
            active.index = index;
        }
    }
}
impl Drop for Lease<'_> {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock().unwrap();
        if state
            .active
            .as_ref()
            .is_some_and(|active| active.token.lease == self.id)
        {
            state.active = None;
            self.registry.changed.send_modify(|revision| *revision += 1);
        }
    }
}
pub(super) async fn serve(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    token: Token,
    owner: u32,
) -> Result<(), String> {
    serve_probe(stream, registry().probe(token, owner)).await
}
async fn serve_probe(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    probe: impl std::future::Future<Output = ProbeResult>,
) -> Result<(), String> {
    use tokio::io::AsyncReadExt;
    let mut byte = [0];
    let result = tokio::select! {
        result = probe => result,
        _ = stream.read(&mut byte) => return Ok(()), // EOF/cancel drops all probe sockets.
    };
    let mut response = rtrust_control::Response::new(
        rtrust_control::State::Idle,
        "Endpoint check only; active VPN unchanged",
    );
    response.endpoint_probe = Some(result);
    tokio::time::timeout(
        Duration::from_secs(3),
        rtrust_control::write(stream, &response),
    )
    .await
    .map_err(|_| "Endpoint probe IPC write timed out")?
}
fn physical_device(bytes: &[u8]) -> Option<String> {
    if bytes.len() > 8192 {
        return None;
    }
    let routes: Vec<serde_json::Value> = serde_json::from_slice(bytes).ok()?;
    let [route] = routes.as_slice() else {
        return None;
    };
    if route.get("type").is_some_and(|kind| kind != "unicast") {
        return None;
    }
    let dev = route["dev"].as_str()?;
    if dev.is_empty()
        || dev.len() > 15
        || !dev
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(dev.into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Physical {
    name: String,
    index: u32,
    device: std::path::PathBuf,
    inode: u64,
}
fn identity(name: &str) -> Option<Physical> {
    use std::os::unix::fs::MetadataExt;
    let name_c = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(name_c.as_ptr()) };
    if index == 0 {
        return None;
    }
    let path = std::path::Path::new("/sys/class/net").join(name);
    Some(Physical {
        name: name.into(),
        index,
        device: path.join("device").canonicalize().ok()?,
        inode: path.metadata().ok()?.ino(),
    })
}
async fn route(
    address: std::net::SocketAddr,
    full: bool,
    interface: Option<&str>,
) -> Option<Physical> {
    use tokio::io::AsyncReadExt;
    let address_text = address.ip().to_string();
    let port = address.port().to_string();
    let mark = if full { "0x5254" } else { "0" };
    let mut command = tokio::process::Command::new("/usr/sbin/ip");
    command.args([
        if address.is_ipv4() { "-4" } else { "-6" },
        "-j",
        "route",
        "get",
        &address_text,
        "mark",
        mark,
        "uid",
        "0",
        "ipproto",
        "tcp",
        "dport",
        &port,
    ]);
    if let Some(interface) = interface {
        command.args(["oif", interface]);
    }
    let mut child = command
        .env_clear()
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let mut bytes = Vec::new();
    let output = child.stdout.take()?;
    let status = tokio::time::timeout(Duration::from_secs(2), async {
        output.take(8193).read_to_end(&mut bytes).await.ok()?;
        if bytes.len() > 8192 {
            return None;
        }
        child.wait().await.ok()
    })
    .await
    .ok()??;
    if !status.success() {
        return None;
    }
    let device = physical_device(&bytes)?;
    if interface.is_some_and(|expected| expected != device) {
        return None;
    }
    identity(&device)
}
fn bind(fd: i32, physical: &Physical, full: bool) -> std::io::Result<()> {
    if identity(&physical.name).as_ref() != Some(physical) {
        return Err(std::io::Error::other("Physical interface changed"));
    }
    let device = std::ffi::CString::new(physical.name.clone()).unwrap();
    let mark: u32 = if full { 0x5254 } else { 0 };
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mark as *const u32).cast(),
            std::mem::size_of_val(&mark) as _,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_ptr().cast(),
            device.as_bytes_with_nul().len() as _,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut installed = [0u8; 16];
    let mut len = installed.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            installed.as_mut_ptr().cast(),
            &mut len,
        )
    } != 0
        || installed[..len as usize] != *device.as_bytes_with_nul()
    {
        return Err(std::io::Error::other("Physical socket binding unconfirmed"));
    }
    let mut actual_mark = 0u32;
    let mut mark_len = std::mem::size_of_val(&actual_mark) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut actual_mark as *mut u32).cast(),
            &mut mark_len,
        )
    } != 0
        || actual_mark != mark
        || identity(&physical.name).as_ref() != Some(physical)
    {
        return Err(std::io::Error::other(
            "Physical socket identity unconfirmed",
        ));
    }
    Ok(())
}
const MAX_PROBE_ADDRESSES: usize = 8;
async fn physical_check(profile: Profile, full: bool, token: Token) -> ProbeResult {
    aggregate(profile, full, token, BUDGET, physical_attempt).await
}
async fn aggregate<F, Fut>(
    profile: Profile,
    full: bool,
    token: Token,
    budget: Duration,
    mut check: F,
) -> ProbeResult
where
    F: FnMut(Profile, bool, Token) -> Fut,
    Fut: std::future::Future<Output = ProbeResult>,
{
    if profile.protocol != rtrust_profile::Protocol::TrustTunnel
        || profile.endpoint.upstream_protocol != "http2"
        || rtrust_engine::check_capabilities(&profile).is_err()
    {
        return ProbeResult::unknown(token, Outcome::Unsupported, Reason::UnsupportedTransport);
    }
    let mut addresses = Vec::new();
    for value in &profile.endpoint.addresses {
        let Ok(address) = value.parse::<std::net::SocketAddr>() else {
            return ProbeResult::unknown(
                token,
                Outcome::Inconclusive,
                Reason::PhysicalPathUnproven,
            );
        };
        if !addresses.contains(&address) {
            addresses.push(address);
        }
        if addresses.len() > MAX_PROBE_ADDRESSES {
            return ProbeResult::unknown(
                token,
                Outcome::Inconclusive,
                Reason::PhysicalPathUnproven,
            );
        }
    }
    if addresses.is_empty() {
        return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven);
    }
    let deadline = tokio::time::Instant::now() + budget;
    let mut failure: Option<ProbeResult> = None;
    let mut uncertain = false;
    for address in addresses {
        if tokio::time::Instant::now() >= deadline {
            return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::Timeout);
        }
        let mut candidate = profile.clone();
        candidate.endpoint.addresses = vec![address.to_string()];
        let Ok(result) = tokio::time::timeout_at(deadline, check(candidate, full, token)).await
        else {
            return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::Timeout);
        };
        if result.outcome == Outcome::Passed && result.independent {
            return result;
        }
        if result.outcome == Outcome::Failed && result.independent {
            if failure
                .as_ref()
                .is_none_or(|old| failure_priority(result.reason) > failure_priority(old.reason))
            {
                failure = Some(result);
            }
        } else {
            uncertain = true;
        }
    }
    if uncertain {
        ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven)
    } else {
        failure.unwrap_or_else(|| {
            ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven)
        })
    }
}
// If every address failed independently, retain the most specific cause:
// authentication > TLS > protocol > refusal > timeout > connection.
fn failure_priority(reason: Reason) -> u8 {
    match reason {
        Reason::AuthenticationFailed => 6,
        Reason::TlsFailed => 5,
        Reason::ProtocolFailed => 4,
        Reason::EndpointRejected => 3,
        Reason::Timeout => 2,
        _ => 1,
    }
}
async fn physical_attempt(mut profile: Profile, full: bool, token: Token) -> ProbeResult {
    if profile.protocol != rtrust_profile::Protocol::TrustTunnel
        || profile.endpoint.upstream_protocol != "http2"
        || rtrust_engine::check_capabilities(&profile).is_err()
    {
        return ProbeResult::unknown(token, Outcome::Unsupported, Reason::UnsupportedTransport);
    }
    let Some(address) = profile
        .endpoint
        .addresses
        .first()
        .and_then(|address| address.parse::<std::net::SocketAddr>().ok())
    else {
        return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven);
    };
    let Some(device) = route(address, full, None).await else {
        return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven);
    };
    if route(address, full, Some(&device.name)).await.as_ref() != Some(&device) {
        return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven);
    }
    profile.endpoint.addresses = vec![address.to_string()];
    let bound = Arc::new(AtomicUsize::new(0));
    let count = bound.clone();
    let physical = device.clone();
    let protector: rtrust_engine::SocketProtector = Arc::new(move |fd| {
        bind(fd, &physical, full)?;
        count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    });
    let checked = tokio::time::timeout(Duration::from_secs(5), async {
        let session = rtrust_engine::Session::connect_protected(&profile, &protector).await?;
        session.health().await
    })
    .await
    .unwrap_or(Err(rtrust_engine::Error::Timeout));
    if bound.load(Ordering::Relaxed) != 1
        || route(address, full, Some(&device.name)).await.as_ref() != Some(&device)
    {
        return ProbeResult::unknown(token, Outcome::Inconclusive, Reason::PhysicalPathUnproven);
    }
    let mut result = ProbeResult::unknown(
        token,
        if checked.is_ok() {
            Outcome::Passed
        } else {
            Outcome::Failed
        },
        if checked.is_ok() {
            Reason::EndpointHealthy
        } else {
            classify(checked.err().unwrap())
        },
    );
    result.independent = true;
    result
}
fn classify(error: rtrust_engine::Error) -> Reason {
    use rtrust_engine::Error;
    match error {
        Error::Tls | Error::Trust => Reason::TlsFailed,
        Error::Authentication => Reason::AuthenticationFailed,
        Error::Protocol => Reason::ProtocolFailed,
        Error::Rejected(_) => Reason::EndpointRejected,
        // Out of stream credit: the endpoint never answered in time either.
        Error::Timeout | Error::Credit => Reason::Timeout,
        _ => Reason::ConnectionFailed,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> Profile {
        Profile::import(
            "hostname='vpn.example'\naddresses=['192.0.2.1:443']\nusername='u'\npassword='p'\n",
        )
        .unwrap()
    }
    #[test]
    fn lease_tokens_invalidate_on_network_change_and_retirement() {
        let registry = Registry::default();
        let lease = registry.publish(&profile(), 42, true, 1, None);
        let first = lease.token().unwrap();
        let mut changes = registry.changed.subscribe();
        lease.update(&profile(), 2, None);
        assert!(changes.has_changed().unwrap());
        changes.borrow_and_update();
        assert_ne!(first, lease.token().unwrap());
        drop(lease);
        assert!(registry.state.lock().unwrap().active.is_none());
        assert!(changes.has_changed().unwrap());
        let replacement = registry.publish(&profile(), 42, true, 1, None);
        assert_ne!(first, replacement.token().unwrap());
    }
    #[tokio::test]
    async fn inactive_or_stale_requests_never_start_io() {
        let registry = Registry::default();
        let token = Token {
            lease: [1; 16],
            generation: 1,
        };
        assert_eq!(registry.probe(token, 42).await.reason, Reason::StaleLease);
        let lease = registry.publish(&profile(), 42, true, 2, None);
        assert_eq!(registry.probe(token, 42).await.reason, Reason::StaleLease);
        let token = lease.token().unwrap();
        assert_eq!(registry.probe(token, 43).await.reason, Reason::StaleLease);
        registry.state.lock().unwrap().last = Some(Instant::now());
        assert_eq!(
            registry.probe(token, 42).await.outcome,
            Outcome::RateLimited
        );
    }
    #[tokio::test]
    async fn stop_and_generation_change_cancel_an_inflight_probe_and_concurrency_is_bounded() {
        for stop in [false, true] {
            let registry = Arc::new(Registry::default());
            let lease = registry.publish(&profile(), 42, true, 1, None);
            let token = lease.token().unwrap();
            let (started, reached) = tokio::sync::oneshot::channel();
            let task_registry = registry.clone();
            let task = tokio::spawn(async move {
                task_registry
                    .probe_with(token, 42, |_, _, _| async move {
                        let _ = started.send(());
                        std::future::pending::<ProbeResult>().await
                    })
                    .await
            });
            reached.await.unwrap();
            assert_eq!(
                registry.probe(token, 42).await.outcome,
                Outcome::RateLimited
            );
            registry.state.lock().unwrap().last = None;
            assert_eq!(
                registry.probe(token, 42).await.outcome,
                Outcome::RateLimited
            ); // semaphore, independently of cooldown
            if stop {
                drop(lease);
            } else {
                lease.update(&profile(), 2, None);
            }
            let result = task.await.unwrap();
            assert_eq!(result.reason, Reason::Cancelled);
            assert!(!result.independent);
            assert_eq!(registry.slots.available_permits(), 1);
        }
    }
    #[tokio::test]
    async fn closed_probe_channel_drops_pending_work_without_stopping_the_vpn_lease() {
        struct Dropped(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Dropped {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Relaxed);
            }
        }
        let registry = Registry::default();
        let lease = registry.publish(&profile(), 42, true, 1, None);
        let token = lease.token().unwrap();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = Dropped(dropped.clone());
        let (mut server, client) = tokio::io::duplex(64);
        let (entered, reached) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            serve_probe(&mut server, async move {
                let _marker = marker;
                let _ = entered.send(());
                std::future::pending::<ProbeResult>().await
            })
            .await
        });
        reached.await.unwrap();
        drop(client);
        task.await.unwrap().unwrap();
        assert!(dropped.load(Ordering::Relaxed));
        assert_eq!(registry.current_token(), Some(token));
    }
    #[test]
    fn route_evidence_rejects_ambiguous_and_unsafe_interfaces() {
        for bytes in [
            b"[]".as_slice(),
            br#"[{"dev":"../eth0"}]"#,
            br#"[{"type":"local","dev":"lo"}]"#,
            br#"[{"dev":"eth0"},{"dev":"eth1"}]"#,
        ] {
            assert!(physical_device(bytes).is_none());
        }
        assert_eq!(
            physical_device(br#"[{"dev":"eth0"}]"#).as_deref(),
            Some("eth0")
        );
    }
    #[tokio::test]
    async fn aggregation_needs_all_failed_addresses_but_any_proven_success_wins() {
        let token = Token {
            lease: [1; 16],
            generation: 1,
        };
        let mut profile = profile();
        profile.endpoint.addresses = vec![
            "192.0.2.1:443".into(),
            "192.0.2.2:443".into(),
            "192.0.2.1:443".into(),
        ];
        for (outcomes, expected, independent) in [
            (
                vec![(Outcome::Failed, true), (Outcome::Passed, true)],
                Outcome::Passed,
                true,
            ),
            (
                vec![(Outcome::Failed, true), (Outcome::Inconclusive, false)],
                Outcome::Inconclusive,
                false,
            ),
            (
                vec![(Outcome::Failed, true), (Outcome::Failed, true)],
                Outcome::Failed,
                true,
            ),
            (
                vec![(Outcome::Inconclusive, false), (Outcome::Passed, true)],
                Outcome::Passed,
                true,
            ),
        ] {
            let mut results = outcomes.into_iter();
            let mut calls = 0;
            let result = aggregate(profile.clone(), true, token, BUDGET, |_, _, token| {
                calls += 1;
                let (outcome, independent) = results.next().unwrap();
                std::future::ready(ProbeResult {
                    independent,
                    ..ProbeResult::unknown(token, outcome, Reason::ConnectionFailed)
                })
            })
            .await;
            assert_eq!(result.outcome, expected);
            assert_eq!(result.independent, independent);
            assert_eq!(calls, 2); // duplicate pinned address is not counted twice
        }
        let mut partial_calls = 0;
        let partial = aggregate(
            profile.clone(),
            true,
            token,
            Duration::from_millis(5),
            |_, _, token| {
                partial_calls += 1;
                let first = partial_calls == 1;
                async move {
                    if first {
                        ProbeResult {
                            independent: true,
                            ..ProbeResult::unknown(token, Outcome::Failed, Reason::ConnectionFailed)
                        }
                    } else {
                        std::future::pending::<ProbeResult>().await
                    }
                }
            },
        )
        .await;
        assert_eq!(partial.outcome, Outcome::Inconclusive);
        assert_eq!(partial.reason, Reason::Timeout);
        assert!(!partial.independent);
        let result = aggregate(profile, true, token, Duration::ZERO, |_, _, _| async {
            panic!("expired budget must not start another attempt")
        })
        .await;
        assert_eq!(result.outcome, Outcome::Inconclusive);
        assert_eq!(result.reason, Reason::Timeout);
        assert!(!result.independent);
    }
    #[tokio::test]
    async fn aggregation_rejects_unpinned_or_truncated_sets_without_endpoint_failure() {
        let token = Token {
            lease: [1; 16],
            generation: 1,
        };
        for addresses in [
            vec!["192.0.2.1:443".into(), "vpn.example:443".into()],
            (1..=9).map(|n| format!("192.0.2.{n}:443")).collect(),
        ] {
            let mut profile = profile();
            profile.endpoint.addresses = addresses;
            let result = aggregate(profile, true, token, BUDGET, |_, _, _| async {
                panic!("incomplete address sets cannot establish aggregate failure")
            })
            .await;
            assert_eq!(result.outcome, Outcome::Inconclusive);
            assert!(!result.independent);
        }
    }
    #[tokio::test]
    async fn rate_limited_valid_backup_keeps_its_active_index() {
        let registry = Registry::default();
        let lease = registry.publish(&profile(), 42, true, 1, Some(2));
        let token = lease.token().unwrap();
        registry.state.lock().unwrap().last = Some(Instant::now());
        let result = registry.probe(token, 42).await;
        assert_eq!(result.outcome, Outcome::RateLimited);
        assert_eq!(result.active_profile, Some(2));
        registry.state.lock().unwrap().last = None;
        let _permit = registry.slots.clone().try_acquire_owned().unwrap();
        let result = registry.probe(token, 42).await;
        assert_eq!(result.outcome, Outcome::RateLimited);
        assert_eq!(result.active_profile, Some(2));
    }
    #[tokio::test]
    async fn unsupported_profiles_and_unpinned_paths_fail_closed() {
        let token = Token {
            lease: [1; 16],
            generation: 1,
        };
        let mut profile = profile();
        profile.endpoint.skip_verification = true;
        let result = physical_check(profile, true, token).await;
        assert_eq!(result.outcome, Outcome::Unsupported);
        assert!(!result.independent);
        let mut profile = self::profile();
        profile.endpoint.addresses = vec!["vpn.example:443".into()];
        let result = physical_check(profile, true, token).await;
        assert_eq!(result.reason, Reason::PhysicalPathUnproven);
        assert!(!result.independent);
    }
}
