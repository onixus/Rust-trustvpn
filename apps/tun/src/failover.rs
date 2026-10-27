//! Opt-in recovery through user-allowed backup profiles (issue #34).
//!
//! The guard is installed once for the union of every candidate's endpoint
//! addresses and UDP needs, so moving between candidates never changes the
//! firewall, routes or DNS: there is no window in which protection is
//! relaxed. Only the transport worker changes profile. Without backups this is
//! the fixed-profile behavior: the same profile is retried indefinitely.
use rtrust_profile::Profile;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct InitialFailure<E> {
    pub last: Option<E>,
    pub transport: rtrust_journal::Transport,
    pub attempts: u32,
}
pub fn journal_attempt(
    path: rtrust_journal::Path,
    transport: rtrust_journal::Transport,
    attempt: u32,
    budget: rtrust_journal::Budget,
) -> rtrust_journal::Attempt {
    let mut guard = rtrust_journal::Attempt::new(path, transport, attempt, budget);
    if cfg!(test) {
        guard.success();
    }
    guard
}
pub fn journal_failure(record: rtrust_journal::Record) {
    #[cfg(not(test))]
    rtrust_journal::service().submit(record);
    #[cfg(test)]
    TEST_RECORDS.with(|records| records.borrow_mut().push(record));
}
#[cfg(test)]
thread_local! { static TEST_RECORDS: std::cell::RefCell<Vec<rtrust_journal::Record>> = const { std::cell::RefCell::new(Vec::new()) }; }
#[cfg(test)]
pub fn take_records() -> Vec<rtrust_journal::Record> {
    TEST_RECORDS.with(|records| std::mem::take(&mut *records.borrow_mut()))
}
/// GUI text stays separate from the closed journal classification.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub class: rtrust_journal::Class,
    pub record: Option<rtrust_journal::Record>,
}
impl Failure {
    pub fn engine(error: rtrust_engine::Error, message: impl Into<String>) -> Self {
        Self {
            class: rtrust_journal::classify(&error),
            message: message.into(),
            record: None,
        }
    }
    pub fn timeout(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: rtrust_journal::Class::Timeout,
            record: None,
        }
    }
}
impl From<rtrust_engine::Error> for Failure {
    fn from(error: rtrust_engine::Error) -> Self {
        let class = rtrust_journal::classify(&error);
        Self {
            class,
            message: error.to_string(),
            record: None,
        }
    }
}
impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            class: rtrust_journal::Class::Other,
            record: None,
        }
    }
}
impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Failure {}

/// Consecutive failed connection attempts before trying the next candidate.
pub const SWITCH_AFTER: u32 = 2;
/// Minimum time between two switches, against oscillation.
pub const COOLDOWN: Duration = Duration::from_secs(20);
/// A session shorter than this counts as a failed attempt, like the backoff reset.
pub const STABLE: Duration = Duration::from_secs(30);

/// How a platform's guard needs endpoint addresses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// macOS pins IPv4 only; the other modes serve Linux and Windows.
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub enum Pin {
    /// The guard has no endpoint exception (Linux selected mode).
    Unresolved,
    /// Every resolved address.
    All,
    /// IPv4 answers only, for guards that pin IPv4 endpoint exceptions.
    Ipv4,
}
/// Per candidate; candidates resolve concurrently.
pub const PIN_LIMIT: Duration = Duration::from_secs(10);

/// Freeze DNS answers for this lease so reconnect cannot route into itself.
pub async fn pin_endpoint(mut profile: Profile, mode: Pin) -> Result<Profile, String> {
    if mode == Pin::Unresolved {
        return Ok(profile);
    }
    let mut addresses = Vec::new();
    for address in &profile.endpoint.addresses {
        for address in tokio::net::lookup_host(address)
            .await
            .map_err(|_| "Cannot resolve endpoint")?
        {
            if mode == Pin::Ipv4 && !address.is_ipv4() {
                continue;
            }
            if addresses.len() >= 64 {
                return Err("Too many endpoint addresses".into());
            }
            let address = address.to_string();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    if addresses.is_empty() {
        return Err("Endpoint has no addresses".into());
    }
    profile.endpoint.addresses = addresses;
    Ok(profile)
}

/// An endpoint exception is tied to one candidate, never a cross-product of
/// all candidate addresses, protocols and hopping ports.
#[cfg(any(target_os = "macos", target_os = "windows", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permit {
    pub address: std::net::SocketAddrV4,
    pub udp: bool,
    pub ports: Vec<(u16, u16)>,
}

pub struct Failover {
    candidates: Vec<Profile>,
    active: usize,
    indices: Vec<u8>,
    failures: u32,
    last_switch: Option<Instant>,
    /// Backups dropped at start because their endpoint could not be pinned.
    pub skipped: usize,
}

impl Failover {
    /// `pin` resolves a candidate's endpoint the way the platform guard needs.
    /// The requested profile must pin; a backup that cannot is left out.
    /// Pins every candidate concurrently, each within its own limit. The
    /// requested profile must pin; a backup that cannot is left out, so a
    /// slow or broken backup never prevents the requested connection.
    pub async fn pin(primary: Profile, fallbacks: Vec<Profile>, mode: Pin) -> Result<Self, String> {
        if fallbacks.len() > rtrust_control::MAX_FALLBACKS {
            return Err("Too many backup profiles".into());
        }
        let mut results =
            futures_util::future::join_all(std::iter::once(primary).chain(fallbacks).map(
                |profile| async move {
                    tokio::time::timeout(PIN_LIMIT, pin_endpoint(profile, mode))
                        .await
                        .unwrap_or_else(|_| Err("Endpoint resolution timed out".into()))
                },
            ))
            .await
            .into_iter();
        let mut candidates = vec![results.next().expect("primary")?];
        let mut indices = vec![0];
        let mut skipped = 0;
        for (index, result) in results.enumerate() {
            match result {
                Ok(profile) => {
                    candidates.push(profile);
                    indices.push((index + 1) as u8);
                }
                Err(_) => skipped += 1,
            }
        }
        let mut failover = Self::new(candidates, skipped);
        failover.indices = indices;
        // The platform guards accept at most 64 pinned endpoint addresses.
        if failover.endpoint_addresses().len() > 64 {
            return Err("Too many endpoint addresses".into());
        }
        Ok(failover)
    }
    /// Track one session ending: a session that lasted is evidence the
    /// candidate works; a short one counts as a failed attempt (flapping).
    pub fn ended(&mut self, lasted: Duration, now: Instant) -> bool {
        if lasted >= STABLE {
            self.connected();
            false
        } else {
            self.failed(now)
        }
    }
    fn new(candidates: Vec<Profile>, skipped: usize) -> Self {
        Self {
            indices: (0..candidates.len() as u8).collect(),
            candidates,
            active: 0,
            failures: 0,
            last_switch: None,
            skipped,
        }
    }
    pub fn current(&self) -> &Profile {
        &self.candidates[self.active]
    }
    /// Reported only when the user allowed backups.
    pub fn active(&self) -> Option<u8> {
        (self.candidates.len() + self.skipped > 1).then_some(self.indices[self.active])
    }
    fn connected(&mut self) {
        self.failures = 0;
    }
    /// Count a failed attempt; true when the next attempt uses another candidate.
    pub fn failed(&mut self, now: Instant) -> bool {
        self.failures = self.failures.saturating_add(1);
        if self.candidates.len() < 2
            || self.failures < SWITCH_AFTER
            || self
                .last_switch
                .is_some_and(|at| now.saturating_duration_since(at) < COOLDOWN)
        {
            return false;
        }
        self.active = (self.active + 1) % self.candidates.len();
        self.failures = 0;
        self.last_switch = Some(now);
        true
    }
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    pub fn permits(&self) -> Result<Vec<Permit>, String> {
        let mut permits = Vec::new();
        for profile in &self.candidates {
            let ports = profile.hop_port_ranges();
            if ports.len() > 64 {
                return Err("Too many endpoint port ranges".into());
            }
            for address in &profile.endpoint.addresses {
                let permit = Permit {
                    address: address
                        .parse()
                        .map_err(|_| "Guard requires pinned IPv4 endpoints")?,
                    udp: profile.udp_transport(),
                    ports: ports.clone(),
                };
                if !permits.contains(&permit) {
                    permits.push(permit);
                }
            }
        }
        Ok(permits)
    }
    /// Startup has one 30 s budget shared by every candidate. Each candidate
    /// gets two attempts before moving on, without extending the IPC deadline.
    /// Cancellation drops the pending attempt. No routes or guard are changed.
    pub async fn connect_initial<T, E, F, Fut>(
        &mut self,
        mut connect: F,
    ) -> Result<T, InitialFailure<E>>
    where
        F: FnMut(Profile) -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        // Keep the original single-profile handshake allowance unchanged.
        let attempts = if self.candidates.len() == 1 {
            1
        } else {
            SWITCH_AFTER
        };
        let budget = Duration::from_secs(30) / (self.candidates.len() as u32 * attempts);
        let mut failure = InitialFailure {
            last: None,
            transport: rtrust_journal::Transport::Unknown,
            attempts: 0,
        };
        for index in 0..self.candidates.len() {
            for _ in 0..attempts {
                failure.attempts += 1;
                failure.transport = rtrust_engine::planned_transport(&self.candidates[index]);
                match tokio::time::timeout(budget, connect(self.candidates[index].clone())).await {
                    Ok(Ok(connected)) => {
                        self.active = index;
                        self.failures = 0;
                        if index != 0 {
                            self.last_switch = Some(Instant::now());
                        }
                        return Ok(connected);
                    }
                    Ok(Err(error)) => failure.last = Some(error),
                    Err(_) => failure.last = None,
                }
            }
        }
        Err(failure)
    }
    pub fn endpoint_addresses(&self) -> Vec<String> {
        let mut addresses = Vec::new();
        for address in self.candidates.iter().flat_map(|p| &p.endpoint.addresses) {
            if !addresses.contains(address) {
                addresses.push(address.clone());
            }
        }
        addresses
    }
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    /// A copy of the requested profile whose endpoint lists every candidate's
    /// pinned addresses, for guard and route code that reads a profile.
    pub fn guard_profile(&self) -> Profile {
        let mut profile = self.candidates[0].clone();
        profile.endpoint.addresses = self.endpoint_addresses();
        profile
    }
    /// Appended to the start message so a dropped backup is not silent.
    pub fn note(&self) -> String {
        match (self.candidates.len() - 1, self.skipped) {
            (0, 0) => String::new(),
            (ready, 0) => format!(" · резервных профилей: {ready}"),
            (ready, skipped) => {
                format!(" · резервных профилей: {ready}; без адреса endpoint пропущено: {skipped}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(host: &str, address: &str) -> Profile {
        Profile::import(&format!(
            "hostname='{host}'\naddresses=['{address}']\nusername='demo'\npassword='synthetic'\n"
        ))
        .unwrap()
    }
    fn failover(count: usize) -> Failover {
        Failover::new(
            (0..count)
                .map(|i| profile(&format!("h{i}.example"), &format!("192.0.2.{}:443", i + 1)))
                .collect(),
            0,
        )
    }

    #[test]
    fn a_fixed_profile_is_never_substituted() {
        let mut f = failover(1);
        let now = Instant::now();
        for i in 0..10 {
            assert!(!f.failed(now + COOLDOWN * i));
        }
        assert_eq!(f.current().endpoint.addresses, ["192.0.2.1:443"]);
        assert_eq!(f.active(), None);
    }

    #[test]
    fn switching_needs_repeated_failure_and_respects_the_cooldown() {
        let mut f = failover(3);
        let start = Instant::now();
        assert!(!f.failed(start));
        assert!(f.failed(start));
        assert_eq!(f.active(), Some(1));
        // Two more failures inside the cooldown keep the same candidate.
        assert!(!f.failed(start + Duration::from_secs(1)));
        assert!(!f.failed(start + Duration::from_secs(2)));
        assert_eq!(f.active(), Some(1));
        // After the cooldown the pending failures move on, wrapping around.
        assert!(f.failed(start + COOLDOWN));
        assert_eq!(f.active(), Some(2));
        assert!(!f.ended(STABLE, start + COOLDOWN * 3));
        assert!(!f.failed(start + COOLDOWN * 3));
        assert!(f.failed(start + COOLDOWN * 3));
        assert_eq!(f.active(), Some(0));
    }

    #[test]
    fn a_stable_session_resets_the_count_but_flapping_sessions_switch() {
        let mut f = failover(2);
        let now = Instant::now();
        assert!(!f.failed(now));
        assert!(!f.ended(STABLE, now));
        assert!(!f.failed(now));
        assert_eq!(f.active(), Some(0));
        // Each reconnect succeeds but dies quickly: still a failing candidate.
        assert!(f.ended(Duration::from_secs(3), now));
        assert_eq!(f.active(), Some(1));
    }

    #[test]
    fn guard_inputs_cover_every_candidate_without_duplicates() {
        let mut f = failover(2);
        f.candidates[1]
            .endpoint
            .addresses
            .push("192.0.2.1:443".into());
        let guard = f.guard_profile();
        assert_eq!(guard.endpoint.addresses, ["192.0.2.1:443", "192.0.2.2:443"]);
        assert_eq!(guard.endpoint.hostname, "h0.example");
        let permits = f.permits().unwrap();
        assert!(permits.iter().all(|p| !p.udp && p.ports.is_empty()));
    }

    #[test]
    fn an_unpinnable_backup_is_dropped_but_the_requested_profile_is_required() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let good = profile("good.example", "192.0.2.1:443");
            let bad = profile("bad.example", "rtrust-unresolvable.invalid:443");
            let f = Failover::pin(
                good.clone(),
                vec![bad.clone(), profile("other.example", "192.0.2.3:443")],
                Pin::All,
            )
            .await
            .unwrap();
            assert_eq!((f.candidates.len(), f.skipped), (2, 1));
            let mut f = f;
            let now = Instant::now();
            assert!(!f.failed(now));
            assert!(f.failed(now));
            assert_eq!(f.active(), Some(2)); // Original index, not compacted 1.
            assert!(f.note().contains("пропущено: 1"));
            assert!(Failover::pin(bad, vec![], Pin::All).await.is_err());
            let many =
                vec![profile("x.example", "192.0.2.9:443"); rtrust_control::MAX_FALLBACKS + 1];
            assert!(Failover::pin(good, many, Pin::All).await.is_err());
        });
    }

    #[tokio::test]
    async fn initial_failure_tries_backups_and_keeps_the_original_index() {
        let mut f = failover(3);
        let mut calls = vec![];
        let result = f
            .connect_initial(|p| {
                let address = p.endpoint.addresses[0].clone();
                calls.push(address.clone());
                async move {
                    if address == "192.0.2.3:443" {
                        Ok(address)
                    } else {
                        Err(())
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(result, "192.0.2.3:443");
        assert_eq!(calls.len(), 5);
        assert_eq!(f.active(), Some(2));
        let mut working = failover(2);
        let mut attempts = 0;
        working
            .connect_initial(|_| {
                attempts += 1;
                async { Ok::<_, ()>(()) }
            })
            .await
            .unwrap();
        assert_eq!(attempts, 1);
        assert_eq!(working.active(), Some(0));
        let mut fixed = failover(1);
        assert!(
            fixed
                .connect_initial(|_| async { Err::<(), _>(()) })
                .await
                .is_err()
        );
        assert_eq!(fixed.active(), None);
    }

    #[tokio::test]
    async fn startup_failure_retains_typed_final_cause_attempts_and_planned_transport() {
        let mut f = failover(2);
        f.candidates[1].endpoint.upstream_protocol = "http3".into();
        let failure = f
            .connect_initial(|_| async { Err::<(), _>(rtrust_engine::Error::Authentication) })
            .await
            .unwrap_err();
        assert_eq!(failure.attempts, 4);
        assert_eq!(failure.transport, rtrust_journal::Transport::H3);
        assert_eq!(
            rtrust_journal::classify(failure.last.as_ref().unwrap()),
            rtrust_journal::Class::Authentication
        );
        assert_eq!(f.active(), Some(0)); // Failed startup never admits a backup.
    }

    #[test]
    fn endpoint_permissions_keep_protocols_and_ports_per_candidate() {
        let mut f = failover(3);
        f.candidates[1].endpoint.upstream_protocol = "http3".into();
        let permits = f.permits().unwrap();
        assert!(!permits[0].udp);
        assert!(permits[1].udp);
        assert!(!permits[2].udp);
        assert_eq!(permits[0].address.to_string(), "192.0.2.1:443");
        assert!(permits.iter().all(|p| p.ports.is_empty()));
        f.candidates[2] =
            Profile::import("hy2://synthetic@192.0.2.3:443,20000-20010/#Hop").unwrap();
        let permits = f.permits().unwrap();
        assert!(!permits[0].udp && permits[0].ports.is_empty());
        assert!(permits[1].udp && permits[1].ports.is_empty());
        assert!(permits[2].udp);
        assert_eq!(permits[2].ports, [(443, 443), (20000, 20010)]);
    }

    #[test]
    fn ipv4_pinning_drops_ipv6_answers_and_unresolved_keeps_names() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut dual = profile("dual.example", "192.0.2.1:443");
            dual.endpoint.addresses.push("[2001:db8::1]:443".into());
            dual.endpoint.addresses.push("192.0.2.1:443".into());
            let v4 = pin_endpoint(dual.clone(), Pin::Ipv4).await.unwrap();
            assert_eq!(v4.endpoint.addresses, ["192.0.2.1:443"]);
            let all = pin_endpoint(dual.clone(), Pin::All).await.unwrap();
            assert_eq!(all.endpoint.addresses.len(), 2);
            let mut v6 = profile("v6.example", "[2001:db8::1]:443");
            v6.endpoint.addresses.truncate(1);
            assert!(pin_endpoint(v6, Pin::Ipv4).await.is_err());
            let named = profile("n.example", "vpn.invalid:443");
            assert_eq!(
                pin_endpoint(named, Pin::Unresolved)
                    .await
                    .unwrap()
                    .endpoint
                    .addresses,
                ["vpn.invalid:443"]
            );
        });
    }
}
