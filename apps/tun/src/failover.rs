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
impl<E> InitialFailure<E> {
    pub fn annotate(
        &self,
        journal: &mut rtrust_journal::Attempt,
        classify: impl FnOnce(&E) -> rtrust_journal::Class,
    ) {
        journal.metadata(self.transport, self.attempts);
        journal.class(
            self.last
                .as_ref()
                .map_or(rtrust_journal::Class::Timeout, classify),
        );
    }
}
pub fn journal_attempt(
    path: rtrust_journal::Path,
    transport: rtrust_journal::Transport,
    attempt: u32,
    budget: rtrust_journal::Budget,
) -> rtrust_journal::Attempt {
    #[cfg(not(test))]
    {
        rtrust_journal::Attempt::new(path, transport, attempt, budget)
    }
    #[cfg(test)]
    {
        rtrust_journal::Attempt::with_recorder(path, transport, attempt, budget, journal_failure)
    }
}
// Inspect only the single envelope accepted by freshness::start. Lease validation
// remains there; this guard must also cover its early authentication rejection.
#[cfg(any(target_os = "linux", windows, test))]
pub fn start_journal(command: &rtrust_control::Command) -> Option<rtrust_journal::Attempt> {
    use rtrust_control::Command;
    let command = match command {
        Command::StartLeased { command, .. } => command.as_ref(),
        command => command,
    };
    match command {
        Command::Start { profile, .. } | Command::StartFull { profile, .. } => {
            Some(journal_attempt(
                rtrust_journal::Path::Start,
                rtrust_engine::planned_transport(profile),
                1,
                rtrust_journal::Budget::Burst,
            ))
        }
        _ => None,
    }
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
// Metadata only: resume while a healthy tunnel survives cannot label an
// unrelated future outage. Callers snapshot path when an attempt is scheduled;
// a resume never relabels an already-running pre-wake worker.
#[cfg(any(target_os = "linux", windows, test))]
#[derive(Default)]
pub struct RecoveryLabels {
    wake_episode: bool,
}
#[cfg(any(target_os = "linux", windows, test))]
impl RecoveryLabels {
    pub fn resumed(&mut self, recovering: bool) {
        self.wake_episode = recovering;
    }
    pub fn connected(&mut self) {
        self.wake_episode = false;
    }
    pub fn path(&self) -> rtrust_journal::Path {
        if self.wake_episode {
            rtrust_journal::Path::WakeReconnect
        } else {
            rtrust_journal::Path::Reconnect
        }
    }
}
/// GUI text stays separate from the closed journal classification.
#[derive(Debug)]
pub struct Failure {
    pub message: String,
    pub class: rtrust_journal::Class,
    // Linux/macOS workers carry deferred accepted-attempt metadata; Windows
    // records its synchronous attempt at the supervisor instead.
    #[cfg(not(windows))]
    pub record: Option<rtrust_journal::Record>,
}
impl Failure {
    #[cfg(target_os = "macos")]
    pub fn engine(error: rtrust_engine::Error, message: impl Into<String>) -> Self {
        Self {
            class: rtrust_journal::classify(&error),
            message: message.into(),
            #[cfg(not(windows))]
            record: None,
        }
    }
    pub fn timeout(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            class: rtrust_journal::Class::Timeout,
            #[cfg(not(windows))]
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
            #[cfg(not(windows))]
            record: None,
        }
    }
}
impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            class: rtrust_journal::Class::Other,
            #[cfg(not(windows))]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinError {
    Resolve,
    Timeout,
    TooManyAddresses,
    NoAddresses,
    TooManyProfiles,
}
impl PinError {
    pub fn class(self) -> rtrust_journal::Class {
        match self {
            Self::Timeout => rtrust_journal::Class::Timeout,
            Self::Resolve | Self::NoAddresses => rtrust_journal::Class::EndpointUnreachable,
            Self::TooManyAddresses | Self::TooManyProfiles => rtrust_journal::Class::Profile,
        }
    }
}
impl std::fmt::Display for PinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Resolve => "Cannot resolve endpoint",
            Self::Timeout => "Endpoint resolution timed out",
            Self::TooManyAddresses => "Too many endpoint addresses",
            Self::NoAddresses => "Endpoint has no addresses",
            Self::TooManyProfiles => "Too many backup profiles",
        })
    }
}
impl std::error::Error for PinError {}
impl From<PinError> for String {
    fn from(error: PinError) -> Self {
        error.to_string()
    }
}
/// Freeze DNS answers for this lease so reconnect cannot route into itself.
pub async fn pin_endpoint(mut profile: Profile, mode: Pin) -> Result<Profile, PinError> {
    if mode == Pin::Unresolved {
        return Ok(profile);
    }
    let mut addresses = Vec::new();
    for address in &profile.endpoint.addresses {
        for address in tokio::net::lookup_host(address)
            .await
            .map_err(|_| PinError::Resolve)?
        {
            if mode == Pin::Ipv4 && !address.is_ipv4() {
                continue;
            }
            if addresses.len() >= 64 {
                return Err(PinError::TooManyAddresses);
            }
            let address = address.to_string();
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    if addresses.is_empty() {
        return Err(PinError::NoAddresses);
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
    pub async fn pin(
        primary: Profile,
        fallbacks: Vec<Profile>,
        mode: Pin,
    ) -> Result<Self, PinError> {
        if fallbacks.len() > rtrust_control::MAX_FALLBACKS {
            return Err(PinError::TooManyProfiles);
        }
        let mut results =
            futures_util::future::join_all(std::iter::once(primary).chain(fallbacks).map(
                |profile| async move {
                    tokio::time::timeout(PIN_LIMIT, pin_endpoint(profile, mode))
                        .await
                        .unwrap_or_else(|_| Err(PinError::Timeout))
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
            return Err(PinError::TooManyAddresses);
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
pub(crate) mod tests {
    use super::*;

    fn start_command(full: bool) -> rtrust_control::Command {
        let profile = Box::new(profile("synthetic.example", "192.0.2.1:443"));
        if full {
            rtrust_control::Command::StartFull {
                profile,
                dns: "198.18.0.53".parse().unwrap(),
                fallbacks: vec![],
            }
        } else {
            rtrust_control::Command::Start {
                profile,
                networks: vec!["198.18.0.0/24".parse().unwrap()],
                exclude: vec![],
                exclude_lan: false,
                dns: None,
                fallbacks: vec![],
            }
        }
    }
    fn leased(command: rtrust_control::Command, expired: bool) -> rtrust_control::Command {
        let now = rtrust_control::freshness::now();
        rtrust_control::Command::StartLeased {
            lease: if expired {
                rtrust_control::freshness::Lease {
                    issued_at_ms: 1,
                    expires_at_ms: 2,
                }
            } else {
                rtrust_control::freshness::Lease {
                    issued_at_ms: now.saturating_sub(1000),
                    expires_at_ms: now + 60_000,
                }
            },
            command: Box::new(command),
        }
    }
    #[test]
    fn start_guard_covers_plain_and_single_leased_start_shapes_only() {
        use rtrust_journal::{Budget, Class, Path, Transport};
        take_records();
        for full in [false, true] {
            for wrapped in [false, true] {
                let command = start_command(full);
                let command = if wrapped {
                    leased(command, false)
                } else {
                    command
                };
                let guard = start_journal(&command).unwrap();
                assert!(rtrust_control::freshness::start(command).is_ok());
                drop(guard);
                let records = take_records();
                assert_eq!(records.len(), 1);
                assert_eq!(
                    (
                        records[0].path,
                        records[0].transport,
                        records[0].attempt,
                        records[0].budget,
                        records[0].class
                    ),
                    (Path::Start, Transport::H2, 1, Budget::Burst, Class::Other)
                );
            }
        }
        assert!(start_journal(&rtrust_control::Command::Capabilities).is_none());
        let invalid = leased(leased(start_command(false), false), false);
        assert!(start_journal(&invalid).is_none());
        assert!(rtrust_control::freshness::start(invalid).is_err());
        assert!(take_records().is_empty());
    }

    // Type-checked on macOS too, but only native Linux/Windows module tests can
    // invoke the actual platform serve handlers. No replacement handler is used.
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub async fn assert_start_serve_failures<F, Fut>(mut serve: F)
    where
        F: FnMut(tokio::io::DuplexStream) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        use rtrust_control::{Command, Request, Response, State, VERSION};
        use rtrust_journal::{Budget, Class, Path, Transport};
        for full in [false, true] {
            // Plain and valid leased starts fail pure validation; expired leases
            // must take precedence over the same deliberately invalid inner input.
            for mode in 0..3 {
                take_records();
                let mut command = start_command(full);
                match &mut command {
                    Command::Start { networks, .. } => networks.clear(),
                    Command::StartFull { dns, .. } => *dns = std::net::Ipv4Addr::UNSPECIFIED,
                    _ => unreachable!(),
                }
                let expired = mode == 2;
                if mode != 0 {
                    command = leased(command, expired);
                }
                let expected_message = if expired {
                    "Access confirmation expired; synchronize the portal".to_owned()
                } else if full {
                    rtrust_control::validate_dns(std::net::Ipv4Addr::UNSPECIFIED).unwrap_err()
                } else {
                    rtrust_control::Selection {
                        include: vec![],
                        exclude: vec![],
                        exclude_lan: false,
                    }
                    .validate()
                    .unwrap_err()
                };
                let (mut client, server) = tokio::io::duplex(1 << 16);
                let service = tokio::spawn(serve(server));
                let response = tokio::time::timeout(Duration::from_secs(2), async {
                    rtrust_control::write(
                        &mut client,
                        &Request {
                            version: VERSION,
                            command,
                        },
                    )
                    .await
                    .unwrap();
                    rtrust_control::read::<Response>(&mut client).await.unwrap()
                })
                .await
                .expect("Start must return a bounded error response");
                tokio::time::timeout(Duration::from_secs(2), service)
                    .await
                    .expect("serve must finish")
                    .expect("serve must not panic")
                    .expect("error response must complete normally");
                assert_eq!(response.version, VERSION);
                assert_eq!(response.state, State::Error);
                assert_eq!(response.message, expected_message);
                let records = take_records();
                assert_eq!(records.len(), 1, "each failed Start must emit exactly once");
                assert_eq!(
                    (
                        records[0].path,
                        records[0].transport,
                        records[0].attempt,
                        records[0].budget
                    ),
                    (Path::Start, Transport::H2, 1, Budget::Burst)
                );
                assert_eq!(
                    records[0].class,
                    if expired {
                        Class::Authentication
                    } else {
                        Class::Profile
                    }
                );
                assert!(take_records().is_empty());
            }
        }
    }

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
    fn recovery_labels_snapshot_pre_wake_workers_and_do_not_linger_after_healthy_resume() {
        use rtrust_journal::Path::*;
        let mut labels = RecoveryLabels::default();
        labels.resumed(false);
        assert_eq!(
            labels.path(),
            Reconnect,
            "healthy tunnel survived wake; later outage is unrelated"
        );
        let pre_wake_attempt = labels.path();
        labels.resumed(true);
        assert_eq!(pre_wake_attempt, Reconnect);
        assert_eq!(labels.path(), WakeReconnect);
        labels.connected();
        assert_eq!(labels.path(), Reconnect);
    }
    #[test]
    fn real_start_raii_guard_uses_injected_typed_sink_without_service_files() {
        use rtrust_journal::{Budget, Class, Path, Transport};
        take_records();
        for class in [
            Class::Cancelled,
            PinError::Timeout.class(),
            PinError::TooManyAddresses.class(),
            PinError::Resolve.class(),
        ] {
            let mut guard = journal_attempt(Path::Start, Transport::H2, 1, Budget::Burst);
            guard.class(class);
            drop(guard);
            let records = take_records();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].class, class);
        }
        let mut guard = journal_attempt(Path::Start, Transport::H2, 1, Budget::Burst);
        guard.success();
        drop(guard);
        assert!(take_records().is_empty());
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
        take_records();
        let mut guard = journal_attempt(
            rtrust_journal::Path::Start,
            rtrust_journal::Transport::H2,
            1,
            rtrust_journal::Budget::Burst,
        );
        failure.annotate(&mut guard, rtrust_journal::classify);
        drop(guard);
        let records = take_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].class, rtrust_journal::Class::Authentication);
        assert_eq!(records[0].transport, rtrust_journal::Transport::H3);
        assert_eq!(records[0].attempt, 4);
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
