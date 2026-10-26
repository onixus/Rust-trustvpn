//! SOCKS reconnect after a degraded tunnel (#99). The proxy has no service
//! supervisor, so the app owns the same bounded policy the system VPN uses:
//! `rtrust_control::recovery::Budget`, one per user-started connection.
//! Fail-closed: the listener stays down between attempts, so applications get
//! a refused connection, never a direct one. Only the profile the user started
//! is retried; there is no fallback profile and no mode change.
use rtrust_control::recovery::Budget;
use rtrust_profile::Profile;
use std::time::{Duration, Instant};

pub struct Recovery {
    profile: Profile,
    port: u16,
    budget: Budget,
    /// When the current proxy was admitted; `None` before that or while an
    /// automatic attempt is pending.
    since: Option<Instant>,
    /// An automatic attempt is waiting or running. The user's own first
    /// attempt is not one: its failure is shown, not retried.
    retrying: bool,
}
/// The next attempt: its delay and whether the burst budget is spent and the
/// delay is the cooldown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retry {
    pub delay: Duration,
    pub cooling: bool,
}
impl Recovery {
    pub fn new(profile: Profile, port: u16) -> Self {
        Self {
            profile,
            port,
            budget: Budget::default(),
            since: None,
            retrying: false,
        }
    }
    pub fn target(&self) -> (Profile, u16) {
        (self.profile.clone(), self.port)
    }
    pub fn retrying(&self) -> bool {
        self.retrying
    }
    pub fn connected(&mut self, now: Instant) {
        self.since = Some(now);
        self.retrying = false;
    }
    /// The admitted proxy carried no traffic. An unproven session (it never
    /// delivered data) does not restore the budget however long it lasted.
    pub fn degraded(&mut self, proven: bool, now: Instant, entropy: u64) -> Retry {
        let connected_for = self
            .since
            .take()
            .map_or(Duration::ZERO, |since| now.saturating_duration_since(since));
        self.budget.disconnected(connected_for, !proven);
        self.next(entropy)
    }
    /// A reconnect attempt failed or timed out before admitting a proxy.
    pub fn attempt_failed(&mut self, entropy: u64) -> Retry {
        self.since = None;
        self.next(entropy)
    }
    fn next(&mut self, entropy: u64) -> Retry {
        self.retrying = true;
        let delay = self.budget.next_delay(entropy);
        Retry {
            delay,
            cooling: self.budget.cooling(),
        }
    }
}
/// Why an automatic attempt failed. `permanent`: retrying the same profile
/// and port cannot help (the port is taken, the profile or its trust store is
/// unusable, the endpoint refused the credentials), so recovery ends.
/// TLS validation stays transient: after wake a captive portal may intercept
/// until the user signs in, and a failed handshake never sends anything direct.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    pub message: String,
    pub permanent: bool,
}
impl From<rtrust_engine::Error> for Failure {
    fn from(error: rtrust_engine::Error) -> Self {
        use rtrust_engine::Error;
        Self {
            permanent: matches!(
                error,
                Error::LocalBind
                    | Error::Profile
                    | Error::Unsupported(_)
                    | Error::Trust
                    | Error::Authentication
            ),
            message: error.to_string(),
        }
    }
}
/// One automatic attempt: the same profile and port, no backups, no lease.
/// A SOCKS start with a freshness lease is refused at the user's own start,
/// and settings stay frozen while connecting, so none applies here.
pub async fn attempt(profile: Profile, port: u16) -> Result<crate::Session, Failure> {
    match tokio::time::timeout(
        rtrust_control::recovery::ATTEMPT_TIMEOUT,
        rtrust_engine::proxy::Proxy::start(&profile, port),
    )
    .await
    {
        Ok(started) => started.map(crate::Session::Socks).map_err(Failure::from),
        Err(_) => Err(Failure::from(rtrust_engine::Error::Timeout)),
    }
}
/// Jitter only; the budget bounds it for any value.
pub fn entropy() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
    );
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_control::recovery::{BURST_ATTEMPTS, COOLDOWN, STABLE_CONNECTION};
    fn recovery() -> Recovery {
        let profile = Profile::import(
            "hostname='first.example'\naddresses=['192.0.2.1:443']\nusername='demo'\npassword='synthetic'\n",
        )
        .unwrap();
        Recovery::new(profile, 1080)
    }
    #[test]
    fn unproven_degraded_sessions_reach_the_cooldown_however_long_they_ran() {
        let mut r = recovery();
        let mut now = Instant::now();
        for seconds in [2, 4, 8, 16, 30, 30, 30, 30] {
            r.connected(now);
            now += Duration::from_secs(3600);
            let retry = r.degraded(false, now, 0);
            assert_eq!(retry.delay, Duration::from_secs(seconds));
            assert!(!retry.cooling && r.retrying());
        }
        r.connected(now);
        now += Duration::from_secs(3600);
        assert_eq!(
            r.degraded(false, now, 0),
            Retry {
                delay: COOLDOWN,
                cooling: true
            }
        );
    }
    #[test]
    fn proven_traffic_after_a_stable_session_restores_the_budget() {
        let mut r = recovery();
        let mut now = Instant::now();
        for _ in 0..BURST_ATTEMPTS - 1 {
            r.attempt_failed(0);
        }
        r.connected(now);
        now += STABLE_CONNECTION;
        assert_eq!(r.degraded(true, now, 0).delay, Duration::from_secs(2));
    }
    #[test]
    fn a_short_proven_session_does_not_restore_the_budget() {
        let mut r = recovery();
        let mut now = Instant::now();
        assert_eq!(r.attempt_failed(0).delay, Duration::from_secs(2));
        r.connected(now);
        now += STABLE_CONNECTION - Duration::from_secs(1);
        assert_eq!(r.degraded(true, now, 0).delay, Duration::from_secs(4));
    }
    #[test]
    fn only_errors_a_retry_cannot_fix_end_recovery() {
        use rtrust_engine::Error;
        for error in [
            Error::LocalBind,
            Error::Profile,
            Error::Unsupported("x"),
            Error::Trust,
            Error::Authentication,
        ] {
            assert!(Failure::from(error).permanent);
        }
        for error in [
            Error::Connect,
            Error::ConnectIo(std::io::ErrorKind::ConnectionRefused),
            Error::Tls,
            Error::Protocol,
            Error::Timeout,
            Error::Io,
            Error::Closed(rtrust_engine::Close::PeerClosed),
            Error::Closed(rtrust_engine::Close::GoAway {
                code: 0,
                remote: true,
            }),
        ] {
            assert!(!Failure::from(error).permanent);
        }
    }
    #[test]
    fn failed_attempts_cool_down_and_jitter_stays_bounded() {
        let mut r = recovery();
        for _ in 0..BURST_ATTEMPTS {
            let retry = r.attempt_failed(u64::MAX);
            assert!(!retry.cooling);
            assert!(retry.delay <= Duration::from_millis(37_500));
        }
        let retry = r.attempt_failed(u64::MAX);
        assert!(retry.cooling);
        assert!((COOLDOWN..=COOLDOWN + Duration::from_secs(30)).contains(&retry.delay));
        assert!(r.retrying());
        r.connected(Instant::now());
        assert!(!r.retrying());
        let _ = entropy();
    }
}
