//! Opt-in recovery through user-allowed backup profiles (issue #34).
//!
//! The guard is installed once for the union of every candidate's endpoint
//! addresses and UDP needs, so moving between candidates never changes the
//! firewall, routes or DNS: there is no window in which protection is
//! relaxed. Only the transport worker changes profile. Without backups this is
//! the fixed-profile behavior: the same profile is retried indefinitely.
use rtrust_profile::Profile;
use std::time::{Duration, Instant};

/// Consecutive failed connection attempts before trying the next candidate.
pub const SWITCH_AFTER: u32 = 2;
/// Minimum time between two switches, against oscillation.
pub const COOLDOWN: Duration = Duration::from_secs(20);
/// A session shorter than this counts as a failed attempt, like the backoff reset.
pub const STABLE: Duration = Duration::from_secs(30);

pub struct Failover {
    candidates: Vec<Profile>,
    active: usize,
    failures: u32,
    last_switch: Option<Instant>,
    /// Backups dropped at start because their endpoint could not be pinned.
    pub skipped: usize,
}

impl Failover {
    /// `pin` resolves a candidate's endpoint the way the platform guard needs.
    /// The requested profile must pin; a backup that cannot is left out.
    pub async fn pin<F, Fut>(
        primary: Profile,
        fallbacks: Vec<Profile>,
        pin: F,
    ) -> Result<Self, String>
    where
        F: FnMut(Profile) -> Fut,
        Fut: std::future::Future<Output = Result<Profile, String>>,
    {
        if fallbacks.len() > rtrust_control::MAX_FALLBACKS {
            return Err("Too many backup profiles".into());
        }
        // Concurrently, so backups do not stretch the Start deadline.
        let mut results =
            futures_util::future::join_all(std::iter::once(primary).chain(fallbacks).map(pin))
                .await
                .into_iter();
        let mut candidates = vec![results.next().expect("primary")?];
        let mut skipped = 0;
        for result in results {
            match result {
                Ok(profile) => candidates.push(profile),
                Err(_) => skipped += 1,
            }
        }
        let failover = Self::new(candidates, skipped);
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
        (self.candidates.len() > 1).then_some(self.active as u8)
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
    /// Guard inputs cover every candidate, so a switch needs no guard change.
    pub fn udp_transport(&self) -> bool {
        self.candidates.iter().any(Profile::udp_transport)
    }
    #[cfg(any(target_os = "macos", target_os = "windows", test))]
    pub fn hop_port_ranges(&self) -> Vec<(u16, u16)> {
        let mut ranges: Vec<_> = self
            .candidates
            .iter()
            .flat_map(Profile::hop_port_ranges)
            .collect();
        ranges.sort_unstable();
        ranges.dedup();
        ranges
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
        assert!(!f.udp_transport());
        assert!(f.hop_port_ranges().is_empty());
    }

    #[test]
    fn an_unpinnable_backup_is_dropped_but_the_requested_profile_is_required() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        runtime.block_on(async {
            let pin = |p: Profile| async move {
                if p.endpoint.hostname == "bad.example" {
                    Err("unresolved".to_string())
                } else {
                    Ok(p)
                }
            };
            let f = Failover::pin(
                profile("good.example", "192.0.2.1:443"),
                vec![
                    profile("bad.example", "192.0.2.2:443"),
                    profile("other.example", "192.0.2.3:443"),
                ],
                pin,
            )
            .await
            .unwrap();
            assert_eq!((f.candidates.len(), f.skipped), (2, 1));
            assert!(f.note().contains("пропущено: 1"));
            assert!(
                Failover::pin(profile("bad.example", "192.0.2.2:443"), vec![], pin)
                    .await
                    .is_err()
            );
            let many =
                vec![profile("x.example", "192.0.2.9:443"); rtrust_control::MAX_FALLBACKS + 1];
            assert!(
                Failover::pin(profile("good.example", "192.0.2.1:443"), many, pin)
                    .await
                    .is_err()
            );
        });
    }
}
