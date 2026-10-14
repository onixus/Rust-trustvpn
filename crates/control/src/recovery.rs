//! Bounded, ordered recovery scheduling. No network or firewall side effects.
use serde::{Deserialize, Serialize};
pub const MAX_BACKUPS: usize = 3;
pub const MAX_ATTEMPTS: u32 = 12;
pub const ATTEMPT_TIMEOUT_SECS: u64 = 45;
pub const COOLDOWN_SECS: u64 = 60;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub enabled: bool,
    pub selected_index: usize,
    pub attempts: u32,
    pub exhausted: bool,
}
/// One budget per service start/configuration, including successful connections.
/// Stable success never replenishes it: repeated flaps cannot consume unlimited energy.
pub struct Planner {
    profiles: usize,
    status: Status,
}
impl Planner {
    pub fn new(backups: usize) -> Result<Self, String> {
        if !(1..=MAX_BACKUPS).contains(&backups) {
            return Err("Select 1 to 3 permitted backup profiles".into());
        }
        Ok(Self {
            profiles: backups + 1,
            status: Status {
                enabled: true,
                selected_index: 0,
                attempts: 0,
                exhausted: false,
            },
        })
    }
    pub fn status(&self) -> Status {
        self.status.clone()
    }
    pub fn begin(&mut self) -> Option<usize> {
        if self.status.attempts >= MAX_ATTEMPTS {
            self.status.exhausted = true;
            return None;
        }
        self.status.attempts += 1;
        Some(self.status.selected_index)
    }
    /// Never jump back to primary merely because it briefly became reachable.
    /// Caller supplies random jitter; it is bounded even for an arbitrary input.
    pub fn failed(&mut self, jitter: u64, connected_seconds: u64) -> u64 {
        self.status.selected_index = (self.status.selected_index + 1) % self.profiles;
        let backoff = (3u64 << self.status.attempts.saturating_sub(1).min(4)).min(48);
        let hysteresis = if connected_seconds > 0 {
            COOLDOWN_SECS.saturating_sub(connected_seconds)
        } else {
            0
        };
        backoff.max(hysteresis) + jitter % 4
    }
}
/// Translate per-worker generations into one supervisor-owned epoch namespace.
/// A new lease starts with stale prior evidence, never with a reused generation 1.
pub struct Observations {
    snapshot: crate::observations::Snapshot,
    attempt: u64,
    worker_generation: Option<u64>,
    worker_epochs: std::collections::BTreeMap<u64, u64>,
    epochs: std::sync::Arc<std::sync::atomic::AtomicU64>,
}
impl Observations {
    pub fn new(
        snapshot: crate::observations::Snapshot,
        epochs: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            snapshot,
            attempt: 0,
            worker_generation: None,
            worker_epochs: std::collections::BTreeMap::new(),
            epochs,
        }
    }
    fn next_epoch(&self) -> u64 {
        self.epochs
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1
    }
    pub fn begin(&mut self, now: u64) -> u64 {
        use crate::observations::{EventKind, Reason};
        self.attempt = self.next_epoch();
        self.worker_generation = None;
        self.worker_epochs.clear();
        self.snapshot
            .invalidate(Reason::SessionChanged, EventKind::Reconnecting, now);
        self.snapshot.generation = self.attempt;
        if let Some(event) = self.snapshot.events.last_mut() {
            event.generation = self.attempt;
        }
        self.attempt
    }
    pub fn snapshot(&self) -> crate::observations::Snapshot {
        self.snapshot.clone()
    }
    pub fn accept(&mut self, attempt: u64, mut incoming: crate::observations::Snapshot) -> bool {
        if attempt != self.attempt
            || self
                .worker_generation
                .is_some_and(|last| incoming.generation < last)
        {
            return false;
        }
        // A schema-2 network/resume event can be followed by a transport
        // transition before the next poll. Keep every unseen worker epoch,
        // not merely the final generation, so the causal event is not lost.
        let previous = self.worker_generation;
        let mut generations: std::collections::BTreeSet<_> = incoming
            .events
            .iter()
            .filter(|event| event.generation <= incoming.generation)
            .map(|event| event.generation)
            .collect();
        generations.insert(incoming.generation);
        for generation in generations {
            if !self.worker_epochs.contains_key(&generation)
                && previous.is_none_or(|last| generation > last)
            {
                self.worker_epochs.insert(generation, self.next_epoch());
            }
        }
        self.worker_generation = Some(incoming.generation);
        incoming.generation = *self
            .worker_epochs
            .get(&incoming.generation)
            .expect("current worker epoch retained");
        let mut events = self.snapshot.events.clone();
        for mut event in incoming.events {
            let Some(epoch) = self.worker_epochs.get(&event.generation) else {
                continue;
            };
            event.generation = *epoch;
            if !events.contains(&event) {
                events.push(event);
            }
        }
        while self.worker_epochs.len() > crate::observations::MAX_EVENTS {
            self.worker_epochs.pop_first();
        }
        let excess = events.len().saturating_sub(crate::observations::MAX_EVENTS);
        events.drain(..excess);
        incoming.events = events;
        self.snapshot = incoming;
        true
    }
}
#[cfg(test)]
mod observation_tests {
    use super::*;
    use crate::observations::{Mode, Monitor, Observation, Outcome, Reason, Source};
    #[test]
    fn schema_two_network_resume_and_failover_events_survive_coalesced_polling() {
        use crate::observations::EventKind;
        let epochs = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut owner =
            Observations::new(crate::observations::Snapshot::unknown(Mode::Full), epochs);
        let attempt = owner.begin(100);
        let mut worker = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        worker.network_changed(101);
        worker.resumed(102);
        worker.transition(false, 103);
        worker.failed_over(104);
        assert!(owner.accept(attempt, worker.sample(104)));
        let snapshot = owner.snapshot();
        for kind in [
            EventKind::NetworkChanged,
            EventKind::Resumed,
            EventKind::FailedOver,
        ] {
            assert!(snapshot.events.iter().any(|event| event.kind == kind));
        }
        assert!(
            snapshot
                .events
                .windows(2)
                .all(|pair| pair[0].generation <= pair[1].generation)
        );
        let before = snapshot.events.len();
        assert!(owner.accept(attempt, worker.sample(105)));
        assert_eq!(owner.snapshot().events.len(), before);
    }
    #[test]
    fn primary_and_backup_worker_generation_one_have_distinct_epochs_and_reject_old_results() {
        let epochs = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let mut owner =
            Observations::new(crate::observations::Snapshot::unknown(Mode::Full), epochs);
        let mut primary = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        primary.transition(true, 100);
        let primary_attempt = owner.begin(100);
        assert!(owner.accept(primary_attempt, primary.sample(100)));
        let primary_epoch = owner.snapshot().generation;
        owner.begin(200);
        assert_eq!(owner.snapshot().transport.outcome, Outcome::Stale);
        let mut backup = Monitor::new(Mode::Full, Source::ServiceLifecycle, 200);
        backup.transition(true, 200);
        assert!(owner.accept(owner.attempt, backup.sample(200)));
        let mut current = owner.snapshot();
        assert_ne!(primary_epoch, current.generation);
        let result = Observation {
            outcome: Outcome::Passed,
            source: Source::SystemProbe,
            observed_at_ms: Some(200),
            valid_for_ms: 6000,
            mode: Mode::Full,
            reason: Reason::SessionRunning,
        };
        assert!(!current.apply_connectivity(primary_epoch, result));
        assert!(!owner.accept(primary_attempt, primary.sample(201)));
        assert!(owner.snapshot().events.len() <= crate::observations::MAX_EVENTS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opt_in_and_budget_are_bounded_even_after_successes() {
        assert!(Planner::new(0).is_err());
        assert!(Planner::new(4).is_err());
        let mut p = Planner::new(2).unwrap();
        for i in 0..MAX_ATTEMPTS {
            assert_eq!(p.begin(), Some(i as usize % 3));
            let delay = p.failed(u64::MAX, 0);
            assert!((3..=51).contains(&delay));
        }
        assert_eq!(p.begin(), None);
        assert!(p.status().exhausted);
    }
    #[test]
    fn a_flapping_success_keeps_the_cooldown_and_order() {
        let mut p = Planner::new(1).unwrap();
        assert_eq!(p.begin(), Some(0));
        assert_eq!(p.failed(0, 1), 59);
        assert_eq!(p.begin(), Some(1));
        assert_eq!(p.failed(0, 90), 6);
        assert_eq!(p.begin(), Some(0));
    }
}

use std::time::Duration;

pub const BURST_ATTEMPTS: u8 = 8;
pub const COOLDOWN: Duration = Duration::from_secs(300);
pub const STABLE_CONNECTION: Duration = Duration::from_secs(30);
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Budget {
    attempts: u8,
    exponent: u8,
    cooling: bool,
}
impl Budget {
    /// Reset only after sustained liveness; a briefly successful endpoint must
    /// not permit an unbounded rapid retry loop. This is not an egress probe.
    /// An `unproven` session ended degraded without ever delivering data:
    /// no liveness evidence, however long it lasted.
    pub fn disconnected(&mut self, connected_for: Duration, unproven: bool) {
        if connected_for >= STABLE_CONNECTION && !unproven {
            *self = Self::default();
        }
    }
    /// Caller supplies randomness, keeping the clock and entropy out of this
    /// deterministic policy. Positive jitter can never shorten the budget.
    pub fn next_delay(&mut self, entropy: u64) -> Duration {
        if self.attempts == BURST_ATTEMPTS {
            self.attempts = 0;
            self.cooling = true;
            // The attempt after the cooldown is still counted in the new burst.
            self.attempts += 1;
            return COOLDOWN + Duration::from_millis(entropy % 30_001);
        }
        self.cooling = false;
        self.attempts += 1;
        let millis = (2_000u64 << self.exponent).min(30_000);
        self.exponent = (self.exponent + 1).min(4);
        Duration::from_millis(millis + entropy % (millis / 4 + 1))
    }
    pub fn cooling(&self) -> bool {
        self.cooling
    }
}

#[cfg(test)]
mod budget_tests {
    use super::*;
    #[test]
    fn outage_and_flapping_cannot_exceed_burst_budget() {
        let mut budget = Budget::default();
        for seconds in [2, 4, 8, 16, 30, 30, 30, 30] {
            assert_eq!(budget.next_delay(0), Duration::from_secs(seconds));
            budget.disconnected(Duration::from_secs(29), false);
        }
        assert_eq!(budget.next_delay(0), COOLDOWN);
        assert!(budget.cooling());
        for _ in 1..BURST_ATTEMPTS {
            assert_eq!(budget.next_delay(0), Duration::from_secs(30));
            assert!(!budget.cooling());
        }
        assert_eq!(budget.next_delay(0), COOLDOWN);
    }
    #[test]
    fn stable_session_restores_budget_and_jitter_is_bounded() {
        let mut budget = Budget::default();
        for _ in 0..100 {
            let delay = budget.next_delay(u64::MAX);
            if budget.cooling() {
                assert!((COOLDOWN..=COOLDOWN + Duration::from_secs(30)).contains(&delay));
            } else {
                assert!((Duration::from_secs(2)..=Duration::from_millis(37_500)).contains(&delay));
            }
        }
        budget.disconnected(STABLE_CONNECTION, false);
        assert_eq!(budget.next_delay(0), Duration::from_secs(2));
    }
    #[test]
    fn unproven_degraded_sessions_never_restore_budget() {
        let mut budget = Budget::default();
        for seconds in [2, 4, 8, 16, 30, 30, 30, 30] {
            assert_eq!(budget.next_delay(0), Duration::from_secs(seconds));
            budget.disconnected(Duration::from_secs(3600), true);
        }
        assert_eq!(budget.next_delay(0), COOLDOWN);
        assert!(budget.cooling());
    }
    #[test]
    fn degraded_exit_after_proven_traffic_restores_budget() {
        let mut budget = Budget::default();
        for _ in 0..7 {
            budget.next_delay(0);
        }
        budget.disconnected(STABLE_CONNECTION, false);
        assert_eq!(budget.next_delay(0), Duration::from_secs(2));
        assert!(!budget.cooling());
    }
}
