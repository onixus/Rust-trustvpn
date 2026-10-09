//! Evidence, not a synonym for the service's Connected lifecycle state.
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA: u32 = 1;
pub const MAX_EVENTS: usize = 64;
pub const FRESH_MS: u64 = 6_000;
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Passed,
    Failed,
    Configured,
    Unknown,
    Stale,
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    ServiceLifecycle,
    MobileLifecycle,
    ProxyLifecycle,
    SystemProbe,
    NotObserved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Full,
    Split,
    Proxy,
    Mobile,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NotChecked,
    SessionRunning,
    WorkerStopped,
    ConfigurationApplied,
    CheckUnavailable,
    ObservationExpired,
    LifecycleGap,
    SessionChanged,
    ControlLost,
    SessionStopped,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub outcome: Outcome,
    pub source: Source,
    pub observed_at_ms: Option<u64>,
    pub valid_for_ms: u64,
    pub mode: Mode,
    pub reason: Reason,
}
impl Observation {
    pub fn unknown(mode: Mode) -> Self {
        Self {
            outcome: Outcome::Unknown,
            source: Source::NotObserved,
            observed_at_ms: None,
            valid_for_ms: FRESH_MS,
            mode,
            reason: Reason::NotChecked,
        }
    }
    pub fn expire(&mut self, now: u64) {
        if matches!(self.outcome, Outcome::Passed | Outcome::Configured)
            && self
                .observed_at_ms
                .is_none_or(|time| now < time || now.saturating_sub(time) > self.valid_for_ms)
        {
            self.outcome = Outcome::Stale;
            self.reason = Reason::ObservationExpired;
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Started,
    Reconnecting,
    Recovered,
    LifecycleGap,
    ControlLost,
    Stopped,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub at_ms: u64,
    pub generation: u64,
    pub kind: EventKind,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u32,
    pub generation: u64,
    pub transport: Observation,
    pub route: Observation,
    pub dns: Observation,
    pub guard: Observation,
    pub connectivity: Observation,
    pub events: Vec<Event>,
}
impl Snapshot {
    pub fn unknown(mode: Mode) -> Self {
        Self {
            schema: SCHEMA,
            generation: 0,
            transport: Observation::unknown(mode),
            route: Observation::unknown(mode),
            dns: Observation::unknown(mode),
            guard: Observation::unknown(mode),
            connectivity: Observation::unknown(mode),
            events: vec![],
        }
    }
    fn observations(&mut self) -> [&mut Observation; 5] {
        [
            &mut self.transport,
            &mut self.route,
            &mut self.dns,
            &mut self.guard,
            &mut self.connectivity,
        ]
    }
    pub fn expire(&mut self, now: u64) {
        for observation in self.observations() {
            observation.expire(now);
        }
    }
    pub fn invalidate(&mut self, reason: Reason, kind: EventKind, now: u64) {
        self.generation = self.generation.saturating_add(1);
        for observation in self.observations() {
            if matches!(observation.outcome, Outcome::Passed | Outcome::Configured) {
                observation.outcome = Outcome::Stale;
                observation.reason = reason;
            }
        }
        self.event(kind, now);
    }
    fn event(&mut self, kind: EventKind, now: u64) {
        if self.events.len() >= MAX_EVENTS {
            self.events.remove(0);
        }
        self.events.push(Event {
            at_ms: now,
            generation: self.generation,
            kind,
        });
    }
    /// Reject results from a task started before Stop, reconnect or a network change.
    pub fn apply_connectivity(&mut self, generation: u64, observation: Observation) -> bool {
        if generation != self.generation || observation.mode != self.transport.mode {
            return false;
        }
        self.connectivity = observation;
        true
    }
    pub fn verified(&self) -> bool {
        [
            &self.transport,
            &self.route,
            &self.dns,
            &self.guard,
            &self.connectivity,
        ]
        .iter()
        .all(|o| {
            o.outcome == Outcome::Passed
                && o.observed_at_ms.is_some_and(|time| {
                    let now = now_ms();
                    now >= time && now - time <= o.valid_for_ms
                })
        })
    }
}
/// Own one instance per lease/worker. Polling never upgrades configuration to proof.
pub struct Monitor {
    snapshot: Snapshot,
    last_poll: u64,
    running: bool,
    gap: bool,
    stopped: bool,
}
impl Monitor {
    pub fn new(mode: Mode, source: Source, now: u64) -> Self {
        let mut snapshot = Snapshot::unknown(mode);
        snapshot.generation = 1;
        snapshot.transport = Observation {
            outcome: Outcome::Configured,
            source,
            observed_at_ms: Some(now),
            valid_for_ms: FRESH_MS,
            mode,
            reason: Reason::SessionRunning,
        };
        // Installed routes and DNS are not audited here. Never infer guard from Blocked.
        if mode == Mode::Proxy {
            for o in [&mut snapshot.route, &mut snapshot.dns, &mut snapshot.guard] {
                o.outcome = Outcome::Unsupported;
                o.reason = Reason::CheckUnavailable;
            }
        }
        snapshot.event(EventKind::Started, now);
        Self {
            snapshot,
            last_poll: now,
            running: true,
            gap: false,
            stopped: false,
        }
    }
    /// An idle adapter has no transport start/failure evidence to report.
    pub fn idle(mode: Mode, source: Source, now: u64) -> Self {
        let mut monitor = Self::new(mode, source, now);
        monitor.snapshot = Snapshot::unknown(mode);
        monitor.snapshot.transport.source = source;
        monitor.running = false;
        monitor.stopped = true;
        monitor
    }
    pub fn transition(&mut self, running: bool, now: u64) {
        if running != self.running {
            let kind = if self.stopped && running {
                EventKind::Started
            } else if running {
                EventKind::Recovered
            } else {
                EventKind::Reconnecting
            };
            self.stopped = false;
            self.snapshot.invalidate(Reason::SessionChanged, kind, now);
            self.running = running;
            self.last_poll = now;
            self.gap = false;
        }
    }
    pub fn stop(&mut self, now: u64) {
        if self.stopped {
            return;
        }
        self.snapshot
            .invalidate(Reason::SessionStopped, EventKind::Stopped, now);
        self.stopped = true;
        self.running = false;
        for observation in self.snapshot.observations() {
            observation.outcome = Outcome::Unknown;
            observation.reason = Reason::SessionStopped;
            observation.observed_at_ms = None;
        }
    }
    pub fn sample(&mut self, now: u64) -> Snapshot {
        if self.stopped {
            return self.snapshot.clone();
        }
        if now < self.last_poll || now.saturating_sub(self.last_poll) > FRESH_MS {
            self.snapshot
                .invalidate(Reason::LifecycleGap, EventKind::LifecycleGap, now);
            self.gap = true;
        }
        self.last_poll = now;
        let transport = &mut self.snapshot.transport;
        if !self.running {
            transport.outcome = Outcome::Failed;
            transport.reason = Reason::WorkerStopped;
            transport.observed_at_ms = Some(now);
        } else if !self.gap {
            transport.outcome = Outcome::Configured;
            transport.reason = Reason::SessionRunning;
            transport.observed_at_ms = Some(now);
        }
        self.snapshot.expire(now);
        self.snapshot.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_new_connection_after_long_idle_is_fresh_without_fabricated_gap() {
        let mut monitor = Monitor::idle(Mode::Mobile, Source::MobileLifecycle, 100);
        assert!(monitor.sample(200).events.is_empty());
        monitor.transition(true, 10_000);
        let started = monitor.sample(10_001);
        assert_eq!(started.transport.outcome, Outcome::Configured);
        assert_eq!(started.events.len(), 1);
        assert_eq!(started.events[0].kind, EventKind::Started);
    }
    #[test]
    fn stop_and_expiration_cannot_leave_a_verified_session() {
        let now = now_ms();
        let mut m = Monitor::new(Mode::Full, Source::ServiceLifecycle, now);
        m.stop(now + 1);
        let stopped = m.sample(now + 2);
        assert!(!stopped.verified());
        assert_eq!(stopped.events.last().unwrap().kind, EventKind::Stopped);
        let mut stale = Snapshot::unknown(Mode::Full);
        for observation in stale.observations() {
            observation.outcome = Outcome::Passed;
            observation.observed_at_ms = Some(now.saturating_sub(FRESH_MS + 1));
        }
        assert!(!stale.verified());
    }
    #[test]
    fn running_transport_does_not_prove_dns_route_guard_or_internet() {
        let mut monitor = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        let state = monitor.sample(101);
        assert_eq!(state.transport.outcome, Outcome::Configured);
        assert_eq!(state.dns.outcome, Outcome::Unknown);
        assert!(!state.verified());
    }
    #[test]
    fn sleep_gap_and_old_probe_cannot_restore_green() {
        let mut monitor = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        let old = monitor.sample(101);
        let mut current = monitor.sample(10_000);
        assert_eq!(current.transport.outcome, Outcome::Stale);
        let mut observation = old.connectivity;
        observation.outcome = Outcome::Passed;
        assert!(!current.apply_connectivity(old.generation, observation));
        assert_eq!(monitor.sample(10_001).transport.outcome, Outcome::Stale);
        monitor.transition(false, 10_002);
        monitor.transition(true, 10_003);
        assert_eq!(
            monitor.sample(10_004).transport.outcome,
            Outcome::Configured
        );
    }
    #[test]
    fn expiration_clock_reversal_and_proxy_unsupported_are_not_passes() {
        let mut m = Monitor::new(Mode::Proxy, Source::ProxyLifecycle, 100);
        let mut s = m.sample(101);
        assert_eq!(s.guard.outcome, Outcome::Unsupported);
        s.expire(99);
        assert_eq!(s.transport.outcome, Outcome::Stale);
        assert!(!s.verified());
    }
    #[test]
    fn journal_is_bounded_and_has_no_free_text_or_destination_fields() {
        let mut s = Snapshot::unknown(Mode::Mobile);
        for i in 0..100 {
            s.invalidate(Reason::SessionChanged, EventKind::Reconnecting, i);
        }
        assert_eq!(s.events.len(), MAX_EVENTS);
        assert_eq!(s.events[0].at_ms, 36);
        let encoded = serde_json::to_string(&s).unwrap();
        assert!(
            !encoded.contains("password")
                && !encoded.contains("hostname")
                && !encoded.contains("message")
        );
        let mut value = serde_json::to_value(s).unwrap();
        value["events"][0]["url"] = "https://example.test/?secret=canary".into();
        assert!(serde_json::from_value::<Snapshot>(value).is_err());
    }
}
