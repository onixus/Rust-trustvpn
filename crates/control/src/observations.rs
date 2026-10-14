//! Evidence, not a synonym for the service's Connected lifecycle state.
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA: u32 = 2;
pub const MAX_EVENTS: usize = 64;
pub const FRESH_MS: u64 = 6_000;
/// The service's own DNS/guard/transport probes: one run per interval, each
/// bounded by the deadline; a result outlives the next overdue run by 5 s.
pub const PROBE_INTERVAL_MS: u64 = 15_000;
pub const PROBE_DEADLINE_MS: u64 = 5_000;
pub const PROBE_TTL_MS: u64 = PROBE_INTERVAL_MS + PROBE_DEADLINE_MS + 5_000;
/// Longest TTL a reader may honour for a source; longer claims are capped.
pub fn ttl_cap(source: Source) -> u64 {
    if source == Source::SystemProbe {
        PROBE_TTL_MS
    } else {
        FRESH_MS
    }
}
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
    /// The desktop GUI's own path check of one user-chosen destination,
    /// folded into its displayed snapshot; never sent by a service.
    AppProbe,
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
    /// The OS reported a link/address change outside the VPN interface.
    NetworkChanged,
    /// The kernel suspend clock advanced: the system slept and resumed.
    SystemResumed,
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
    /// A service probe result: Passed/Failed judge the configuration the
    /// service applied; anything else is an unproven, unavailable check.
    pub fn system(outcome: Outcome, mode: Mode, at: u64) -> Self {
        Self {
            outcome,
            source: Source::SystemProbe,
            observed_at_ms: Some(at),
            valid_for_ms: PROBE_TTL_MS,
            mode,
            reason: if matches!(outcome, Outcome::Passed | Outcome::Failed) {
                Reason::ConfigurationApplied
            } else {
                Reason::CheckUnavailable
            },
        }
    }
    pub fn expire(&mut self, now: u64) {
        // A repeated service probe's failure must not outlive the runs that
        // stopped confirming it; other failures persist until replaced.
        let probe_failure = self.outcome == Outcome::Failed && self.source == Source::SystemProbe;
        if (probe_failure || matches!(self.outcome, Outcome::Passed | Outcome::Configured))
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
    NetworkChanged,
    Resumed,
    /// Opt-in recovery moved to another user-allowed profile.
    FailedOver,
    /// The dataplane drained prior flows and committed a new policy epoch.
    PolicyChanged,
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
            // Probe results of any outcome describe the previous generation.
            if matches!(observation.outcome, Outcome::Passed | Outcome::Configured)
                || (observation.source == Source::SystemProbe
                    && observation.outcome != Outcome::Stale)
            {
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
/// One service probe run, tagged by the caller with the generation it started in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemProbe {
    /// A DNS answer received through the tunnel interface.
    pub transport_proven_at: Option<u64>,
    pub dns: Observation,
    pub guard: Observation,
}
impl SystemProbe {
    /// A timed-out or abandoned run proves nothing.
    pub fn unknown(at: u64) -> Self {
        Self {
            transport_proven_at: None,
            dns: Observation::system(Outcome::Unknown, Mode::Full, at),
            guard: Observation::system(Outcome::Unknown, Mode::Full, at),
        }
    }
}
/// Own one instance per lease/worker. Polling never upgrades configuration to proof.
pub struct Monitor {
    snapshot: Snapshot,
    source: Source,
    last_poll: u64,
    running: bool,
    gap: bool,
    stopped: bool,
    proof: Option<(u64, u64)>,
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
        // Split DNS leaves the tunnel by design and there is no kill switch.
        if mode == Mode::Split {
            for o in [&mut snapshot.dns, &mut snapshot.guard] {
                o.outcome = Outcome::Unsupported;
                o.reason = Reason::CheckUnavailable;
            }
        }
        snapshot.event(EventKind::Started, now);
        Self {
            snapshot,
            source,
            last_poll: now,
            running: true,
            gap: false,
            stopped: false,
            proof: None,
        }
    }
    /// Read-only tag for probe tasks; unlike `sample`, it detects no gap.
    pub fn generation(&self) -> u64 {
        self.snapshot.generation
    }
    /// Accept a whole-computer probe only for the running generation it was
    /// started in. A result started before any invalidation is rejected.
    pub fn apply_system(&mut self, generation: u64, probe: SystemProbe, now: u64) -> bool {
        let mode = self.snapshot.transport.mode;
        let valid = |o: &Observation| {
            o.source == Source::SystemProbe
                && o.mode == mode
                && o.observed_at_ms.is_some_and(|time| time <= now)
        };
        if self.stopped
            || !self.running
            || mode != Mode::Full
            || generation != self.snapshot.generation
            || !valid(&probe.dns)
            || !valid(&probe.guard)
            || probe.transport_proven_at.is_some_and(|time| time > now)
        {
            return false;
        }
        for (target, mut observation) in [
            (&mut self.snapshot.dns, probe.dns),
            (&mut self.snapshot.guard, probe.guard),
        ] {
            observation.valid_for_ms = observation.valid_for_ms.min(PROBE_TTL_MS);
            *target = observation;
        }
        if let Some(time) = probe.transport_proven_at {
            self.proof = Some((generation, time));
        }
        true
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
    /// A native OS notification, unlike a polling gap. Earlier proof is stale
    /// and probes started before it are rejected by the new generation.
    pub fn network_changed(&mut self, now: u64) {
        if !self.stopped {
            self.snapshot
                .invalidate(Reason::NetworkChanged, EventKind::NetworkChanged, now);
        }
    }
    /// The worker may not have noticed a dead session yet: like a polling gap,
    /// transport stays stale until a real worker transition.
    pub fn policy_changed(&mut self, now: u64) {
        if !self.stopped {
            self.snapshot
                .invalidate(Reason::SessionChanged, EventKind::PolicyChanged, now);
        }
    }
    pub fn resumed(&mut self, now: u64) {
        if !self.stopped {
            self.snapshot
                .invalidate(Reason::SystemResumed, EventKind::Resumed, now);
            self.gap = true;
        }
    }
    /// Recorded before the new transport starts; its own transition follows.
    pub fn failed_over(&mut self, now: u64) {
        if !self.stopped {
            self.snapshot.event(EventKind::FailedOver, now);
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
            transport.source = self.source;
            transport.reason = Reason::WorkerStopped;
            transport.observed_at_ms = Some(now);
            transport.valid_for_ms = FRESH_MS;
        } else if !self.gap {
            match self.proof.filter(|&(generation, time)| {
                generation == self.snapshot.generation && now >= time && now - time <= PROBE_TTL_MS
            }) {
                Some((_, time)) => {
                    transport.outcome = Outcome::Passed;
                    transport.source = Source::SystemProbe;
                    transport.reason = Reason::ConfigurationApplied;
                    transport.observed_at_ms = Some(time);
                    transport.valid_for_ms = PROBE_TTL_MS;
                }
                None => {
                    transport.outcome = Outcome::Configured;
                    transport.source = self.source;
                    transport.reason = Reason::SessionRunning;
                    transport.observed_at_ms = Some(now);
                    transport.valid_for_ms = FRESH_MS;
                }
            }
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
    fn native_network_change_and_resume_invalidate_old_proof() {
        let mut monitor = Monitor::new(Mode::Split, Source::ServiceLifecycle, 100);
        let before = monitor.sample(101);
        monitor.network_changed(102);
        let after = monitor.sample(103);
        assert!(after.generation > before.generation);
        assert_eq!(after.events.last().unwrap().kind, EventKind::NetworkChanged);
        let mut late = after.clone();
        let mut probe = before.connectivity.clone();
        probe.outcome = Outcome::Passed;
        assert!(!late.apply_connectivity(before.generation, probe));
        // The worker still runs: lifecycle configuration is not proof either way.
        assert_eq!(after.transport.outcome, Outcome::Configured);
        monitor.resumed(104);
        let resumed = monitor.sample(105);
        assert_eq!(resumed.events.last().unwrap().kind, EventKind::Resumed);
        assert_eq!(resumed.transport.outcome, Outcome::Stale);
        assert_eq!(resumed.transport.reason, Reason::SystemResumed);
        monitor.transition(false, 106);
        monitor.transition(true, 107);
        assert_eq!(monitor.sample(108).transport.outcome, Outcome::Configured);
        monitor.stop(109);
        monitor.network_changed(110);
        monitor.resumed(111);
        assert_eq!(
            monitor.sample(112).events.last().unwrap().kind,
            EventKind::Stopped
        );
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
    fn probe(outcome: Outcome, at: u64) -> SystemProbe {
        SystemProbe {
            transport_proven_at: Some(at),
            dns: Observation::system(outcome, Mode::Full, at),
            guard: Observation::system(outcome, Mode::Full, at),
        }
    }
    #[test]
    fn system_probe_proves_transport_dns_and_guard_only_while_fresh() {
        let mut m = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        m.transition(true, 100);
        let generation = m.generation();
        assert_eq!(m.sample(200).generation, generation);
        assert!(m.apply_system(generation, probe(Outcome::Passed, 1_000), 1_000));
        let s = m.sample(1_001);
        for o in [&s.transport, &s.dns, &s.guard] {
            assert_eq!(
                (o.outcome, o.source, o.valid_for_ms),
                (Outcome::Passed, Source::SystemProbe, PROBE_TTL_MS)
            );
        }
        assert_eq!(s.transport.observed_at_ms, Some(1_000));
        assert_eq!(s.route.outcome, Outcome::Unknown);
        // Without a repeat, every probe row expires; transport is lifecycle again.
        let mut now = 1_001;
        while now <= 1_000 + PROBE_TTL_MS {
            now += FRESH_MS - 1;
            m.sample(now);
        }
        let s = m.sample(now);
        assert_eq!(
            (s.transport.outcome, s.transport.source),
            (Outcome::Configured, Source::ServiceLifecycle)
        );
        assert_eq!(s.transport.valid_for_ms, FRESH_MS);
        assert_eq!(s.dns.outcome, Outcome::Stale);
        assert_eq!(s.guard.reason, Reason::ObservationExpired);
    }
    #[test]
    fn stale_generation_stopped_split_and_forged_probes_are_rejected() {
        let mut m = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        let old = m.generation();
        m.network_changed(101);
        assert!(!m.apply_system(old, probe(Outcome::Passed, 102), 102));
        let current = m.generation();
        let mut forged = probe(Outcome::Passed, 102);
        forged.dns.source = Source::AppProbe;
        assert!(!m.apply_system(current, forged, 102));
        let mut split = probe(Outcome::Passed, 102);
        split.guard.mode = Mode::Split;
        assert!(!m.apply_system(current, split, 102));
        let mut future = probe(Outcome::Passed, 102);
        future.guard.observed_at_ms = Some(500);
        assert!(!m.apply_system(current, future, 102));
        let mut untimed = probe(Outcome::Passed, 102);
        untimed.dns.observed_at_ms = None;
        assert!(!m.apply_system(current, untimed, 102));
        assert!(!m.apply_system(current, probe(Outcome::Passed, 200), 102));
        // An oversized TTL claim is capped at the probe TTL.
        let mut long = probe(Outcome::Passed, 102);
        long.dns.valid_for_ms = u64::MAX;
        assert!(m.apply_system(current, long, 102));
        assert_eq!(m.sample(103).dns.valid_for_ms, PROBE_TTL_MS);
        // A worker outage and Stop refuse late results.
        m.transition(false, 104);
        let blocked = m.generation();
        assert!(!m.apply_system(blocked, probe(Outcome::Passed, 105), 105));
        assert_eq!(m.sample(105).transport.outcome, Outcome::Failed);
        assert_eq!(m.sample(106).transport.source, Source::ServiceLifecycle);
        m.transition(true, 107);
        m.stop(108);
        assert!(!m.apply_system(m.generation(), probe(Outcome::Passed, 109), 109));
        let mut split = Monitor::new(Mode::Split, Source::ServiceLifecycle, 100);
        let mut p = probe(Outcome::Passed, 101);
        for o in [&mut p.dns, &mut p.guard] {
            o.mode = Mode::Split;
        }
        assert!(!split.apply_system(split.generation(), p, 101));
        split.network_changed(102);
        let s = split.sample(103);
        assert_eq!(
            (s.dns.outcome, s.guard.outcome),
            (Outcome::Unsupported, Outcome::Unsupported)
        );
        assert_eq!(s.transport.outcome, Outcome::Configured);
    }
    #[test]
    fn a_probe_failure_does_not_outlive_its_generation_or_ttl() {
        let mut m = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        let mut failed = probe(Outcome::Failed, 101);
        failed.transport_proven_at = None;
        assert!(m.apply_system(m.generation(), failed.clone(), 101));
        let s = m.sample(102);
        assert_eq!(
            (s.dns.outcome, s.transport.outcome),
            (Outcome::Failed, Outcome::Configured)
        );
        m.resumed(103);
        let s = m.sample(104);
        assert_eq!(
            (s.dns.outcome, s.dns.reason),
            (Outcome::Stale, Reason::SystemResumed)
        );
        assert_eq!(s.guard.outcome, Outcome::Stale);
        // Gap after resume: no transport proof until a real transition.
        assert!(m.apply_system(m.generation(), probe(Outcome::Passed, 105), 105));
        assert_eq!(m.sample(106).transport.outcome, Outcome::Stale);
        m.transition(false, 107);
        m.transition(true, 108);
        assert!(m.apply_system(m.generation(), failed, 109));
        let mut now = 109;
        while now <= 101 + PROBE_TTL_MS + 109 {
            now += FRESH_MS - 1;
            m.sample(now);
        }
        assert_eq!(m.sample(now).guard.outcome, Outcome::Stale);
    }
    #[test]
    fn probe_rows_never_carry_free_text_or_addresses() {
        let mut m = Monitor::new(Mode::Full, Source::ServiceLifecycle, 100);
        assert!(m.apply_system(m.generation(), probe(Outcome::Passed, 101), 101));
        let encoded = serde_json::to_string(&m.sample(102)).unwrap();
        assert!(!encoded.contains('.') && !encoded.contains("::"));
        let mut value = serde_json::to_value(m.sample(103)).unwrap();
        value["dns"]["resolver"] = "198.51.100.53".into();
        assert!(serde_json::from_value::<Snapshot>(value).is_err());
    }
}
