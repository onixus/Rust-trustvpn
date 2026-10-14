//! Per-session data-plane liveness, held in memory as fixed-size atomics:
//! counters, timestamps and a 64-bit set of host hashes keyed per session.
//! No flow, destination or address is kept, and the hash bits are never
//! stored, logged or exposed. Each session owns its own instance, so a stale
//! flow of a previous session can never vouch for a newer one.
use std::{
    hash::BuildHasher,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed},
    time::{Duration, Instant},
};

/// Outbound demand must stay unanswered this long before a session is judged.
pub(crate) const SILENCE: Duration = Duration::from_secs(20);
/// Evidence counts only within a window of this many silence periods; older
/// failures (an idle tunnel hitting dead hosts now and then) start afresh.
pub(crate) const WINDOW: u32 = 3;
/// Opens of one kind (failed in transport, or accepted yet silent) within
/// one evidence window and since the last inbound byte.
pub(crate) const OPENS: u32 = 5;
/// Distinct destinations among those opens: an application retrying one or
/// two dead hosts on an otherwise idle session is not a dead session.
pub(crate) const DESTINATIONS: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Healthy,
    Degraded,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Tally {
    /// Start of the current evidence window.
    pub since: Option<Duration>,
    pub opens: u32,
    /// Lower bound: destinations whose keyed hashes collide count once.
    pub destinations: u32,
}
impl Tally {
    fn conclusive(&self, now: Duration, window: Duration) -> bool {
        self.since
            .is_some_and(|since| now.saturating_sub(since) < window)
            && self.opens >= OPENS
            && self.destinations >= DESTINATIONS
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    /// Oldest outbound demand not followed by any inbound byte.
    pub demand: Option<Duration>,
    pub failed: Tally,
    pub silent: Tally,
}
/// Degraded only with unanswered demand AND recent opens failing (or
/// accepted but silent) across several destinations. An idle session stays
/// healthy, and lost `_check` responses are no evidence: endpoint 1.1.0 loses
/// them on flow-control-blocked streams during long uploads. An endpoint that
/// answers `_check` but rejects every CONNECT (5xx) is out of scope: a
/// rejection is an answer, so it is neutral here.
pub(crate) fn verdict(s: &Snapshot, now: Duration, silence: Duration) -> Verdict {
    let window = silence * WINDOW;
    let unanswered = s
        .demand
        .is_some_and(|since| now.saturating_sub(since) >= silence);
    if unanswered && (s.failed.conclusive(now, window) || s.silent.conclusive(now, window)) {
        Verdict::Degraded
    } else {
        Verdict::Healthy
    }
}

/// Millisecond stamps relative to the session epoch, plus one; zero is unset.
fn stamp(at: Duration) -> u64 {
    at.as_millis() as u64 + 1
}
fn unstamp(value: u64) -> Option<Duration> {
    (value != 0).then(|| Duration::from_millis(value - 1))
}

/// Open count plus a 64-bit set of keyed destination hashes, both for the
/// window starting at `since`.
#[derive(Default)]
struct Evidence {
    since: AtomicU64,
    opens: AtomicU32,
    spread: AtomicU64,
}
impl Evidence {
    fn add(&self, bit: u64, now: Duration, window: Duration) {
        let fresh = unstamp(self.since.load(Relaxed))
            .is_some_and(|since| now.saturating_sub(since) < window);
        if fresh {
            self.opens.fetch_add(1, Relaxed);
            self.spread.fetch_or(bit, Relaxed);
        } else {
            self.since.store(stamp(now), Relaxed);
            self.opens.store(1, Relaxed);
            self.spread.store(bit, Relaxed);
        }
    }
    fn clear(&self) {
        for value in [&self.since, &self.spread] {
            if value.load(Relaxed) != 0 {
                value.store(0, Relaxed);
            }
        }
        if self.opens.load(Relaxed) != 0 {
            self.opens.store(0, Relaxed);
        }
    }
    fn tally(&self) -> Tally {
        Tally {
            since: unstamp(self.since.load(Relaxed)),
            opens: self.opens.load(Relaxed),
            destinations: self.spread.load(Relaxed).count_ones(),
        }
    }
}

pub(crate) struct Liveness {
    epoch: Instant,
    silence: Duration,
    /// Per-session key: the set reveals nothing comparable across sessions.
    keys: std::collections::hash_map::RandomState,
    demand: AtomicU64,
    failed: Evidence,
    silent: Evidence,
    /// Ever received an inbound byte; never cleared.
    delivered: AtomicBool,
}
impl Liveness {
    pub fn new(silence: Duration) -> Self {
        Self {
            epoch: Instant::now(),
            silence,
            keys: Default::default(),
            demand: AtomicU64::new(0),
            failed: Evidence::default(),
            silent: Evidence::default(),
            delivered: AtomicBool::new(false),
        }
    }
    /// Session clock; `open_tcp` passes its start back to `opened`.
    pub fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
    pub fn outbound(&self) {
        self.demand_at(self.now());
    }
    /// Keeps the oldest pending demand; later demand does not move it forward.
    fn demand_at(&self, at: Duration) {
        let at = stamp(at);
        // Explicit CAS loop: `fetch_update` is deprecated on new toolchains
        // and its replacement is newer than the MSRV.
        let mut current = self.demand.load(Relaxed);
        while current == 0 || current > at {
            match self
                .demand
                .compare_exchange_weak(current, at, Relaxed, Relaxed)
            {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }
    /// Any byte from the endpoint answers all pending demand. Loads first:
    /// this runs on every read.
    pub fn inbound(&self) {
        self.failed.clear();
        self.silent.clear();
        if !self.delivered.load(Relaxed) {
            self.delivered.store(true, Relaxed);
        }
        if self.demand.load(Relaxed) != 0 {
            self.demand.store(0, Relaxed);
        }
    }
    pub fn opened(&self, outcome: &crate::Result<()>, target: &str, started: Duration) {
        self.opened_at(outcome, target, started, self.now());
    }
    /// A per-destination TCP CONNECT outcome. `target` is hashed by host only
    /// (ports of one host are one destination) and never stored. Shared
    /// UDP/ICMP relay streams are not reported: the endpoint may recycle
    /// them, and they name no destination. Only a counted outcome is demand,
    /// dated from the attempt's start: a neutral answer leaves none.
    fn opened_at(
        &self,
        outcome: &crate::Result<()>,
        target: &str,
        started: Duration,
        now: Duration,
    ) {
        use crate::Error;
        let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
        let bit = 1u64 << (self.keys.hash_one(host) % 64);
        let window = self.silence * WINDOW;
        match outcome {
            Ok(()) => self.silent.add(bit, now, window),
            Err(Error::Protocol | Error::Timeout | Error::Io) => self.failed.add(bit, now, window),
            // Rejected, authentication or destination: the endpoint answered.
            _ => return,
        }
        self.demand_at(started);
    }
    pub fn delivered(&self) -> bool {
        self.delivered.load(Relaxed)
    }
    fn snapshot(&self) -> Snapshot {
        Snapshot {
            demand: unstamp(self.demand.load(Relaxed)),
            failed: self.failed.tally(),
            silent: self.silent.tally(),
        }
    }
    pub fn verdict(&self) -> Verdict {
        self.verdict_at(self.now())
    }
    fn verdict_at(&self, now: Duration) -> Verdict {
        verdict(&self.snapshot(), now, self.silence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const S: fn(u64) -> Duration = Duration::from_secs;
    fn host(i: u32) -> String {
        format!("192.0.2.{i}:443")
    }
    /// Distinct test hosts whose keyed hashes do not collide in this session.
    fn hosts(l: &Liveness, n: usize) -> Vec<String> {
        let mut seen = 0u64;
        let mut out = Vec::new();
        for i in 1.. {
            let h = host(i);
            let name = h.rsplit_once(':').unwrap().0;
            let bit = 1u64 << (l.keys.hash_one(name) % 64);
            if seen & bit == 0 {
                seen |= bit;
                out.push(h);
            }
            if out.len() == n {
                return out;
            }
        }
        unreachable!()
    }
    /// Replays events on an injected clock, one step per second; `event(t)`
    /// runs before judging at `t`. Returns the first degraded second.
    fn run(l: &Liveness, seconds: u64, mut event: impl FnMut(&Liveness, Duration)) -> Option<u64> {
        (0..=seconds).find(|&t| {
            event(l, S(t));
            l.verdict_at(S(t)) == Verdict::Degraded
        })
    }
    fn fail(l: &Liveness, target: &str, t: Duration) {
        l.opened_at(&Err(crate::Error::Timeout), target, t, t);
    }
    #[test]
    fn idle_session_stays_healthy() {
        let l = Liveness::new(SILENCE);
        assert_eq!(run(&l, 600, |_, _| {}), None);
    }
    #[test]
    fn one_or_two_dead_destinations_retried_for_a_minute_are_healthy() {
        for n in [1, 2] {
            let l = Liveness::new(SILENCE);
            let dead = hosts(&l, n);
            let degraded = run(&l, 60, |l, t| {
                l.demand_at(t);
                if t.as_secs() % 2 == 0 {
                    for (port, target) in dead.iter().enumerate() {
                        let other = target.replace(":443", &format!(":{}", 80 + port));
                        fail(l, target, t);
                        l.opened_at(&Err(crate::Error::Protocol), &other, t, t);
                    }
                }
            });
            assert_eq!(degraded, None, "{n} dead destination(s)");
        }
    }
    #[test]
    fn relay_stream_failures_do_not_add_breadth() {
        // Relay opens (`_udp2`, `_icmp`) never reach `opened`; the session
        // path is covered in tests/h3_transport.rs. Two dead TCP hosts for a
        // minute stay below the breadth threshold.
        let l = Liveness::new(SILENCE);
        let dead = hosts(&l, 2);
        let degraded = run(&l, 60, |l, t| {
            l.demand_at(t);
            if t.as_secs() % 2 == 0 {
                for target in &dead {
                    fail(l, target, t);
                }
            }
        });
        assert_eq!(degraded, None);
    }
    #[test]
    fn upload_and_long_poll_on_one_silent_flow_are_healthy() {
        let l = Liveness::new(SILENCE);
        let [one] = hosts(&l, 1).try_into().unwrap();
        l.opened_at(&Ok(()), &one, S(0), S(0));
        // Outbound progress, checks losing responses, no inbound byte.
        assert_eq!(run(&l, 60, |l, t| l.demand_at(t)), None);
        let l = Liveness::new(SILENCE);
        l.opened_at(&Ok(()), &one, S(0), S(0));
        assert_eq!(run(&l, 60, |_, _| {}), None);
    }
    #[test]
    fn incident_pattern_degrades_exactly_at_the_silence_window() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 3);
        let degraded = run(&l, 60, |l, t| {
            let target = &targets[t.as_secs() as usize % 3];
            let error = if t.as_secs() % 2 == 0 {
                crate::Error::Timeout
            } else {
                crate::Error::Protocol
            };
            l.opened_at(&Err(error), target, t, t);
        });
        assert_eq!(degraded, Some(SILENCE.as_secs()));
    }
    #[test]
    fn failures_spread_over_hours_are_stale_but_a_burst_is_not() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 5);
        // A one-way UDP write stamped demand long ago and nothing answered.
        l.demand_at(S(0));
        for (i, target) in targets.iter().enumerate() {
            let t = S(600 + 1500 * i as u64);
            fail(&l, target, t);
            assert_eq!(l.verdict_at(t), Verdict::Healthy);
        }
        assert_eq!(l.verdict_at(S(7200)), Verdict::Healthy);
        // The same five failures inside one window: degraded at once, as the
        // demand is already older than the silence period.
        let start = S(8000);
        for (i, target) in targets.iter().enumerate() {
            fail(&l, target, start + S(i as u64));
        }
        assert_eq!(l.verdict_at(start + S(4)), Verdict::Degraded);
        // Once the window has passed without new evidence, it is stale.
        let window = SILENCE * WINDOW;
        assert_eq!(l.verdict_at(start + window - S(1)), Verdict::Degraded);
        assert_eq!(l.verdict_at(start + window), Verdict::Healthy);
    }
    #[test]
    fn neutral_answers_leave_no_demand_and_counted_ones_date_from_the_attempt() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 5);
        for target in &targets {
            for error in [
                crate::Error::Rejected(502),
                crate::Error::Authentication,
                crate::Error::Destination,
                crate::Error::Unsupported("x"),
            ] {
                l.opened_at(&Err(error), target, S(0), S(10));
            }
        }
        let s = l.snapshot();
        assert!(s.demand.is_none());
        assert_eq!((s.failed.opens, s.silent.opens), (0, 0));
        // A CONNECT that timed out after 10 s was demand from its start.
        l.opened_at(&Err(crate::Error::Timeout), &targets[0], S(30), S(40));
        assert_eq!(l.snapshot().demand, Some(S(30)));
        // A later write does not move the oldest demand forward.
        l.demand_at(S(50));
        assert_eq!(l.snapshot().demand, Some(S(30)));
    }
    #[test]
    fn accepted_but_silent_flows_across_destinations_degrade() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 3);
        let degraded = run(&l, 60, |l, t| {
            l.demand_at(t);
            if t < S(5) {
                l.opened_at(&Ok(()), &targets[t.as_secs() as usize % 3], t, t);
            }
        });
        assert_eq!(degraded, Some(SILENCE.as_secs()));
    }
    #[test]
    fn thresholds_need_both_count_and_spread() {
        let at = |opens, destinations| Snapshot {
            demand: Some(S(0)),
            failed: Tally {
                since: Some(S(0)),
                opens,
                destinations,
            },
            ..Default::default()
        };
        assert_eq!(verdict(&at(5, 3), S(19), SILENCE), Verdict::Healthy);
        assert_eq!(verdict(&at(5, 3), S(20), SILENCE), Verdict::Degraded);
        assert_eq!(verdict(&at(4, 3), S(30), SILENCE), Verdict::Healthy);
        assert_eq!(verdict(&at(50, 2), S(30), SILENCE), Verdict::Healthy);
        let none = Snapshot {
            demand: None,
            ..at(50, 50)
        };
        assert_eq!(verdict(&none, S(30), SILENCE), Verdict::Healthy);
    }
    #[test]
    fn inbound_answers_demand_and_clears_evidence() {
        let l = Liveness::new(SILENCE);
        l.demand_at(S(0));
        for target in hosts(&l, 6) {
            fail(&l, &target, S(1));
            l.opened_at(&Ok(()), &target, S(1), S(1));
        }
        l.inbound();
        let s = l.snapshot();
        assert!(s.demand.is_none());
        assert_eq!((s.failed.opens, s.failed.destinations), (0, 0));
        assert_eq!((s.silent.opens, s.silent.destinations), (0, 0));
        assert!(s.failed.since.is_none());
        // Proof of delivery outlives the counters it reset.
        assert!(l.delivered());
        fail(&l, "192.0.2.1:443", S(2));
        assert!(l.delivered());
        assert!(!Liveness::new(SILENCE).delivered());
    }
    #[test]
    fn sessions_do_not_share_evidence() {
        let old = Liveness::new(SILENCE);
        let new = Liveness::new(SILENCE);
        for target in hosts(&new, 5) {
            new.opened_at(&Err(crate::Error::Protocol), &target, S(0), S(0));
        }
        old.inbound();
        let s = new.snapshot();
        assert!(s.demand.is_some());
        assert_eq!((s.failed.opens, s.failed.destinations), (5, 5));
        assert_eq!(new.verdict_at(S(20)), Verdict::Degraded);
    }
}
