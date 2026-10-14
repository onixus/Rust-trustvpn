//! Per-session data-plane liveness, held in memory as fixed-size atomics:
//! counters, a demand timestamp and a 64-bit set of host hashes keyed per
//! session. No flow, destination or address is kept, and the hash bits are
//! never stored, logged or exposed. Each session owns its own instance, so a
//! stale flow of a previous session can never vouch for a newer one.
use std::{
    hash::BuildHasher,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::Relaxed},
    time::{Duration, Instant},
};

/// Outbound demand must stay unanswered this long before a session is judged.
pub(crate) const SILENCE: Duration = Duration::from_secs(20);
/// Opens of one kind (failed in transport, or accepted yet silent) since the
/// last inbound byte.
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
    pub opens: u32,
    /// Lower bound: destinations whose keyed hashes collide count once.
    pub destinations: u32,
}
impl Tally {
    fn conclusive(&self) -> bool {
        self.opens >= OPENS && self.destinations >= DESTINATIONS
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    /// Oldest outbound demand not followed by any inbound byte.
    pub demand: Option<Duration>,
    pub failed: Tally,
    pub silent: Tally,
}
/// Degraded only with unanswered demand AND opens failing (or accepted but
/// silent) across several destinations. An idle session stays healthy, and
/// lost `_check` responses are no evidence: endpoint 1.1.0 loses them on
/// flow-control-blocked streams during long uploads. An endpoint that answers
/// `_check` but rejects every CONNECT (5xx) is out of scope: a rejection is
/// an answer, so it is neutral here.
pub(crate) fn verdict(s: &Snapshot, now: Duration, silence: Duration) -> Verdict {
    let unanswered = s
        .demand
        .is_some_and(|since| now.saturating_sub(since) >= silence);
    if unanswered && (s.failed.conclusive() || s.silent.conclusive()) {
        Verdict::Degraded
    } else {
        Verdict::Healthy
    }
}

/// Open count plus a 64-bit set of keyed destination hashes.
#[derive(Default)]
struct Evidence {
    opens: AtomicU32,
    spread: AtomicU64,
}
impl Evidence {
    fn add(&self, bit: u64) {
        self.opens.fetch_add(1, Relaxed);
        self.spread.fetch_or(bit, Relaxed);
    }
    fn clear(&self) {
        if self.opens.load(Relaxed) != 0 {
            self.opens.store(0, Relaxed);
        }
        if self.spread.load(Relaxed) != 0 {
            self.spread.store(0, Relaxed);
        }
    }
    fn tally(&self) -> Tally {
        Tally {
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
    /// Milliseconds since `epoch` plus one; zero means no unanswered demand.
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
    fn now(&self) -> Duration {
        self.epoch.elapsed()
    }
    /// Keeps the oldest pending demand; later writes do not move it forward.
    pub fn outbound(&self) {
        if self.demand.load(Relaxed) == 0 {
            let stamp = self.now().as_millis() as u64 + 1;
            let _ = self.demand.compare_exchange(0, stamp, Relaxed, Relaxed);
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
    /// A per-destination TCP CONNECT outcome. `target` is hashed by host only
    /// (ports of one host are one destination) and never stored. Shared
    /// UDP/ICMP relay streams are not reported: the endpoint may recycle
    /// them, and they name no destination.
    pub fn opened(&self, outcome: &crate::Result<()>, target: &str) {
        use crate::Error;
        let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
        let bit = 1u64 << (self.keys.hash_one(host) % 64);
        match outcome {
            Ok(()) => self.silent.add(bit),
            Err(Error::Protocol | Error::Timeout | Error::Io) => self.failed.add(bit),
            // Rejected, authentication or destination: the endpoint answered.
            _ => {}
        }
    }
    pub fn delivered(&self) -> bool {
        self.delivered.load(Relaxed)
    }
    fn snapshot(&self) -> Snapshot {
        let demand = self.demand.load(Relaxed);
        Snapshot {
            demand: (demand != 0).then(|| Duration::from_millis(demand - 1)),
            failed: self.failed.tally(),
            silent: self.silent.tally(),
        }
    }
    pub fn verdict(&self) -> Verdict {
        verdict(&self.snapshot(), self.now(), self.silence)
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
    /// Replays one event per second; `event(t)` runs before judging at `t`.
    fn run(l: &Liveness, seconds: u64, mut event: impl FnMut(&Liveness, u64)) -> Option<u64> {
        for t in 0..=seconds {
            event(l, t);
            let mut s = l.snapshot();
            // Demand stamps use real time; rebase them on the replay clock.
            s.demand = s.demand.map(|_| S(0));
            if verdict(&s, S(t), SILENCE) == Verdict::Degraded {
                return Some(t);
            }
        }
        None
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
                l.outbound();
                if t % 2 == 0 {
                    for (port, target) in dead.iter().enumerate() {
                        let other = target.replace(":443", &format!(":{}", 80 + port));
                        l.opened(&Err(crate::Error::Timeout), target);
                        l.opened(&Err(crate::Error::Protocol), &other);
                    }
                }
            });
            assert_eq!(degraded, None, "{n} dead destination(s)");
        }
    }
    #[test]
    fn upload_and_long_poll_on_one_silent_flow_are_healthy() {
        let l = Liveness::new(SILENCE);
        let [one] = hosts(&l, 1).try_into().unwrap();
        l.opened(&Ok(()), &one);
        // Outbound progress, checks losing responses, no inbound byte.
        assert_eq!(run(&l, 60, |l, _| l.outbound()), None);
        let l = Liveness::new(SILENCE);
        l.opened(&Ok(()), &one);
        assert_eq!(run(&l, 60, |_, _| {}), None);
    }
    #[test]
    fn incident_pattern_degrades_exactly_at_the_silence_window() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 3);
        let degraded = run(&l, 60, |l, t| {
            l.outbound();
            let target = &targets[t as usize % 3];
            let error = if t % 2 == 0 {
                crate::Error::Timeout
            } else {
                crate::Error::Protocol
            };
            l.opened(&Err(error), target);
        });
        assert_eq!(degraded, Some(SILENCE.as_secs()));
    }
    #[test]
    fn accepted_but_silent_flows_across_destinations_degrade() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 3);
        let degraded = run(&l, 60, |l, t| {
            l.outbound();
            if t < 5 {
                l.opened(&Ok(()), &targets[t as usize % 3]);
            }
        });
        assert_eq!(degraded, Some(SILENCE.as_secs()));
    }
    #[test]
    fn relay_stream_failures_do_not_add_breadth() {
        // Relay opens (`_udp2`, `_icmp`) never reach `opened`; the session
        // path is covered in tests/h3_transport.rs. Two dead TCP hosts for a
        // minute stay below the breadth threshold.
        let l = Liveness::new(SILENCE);
        let dead = hosts(&l, 2);
        let degraded = run(&l, 60, |l, t| {
            l.outbound();
            if t % 2 == 0 {
                for target in &dead {
                    l.opened(&Err(crate::Error::Timeout), target);
                }
            }
        });
        assert_eq!(degraded, None);
    }
    #[test]
    fn thresholds_need_both_count_and_spread() {
        let at = |opens, destinations| Snapshot {
            demand: Some(S(0)),
            failed: Tally {
                opens,
                destinations,
            },
            ..Default::default()
        };
        assert_eq!(verdict(&at(5, 3), S(19), SILENCE), Verdict::Healthy);
        assert_eq!(verdict(&at(5, 3), S(20), SILENCE), Verdict::Degraded);
        assert_eq!(verdict(&at(4, 3), S(600), SILENCE), Verdict::Healthy);
        assert_eq!(verdict(&at(50, 2), S(600), SILENCE), Verdict::Healthy);
        let none = Snapshot {
            demand: None,
            ..at(50, 50)
        };
        assert_eq!(verdict(&none, S(600), SILENCE), Verdict::Healthy);
    }
    #[test]
    fn inbound_answers_demand_and_clears_evidence() {
        let l = Liveness::new(SILENCE);
        l.outbound();
        for target in hosts(&l, 6) {
            l.opened(&Err(crate::Error::Timeout), &target);
            l.opened(&Ok(()), &target);
        }
        l.inbound();
        let s = l.snapshot();
        assert!(s.demand.is_none());
        assert_eq!((s.failed.opens, s.failed.destinations), (0, 0));
        assert_eq!((s.silent.opens, s.silent.destinations), (0, 0));
        // Proof of delivery outlives the counters it reset.
        assert!(l.delivered());
        l.outbound();
        l.opened(&Err(crate::Error::Timeout), "192.0.2.1:443");
        assert!(l.delivered());
        assert!(!Liveness::new(SILENCE).delivered());
    }
    #[test]
    fn rejected_and_local_errors_are_neutral() {
        let l = Liveness::new(SILENCE);
        for target in hosts(&l, 10) {
            for error in [
                crate::Error::Rejected(502),
                crate::Error::Authentication,
                crate::Error::Destination,
                crate::Error::Unsupported("x"),
            ] {
                l.opened(&Err(error), &target);
            }
        }
        let s = l.snapshot();
        assert_eq!((s.failed.opens, s.silent.opens), (0, 0));
    }
    #[test]
    fn sessions_do_not_share_evidence() {
        let old = Liveness::new(SILENCE);
        let new = Liveness::new(SILENCE);
        new.outbound();
        for target in hosts(&new, 5) {
            new.opened(&Err(crate::Error::Protocol), &target);
        }
        old.inbound();
        let s = new.snapshot();
        assert!(s.demand.is_some());
        assert_eq!((s.failed.opens, s.failed.destinations), (5, 5));
    }
}
