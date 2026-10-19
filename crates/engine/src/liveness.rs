//! Per-session data-plane liveness, held in memory as fixed-size atomics:
//! counters, timestamps and 64-bit sets of host hashes keyed per session.
//! No flow, destination or address is kept, and the hash bits are never
//! stored, logged or exposed. Each session owns its own instance, so a stale
//! flow of a previous session can never vouch for a newer one.
//!
//! Two independent verdicts:
//! - A (`verdict`): unanswered demand while opens fail or stay silent. Any
//!   inbound byte, on any stream, answers it.
//! - B (`quiet`, issue #99): most TCP flows to servers that must answer the
//!   client's first write (TLS, HTTP) wrote and never got a byte back, across
//!   several hosts. A handful of live flows, the shared UDP relay or ICMP do
//!   not clear it: it compares answered with unanswered flows over a sliding
//!   window of fixed slots instead of resetting on inbound traffic.
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
    /// Verdict A; reported with the session's delivery proof.
    Degraded,
    /// Verdict B only. Always reported unproven: the few flows that did get
    /// answers must not reset the reconnect budget, or a session that keeps
    /// coming back in this state would reconnect without a cooldown.
    Quiet,
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

/// Verdict B buckets flows into slots of this length by their first write.
pub(crate) const SLOT: Duration = Duration::from_secs(5);
/// A slot is judged only once its last write is this old: a live server
/// answers a ClientHello or an HTTP request well within it, even after a
/// wake on a slow path.
pub(crate) const GRACE: Duration = Duration::from_secs(10);
/// Mature slots judged together: 12 x 5 s = the last 60 s past the grace.
pub(crate) const RECENT: u64 = 12;
/// Ring size: the judged slots plus those still inside the grace period
/// (the current one and two more), rounded up. Older slots are recycled.
const SLOTS: usize = 16;
const _: () = assert!(SLOTS as u64 > RECENT + GRACE.as_secs() / SLOT.as_secs());
/// Unanswered flows (written but silent, or failed to open) needed within
/// the judged window. The #99 wakes left 130 to 1427 such flows within a
/// minute; an ordinary minute (~80 opens, 13-21% silent) stays far below.
pub(crate) const QUIET: u32 = 24;
/// Share of unanswered among all judged flows, as numerator/denominator:
/// 80%. Bad reconnects in #99 were 96-100% silent, good ones 13-21%.
pub(crate) const QUIET_SHARE: (u64, u64) = (4, 5);
/// Distinct keyed host buckets among unanswered flows not shared with any
/// answered one: an application hammering one or two dead hosts is not a
/// dead session.
pub(crate) const QUIET_HOSTS: u32 = 6;
/// Ports whose servers must answer the client's first write: HTTPS, DoT,
/// alternate HTTPS and HTTP. Server-first or idle protocols stay out.
pub(crate) const ANSWERING_PORTS: [u16; 4] = [443, 853, 8443, 80];

/// Totals over the judged slots of verdict B.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Quiet {
    /// Watched flows that wrote; the answered ones are a subset.
    pub wrote: u32,
    pub answered: u32,
    /// Watched opens that timed out or found no stream credit.
    pub failed: u32,
    /// Lower bound: hosts whose keyed hashes collide count once.
    pub hosts: u32,
}
/// Verdict B thresholds; see the constants for their grounds.
pub(crate) fn quiet(q: &Quiet) -> bool {
    let answered = q.answered.min(q.wrote) as u64;
    let unanswered = q.failed as u64 + (q.wrote as u64 - answered);
    let (part, whole) = QUIET_SHARE;
    unanswered >= QUIET as u64
        && unanswered * whole >= (unanswered + answered) * part
        && q.hosts >= QUIET_HOSTS
}

/// Per-flow state of verdict B, held by the flow's tunnel. A flow counts
/// only when it writes first; a byte from the server before any write
/// (server-first protocols) or a flow that never writes is neutral.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Watch {
    #[default]
    Off,
    Fresh(u64),
    /// Host bit and the absolute slot of the first write.
    Wrote(u64, u64),
}

/// Process-wide flow counts across sessions: plain numbers only.
pub(crate) struct Flows {
    pub opened: AtomicU64,
    pub answered: AtomicU64,
    pub quiet: AtomicU64,
    pub failed: AtomicU64,
    pub credit: AtomicU64,
}
pub(crate) static FLOWS: Flows = Flows {
    opened: AtomicU64::new(0),
    answered: AtomicU64::new(0),
    quiet: AtomicU64::new(0),
    failed: AtomicU64::new(0),
    credit: AtomicU64::new(0),
};
fn count(counter: &AtomicU64) {
    counter.fetch_add(1, Relaxed);
}
/// A watched flow ending before any byte answered its write.
pub(crate) fn closed(watch: Watch) {
    if let Watch::Wrote(..) = watch {
        count(&FLOWS.quiet);
    }
}

/// One slot of verdict B. Recycled lazily: the first event of a newer slot
/// number claims it by CAS and zeroes it. Events racing with the claim may
/// be lost, which can only undercount; `quiet` clamps answers to writes.
#[derive(Default)]
struct Slot {
    /// Absolute slot number plus one; zero is unset.
    number: AtomicU64,
    wrote: AtomicU32,
    answered: AtomicU32,
    failed: AtomicU32,
    wrote_hosts: AtomicU64,
    answered_hosts: AtomicU64,
    failed_hosts: AtomicU64,
}
impl Slot {
    fn is(&self, number: u64) -> bool {
        self.number.load(Relaxed) == number + 1
    }
    fn reset(&self) {
        for value in [&self.wrote, &self.answered, &self.failed] {
            value.store(0, Relaxed);
        }
        for value in [&self.wrote_hosts, &self.answered_hosts, &self.failed_hosts] {
            value.store(0, Relaxed);
        }
    }
}
fn slot_of(at: Duration) -> u64 {
    (at.as_millis() / SLOT.as_millis()) as u64
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
    /// Verdict B ring, indexed by absolute slot number modulo its size.
    slots: [Slot; SLOTS],
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
            slots: Default::default(),
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
        let bit = self.host(target);
        let window = self.silence * WINDOW;
        // Verdict B: an open that never got an answer from the endpoint.
        if matches!(outcome, Err(Error::Timeout | Error::Credit)) && answers_first(target) {
            self.failed_at(bit, now);
        }
        match outcome {
            Ok(()) => self.silent.add(bit, now, window),
            Err(Error::Protocol | Error::Timeout | Error::Credit | Error::Io) => {
                count(&FLOWS.failed);
                self.failed.add(bit, now, window)
            }
            // Rejected, authentication or destination: the endpoint answered.
            _ => return,
        }
        self.demand_at(started);
    }
    /// Keyed bit of the target's host; ports of one host are one host.
    fn host(&self, target: &str) -> u64 {
        let host = target.rsplit_once(':').map_or(target, |(host, _)| host);
        1u64 << (self.keys.hash_one(host) % 64)
    }
    /// Verdict B state for a newly opened TCP flow to `target`.
    pub fn watch(&self, target: &str) -> Watch {
        if answers_first(target) {
            Watch::Fresh(self.host(target))
        } else {
            Watch::Off
        }
    }
    pub fn wrote(&self, watch: &mut Watch) {
        if let Watch::Fresh(_) = watch {
            self.wrote_at(watch, self.now());
        }
    }
    /// The flow's first write dates it into a slot; later writes do not.
    fn wrote_at(&self, watch: &mut Watch, now: Duration) {
        if let Watch::Fresh(bit) = *watch {
            let number = slot_of(now);
            if let Some(slot) = self.claim(number) {
                slot.wrote.fetch_add(1, Relaxed);
                slot.wrote_hosts.fetch_or(bit, Relaxed);
            }
            *watch = Watch::Wrote(bit, number);
        }
    }
    /// The flow's first inbound byte. It answers the write in the slot of
    /// that write; a slot already recycled ignores it. A byte before any
    /// write makes the flow neutral.
    pub fn read(&self, watch: &mut Watch) {
        if let Watch::Wrote(bit, number) = *watch {
            count(&FLOWS.answered);
            let slot = &self.slots[number as usize % SLOTS];
            if slot.is(number) {
                slot.answered.fetch_add(1, Relaxed);
                slot.answered_hosts.fetch_or(bit, Relaxed);
            }
        }
        if *watch != Watch::Off {
            *watch = Watch::Off;
        }
    }
    fn failed_at(&self, bit: u64, now: Duration) {
        if let Some(slot) = self.claim(slot_of(now)) {
            slot.failed.fetch_add(1, Relaxed);
            slot.failed_hosts.fetch_or(bit, Relaxed);
        }
    }
    /// The ring slot for `number`, recycled if it held an older one; none
    /// when it already holds a newer one (a late event).
    fn claim(&self, number: u64) -> Option<&Slot> {
        let slot = &self.slots[number as usize % SLOTS];
        let tag = number + 1;
        let mut current = slot.number.load(Relaxed);
        loop {
            if current == tag {
                return Some(slot);
            }
            if current > tag {
                return None;
            }
            match slot
                .number
                .compare_exchange_weak(current, tag, Relaxed, Relaxed)
            {
                Ok(_) => {
                    slot.reset();
                    return Some(slot);
                }
                Err(actual) => current = actual,
            }
        }
    }
    /// Verdict B totals over the mature slots of the judged window.
    fn quiet_at(&self, now: Duration) -> Quiet {
        let mut q = Quiet::default();
        let Some(mature) = now.checked_sub(GRACE) else {
            return q;
        };
        // Slot n ends at (n + 1) * SLOT; mature ones end by `mature`.
        let end = slot_of(mature);
        let (mut wrote, mut answered, mut failed) = (0u64, 0u64, 0u64);
        for number in end.saturating_sub(RECENT)..end {
            let slot = &self.slots[number as usize % SLOTS];
            if !slot.is(number) {
                continue;
            }
            let written = slot.wrote.load(Relaxed);
            q.wrote = q.wrote.saturating_add(written);
            q.answered = q
                .answered
                .saturating_add(slot.answered.load(Relaxed).min(written));
            q.failed = q.failed.saturating_add(slot.failed.load(Relaxed));
            wrote |= slot.wrote_hosts.load(Relaxed);
            answered |= slot.answered_hosts.load(Relaxed);
            failed |= slot.failed_hosts.load(Relaxed);
        }
        q.hosts = ((wrote | failed) & !answered).count_ones();
        q
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
    /// Verdict A first: it keeps its own delivery proof.
    fn verdict_at(&self, now: Duration) -> Verdict {
        match verdict(&self.snapshot(), now, self.silence) {
            Verdict::Healthy if quiet(&self.quiet_at(now)) => Verdict::Quiet,
            verdict => verdict,
        }
    }
    /// `Some(proven)` when degraded; see `Verdict::Quiet` for why verdict B
    /// is never proven.
    pub fn degraded(&self) -> Option<bool> {
        self.degraded_at(self.now())
    }
    fn degraded_at(&self, now: Duration) -> Option<bool> {
        match self.verdict_at(now) {
            Verdict::Healthy => None,
            Verdict::Degraded => Some(self.delivered()),
            Verdict::Quiet => Some(false),
        }
    }
}
/// TCP targets on a port in `ANSWERING_PORTS`.
fn answers_first(target: &str) -> bool {
    target
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some_and(|port| ANSWERING_PORTS.contains(&port))
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

    // Verdict B (issue #99). Targets from `hosts` are on :443, a watched port.
    fn quiet_flow(l: &Liveness, target: &str, t: Duration) -> Watch {
        let mut watch = l.watch(target);
        l.wrote_at(&mut watch, t);
        watch
    }
    fn answered_flow(l: &Liveness, target: &str, t: Duration) {
        let mut watch = quiet_flow(l, target, t);
        l.inbound();
        l.read(&mut watch);
    }
    /// Like `run`, with the session-level outcome: `Some((second, proven))`.
    fn run_b(
        l: &Liveness,
        seconds: u64,
        mut event: impl FnMut(&Liveness, Duration),
    ) -> Option<(u64, bool)> {
        (0..=seconds).find_map(|t| {
            event(l, S(t));
            l.degraded_at(S(t)).map(|proven| (t, proven))
        })
    }
    /// The #99 wake: ~3 opens/s accepted and written to, never answered,
    /// across many hosts, while four flows get answers and keep delivering
    /// every 2 s. Verdict A never fires (every inbound byte answers it).
    fn wake(l: &Liveness, targets: &[String], t: Duration, open: impl Fn(&Liveness, &str)) {
        let s = t.as_secs();
        if s == 0 || s == 2 {
            for target in &targets[..2] {
                l.opened_at(&Ok(()), target, t, t);
                answered_flow(l, target, t);
            }
        }
        if s.is_multiple_of(2) {
            l.inbound();
        }
        for i in 0..3 {
            let target = &targets[(3 * s as usize + i) % targets.len()];
            l.demand_at(t);
            open(l, target);
        }
    }
    #[test]
    fn issue_99_wake_with_a_few_live_flows_degrades_unproven() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 24);
        let found = run_b(&l, 65, |l, t| {
            wake(l, &targets, t, |l, target| {
                l.opened_at(&Ok(()), target, t, t);
                quiet_flow(l, target, t);
            })
        });
        // The first two slots mature at 20 s: 30 silent, 4 answered.
        assert_eq!(found, Some((20, false)));
        assert_eq!(l.verdict_at(S(20)), Verdict::Quiet);
        // Delivery happened; verdict A alone would have called it proven.
        assert!(l.delivered());
    }
    #[test]
    fn issue_99_wake_with_credit_and_timeouts_degrades_unproven() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 24);
        let found = run_b(&l, 65, |l, t| {
            wake(l, &targets, t, |l, target| {
                let error = if t.as_secs() % 2 == 0 {
                    crate::Error::Credit
                } else {
                    crate::Error::Timeout
                };
                l.opened_at(&Err(error), target, t, t);
            })
        });
        assert!(
            found.is_some_and(|(t, proven)| t <= 35 && !proven),
            "{found:?}"
        );
    }
    #[test]
    fn idle_and_slow_flows_stay_healthy_for_verdict_b() {
        let l = Liveness::new(SILENCE);
        assert_eq!(run_b(&l, 600, |_, _| {}), None);
        // Three flows that wait 50 s for their answer, or never get one.
        for answer in [true, false] {
            let l = Liveness::new(SILENCE);
            let targets = hosts(&l, 3);
            let mut flows: Vec<_> = targets.iter().map(|t| quiet_flow(&l, t, S(0))).collect();
            let found = run_b(&l, 60, |l, t| {
                if answer && t == S(50) {
                    flows.iter_mut().for_each(|w| l.read(w));
                }
            });
            assert_eq!(found, None);
        }
    }
    #[test]
    fn ordinary_traffic_with_a_fifth_silent_stays_healthy() {
        // ~80 and ~300 opens a minute, every fifth silent. Silent flows go to
        // hosts that never answer, so only the share keeps this healthy at
        // the higher rate (60 silent a minute on 10 hosts).
        for step in [750, 200] {
            let l = Liveness::new(SILENCE);
            let targets = hosts(&l, 30);
            let (silent, live) = targets.split_at(10);
            for (i, ms) in (0..600_000).step_by(step).enumerate() {
                let t = Duration::from_millis(ms);
                if i % 5 == 0 {
                    quiet_flow(&l, &silent[i / 5 % silent.len()], t);
                } else {
                    answered_flow(&l, &live[i % live.len()], t);
                }
                if ms % 1000 < step as u64 {
                    assert_eq!(l.degraded_at(t), None, "{step} ms at {t:?}");
                }
            }
        }
    }
    #[test]
    fn verdict_b_needs_count_and_spread() {
        // 23 silent flows across 10 hosts in one slot: one short.
        for (n, expected) in [(23, None), (24, Some((15, false)))] {
            let l = Liveness::new(SILENCE);
            let targets = hosts(&l, 10);
            for i in 0..n {
                quiet_flow(&l, &targets[i % 10], S(0));
            }
            assert_eq!(run_b(&l, 70, |_, _| {}), expected, "{n}");
        }
        // Slot 0 leaves the judged window at 75 s.
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 10);
        for i in 0..24 {
            quiet_flow(&l, &targets[i % 10], S(0));
        }
        assert_eq!(l.degraded_at(S(74)), Some(false));
        assert_eq!(l.degraded_at(S(75)), None);
        // A hundred silent flows to two hosts are an application retrying.
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 2);
        let found = run_b(&l, 65, |l, t| {
            for target in &targets {
                quiet_flow(l, target, t);
            }
        });
        assert_eq!(found, None);
    }
    #[test]
    fn verdict_b_thresholds() {
        let q = |wrote, answered, failed, hosts| Quiet {
            wrote,
            answered,
            failed,
            hosts,
        };
        assert!(quiet(&q(24, 0, 0, 6)));
        assert!(quiet(&q(0, 0, 24, 6)));
        assert!(!quiet(&q(23, 0, 0, 6)));
        assert!(!quiet(&q(24, 0, 0, 5)));
        // Exactly 80% unanswered passes; just below does not.
        assert!(quiet(&q(30, 6, 0, 6)));
        assert!(!quiet(&q(31, 7, 0, 6)));
        // Answers beyond writes (a race on recycling) are clamped.
        assert!(quiet(&q(0, 10, 24, 6)));
        assert!(!quiet(&Quiet::default()));
    }
    #[test]
    fn unwatched_ports_and_neutral_flows_do_not_count() {
        assert!(!answers_first("192.0.2.1:6881"));
        assert!(answers_first("[2001:db8::1]:853"));
        assert!(answers_first("example.invalid:8443"));
        assert!(!answers_first("192.0.2.1"));
        let l = Liveness::new(SILENCE);
        let targets: Vec<_> = hosts(&l, 30)
            .into_iter()
            .map(|t| t.replace(":443", ":6881"))
            .collect();
        let found = run_b(&l, 65, |l, t| {
            l.inbound();
            for target in &targets {
                assert_eq!(quiet_flow(l, target, t), Watch::Off);
                l.opened_at(&Err(crate::Error::Timeout), target, t, t);
            }
        });
        assert_eq!(found, None);
        // Watched flows that never write, or hear from the server first.
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 24);
        let found = run_b(&l, 65, |l, t| {
            for target in &targets {
                let mut idle = l.watch(target);
                assert!(matches!(idle, Watch::Fresh(_)));
                let mut first = l.watch(target);
                l.read(&mut first);
                l.wrote_at(&mut first, t);
                assert_eq!(first, Watch::Off);
                // Dropped unwritten: neither quiet nor answered.
                l.read(&mut idle);
            }
        });
        assert_eq!(found, None);
    }
    #[test]
    fn relay_inbound_does_not_clear_verdict_b() {
        let l = Liveness::new(SILENCE);
        let targets = hosts(&l, 10);
        let found = run_b(&l, 65, |l, t| {
            // Shared UDP relay and ICMP replies arrive every second.
            l.inbound();
            if t < S(5) {
                for target in &targets {
                    quiet_flow(l, target, t);
                }
            }
        });
        assert_eq!(found, Some((15, false)));
    }
    #[test]
    fn late_answers_after_rollover_are_ignored() {
        let l = Liveness::new(SILENCE);
        let [one] = hosts(&l, 1).try_into().unwrap();
        let mut old = quiet_flow(&l, &one, S(0));
        assert_eq!(old, Watch::Wrote(l.host(&one), 0));
        // Slot 16 reuses ring position 0.
        let later = SLOT * SLOTS as u32;
        quiet_flow(&l, &one, later);
        l.read(&mut old);
        let slot = &l.slots[0];
        assert!(slot.is(SLOTS as u64));
        assert_eq!(
            (slot.wrote.load(Relaxed), slot.answered.load(Relaxed)),
            (1, 0)
        );
        // A late write dated into the recycled slot is dropped too.
        quiet_flow(&l, &one, S(0));
        assert_eq!(slot.wrote.load(Relaxed), 1);
        assert!(
            l.quiet_at(later + GRACE + SLOT).answered <= l.quiet_at(later + GRACE + SLOT).wrote
        );
    }
    #[test]
    fn verdict_b_is_per_session_and_counts_flows_process_wide() {
        let old = Liveness::new(SILENCE);
        let new = Liveness::new(SILENCE);
        let before = FLOWS.answered.load(Relaxed);
        for target in hosts(&old, 10) {
            for _ in 0..3 {
                closed(quiet_flow(&old, &target, S(0)));
            }
        }
        assert_eq!(old.degraded_at(S(15)), Some(false));
        assert_eq!(new.degraded_at(S(15)), None);
        answered_flow(&new, "192.0.2.1:443", S(0));
        assert!(FLOWS.answered.load(Relaxed) > before);
        assert!(FLOWS.quiet.load(Relaxed) >= 30);
    }
}

// Independent tester coverage (issue #99); test-only, separate file.
#[cfg(test)]
mod tester_tests;
