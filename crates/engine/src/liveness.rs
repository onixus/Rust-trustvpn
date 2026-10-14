//! Per-session data-plane liveness. Fixed-size counters only: no flow,
//! destination or address is kept. Each session owns its own instance, so a
//! stale flow of a previous session can never vouch for a newer one.
use std::{
    sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed},
    time::{Duration, Instant},
};

/// Outbound demand must stay unanswered this long before a session is judged.
pub(crate) const SILENCE: Duration = Duration::from_secs(20);
/// Opens that failed in transport (timeout, protocol, I/O) since the last inbound byte.
pub(crate) const FAILED_OPENS: u32 = 3;
/// Accepted TCP CONNECTs since the last inbound byte: accepted, yet all silent.
pub(crate) const SILENT_OPENS: u32 = 5;
/// Consecutive health checks finished without their response.
pub(crate) const LOST_CHECKS: u32 = 2;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Healthy,
    Degraded,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Snapshot {
    /// Oldest outbound demand not followed by any inbound byte.
    pub demand: Option<Duration>,
    pub failed: u32,
    pub silent: u32,
    pub lost: u32,
}
/// Degraded only with unanswered demand AND transport failure evidence. An
/// idle session stays healthy whatever its checks report (endpoint 1.1.0
/// loses `_check` responses on blocked streams).
pub(crate) fn verdict(s: &Snapshot, now: Duration, silence: Duration) -> Verdict {
    let unanswered = s
        .demand
        .is_some_and(|since| now.saturating_sub(since) >= silence);
    if unanswered && (s.failed >= FAILED_OPENS || s.lost >= LOST_CHECKS || s.silent >= SILENT_OPENS)
    {
        Verdict::Degraded
    } else {
        Verdict::Healthy
    }
}

pub(crate) struct Liveness {
    epoch: Instant,
    silence: Duration,
    /// Milliseconds since `epoch` plus one; zero means no unanswered demand.
    demand: AtomicU64,
    failed: AtomicU32,
    silent: AtomicU32,
    lost: AtomicU32,
}
impl Liveness {
    pub fn new(silence: Duration) -> Self {
        Self {
            epoch: Instant::now(),
            silence,
            demand: AtomicU64::new(0),
            failed: AtomicU32::new(0),
            silent: AtomicU32::new(0),
            lost: AtomicU32::new(0),
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
        for counter in [&self.failed, &self.silent] {
            if counter.load(Relaxed) != 0 {
                counter.store(0, Relaxed);
            }
        }
        if self.demand.load(Relaxed) != 0 {
            self.demand.store(0, Relaxed);
        }
    }
    pub fn opened(&self, outcome: &crate::Result<()>, flow: bool) {
        use crate::Error;
        match outcome {
            Ok(()) if flow => {
                self.silent.fetch_add(1, Relaxed);
            }
            Err(Error::Protocol | Error::Timeout | Error::Io) => {
                self.failed.fetch_add(1, Relaxed);
            }
            // Rejected, authentication or destination: the endpoint answered.
            _ => {}
        }
    }
    pub fn checked(&self, answered: bool) {
        if answered {
            self.lost.store(0, Relaxed);
        } else {
            self.lost.fetch_add(1, Relaxed);
        }
    }
    fn snapshot(&self) -> Snapshot {
        let demand = self.demand.load(Relaxed);
        Snapshot {
            demand: (demand != 0).then(|| Duration::from_millis(demand - 1)),
            failed: self.failed.load(Relaxed),
            silent: self.silent.load(Relaxed),
            lost: self.lost.load(Relaxed),
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
    fn judge(s: &Snapshot, now: u64) -> Verdict {
        verdict(s, S(now), SILENCE)
    }
    #[test]
    fn idle_session_with_lost_checks_stays_healthy() {
        let l = Liveness::new(SILENCE);
        l.checked(true);
        for _ in 0..120 {
            l.checked(false);
        }
        let s = l.snapshot();
        assert_eq!(s.lost, 120);
        assert_eq!(judge(&s, 600), Verdict::Healthy);
    }
    #[test]
    fn failed_opens_degrade_only_after_the_silence_window() {
        let s = Snapshot {
            demand: Some(S(100)),
            failed: 3,
            ..Default::default()
        };
        assert_eq!(judge(&s, 119), Verdict::Healthy);
        assert_eq!(judge(&s, 120), Verdict::Degraded);
        let two = Snapshot { failed: 2, ..s };
        assert_eq!(judge(&two, 200), Verdict::Healthy);
    }
    #[test]
    fn inbound_answers_demand_and_clears_failures() {
        let l = Liveness::new(SILENCE);
        l.outbound();
        for _ in 0..3 {
            l.opened(&Err(crate::Error::Timeout), true);
        }
        l.inbound();
        let s = l.snapshot();
        assert!(s.demand.is_none());
        assert_eq!((s.failed, s.silent), (0, 0));
        assert_eq!(judge(&s, 3600), Verdict::Healthy);
    }
    #[test]
    fn one_way_traffic_without_failure_evidence_is_healthy() {
        let l = Liveness::new(SILENCE);
        for _ in 0..1000 {
            l.outbound();
        }
        assert_eq!(l.snapshot().demand, Some(Duration::ZERO));
        let s = Snapshot {
            demand: Some(S(0)),
            ..Default::default()
        };
        assert_eq!(judge(&s, 3600), Verdict::Healthy);
    }
    #[test]
    fn consecutive_lost_checks_with_demand_degrade_and_an_answer_resets() {
        let l = Liveness::new(SILENCE);
        l.checked(false);
        l.checked(false);
        let mut s = l.snapshot();
        s.demand = Some(S(0));
        assert_eq!(judge(&s, 20), Verdict::Degraded);
        l.checked(false);
        l.checked(true);
        l.checked(false);
        let mut s = l.snapshot();
        assert_eq!(s.lost, 1);
        s.demand = Some(S(0));
        assert_eq!(judge(&s, 20), Verdict::Healthy);
    }
    #[test]
    fn rejected_and_local_errors_are_neutral() {
        let l = Liveness::new(SILENCE);
        for error in [
            crate::Error::Rejected(502),
            crate::Error::Authentication,
            crate::Error::Destination,
            crate::Error::Unsupported("x"),
        ] {
            for _ in 0..10 {
                l.opened(&Err(error.clone()), true);
            }
        }
        let mut s = l.snapshot();
        assert_eq!((s.failed, s.silent), (0, 0));
        s.demand = Some(S(0));
        assert_eq!(judge(&s, 3600), Verdict::Healthy);
    }
    #[test]
    fn accepted_but_silent_flows_degrade() {
        let l = Liveness::new(SILENCE);
        for _ in 0..4 {
            l.opened(&Ok(()), true);
        }
        // Shared UDP/ICMP relay streams are not individual flows.
        for _ in 0..10 {
            l.opened(&Ok(()), false);
        }
        let mut s = l.snapshot();
        s.demand = Some(S(0));
        assert_eq!(judge(&s, 20), Verdict::Healthy);
        l.opened(&Ok(()), true);
        let mut s = l.snapshot();
        s.demand = Some(S(0));
        assert_eq!(judge(&s, 19), Verdict::Healthy);
        assert_eq!(judge(&s, 20), Verdict::Degraded);
    }
    #[test]
    fn sessions_do_not_share_evidence() {
        let old = Liveness::new(SILENCE);
        let new = Liveness::new(SILENCE);
        new.outbound();
        for _ in 0..3 {
            new.opened(&Err(crate::Error::Protocol), true);
        }
        old.inbound();
        let mut s = new.snapshot();
        assert_eq!(s.failed, 3);
        assert!(s.demand.is_some());
        s.demand = Some(S(0));
        assert_eq!(judge(&s, 20), Verdict::Degraded);
    }
}
