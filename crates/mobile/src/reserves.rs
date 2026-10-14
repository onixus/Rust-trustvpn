//! Explicit permitted candidates, one finite budget per logical mobile session.
use std::time::Duration;
pub const LIMIT: u32 = rtrust_control::recovery::MAX_ATTEMPTS;
pub struct Planner {
    count: usize,
    selected: usize,
    attempts: u32,
    denied: [bool; 4],
}
impl Planner {
    pub fn new(count: usize) -> Result<Self, String> {
        if !(1..=4).contains(&count) {
            return Err("Permit primary and at most three backups".into());
        }
        Ok(Self {
            count,
            selected: 0,
            attempts: 0,
            denied: [false; 4],
        })
    }
    pub fn begin(&mut self) -> Option<usize> {
        if self.attempts >= LIMIT || self.denied[..self.count].iter().all(|v| *v) {
            return None;
        }
        while self.denied[self.selected] {
            self.selected = (self.selected + 1) % self.count;
        }
        self.attempts += 1;
        Some(self.selected)
    }
    pub fn attempts(&self) -> u32 {
        self.attempts
    }
    pub fn selected(&self) -> usize {
        self.selected
    }
    /// A degraded exit after a stable session that delivered traffic is not a
    /// failed attempt: refund it, so such exits over days cannot exhaust the
    /// finite budget. Unproven or short sessions still count.
    pub fn degraded(&mut self, proven: bool, connected: Duration) {
        if proven && connected >= rtrust_control::recovery::STABLE_CONNECTION {
            self.attempts = self.attempts.saturating_sub(1);
        }
    }
    pub fn failed(&mut self, fatal: bool, connected: Duration, jitter: u64) -> Duration {
        if fatal {
            self.denied[self.selected] = true;
        }
        self.selected = (self.selected + 1) % self.count;
        let backoff = (3u64 << self.attempts.saturating_sub(1).min(4)).min(48);
        let cooldown = if connected.is_zero() {
            0
        } else {
            60u64.saturating_sub(connected.as_secs())
        };
        Duration::from_secs(backoff.max(cooldown) + jitter % 4)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_candidates_budget_and_fatal_isolation() {
        let mut p = Planner::new(3).unwrap();
        assert_eq!(p.begin(), Some(0));
        p.failed(true, Duration::ZERO, 0);
        assert_eq!(p.begin(), Some(1));
        p.failed(false, Duration::from_secs(1), 0);
        assert_eq!(p.begin(), Some(2));
        p.failed(false, Duration::ZERO, 0);
        assert_eq!(p.begin(), Some(1));
        for _ in 4..LIMIT {
            p.failed(false, Duration::ZERO, 0);
            assert!(p.begin().is_some());
        }
        assert!(p.begin().is_none());
        assert_eq!(p.attempts(), LIMIT);
        let mut fixed = Planner::new(1).unwrap();
        fixed.begin();
        fixed.failed(true, Duration::ZERO, 0);
        assert!(fixed.begin().is_none());
    }
    #[test]
    fn only_proven_stable_degraded_exits_are_refunded() {
        use rtrust_control::recovery::STABLE_CONNECTION;
        let mut p = Planner::new(1).unwrap();
        for _ in 0..10 * LIMIT {
            assert!(p.begin().is_some());
            p.degraded(true, STABLE_CONNECTION);
            p.failed(false, STABLE_CONNECTION, 0);
        }
        assert_eq!(p.attempts(), 0);
        for (proven, connected) in [
            (false, Duration::from_secs(3600)),
            (true, STABLE_CONNECTION - Duration::from_secs(1)),
        ] {
            let mut p = Planner::new(1).unwrap();
            for _ in 0..LIMIT {
                assert!(p.begin().is_some());
                p.degraded(proven, connected);
                p.failed(false, connected, 0);
            }
            assert!(p.begin().is_none());
        }
    }
}
