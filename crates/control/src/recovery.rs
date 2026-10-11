//! Resource budget for guarded reconnects. Scheduling never changes VPN policy.
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
    pub fn disconnected(&mut self, connected_for: Duration) {
        if connected_for >= STABLE_CONNECTION {
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
mod tests {
    use super::*;
    #[test]
    fn outage_and_flapping_cannot_exceed_burst_budget() {
        let mut budget = Budget::default();
        for seconds in [2, 4, 8, 16, 30, 30, 30, 30] {
            assert_eq!(budget.next_delay(0), Duration::from_secs(seconds));
            budget.disconnected(Duration::from_secs(29));
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
        budget.disconnected(STABLE_CONNECTION);
        assert_eq!(budget.next_delay(0), Duration::from_secs(2));
    }
}
