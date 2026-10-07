//! Detect a suspended process even on Darwin, where Instant excludes system sleep.
use std::time::{Duration, Instant, SystemTime};

pub struct Watch {
    wall: SystemTime,
    monotonic: Instant,
}
impl Default for Watch {
    fn default() -> Self {
        Self {
            wall: SystemTime::now(),
            monotonic: Instant::now(),
        }
    }
}
impl Watch {
    pub fn resumed(&mut self, expected: Duration) -> bool {
        let wall = SystemTime::now();
        let monotonic = Instant::now();
        let result = gap(
            wall.duration_since(self.wall).unwrap_or_default(),
            monotonic.duration_since(self.monotonic),
            expected,
        );
        self.wall = wall;
        self.monotonic = monotonic;
        result
    }
}
fn gap(wall: Duration, monotonic: Duration, expected: Duration) -> bool {
    let tolerance = Duration::from_secs(2);
    wall > monotonic.saturating_add(tolerance) || monotonic > expected.saturating_add(tolerance)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_darwin_sleep_and_process_suspension() {
        let seconds = Duration::from_secs;
        assert!(gap(seconds(300), seconds(2), seconds(2)));
        assert!(gap(seconds(300), seconds(300), seconds(2)));
        assert!(!gap(seconds(2), seconds(2), seconds(2)));
        assert!(!gap(seconds(3), seconds(2), seconds(2)));
        assert!(!gap(Duration::ZERO, seconds(2), seconds(2)));
    }
}
