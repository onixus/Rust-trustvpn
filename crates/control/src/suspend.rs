//! Detect Darwin sleep from kernel clocks, never from wall-clock corrections.
use std::time::Duration;

pub struct Watch {
    clocks: Option<(Duration, Duration)>,
}
impl Default for Watch {
    fn default() -> Self {
        Self { clocks: clocks() }
    }
}
impl Watch {
    pub fn resumed(&mut self) -> bool {
        let current = clocks();
        let previous = std::mem::replace(&mut self.clocks, current);
        match (previous, current) {
            (Some((before_sleep, before_awake)), Some((sleep, awake))) => gap(
                sleep.saturating_sub(before_sleep),
                awake.saturating_sub(before_awake),
            ),
            _ => false,
        }
    }
}
fn clocks() -> Option<(Duration, Duration)> {
    fn read(clock: libc::clockid_t) -> Option<Duration> {
        let mut value = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(clock, &mut value) } != 0
            || value.tv_sec < 0
            || !(0..1_000_000_000).contains(&value.tv_nsec)
        {
            return None;
        }
        Some(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
    }
    let awake = read(libc::CLOCK_UPTIME_RAW)?;
    Some((read(libc::CLOCK_MONOTONIC)?, awake))
}
fn gap(with_sleep: Duration, awake: Duration) -> bool {
    with_sleep > awake.saturating_add(Duration::from_secs(2))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinguishes_sleep_from_scheduler_delay() {
        let seconds = Duration::from_secs;
        assert!(gap(seconds(300), seconds(2)));
        assert!(!gap(seconds(300), seconds(300)));
        assert!(!gap(seconds(3), seconds(2)));
        assert!(!gap(Duration::ZERO, seconds(2)));
    }
    #[test]
    fn kernel_clocks_are_available_without_privileges() {
        let mut watch = Watch::default();
        assert!(watch.clocks.is_some());
        assert!(!watch.resumed());
    }
}
