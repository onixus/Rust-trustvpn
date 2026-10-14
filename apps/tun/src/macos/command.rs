//! Bounded execution of fixed system tools, without a shell or inherited PATH.
use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
// Fast route/netstat processes should not pay a fixed 20 ms wait per call.
// Back off for longer operations so polling remains bounded and inexpensive.
fn poll_interval(elapsed: Duration) -> Duration {
    Duration::from_millis(if elapsed < Duration::from_millis(20) {
        1
    } else if elapsed < Duration::from_millis(100) {
        5
    } else {
        20
    })
}
pub(super) fn capture(path: &str, args: &[&str]) -> Result<(String, String), String> {
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| format!("Cannot start {path}"))?;
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut bytes = vec![];
        stdout.take(262145).read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = std::thread::spawn(move || {
        let mut bytes = vec![];
        stderr.take(4097).read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let until = started + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < until => {
                let now = Instant::now();
                std::thread::sleep(
                    poll_interval(now.duration_since(started))
                        .min(until.saturating_duration_since(now)),
                );
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdout = out
        .join()
        .map_err(|_| "System output reader failed")?
        .map_err(|_| "Cannot read system output")?;
    let stderr = err
        .join()
        .map_err(|_| "System error reader failed")?
        .map_err(|_| "Cannot read system error output")?;
    if !status.is_some_and(|s| s.success()) || stdout.len() > 262144 || stderr.len() > 4096 {
        return Err(format!("System operation failed or timed out: {path}"));
    }
    Ok((
        String::from_utf8(stdout).map_err(|_| "Invalid system output")?,
        String::from_utf8(stderr).map_err(|_| "Invalid system error output")?,
    ))
}

pub(super) fn run(path: &str, args: &[&str]) -> Result<String, String> {
    capture(path, args).map(|v| v.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adaptive_polling_bounds_fast_and_slow_waits() {
        for (elapsed_ms, wait_ms) in [(0, 1), (19, 1), (20, 5), (99, 5), (100, 20), (15000, 20)] {
            assert_eq!(
                poll_interval(Duration::from_millis(elapsed_ms)),
                Duration::from_millis(wait_ms)
            );
        }
    }
    #[test]
    fn real_short_command_capture_preserves_empty_output() {
        let started = Instant::now();
        let mut durations = vec![];
        for _ in 0..10 {
            let before = Instant::now();
            assert_eq!(
                capture("/usr/bin/true", &[]).unwrap(),
                (String::new(), String::new())
            );
            durations.push(before.elapsed().as_micros());
        }
        // Observed local command timings, deliberately no flaky performance
        // assertion or claim about native VPN Stop acceptance.
        eprintln!(
            "short_command samples_us={durations:?} total_us={}",
            started.elapsed().as_micros()
        );
    }
}
