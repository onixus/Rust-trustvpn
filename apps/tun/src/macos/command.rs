//! Bounded execution of fixed system tools, without a shell or inherited PATH.
use std::{
    io::Read,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
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
    let until = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
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
