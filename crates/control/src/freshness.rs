//! Finite managed access. Expiry never authorizes releasing a route guard.
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}
pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
impl Lease {
    pub fn validate_at(&self, now: u64) -> Result<(), String> {
        if self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > 86400000
            || now < self.issued_at_ms
            || now >= self.expires_at_ms
        {
            return Err("Access confirmation expired; synchronize the portal".into());
        }
        Ok(())
    }
}
fn uptime() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) } == 0 {
            return t.tv_sec as u64 * 1000 + t.tv_nsec as u64 / 1000000;
        }
    }
    #[cfg(target_os = "windows")]
    {
        unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }
    }
    #[cfg(not(target_os = "windows"))]
    {
        static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
        START
            .get_or_init(std::time::Instant::now)
            .elapsed()
            .as_millis() as u64
    }
}
pub struct Deadline {
    lease: Lease,
    start: u64,
    limit: u64,
    last_wall: u64,
    invalid: bool,
}
impl Deadline {
    pub fn new(lease: Lease) -> Result<Self, String> {
        let wall = now();
        lease.validate_at(wall)?;
        let start = uptime();
        let limit = start
            .checked_add(lease.expires_at_ms - wall)
            .ok_or("Invalid lease")?;
        Ok(Self {
            lease,
            start,
            limit,
            last_wall: wall,
            invalid: false,
        })
    }
    fn valid_at(&mut self, wall: u64, elapsed: u64) -> bool {
        let valid = !self.invalid
            && self.lease.validate_at(wall).is_ok()
            && wall >= self.last_wall
            && elapsed >= self.start
            && elapsed < self.limit;
        self.invalid |= !valid;
        self.last_wall = self.last_wall.max(wall);
        valid
    }
    pub async fn expired(&mut self) {
        loop {
            if !self.valid_at(now(), uptime()) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}
pub fn start(command: crate::Command) -> Result<(Option<Deadline>, crate::Command), String> {
    match command {
        crate::Command::StartLeased { lease, command } => {
            if !matches!(
                *command,
                crate::Command::Start { .. } | crate::Command::StartFull { .. }
            ) {
                return Err("Lease requires a normal start".into());
            }
            Ok((Some(Deadline::new(lease)?), *command))
        }
        command => Ok((None, command)),
    }
}
pub async fn while_valid<T>(
    deadline: Option<&mut Deadline>,
    future: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match deadline {
        None => future.await,
        Some(deadline) => {
            tokio::select! {biased;_=deadline.expired()=>Err("Access confirmation expired; synchronize the portal".into()),result=future=>result}
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn clock_sleep_and_expiry_cannot_extend_authority() {
        let lease = Lease {
            issued_at_ms: 1000,
            expires_at_ms: 6000,
        };
        let mut deadline = Deadline {
            lease,
            start: 100,
            limit: 5100,
            last_wall: 1000,
            invalid: false,
        };
        assert!(deadline.valid_at(2000, 1100));
        assert!(!deadline.valid_at(1999, 1101));
        assert!(!deadline.valid_at(3000, 2100));
        assert!(!deadline.valid_at(3000, 5100));
        assert!(
            Lease {
                issued_at_ms: 1,
                expires_at_ms: 86400002
            }
            .validate_at(2)
            .is_err()
        );
    }
}
