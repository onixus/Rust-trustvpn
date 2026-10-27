//! Rotation/retention policy, independent of the wall clock and platform APIs.
use crate::Config;
#[cfg(unix)]
use crate::unix::Directory;
#[cfg(windows)]
use crate::windows::Directory;
use std::io::{self, Read, Write};
pub(crate) const SEGMENT: u64 = 1_000_000;
pub(crate) const TOTAL: u64 = 15_000_000;
pub(crate) const AGE: u64 = 7 * 24 * 60 * 60 * 1000;
const MAX_SEGMENTS: usize = 1024;
fn invalid() -> io::Error {
    io::Error::other("unsafe journal state")
}
pub(crate) struct Store {
    dir: Directory,
    base: &'static str,
    segment: u64,
    total: u64,
}
impl Store {
    pub fn open(config: Config) -> io::Result<Self> {
        if !matches!(config.file, "events.log" | "socks-events.log") {
            return Err(invalid());
        }
        let dir = Directory::open(&config.directory, config.owner)?;
        Ok(Self {
            dir,
            base: config.file,
            segment: SEGMENT,
            total: TOTAL,
        })
    }
    fn segments(&self) -> io::Result<Vec<(u64, String, u64)>> {
        let mut entries = Vec::new();
        for name in self.dir.names()? {
            let seq = if name == self.base {
                Some(u64::MAX)
            } else {
                name.strip_prefix(self.base)
                    .and_then(|n| n.strip_prefix('.'))
                    .filter(|n| {
                        !n.is_empty()
                            && n.len() <= 20
                            && n.bytes().all(|b| b.is_ascii_digit())
                            && !n.starts_with('0')
                    })
                    .and_then(|n| n.parse::<u64>().ok())
                    .filter(|n| *n < u64::MAX)
            };
            if let Some(seq) = seq {
                if entries.len() >= MAX_SEGMENTS {
                    return Err(invalid());
                }
                let file = self.dir.file(&name, false)?;
                let size = file.metadata()?.len();
                if size > self.segment {
                    return Err(invalid());
                }
                entries.push((seq, name, size));
            }
        }
        entries.sort_by_key(|e| e.0);
        Ok(entries)
    }
    pub fn prune(&mut self, now: u64) -> io::Result<()> {
        let _lock = self.dir.lock()?;
        self.prune_locked(now)
    }
    fn prune_locked(&self, now: u64) -> io::Result<()> {
        // Read at most one bounded segment at a time. Mixed current segments are
        // rewritten too: a recent tail must not retain expired records forever.
        // A crash may leave an owned atomic-rewrite temporary. Verify before
        // removing it; it must never silently consume unaccounted cap space.
        match self.dir.file("events.tmp", false) {
            Ok(file) => {
                drop(file);
                self.dir.remove("events.tmp")?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        for (sequence, name, _) in self.segments()? {
            let mut bytes = Vec::new();
            // Skip only confirmed absence, never permission/unsafe-object errors.
            let file = match self.dir.file(&name, false) {
                Ok(file) => file,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            file.take(self.segment + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > self.segment {
                return Err(invalid());
            }
            let mut kept = Vec::new();
            for line in bytes.split_inclusive(|b| *b == b'\n') {
                if line.len() > 1024 || line.last() != Some(&b'\n') {
                    continue;
                }
                let time = line
                    .split(|b| *b == b' ')
                    .next()
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .and_then(|s| s.parse::<u64>().ok());
                if time.is_some_and(|t| now.saturating_sub(t) <= AGE) {
                    kept.extend_from_slice(line);
                }
            }
            if kept == bytes {
                continue;
            }
            if kept.is_empty() {
                self.dir.remove(&name)?;
            } else {
                // Temporary data also counts towards the disk cap. Only evict
                // older segments; if insufficient, discard this target rather
                // than sacrificing any newer history for its temporary copy.
                let entries = self.segments()?;
                let mut size: u64 = entries.iter().map(|e| e.2).sum();
                for (other_sequence, other, len) in entries {
                    if size + kept.len() as u64 <= self.total || other_sequence >= sequence {
                        break;
                    }
                    self.dir.remove(&other)?;
                    size -= len;
                }
                if size + kept.len() as u64 > self.total {
                    self.dir.remove(&name)?;
                    continue;
                }
                self.dir.replace(&name, &kept)?;
            }
        }
        Ok(())
    }
    pub fn append(&mut self, line: &str, now: u64) -> io::Result<()> {
        if line.len() > 1024 || line.len() as u64 > self.segment {
            return Err(invalid());
        }
        let _lock = self.dir.lock()?;
        self.prune_locked(now)?;
        let mut entries = self.segments()?;
        let current = entries.iter().find(|e| e.0 == u64::MAX).map_or(0, |e| e.2);
        if current + line.len() as u64 > self.segment {
            let seq = entries
                .iter()
                .filter(|e| e.0 != u64::MAX)
                .map(|e| e.0)
                .max()
                .unwrap_or(0)
                .checked_add(1)
                .filter(|n| *n < u64::MAX)
                .ok_or_else(invalid)?;
            self.dir
                .rename(self.base, &format!("{}.{seq}", self.base))?;
            entries = self.segments()?;
        }
        let mut size: u64 = entries.iter().map(|e| e.2).sum();
        for (seq, name, len) in entries {
            if size + line.len() as u64 <= self.total {
                break;
            }
            if seq == u64::MAX {
                return Err(invalid());
            }
            self.dir.remove(&name)?;
            size -= len;
        }
        if size + line.len() as u64 > self.total {
            return Err(invalid());
        }
        let mut file = self.dir.file(self.base, true)?;
        file.write_all(line.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Owner;
    fn store() -> (tempfile::TempDir, Store) {
        let tmp = tempfile::tempdir().unwrap();
        let directory = tmp.path().canonicalize().unwrap().join("journal");
        let s = Store::open(Config {
            directory,
            file: "events.log",
            owner: Owner::CurrentUser,
        })
        .unwrap();
        (tmp, s)
    }
    #[test]
    fn strict_cap_after_every_append_and_recent_suffix_survives() {
        let (_tmp, mut s) = store();
        s.segment = 200;
        s.total = 600;
        for i in 0..200 {
            let line = format!("100 item={i:04} {}\n", "x".repeat(50));
            s.append(&line, 100).unwrap();
            let entries = s.segments().unwrap();
            assert!(entries.iter().map(|e| e.2).sum::<u64>() <= 600);
            assert!(entries.iter().map(|e| e.2).sum::<u64>() > 0);
            let mut text = String::new();
            s.dir
                .file("events.log", false)
                .unwrap()
                .read_to_string(&mut text)
                .unwrap();
            assert!(text.ends_with(&line));
        }
        assert!(s.segments().unwrap().iter().any(|e| e.0 != u64::MAX));
    }
    #[test]
    fn per_record_retention_in_current_and_rotated_boundary_and_future() {
        let (_tmp, mut s) = store();
        s.append("100 old\n", 100).unwrap();
        s.append(&format!("{} boundary\n", AGE + 100), AGE + 100)
            .unwrap();
        let mut text = String::new();
        s.dir
            .file("events.log", false)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.contains("old"));
        s.prune(AGE + 101).unwrap();
        text.clear();
        s.dir
            .file("events.log", false)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(!text.contains("old"));
        assert!(text.contains("boundary"));
        s.dir.rename("events.log", "events.log.9").unwrap();
        s.append(&format!("{} fresh\n", AGE * 2 + 102), AGE * 2 + 102)
            .unwrap();
        assert!(!s.segments().unwrap().iter().any(|e| e.1 == "events.log.9"));
        s.prune(1).unwrap();
        let mut rollback = String::new();
        s.dir
            .file("events.log", false)
            .unwrap()
            .read_to_string(&mut rollback)
            .unwrap();
        assert!(
            rollback.contains("fresh"),
            "RTC rollback must preserve future-dated history"
        );
        s.prune(AGE * 3 + 103).unwrap();
        assert!(s.segments().unwrap().is_empty());
    }
    #[test]
    fn near_cap_mixed_rewrite_discards_oldest_target_never_newer_history() {
        let (_tmp, mut s) = store();
        s.segment = 200;
        s.total = 600;
        let now = AGE + 2;
        let old = format!("1 {}\n", "x".repeat(97));
        let prefix = format!("{now} ");
        let fresh = format!("{prefix}{}\n", "y".repeat(99 - prefix.len()));
        assert_eq!(old.len(), 100);
        assert_eq!(fresh.len(), 100);
        for name in ["events.log.1", "events.log.2", "events.log"] {
            let mut file = s.dir.file(name, true).unwrap();
            file.write_all(format!("{old}{fresh}").as_bytes()).unwrap();
        }
        s.append(&format!("{now} newest\n"), now).unwrap();
        assert!(s.segments().unwrap().iter().map(|e| e.2).sum::<u64>() <= 600);
        assert!(s.dir.file("events.log.1", false).is_err());
        let mut newer = String::new();
        s.dir
            .file("events.log.2", false)
            .unwrap()
            .read_to_string(&mut newer)
            .unwrap();
        assert_eq!(newer, fresh);
        let mut text = String::new();
        s.dir
            .file("events.log", false)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert!(text.ends_with("newest\n"));
        assert!(!text.contains('x'));
    }
    #[test]
    fn two_appends_and_restart_preserve_previous_records() {
        let (tmp, mut s) = store();
        s.append("100 first\n", 100).unwrap();
        s.append("100 second\n", 100).unwrap();
        drop(s);
        let mut s = Store::open(Config {
            directory: tmp.path().canonicalize().unwrap().join("journal"),
            file: "events.log",
            owner: Owner::CurrentUser,
        })
        .unwrap();
        s.append("100 third\n", 100).unwrap();
        let mut text = String::new();
        s.dir
            .file("events.log", false)
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "100 first\n100 second\n100 third\n");
    }
    #[cfg(windows)]
    #[test]
    fn native_hardlink_is_rejected_without_modifying_canary() {
        let (tmp, mut s) = store();
        let external = tmp.path().join("canary");
        std::fs::write(&external, b"unchanged").unwrap();
        std::fs::hard_link(&external, tmp.path().join("journal/events.log")).unwrap();
        assert!(s.append("1 test\n", 1).is_err());
        assert_eq!(std::fs::read(&external).unwrap(), b"unchanged");
    }
    #[cfg(windows)]
    #[test]
    #[ignore = "requires Windows symbolic-link privilege or Developer Mode; native device gate"]
    fn native_reparse_is_rejected_without_modifying_canary() {
        let (tmp, mut s) = store();
        let external = tmp.path().join("canary");
        std::fs::write(&external, b"unchanged").unwrap();
        std::os::windows::fs::symlink_file(&external, tmp.path().join("journal/events.log"))
            .unwrap();
        assert!(s.append("1 test\n", 1).is_err());
        assert_eq!(std::fs::read(&external).unwrap(), b"unchanged");
    }
    #[cfg(unix)]
    #[test]
    fn private_directory_and_file_modes_are_repaired() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (tmp, mut s) = store();
        let dir = tmp.path().join("journal");
        s.append("1 test\n", 1).unwrap();
        let file = dir.join("events.log");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        s.append("1 next\n", 1).unwrap();
        assert_eq!(std::fs::metadata(file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(dir).unwrap().mode() & 0o777, 0o700);
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_reserved_objects_never_followed_or_changed() {
        use std::os::unix::fs::symlink;
        for name in ["events.log.1", "events.lock", "events.tmp"] {
            for kind in 0..3 {
                let (tmp, mut s) = store();
                let external = tmp.path().join("canary");
                std::fs::write(&external, b"unchanged").unwrap();
                let path = tmp.path().join("journal").join(name);
                match kind {
                    0 => symlink(&external, &path).unwrap(),
                    1 => std::fs::hard_link(&external, &path).unwrap(),
                    _ => std::fs::create_dir(&path).unwrap(),
                };
                assert!(s.append("1 test\n", 1).is_err());
                assert_eq!(std::fs::read(&external).unwrap(), b"unchanged");
            }
        }
    }
    #[cfg(unix)]
    #[test]
    fn unsafe_files_never_followed_or_changed() {
        use std::os::unix::fs::symlink;
        for kind in 0..3 {
            let (tmp, mut s) = store();
            let external = tmp.path().join("canary");
            std::fs::write(&external, b"unchanged").unwrap();
            let path = tmp.path().join("journal/events.log");
            match kind {
                0 => symlink(&external, &path).unwrap(),
                1 => std::fs::hard_link(&external, &path).unwrap(),
                _ => std::fs::create_dir(&path).unwrap(),
            }
            assert!(s.append("1 test\n", 1).is_err());
            assert_eq!(std::fs::read(external).unwrap(), b"unchanged");
        }
    }
}
