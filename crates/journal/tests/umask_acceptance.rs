//! Independent, unprivileged public-API regressions; NOT native Root acceptance.
//! Only child processes change umask, before exec and before journal threads exist.
#![cfg(unix)]

use rtrust_journal::{Budget, Class, Config, Journal, Owner, Path, Record, Transport};
use std::{
    ffi::CString,
    fs,
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, PermissionsExt, symlink},
        process::CommandExt,
    },
    path::{Path as FsPath, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const FLAG: &str = "RTRUST_INDEPENDENT_UMASK_CHILD";
const MASK: &str = "RTRUST_INDEPENDENT_UMASK_VALUE";
const WAIT: Duration = Duration::from_secs(5);

#[test]
fn current_user_creation_isolated_umasks() {
    run_children("creation");
}

#[test]
fn current_user_retention_preserves_private_active_and_archive() {
    run_children("retention");
}

#[test]
fn current_user_unsafe_objects_and_readonly_files_unchanged() {
    run_children("unsafe");
}

fn run_children(scenario: &str) {
    // Never turn a root-run suite into apparent ordinary-user evidence.
    assert_ne!(unsafe { libc::geteuid() }, 0, "requires nonroot runner");
    for mask in [0o022, 0o077] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "controlled_umask_child",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(FLAG, scenario)
            .env(MASK, mask.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        // Only an async-signal-safe syscall runs after fork. Parent umask is untouched.
        unsafe {
            command.pre_exec(move || {
                libc::umask(mask);
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("controlled umask child exceeded deadline: {scenario}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "umask child failed: {scenario}, mask={mask:o}\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(stdout.contains("1 passed; 0 failed"));
        assert!(stdout.contains(&format!("PASS: independent {scenario} mask={mask:o}")));
    }
}

#[test]
#[ignore = "exact subprocess helper; only invoked by the three parent tests"]
fn controlled_umask_child() {
    assert_ne!(unsafe { libc::geteuid() }, 0, "requires nonroot runner");
    let scenario = std::env::var(FLAG).expect("controlled child marker required");
    let mask: libc::mode_t = std::env::var(MASK).unwrap().parse().unwrap();
    assert!([0o022, 0o077].contains(&mask));
    // Only this already isolated child changes/observes its process-global mask.
    assert_eq!(unsafe { libc::umask(mask) }, mask);
    match scenario.as_str() {
        "creation" => creation(),
        "retention" => retention(),
        "unsafe" => unsafe_objects(),
        _ => panic!("unknown controlled scenario"),
    }
    println!("PASS: independent {scenario} mask={mask:o}");
}

fn config(path: PathBuf) -> Config {
    Config {
        directory: path,
        file: "events.log",
        owner: Owner::CurrentUser,
    }
}

fn chmod(path: &FsPath, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn mode(path: &FsPath) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn identity(path: &FsPath) -> (u64, u64, u32, u32, u64) {
    let meta = fs::symlink_metadata(path).unwrap();
    (
        meta.dev(),
        meta.ino(),
        meta.uid(),
        meta.mode(),
        meta.nlink(),
    )
}

fn record() -> Record {
    Record::failure(
        Path::Start,
        Class::Other,
        Transport::H2,
        98761,
        Budget::Burst,
        Duration::from_millis(19),
    )
}

fn submit(config: Config) -> Journal {
    let journal = Journal::spawn(move || Some(config));
    journal.submit(record());
    journal
}

fn acknowledged(journal: &Journal) {
    assert!(
        journal.flush(WAIT),
        "bounded writer acknowledgement missing"
    );
}

fn assert_written(path: &FsPath) {
    let text = fs::read_to_string(path).unwrap();
    assert_eq!(text.matches("attempt=98761 ").count(), 1);
}

fn creation() {
    for parent_mode in [0o755, 0o775] {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        let parent = base.join("existing-parent");
        fs::create_dir(&parent).unwrap();
        chmod(&parent, parent_mode);
        let before = identity(&parent);
        let leaf = parent.join("new-intermediate/journal");
        let journal = submit(config(leaf.clone()));
        acknowledged(&journal);
        assert_written(&leaf.join("events.log"));
        assert_eq!(mode(leaf.parent().unwrap()), 0o700);
        assert_eq!(mode(&leaf), 0o700);
        for name in ["events.log", "events.lock"] {
            assert_eq!(mode(&leaf.join(name)), 0o600);
            assert_eq!(fs::metadata(leaf.join(name)).unwrap().uid(), unsafe {
                libc::geteuid()
            });
        }
        let after = identity(&parent);
        // Creating a child directory legitimately changes the parent's nlink.
        assert_eq!(
            (after.0, after.1, after.2, after.3),
            (before.0, before.1, before.2, before.3),
            "existing ancestor identity/owner/mode changed"
        );
        assert!(!leaf.join("events.tmp").exists());
        drop(journal);
    }
    // Existing private modes are retained; broader user objects may only narrow.
    for file_mode in [0o600, 0o640] {
        let temp = tempfile::tempdir().unwrap();
        let leaf = temp.path().canonicalize().unwrap().join("existing");
        fs::create_dir(&leaf).unwrap();
        chmod(&leaf, 0o700);
        let file = leaf.join("events.log");
        fs::write(&file, seed_line(now(), 123)).unwrap();
        chmod(&file, file_mode);
        let before = fs::metadata(&file).unwrap();
        let journal = submit(config(leaf.clone()));
        acknowledged(&journal);
        assert_written(&file);
        assert_eq!(mode(&file), 0o600);
        assert_eq!(mode(&leaf), 0o700);
        assert_eq!(fs::metadata(&file).unwrap().ino(), before.ino());
        drop(journal);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn seed_line(time: u64, attempt: u32) -> String {
    format!(
        "{time} pid=123 connect_failed path=start class=other transport=h2 attempt={attempt} budget=burst duration_ms=19\n"
    )
}

fn retention() {
    for initial_mode in [0o600, 0o640] {
        let temp = tempfile::tempdir().unwrap();
        let leaf = temp.path().canonicalize().unwrap().join("journal");
        fs::create_dir(&leaf).unwrap();
        chmod(&leaf, 0o755);
        let mut old_files = Vec::new();
        for (name, attempt) in [("events.log", 41), ("events.log.1", 42)] {
            let path = leaf.join(name);
            let current = seed_line(now(), attempt);
            let expired = seed_line(1, attempt + 100);
            fs::write(&path, format!("{expired}{current}")).unwrap();
            chmod(&path, initial_mode);
            // Pin the original inode: a changed inode cannot be an allocation reuse.
            old_files.push((name, current, fs::File::open(&path).unwrap()));
        }
        fs::write(leaf.join("events.lock"), b"").unwrap();
        chmod(&leaf.join("events.lock"), 0o600);
        let lock_before = identity(&leaf.join("events.lock"));
        let journal = submit(config(leaf.clone()));
        acknowledged(&journal);
        for (name, current, pinned) in old_files {
            let path = leaf.join(name);
            let text = fs::read_to_string(&path).unwrap();
            assert!(text.starts_with(&current));
            assert!(!text.lines().any(|line| line.starts_with("1 ")));
            assert_ne!(
                fs::metadata(&path).unwrap().ino(),
                pinned.metadata().unwrap().ino()
            );
            assert_eq!(mode(&path), 0o600, "retained bytes must stay private");
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        }
        assert_written(&leaf.join("events.log"));
        assert_eq!(mode(&leaf), 0o700);
        assert_eq!(identity(&leaf.join("events.lock")), lock_before);
        assert!(!leaf.join("events.tmp").exists());
        drop(journal);
    }
}

fn unsafe_objects() {
    for name in ["events.log", "events.log.1", "events.lock", "events.tmp"] {
        for kind in ["symlink", "hardlink", "directory", "fifo"] {
            let temp = tempfile::tempdir().unwrap();
            let base = temp.path().canonicalize().unwrap();
            let leaf = base.join("journal");
            fs::create_dir(&leaf).unwrap();
            chmod(&leaf, 0o700);
            let canary = base.join("canary");
            fs::write(&canary, b"synthetic private sentinel\n").unwrap();
            chmod(&canary, 0o640);
            let object = leaf.join(name);
            match kind {
                "symlink" => symlink(&canary, &object).unwrap(),
                "hardlink" => fs::hard_link(&canary, &object).unwrap(),
                "directory" => fs::create_dir(&object).unwrap(),
                "fifo" => {
                    let c = CString::new(object.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                }
                _ => unreachable!(),
            }
            let canary_before = identity(&canary);
            let object_before = identity(&object);
            let journal = submit(config(leaf.clone()));
            acknowledged(&journal);
            assert_eq!(identity(&canary), canary_before);
            assert_eq!(identity(&object), object_before);
            assert_eq!(fs::read(&canary).unwrap(), b"synthetic private sentinel\n");
            // No unsafe managed object may be bypassed to create a successful record.
            if name != "events.log" {
                assert!(!leaf.join("events.log").exists());
            }
            drop(journal);
        }
        for private_mode in [0o400, 0o000] {
            let temp = tempfile::tempdir().unwrap();
            let leaf = temp.path().canonicalize().unwrap().join("journal");
            fs::create_dir(&leaf).unwrap();
            chmod(&leaf, 0o700);
            let file = leaf.join(name);
            let bytes = seed_line(now(), 617);
            fs::write(&file, &bytes).unwrap();
            let mut pinned = fs::File::open(&file).unwrap();
            chmod(&file, private_mode);
            let before = identity(&file);
            let journal = submit(config(leaf.clone()));
            acknowledged(&journal);
            assert_eq!(
                identity(&file),
                before,
                "inaccessible file must not be repaired"
            );
            let mut after = String::new();
            pinned.read_to_string(&mut after).unwrap();
            assert_eq!(after, bytes);
            assert!(!leaf.join("events.tmp").exists() || name == "events.tmp");
            drop(journal);
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let base = temp.path().canonicalize().unwrap();
    let target = base.join("untouched-target");
    fs::create_dir(&target).unwrap();
    chmod(&target, 0o750);
    let before = identity(&target);
    let leaf = base.join("journal");
    symlink(&target, &leaf).unwrap();
    let journal = submit(config(leaf));
    assert!(
        !journal.flush(WAIT),
        "unsafe leaf must disable initialization"
    );
    assert_eq!(identity(&target), before);
    assert_eq!(fs::read_dir(&target).unwrap().count(), 0);
}
