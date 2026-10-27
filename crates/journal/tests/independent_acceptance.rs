//! Independent acceptance through public APIs only; never opens the global sinks.
//! Fixtures are canonical temporary children, not installed service/device evidence.
use rtrust_journal::{Attempt, Budget, Class, Config, Journal, Owner, Path, Record, Transport};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, mpsc},
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(10);
const AGE: u64 = 7 * 24 * 60 * 60 * 1000;
const CANARIES: [&str; 7] = [
    "192.0.2.187:49123",
    "[2001:db8::187]:49123",
    "independent-host.invalid",
    "independent-sni.invalid",
    "independent-profile-secret",
    "independent-token-secret",
    "independent-username-secret",
];

fn fixture() -> (tempfile::TempDir, Config) {
    let temp = tempfile::tempdir().unwrap();
    let config = Config {
        directory: temp.path().canonicalize().unwrap().join("journal"),
        file: "events.log",
        owner: Owner::CurrentUser,
    };
    (temp, config)
}
fn spawn(config: Config) -> Journal {
    Journal::spawn(move || Some(config))
}
fn record(attempt: u32) -> Record {
    Record::failure(
        Path::Start,
        Class::Other,
        Transport::H2,
        attempt,
        Budget::Burst,
        Duration::from_millis(19),
    )
}
fn drain(journal: &Journal) {
    let deadline = Instant::now() + WAIT;
    while !journal.flush(Duration::from_millis(25)) {
        assert!(
            Instant::now() < deadline,
            "writer did not acknowledge bounded drain"
        );
        std::thread::yield_now();
    }
}
fn files(config: &Config) -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(&config.directory)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("events.log")
        })
        .collect();
    paths.sort();
    paths
}
fn contents(config: &Config) -> String {
    files(config)
        .into_iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect()
}
fn seed_line(time: u64, attempt: u32) -> String {
    format!(
        "{time} pid=1 connect_failed path=start class=other transport=h2 attempt={attempt} budget=burst duration_ms=19\n"
    )
}
fn assert_schema(text: &str) {
    for line in text.lines() {
        assert!(line.len() < 1024);
        assert!(!line.bytes().any(|b| b.is_ascii_control()));
        let fields: Vec<_> = line.split(' ').collect();
        assert_eq!(fields.len(), 9, "unexpected free-text/schema field");
        fields[0].parse::<u64>().unwrap();
        assert_eq!(fields[2], "connect_failed");
        fields[1]
            .strip_prefix("pid=")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(
            [
                "path=start",
                "path=reconnect",
                "path=wake_reconnect",
                "path=socks_recovery"
            ]
            .contains(&fields[3])
        );
        assert!(
            [
                "class=endpoint_unreachable",
                "class=tls",
                "class=authentication",
                "class=profile",
                "class=timeout",
                "class=local_bind",
                "class=protocol",
                "class=cancelled",
                "class=other"
            ]
            .contains(&fields[4])
        );
        assert!(
            [
                "transport=h2",
                "transport=h3",
                "transport=hysteria",
                "transport=amneziawg",
                "transport=unknown"
            ]
            .contains(&fields[5])
        );
        fields[6]
            .strip_prefix("attempt=")
            .unwrap()
            .parse::<u32>()
            .unwrap();
        assert!(["budget=burst", "budget=cooldown"].contains(&fields[7]));
        fields[8]
            .strip_prefix("duration_ms=")
            .unwrap()
            .parse::<u64>()
            .unwrap();
    }
    for canary in CANARIES {
        assert!(
            !text.contains(canary),
            "synthetic private input escaped typed schema"
        );
    }
}

#[test]
fn typed_classes_schema_and_canaries_survive_real_rotation() {
    use rtrust_engine::Error as E;
    let (_temp, config) = fixture();
    fs::create_dir(&config.directory).unwrap();
    let seed = seed_line(rtrust_journal::now_ms(), 0);
    let count = 1_000_000 / seed.len();
    fs::write(config.directory.join("events.log"), seed.repeat(count)).unwrap();
    let journal = spawn(config.clone());
    let raw = CANARIES.join(" ");
    let boxed = std::io::Error::other(raw);
    assert_eq!(rtrust_journal::classify_boxed(&boxed), Class::Other);
    let cases = [
        (E::Connect, Class::EndpointUnreachable),
        (E::Tls, Class::Tls),
        (E::Authentication, Class::Authentication),
        (
            E::Unsupported(
                "192.0.2.187:49123 [2001:db8::187]:49123 independent-host.invalid independent-sni.invalid independent-profile-secret independent-token-secret independent-username-secret",
            ),
            Class::Profile,
        ),
        (E::Timeout, Class::Timeout),
        (E::LocalBind, Class::LocalBind),
        (E::Rejected(503), Class::Protocol),
        (E::Closed(rtrust_engine::Close::Local), Class::Cancelled),
        (E::Io, Class::Other),
    ];
    let mut number = 0;
    for (error, expected) in cases {
        assert_eq!(rtrust_journal::classify(&error), expected);
        for path in [
            Path::Start,
            Path::Reconnect,
            Path::WakeReconnect,
            Path::SocksRecovery,
        ] {
            for transport in [
                Transport::H2,
                Transport::H3,
                Transport::Hysteria,
                Transport::AmneziaWg,
                Transport::Unknown,
            ] {
                for budget in [Budget::Burst, Budget::Cooldown] {
                    number += 1;
                    journal.submit(Record {
                        path,
                        class: expected,
                        transport,
                        budget,
                        ..record(number)
                    });
                }
            }
            drain(&journal);
        }
    }
    assert!(
        files(&config).len() >= 2,
        "must inspect actual rotated and current files"
    );
    let text = contents(&config);
    assert_schema(&text);
    assert_eq!(text.lines().count(), count + number as usize);
    for n in 1..=number {
        assert_eq!(text.matches(&format!(" attempt={n} ")).count(), 1);
    }
}

#[test]
fn mixed_current_and_rotated_files_prune_records_not_whole_recent_segments() {
    let (_temp, config) = fixture();
    fs::create_dir(&config.directory).unwrap();
    let now = rtrust_journal::now_ms();
    let old = seed_line(now - AGE - 60_000, 11);
    let recent = seed_line(now - 60_000, 22);
    for name in ["events.log.1", "events.log.9", "events.log"] {
        fs::write(
            config.directory.join(name),
            format!("{old}{recent}{old}{recent}"),
        )
        .unwrap();
    }
    let journal = spawn(config.clone());
    journal.submit(record(33));
    drain(&journal);
    let text = contents(&config);
    assert!(!text.contains("attempt=11 "));
    assert_eq!(text.matches("attempt=22 ").count(), 6);
    assert_eq!(text.matches("attempt=33 ").count(), 1);
    assert_schema(&text);
    drop(journal);
    let restarted = spawn(config.clone());
    restarted.submit(record(44));
    drain(&restarted);
    let text = contents(&config);
    assert_eq!(text.matches("attempt=22 ").count(), 6);
    assert_eq!(text.matches("attempt=33 ").count(), 1);
    assert_eq!(text.matches("attempt=44 ").count(), 1);
}

#[test]
fn genuine_decimal_15mb_cap_evicts_oldest_preserves_recent_suffix_and_restart() {
    let (_temp, config) = fixture();
    fs::create_dir(&config.directory).unwrap();
    let now = rtrust_journal::now_ms();
    // Exact 1,000-byte synthetic lifecycle lines, all valid and recent. Seed the
    // genuine default cap efficiently; no scaled/internal Store knobs are used.
    let prefix = format!("{now} synthetic_retention_fixture ");
    let row = format!("{prefix}{}\n", "x".repeat(999 - prefix.len()));
    assert_eq!(row.len(), 1000);
    let segment = row.repeat(1000);
    for n in 1..=14 {
        fs::write(config.directory.join(format!("events.log.{n}")), &segment).unwrap();
    }
    fs::write(config.directory.join("events.log"), &segment).unwrap();
    assert_eq!(
        files(&config)
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>(),
        15_000_000
    );
    let journal = spawn(config.clone());
    journal.submit(record(771));
    drain(&journal);
    assert!(!config.directory.join("events.log.1").exists());
    assert!(config.directory.join("events.log.2").exists());
    assert!(config.directory.join("events.log.15").exists());
    let size: u64 = files(&config)
        .iter()
        .map(|p| fs::metadata(p).unwrap().len())
        .sum();
    assert!((14_000_000..=15_000_000).contains(&size));
    assert!(
        fs::read_to_string(config.directory.join("events.log"))
            .unwrap()
            .contains("attempt=771 ")
    );
    drop(journal);
    let restarted = spawn(config.clone());
    restarted.submit(record(772));
    drain(&restarted);
    let text = fs::read_to_string(config.directory.join("events.log")).unwrap();
    assert_eq!(text.matches("attempt=771 ").count(), 1);
    assert_eq!(text.matches("attempt=772 ").count(), 1);
    assert!(config.directory.join("events.log.2").exists());
    assert!(
        files(&config)
            .iter()
            .map(|p| fs::metadata(p).unwrap().len())
            .sum::<u64>()
            <= 15_000_000
    );
}

// Dropping the sender releases recv even if an assertion unwinds before release.
struct Release(Option<mpsc::SyncSender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.try_send(());
        }
    }
}
#[test]
fn blocked_initializer_has_exact_bounded_queue_and_nonblocking_producer() {
    let (_temp, config) = fixture();
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let release = Release(Some(release_tx));
    let saved = config.clone();
    let (spawn_tx, spawn_rx) = mpsc::sync_channel(1);
    // A synchronous-initialization regression must fail a deadline, not deadlock
    // this test before the RAII release can run.
    let spawner = std::thread::spawn(move || {
        let caller = std::thread::current().id();
        let journal = Journal::spawn(move || {
            ready_tx.send(std::thread::current().id()).unwrap();
            let _ = release_rx.recv();
            Some(saved)
        });
        let _ = spawn_tx.send((caller, Arc::new(journal)));
    });
    let initializer = ready_rx.recv_timeout(WAIT).unwrap();
    let (caller, journal) = spawn_rx.recv_timeout(WAIT).unwrap();
    assert_ne!(initializer, caller);
    spawner.join().unwrap();
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let producer_sink = journal.clone();
    let producer = std::thread::spawn(move || {
        let start = Instant::now();
        for n in 1..=10_000 {
            producer_sink.submit(record(n));
        }
        let _ = done_tx.send(start.elapsed());
    });
    assert!(done_rx.recv_timeout(Duration::from_secs(2)).unwrap() < Duration::from_secs(2));
    producer.join().unwrap();
    assert!(
        !config.directory.exists(),
        "producer initialized filesystem"
    );
    let (flush_tx, flush_rx) = mpsc::sync_channel(1);
    let flush_sink = journal.clone();
    let flusher = std::thread::spawn(move || {
        let _ = flush_tx.send(flush_sink.flush(Duration::from_millis(30)));
    });
    assert!(!flush_rx.recv_timeout(Duration::from_secs(1)).unwrap());
    flusher.join().unwrap();
    drop(release);
    drain(&journal);
    let text = contents(&config);
    assert_eq!(text.matches("connect_failed ").count(), 256);
    assert_eq!(text.matches("journal_dropped count=9744").count(), 1);
    assert!(text.contains("attempt=256 "));
    assert!(!text.contains("attempt=257 "));
}

#[test]
fn initializer_panic_none_and_invalid_directory_are_best_effort() {
    let panic_sink = Journal::spawn(|| panic!("synthetic initializer failure"));
    let none_sink = Journal::spawn(|| None);
    let (_temp, config) = fixture();
    fs::write(&config.directory, b"external-sentinel").unwrap();
    let invalid_sink = spawn(config.clone());
    for sink in [&panic_sink, &none_sink, &invalid_sink] {
        let start = Instant::now();
        for n in 0..1000 {
            sink.submit(record(n));
        }
        assert!(!sink.flush(Duration::from_millis(50)));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    assert_eq!(fs::read(config.directory).unwrap(), b"external-sentinel");
}

#[test]
fn explicit_sink_raii_failure_cancel_success_are_exactly_once() {
    let (_temp, config) = fixture();
    let sink = Arc::new(spawn(config.clone()));
    for path in [
        Path::Start,
        Path::Reconnect,
        Path::WakeReconnect,
        Path::SocksRecovery,
    ] {
        let mut failed = Attempt::with_sink(path, Transport::H3, 1, Budget::Cooldown, sink.clone());
        failed.class(Class::Authentication);
        drop(failed);
        let mut cancelled = Attempt::with_sink(path, Transport::H2, 2, Budget::Burst, sink.clone());
        cancelled.cancelled();
        drop(cancelled);
        let mut success =
            Attempt::with_sink(path, Transport::Unknown, 3, Budget::Burst, sink.clone());
        success.success();
        drop(success);
    }
    drain(&sink);
    let text = contents(&config);
    assert_schema(&text);
    assert_eq!(text.lines().count(), 8);
    assert_eq!(text.matches("class=authentication ").count(), 4);
    assert_eq!(text.matches("class=cancelled ").count(), 4);
    assert!(!text.contains("attempt=3 "));
}

#[cfg(unix)]
#[test]
fn unix_unsafe_current_rotated_temp_lock_objects_preserve_external_sentinel() {
    use std::{
        ffi::CString,
        os::unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, symlink},
        },
    };
    for name in ["events.log", "events.log.1", "events.tmp", "events.lock"] {
        for kind in 0..4 {
            let (temp, config) = fixture();
            fs::create_dir(&config.directory).unwrap();
            let sentinel = temp
                .path()
                .canonicalize()
                .unwrap()
                .join("external-sentinel");
            fs::write(&sentinel, b"external-sentinel").unwrap();
            let before = fs::metadata(&sentinel).unwrap();
            let unsafe_path = config.directory.join(name);
            match kind {
                0 => symlink(&sentinel, &unsafe_path).unwrap(),
                1 => fs::hard_link(&sentinel, &unsafe_path).unwrap(),
                2 => fs::create_dir(&unsafe_path).unwrap(),
                _ => {
                    let path = CString::new(unsafe_path.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
                }
            }
            let identity = fs::symlink_metadata(&unsafe_path).unwrap();
            let start = Instant::now();
            let journal = spawn(config.clone());
            journal.submit(record(991));
            // Initialization may succeed even though individual appends fail.
            let _ = journal.flush(Duration::from_millis(500));
            assert!(start.elapsed() < Duration::from_secs(2));
            let after = fs::metadata(&sentinel).unwrap();
            assert_eq!(fs::read(&sentinel).unwrap(), b"external-sentinel");
            assert_eq!(before.ino(), after.ino());
            assert_eq!(before.mode(), after.mode());
            let unchanged = fs::symlink_metadata(&unsafe_path).unwrap();
            assert_eq!(identity.ino(), unchanged.ino());
            assert_eq!(
                identity.file_type().is_fifo(),
                unchanged.file_type().is_fifo()
            );
            if name != "events.log" && config.directory.join("events.log").exists() {
                assert!(
                    !fs::read_to_string(config.directory.join("events.log"))
                        .unwrap()
                        .contains("connect_failed")
                );
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn unix_busy_lock_drops_without_waiting_then_recovers() {
    use std::os::fd::AsRawFd;
    let (_temp, config) = fixture();
    fs::create_dir(&config.directory).unwrap();
    let lock = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config.directory.join("events.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let journal = spawn(config.clone());
    let start = Instant::now();
    journal.submit(record(901));
    drain(&journal);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(!config.directory.join("events.log").exists());
    drop(lock);
    journal.submit(record(902));
    drain(&journal);
    let text = contents(&config);
    assert!(!text.contains("attempt=901 "));
    assert!(text.contains("attempt=902 "));
    assert!(text.contains("journal_dropped count=1"));
}

#[cfg(unix)]
#[test]
fn unix_symlink_directory_is_rejected_without_touching_target() {
    use std::os::unix::fs::{MetadataExt, symlink};
    let (temp, config) = fixture();
    let external = temp
        .path()
        .canonicalize()
        .unwrap()
        .join("external-directory");
    fs::create_dir(&external).unwrap();
    fs::write(external.join("sentinel"), b"unchanged").unwrap();
    let before = fs::metadata(&external).unwrap();
    symlink(&external, &config.directory).unwrap();
    let journal = spawn(config);
    journal.submit(record(903));
    assert!(!journal.flush(Duration::from_millis(100)));
    assert_eq!(fs::read_dir(&external).unwrap().count(), 1);
    assert_eq!(fs::read(external.join("sentinel")).unwrap(), b"unchanged");
    assert_eq!(fs::metadata(external).unwrap().mode(), before.mode());
}

#[test]
fn lifecycle_control_characters_and_record_size_remain_bounded() {
    let (_temp, config) = fixture();
    let journal = spawn(config.clone());
    journal.lifecycle(&format!("synthetic\n\r\t\0é{}", "x".repeat(2000)));
    journal.submit(Record {
        attempt: u32::MAX,
        duration_ms: u64::MAX,
        ..record(1)
    });
    drain(&journal);
    let text = contents(&config);
    assert_eq!(text.lines().count(), 2);
    for line in text.lines() {
        assert!(line.len() < 1024);
        assert!(line.is_ascii());
        assert!(!line.bytes().any(|b| b.is_ascii_control()));
    }
    assert_schema(text.lines().nth(1).unwrap());
}

#[test]
fn actual_loopback_bind_error_is_classified_without_endpoint_text() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let error = std::net::TcpListener::bind(address).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    let (_temp, config) = fixture();
    let journal = spawn(config.clone());
    journal.submit(Record {
        class: rtrust_journal::classify_boxed(&error),
        ..record(881)
    });
    drain(&journal);
    let text = contents(&config);
    assert!(text.contains("class=local_bind "));
    assert!(!text.contains(&address.to_string()));
    assert_schema(&text);
}
