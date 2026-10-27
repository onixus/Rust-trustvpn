use super::*;
use std::io::Read;

fn config(tmp: &tempfile::TempDir) -> Config {
    Config {
        directory: tmp.path().canonicalize().unwrap().join("journal"),
        file: "events.log",
        owner: Owner::CurrentUser,
    }
}
fn record() -> Record {
    Record::failure(
        Path::Start,
        Class::Other,
        Transport::H2,
        1,
        Budget::Burst,
        Duration::from_millis(23),
    )
}

#[test]
fn planned_transport_uses_closed_engine_dispatch_not_profile_strings() {
    let mut profile=rtrust_profile::Profile::import("hostname='hostname-canary.invalid'\naddresses=['192.0.2.45:443']\nusername='username-canary'\npassword='token-canary'\n").unwrap();
    assert_eq!(rtrust_engine::planned_transport(&profile), Transport::H2);
    profile.endpoint.upstream_protocol = "http3".into();
    assert_eq!(rtrust_engine::planned_transport(&profile), Transport::H3);
    profile.endpoint.upstream_protocol = "transport-canary".into();
    assert_eq!(rtrust_engine::planned_transport(&profile), Transport::H2);
    profile.protocol = rtrust_profile::Protocol::Hysteria2;
    assert_eq!(
        rtrust_engine::planned_transport(&profile),
        Transport::Hysteria
    );
    profile.protocol = rtrust_profile::Protocol::AmneziaWg;
    assert_eq!(
        rtrust_engine::planned_transport(&profile),
        Transport::AmneziaWg
    );
    profile.protocol = rtrust_profile::Protocol::Vless;
    assert_eq!(
        rtrust_engine::planned_transport(&profile),
        Transport::Unknown
    );
}

#[test]
fn typed_classes_and_transport_tokens_never_include_error_payloads() {
    use rtrust_engine::{Close, Error as E};
    let cases = [
        (E::Connect, Class::EndpointUnreachable),
        (E::Tls, Class::Tls),
        (E::Authentication, Class::Authentication),
        (E::Profile, Class::Profile),
        (E::Timeout, Class::Timeout),
        (E::LocalBind, Class::LocalBind),
        (E::Rejected(503), Class::Protocol),
        (E::Closed(Close::Local), Class::Cancelled),
        (E::Io, Class::Other),
        (E::ConnectIo(std::io::ErrorKind::TimedOut), Class::Timeout),
        (
            E::ConnectIo(std::io::ErrorKind::ConnectionRefused),
            Class::EndpointUnreachable,
        ),
        (
            E::Closed(Close::QuicTransport {
                code: 0x102,
                remote: true,
            }),
            Class::Tls,
        ),
        (
            E::Closed(Close::GoAway {
                code: 2,
                remote: true,
            }),
            Class::Protocol,
        ),
        (
            E::Unsupported("token-canary hostname-canary 192.0.2.45 sni-canary profile-canary"),
            Class::Profile,
        ),
        (E::Unanswered, Class::Other),
    ];
    for (error, class) in cases {
        assert_eq!(classify(&error), class);
        for transport in [
            Transport::H2,
            Transport::H3,
            Transport::Hysteria,
            Transport::AmneziaWg,
            Transport::Unknown,
        ] {
            let text = Record {
                class: classify(&error),
                transport,
                ..record()
            }
            .line();
            assert!(text.contains(class.as_str()));
            assert!(text.contains(transport_token(transport)));
            assert!(!text.contains("canary"));
            assert!(!text.contains("192.0.2.45"));
            assert_eq!(text.lines().count(), 1);
        }
    }
    assert_eq!(
        classify_boxed(&std::io::Error::from(std::io::ErrorKind::AddrInUse)),
        Class::LocalBind
    );
    assert_eq!(
        classify_boxed(&std::io::Error::from(std::io::ErrorKind::TimedOut)),
        Class::Timeout
    );
}

#[test]
fn attempt_failure_cancel_and_success_are_exactly_once_in_injected_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(&tmp);
    let file = cfg.directory.join(cfg.file);
    let journal = Arc::new(Journal::spawn(move || Some(cfg)));
    for path in [
        Path::Start,
        Path::Reconnect,
        Path::WakeReconnect,
        Path::SocksRecovery,
    ] {
        let mut failed =
            Attempt::with_sink(path, Transport::H3, 2, Budget::Cooldown, journal.clone());
        failed.class(Class::Tls);
        drop(failed);
        let mut cancelled =
            Attempt::with_sink(path, Transport::H2, 1, Budget::Burst, journal.clone());
        cancelled.cancelled();
        drop(cancelled);
        let mut success =
            Attempt::with_sink(path, Transport::Unknown, 1, Budget::Burst, journal.clone());
        success.success();
        success.class(Class::Other);
        drop(success);
    }
    assert!(journal.flush(Duration::from_secs(5)));
    let text = std::fs::read_to_string(file).unwrap();
    assert_eq!(text.lines().count(), 8);
    for path in [
        Path::Start,
        Path::Reconnect,
        Path::WakeReconnect,
        Path::SocksRecovery,
    ] {
        assert_eq!(
            text.lines()
                .filter(|l| l.contains(&format!("path={} ", path.as_str())))
                .count(),
            2
        );
    }
    assert_eq!(text.matches("class=cancelled ").count(), 4);
    assert_eq!(text.matches("class=tls ").count(), 4);
}

#[test]
fn queue_saturation_and_dropped_marker_do_not_wait_for_writer() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(&tmp);
    let file = cfg.directory.join(cfg.file);
    let (ready, entered) = mpsc::sync_channel(1);
    let (release, wait) = mpsc::sync_channel(1);
    let journal = Journal::spawn(move || {
        ready.send(()).unwrap();
        wait.recv().unwrap();
        Some(cfg)
    });
    entered.recv_timeout(Duration::from_secs(5)).unwrap();
    let started = Instant::now();
    for _ in 0..1000 {
        journal.submit(record());
    }
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(journal.dropped.load(Ordering::Relaxed), 744);
    release.send(()).unwrap();
    // A flush may encounter the intentionally full queue; drain acknowledgement
    // via a retry bounded by wall time, not a blocking producer operation.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !journal.flush(Duration::from_millis(20)) {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    let text = std::fs::read_to_string(file).unwrap();
    assert!(text.contains("journal_dropped count=744"));
}

#[test]
fn init_panic_and_unavailable_directory_are_best_effort() {
    let journal = Journal::spawn(|| panic!("controlled writer initialization failure"));
    for _ in 0..1000 {
        journal.submit(record());
    }
    assert!(!journal.flush(Duration::from_millis(100)));
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(&tmp);
    std::fs::write(&cfg.directory, b"unchanged").unwrap();
    let path = cfg.directory.clone();
    let journal = Journal::spawn(move || Some(cfg));
    journal.submit(record());
    assert!(!journal.flush(Duration::from_millis(100)));
    assert_eq!(std::fs::read(path).unwrap(), b"unchanged");
}

#[test]
fn lock_contention_drops_write_without_changing_foreign_file() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(&tmp);
    let mut store = storage::Store::open(cfg.clone()).unwrap();
    let dir = {
        #[cfg(unix)]
        {
            crate::unix::Directory::open(&cfg.directory, cfg.owner).unwrap()
        }
        #[cfg(windows)]
        {
            crate::windows::Directory::open(&cfg.directory, cfg.owner).unwrap()
        }
    };
    let lock = dir.lock().unwrap();
    let started = Instant::now();
    assert!(store.append("100 test\n", 100).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(lock);
    store.append("100 test\n", 100).unwrap();
    let mut text = String::new();
    dir.file(cfg.file, false)
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "100 test\n");
}

#[test]
fn idle_retention_uses_injected_clock_without_new_records() {
    let tmp = tempfile::tempdir().unwrap();
    let cfg = config(&tmp);
    let file = cfg.directory.join(cfg.file);
    let clock = Arc::new(AtomicU64::new(100));
    let observed = clock.clone();
    let journal = Journal::spawn_with_clock(
        move || Some(cfg),
        move || observed.load(Ordering::SeqCst),
        Duration::from_millis(10),
    );
    journal.submit(Record {
        time: 100,
        ..record()
    });
    assert!(journal.flush(Duration::from_secs(5)));
    assert!(file.exists());
    clock.store(storage::AGE + 101, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(5);
    while file.exists() {
        assert!(Instant::now() < deadline);
        std::thread::yield_now();
    }
    assert!(journal.flush(Duration::from_secs(5)));
}
