//! Independent tester checks for the #99 SOCKS degraded reconnect. These
//! drive the App through its public messages and the recovery policy through
//! its public API; they do not restate the implementation's arithmetic.
use super::*;
use rtrust_control::recovery::{BURST_ATTEMPTS, COOLDOWN, STABLE_CONNECTION};
use std::time::{Duration, Instant};

const CANARY: &str = "CANARY-pw-7d41e0-not-a-real-secret";
const CANARY_USER: &str = "canary-user-5b2f";

fn canary_profile(host: &str, address: &str) -> Profile {
    Profile::import(&format!(
        "hostname='{host}'\naddresses=['{address}']\nusername='{CANARY_USER}'\npassword='{CANARY}'\n"
    ))
    .unwrap()
}
fn app() -> App {
    let mut app = crate::tests::app();
    app.profiles = vec![
        canary_profile("first.example", "192.0.2.1:443"),
        canary_profile("second.example", "192.0.2.2:443"),
    ];
    app
}
/// What the user sees and what is stored as the failure must never echo
/// profile secrets.
fn assert_no_secret(app: &App) {
    for text in [Some(app.status.as_str()), app.last_error.as_deref()]
        .into_iter()
        .flatten()
    {
        assert!(!text.contains(CANARY), "password leaked: {text}");
        assert!(!text.contains(CANARY_USER), "username leaked: {text}");
    }
}
/// A SOCKS connection the user started and the proxy admitted `ago`.
fn admitted(app: &mut App, ago: Duration) {
    app.mode = Mode::Socks;
    let mut recovery = socks_recovery::Recovery::new(app.profiles[0].clone(), 1080);
    recovery.connected(Instant::now() - ago);
    app.socks_recovery = Some(recovery);
    app.connection_name = app.profiles[0].name.clone();
}
fn transient() -> socks_recovery::Failure {
    rtrust_engine::Error::Connect.into()
}
fn degraded(proven: bool, kind: rtrust_engine::Stall) -> connection::HealthError {
    connection::HealthError::from(rtrust_engine::Error::Degraded { proven, kind })
}
fn waiting(app: &App) -> bool {
    app.connecting
        && app.session.is_none()
        && app.connection_task.is_some()
        && app
            .socks_recovery
            .as_ref()
            .is_some_and(socks_recovery::Recovery::retrying)
}
/// Seconds announced in the wait notice.
fn announced(status: &str) -> u64 {
    let tail = status.rsplit("через ").next().unwrap();
    tail.split(' ').next().unwrap().parse().unwrap()
}

// Criterion 1: every degraded verdict (proven/unproven x Silent/Quiet) waits
// and retries the same profile; none is a hard disconnect.
#[test]
fn every_degraded_verdict_is_retried_not_dropped() {
    use rtrust_engine::Stall;
    for proven in [false, true] {
        for kind in [Stall::Silent, Stall::Quiet] {
            let mut app = app();
            admitted(&mut app, Duration::from_secs(5));
            let before = app.connection_epoch;
            let _ = app.socks_lost(degraded(proven, kind));
            assert!(waiting(&app), "proven={proven} kind={kind:?}");
            assert!(app.connection_epoch > before);
            assert!(!app.status.contains("Соединение потеряно"));
            assert!(app.status.contains("Прямых соединений нет"));
            let (profile, port) = app.socks_recovery.as_ref().unwrap().target();
            assert_eq!(
                (profile.name.as_str(), port),
                (app.profiles[0].name.as_str(), 1080)
            );
            assert_no_secret(&app);
        }
    }
}

// Criterion 2: unproven sessions never restore the budget, even after an hour.
#[test]
fn unproven_hour_long_sessions_still_walk_into_the_cooldown() {
    let mut app = app();
    admitted(&mut app, Duration::from_secs(3600));
    let mut shown = Vec::new();
    for _ in 0..=BURST_ATTEMPTS {
        let _ = app.socks_lost(degraded(false, rtrust_engine::Stall::Quiet));
        shown.push(announced(&app.status));
        // Pretend the attempt was admitted long ago (public API only).
        app.socks_recovery
            .as_mut()
            .unwrap()
            .connected(Instant::now() - Duration::from_secs(3600));
    }
    // Growing burst, then the cooldown on the 9th verdict.
    assert!(shown.windows(2).take(4).all(|w| w[0] < w[1]), "{shown:?}");
    assert!(shown[..8].iter().all(|&s| s <= 38), "{shown:?}");
    assert!(*shown.last().unwrap() >= COOLDOWN.as_secs(), "{shown:?}");
    assert!(app.status.contains("Несколько попыток подряд не удались"));
}

// Criterion 2: proven restores only at/after STABLE_CONNECTION.
#[test]
fn proven_restores_only_after_a_stable_session() {
    let burn = |r: &mut socks_recovery::Recovery| {
        for _ in 0..BURST_ATTEMPTS {
            r.attempt_failed(0);
        }
    };
    let profile = app().profiles[0].clone();
    // Short proven session: the next delay is the cooldown, no reset.
    let mut r = socks_recovery::Recovery::new(profile.clone(), 1080);
    burn(&mut r);
    let now = Instant::now();
    r.connected(now);
    let retry = r.degraded(true, now + STABLE_CONNECTION - Duration::from_millis(1), 0);
    assert!(retry.cooling && retry.delay >= COOLDOWN);
    // Stable proven session: the burst starts over at its smallest delay.
    let mut r = socks_recovery::Recovery::new(profile.clone(), 1080);
    burn(&mut r);
    r.connected(now);
    let first = r.degraded(true, now + STABLE_CONNECTION, 0);
    assert!(!first.cooling);
    let mut fresh = socks_recovery::Recovery::new(profile.clone(), 1080);
    assert_eq!(first.delay, fresh.attempt_failed(0).delay);
    // Same stable duration, unproven: still cooling.
    let mut r = socks_recovery::Recovery::new(profile, 1080);
    burn(&mut r);
    r.connected(now);
    assert!(r.degraded(false, now + STABLE_CONNECTION * 100, 0).cooling);
    // A degraded verdict without an admission timestamp counts as zero time.
    let _ = r.attempt_failed(0);
    assert!(!r.degraded(true, now + STABLE_CONNECTION * 100, 0).cooling);
}

// Criterion 2: jitter is bounded for any entropy; the cooldown repeats.
#[test]
fn jitter_is_bounded_for_any_entropy_and_cooldown_recurs() {
    let profile = app().profiles[0].clone();
    for entropy in [0, 1, 7, 0xdead_beef, u64::MAX / 3, u64::MAX] {
        let mut r = socks_recovery::Recovery::new(profile.clone(), 1080);
        for round in 0..3 {
            for i in 0..BURST_ATTEMPTS {
                let retry = r.attempt_failed(entropy);
                if round > 0 && i == 0 {
                    assert!(retry.cooling, "entropy={entropy} round={round}");
                    assert!(retry.delay >= COOLDOWN);
                    assert!(retry.delay <= COOLDOWN + Duration::from_secs(30));
                } else {
                    assert!(!retry.cooling);
                    assert!(retry.delay >= Duration::from_secs(2));
                    assert!(retry.delay <= Duration::from_millis(37_500));
                }
            }
        }
        for _ in 0..1000 {
            let _ = socks_recovery::entropy();
        }
    }
}

// Criterion 4: stale results and health verdicts cannot touch a wait.
#[test]
fn stale_results_during_a_wait_are_ignored() {
    let mut app = app();
    admitted(&mut app, Duration::from_secs(1));
    let old = app.connection_epoch;
    let _ = app.socks_lost(degraded(true, rtrust_engine::Stall::Silent));
    let epoch = app.connection_epoch;
    let status = app.status.clone();
    let _ = app.update(Message::SocksAttempt(old, Err(transient())));
    let _ = app.update(Message::Health(
        old,
        Err(degraded(false, rtrust_engine::Stall::Quiet)),
    ));
    let _ = app.update(Message::Health(
        epoch,
        Err(degraded(false, rtrust_engine::Stall::Quiet)),
    ));
    assert!(waiting(&app));
    assert_eq!(
        (app.connection_epoch, app.status.as_str()),
        (epoch, status.as_str())
    );
}

// Criterion 4: Cancel during the wait and during the attempt; nothing revives.
#[test]
fn cancel_ends_the_wait_and_late_results_cannot_revive_it() {
    for failed_attempts in [0, 3] {
        let mut app = app();
        admitted(&mut app, Duration::from_secs(1));
        let _ = app.socks_lost(degraded(false, rtrust_engine::Stall::Quiet));
        for _ in 0..failed_attempts {
            let _ = app.update(Message::SocksAttempt(
                app.connection_epoch,
                Err(transient()),
            ));
            assert!(waiting(&app));
        }
        let pending = app.connection_epoch;
        let _ = app.update(Message::ToggleConnection);
        assert!(!app.connecting && app.session.is_none());
        assert!(app.socks_recovery.is_none() && app.connection_task.is_none());
        assert!(app.connection_name.is_empty() && app.last_error.is_none());
        assert_eq!(app.status, "Отключено.");
        for epoch in [pending, app.connection_epoch] {
            let _ = app.update(Message::SocksAttempt(epoch, Err(transient())));
            assert!(!app.connecting && app.socks_recovery.is_none());
            assert_eq!(app.status, "Отключено.");
        }
    }
}

// Criterion 4: ToggleDefaultConnection is also a Cancel during the wait.
#[test]
fn default_toggle_during_a_wait_cancels_instead_of_starting_another() {
    let mut app = app();
    admitted(&mut app, Duration::from_secs(1));
    app.selected = 1;
    let _ = app.socks_lost(degraded(true, rtrust_engine::Stall::Quiet));
    let _ = app.update(Message::ToggleDefaultConnection);
    assert!(!app.connecting && app.socks_recovery.is_none() && app.connection_task.is_none());
}

// Criterion 4: Exit during the wait and during an automatic attempt; a
// user-initiated attempt still blocks exit (regression).
#[test]
fn exit_ends_automatic_waits_but_not_a_user_attempt() {
    for failed_attempts in [0, 2] {
        let mut app = app();
        admitted(&mut app, Duration::from_secs(1));
        let _ = app.socks_lost(degraded(false, rtrust_engine::Stall::Silent));
        for _ in 0..failed_attempts {
            let _ = app.update(Message::SocksAttempt(
                app.connection_epoch,
                Err(transient()),
            ));
        }
        let pending = app.connection_epoch;
        let _ = app.update(Message::ExitRequested);
        assert!(!app.connecting && app.socks_recovery.is_none() && app.connection_task.is_none());
        let _ = app.update(Message::SocksAttempt(pending, Err(transient())));
        assert!(!app.connecting && app.socks_recovery.is_none());
    }
    let mut app = app();
    app.mode = Mode::Socks;
    let _ = app.update(Message::ToggleConnection);
    assert!(app.connecting);
    let _ = app.update(Message::ExitRequested);
    assert!(app.connecting && app.status.contains("Дождитесь"));
}

// Criteria 3/4: profile, port and mode edits are refused during the wait;
// selecting another profile does not change what is retried.
#[test]
fn edits_during_a_wait_cannot_redirect_the_retry() {
    let mut app = app();
    admitted(&mut app, Duration::from_secs(1));
    let _ = app.socks_lost(degraded(true, rtrust_engine::Stall::Quiet));
    let first = app.profiles[0].name.clone();
    let count = app.profiles.len();
    let _ = app.update(Message::Mode(Mode::Tun));
    let _ = app.update(Message::ProxyPort("9999".into()));
    let _ = app.update(Message::Select(1));
    let _ = app.update(Message::Delete);
    let _ = app.update(Message::Delete);
    assert_eq!(app.mode, Mode::Socks);
    assert_eq!(app.profiles.len(), count);
    assert!(waiting(&app));
    // The next failure reschedules the same profile and port, not selection 1.
    let _ = app.update(Message::SocksAttempt(
        app.connection_epoch,
        Err(transient()),
    ));
    let (profile, port) = app.socks_recovery.as_ref().unwrap().target();
    assert_eq!((profile.name, port), (first.clone(), 1080));
    assert_eq!(app.connection_name, first);
}

// Criterion 3: a user start with fallbacks configured retries only the
// primary profile, in SOCKS mode, on the user's port.
#[test]
fn a_user_socks_start_records_only_its_own_profile_and_port() {
    let mut app = app();
    app.mode = Mode::Socks;
    app.proxy_port = "1090".into();
    app.saved_connection.fallback_profiles = vec![app.profiles[1].name.clone()];
    let _ = app.update(Message::ToggleConnection);
    assert!(app.connecting);
    let recovery = app.socks_recovery.as_ref().unwrap();
    assert!(!recovery.retrying());
    let (profile, port) = recovery.target();
    assert_eq!((profile.name, port), (app.profiles[0].name.clone(), 1090));
    // TUN starts create no SOCKS recovery at all.
    let _ = app.update(Message::ToggleConnection);
    let mut app = crate::tests::app();
    app.mode = Mode::Tun;
    let _ = app.update(Message::ToggleConnection);
    assert!(app.socks_recovery.is_none());
}

// Criterion 4: diagnostics cannot start a reconnect of their own during a wait.
#[test]
fn diagnostic_reconnect_during_a_wait_is_inert() {
    use rtrust_desktop::diagnostics::{Action, Report};
    let mut app = app();
    admitted(&mut app, Duration::from_secs(1));
    let _ = app.socks_lost(degraded(true, rtrust_engine::Stall::Quiet));
    let epoch = app.connection_epoch;
    let snapshot =
        rtrust_control::observations::Snapshot::unknown(rtrust_control::observations::Mode::Full);
    app.diagnostic_report = Some((epoch, Report::new(snapshot)));
    let _ = app.update(Message::DiagnosticAction(Action::Reconnect));
    assert!(!app.reconnect_then_check);
    assert!(waiting(&app) && app.connection_epoch == epoch);
    let _ = app.update(Message::DiagnosticAction(Action::Recheck));
    let _ = app.update(Message::Diagnose);
    assert!(waiting(&app) && app.connection_epoch == epoch);
}

// Criterion 5: non-degraded engine failures keep the old hard disconnect.
#[test]
fn non_degraded_engine_errors_still_disconnect() {
    use rtrust_engine::Error;
    for error in [
        Error::Io,
        Error::Timeout,
        Error::Connect,
        Error::Authentication,
    ] {
        let expected = format!("Соединение потеряно: {error}");
        let mut app = app();
        admitted(&mut app, Duration::from_secs(60));
        let _ = app.socks_lost(connection::HealthError::from(error));
        assert!(!app.connecting && app.socks_recovery.is_none() && app.connection_task.is_none());
        assert_eq!(app.status, expected);
        assert_eq!(app.last_error.as_deref(), Some(expected.as_str()));
        assert_no_secret(&app);
    }
}

// Criteria 3/6: a real automatic attempt against a closed loopback endpoint
// fails without leaving a listener, without leaking secrets, and schedules
// the next attempt. Loopback only; no system network state is touched.
#[test]
fn a_real_failed_attempt_leaves_no_listener_and_no_secret() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let free = || {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    };
    let (endpoint, socks) = (free(), free());
    let profile = canary_profile("localhost", &format!("127.0.0.1:{endpoint}"));
    let mut app = app();
    app.profiles[0] = profile.clone();
    app.mode = Mode::Socks;
    let mut recovery = socks_recovery::Recovery::new(profile.clone(), socks);
    recovery.connected(Instant::now());
    app.socks_recovery = Some(recovery);
    let _ = app.socks_lost(degraded(false, rtrust_engine::Stall::Quiet));
    assert!(waiting(&app));
    let (target, port) = app.socks_recovery.as_ref().unwrap().target();
    let result = runtime.block_on(socks_recovery::attempt(target, port));
    let error = result.err().expect("closed endpoint must fail");
    assert!(
        !error.permanent,
        "a closed endpoint is worth another attempt"
    );
    assert!(!error.message.contains(CANARY) && !error.message.contains(CANARY_USER));
    // Fail-closed: nothing listens on the SOCKS port after the failure.
    assert!(std::net::TcpStream::connect(("127.0.0.1", socks)).is_err());
    std::net::TcpListener::bind(("127.0.0.1", socks)).expect("port released");
    let _ = app.update(Message::SocksAttempt(app.connection_epoch, Err(error)));
    assert!(waiting(&app));
    assert!(app.status.contains("Переподключение через"));
    assert_no_secret(&app);
}
