//! Independent regression checks: no device, routes, DNS, or privileged tools.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

fn finite_access(milliseconds: u64) -> Freshness {
    let wall = rtrust_control::freshness::now();
    Freshness(Some(Arc::new(std::sync::Mutex::new(
        rtrust_control::freshness::Deadline::new(rtrust_control::freshness::Lease {
            issued_at_ms: wall - 1,
            expires_at_ms: wall + milliseconds,
        })
        .unwrap(),
    ))))
}

async fn synthetic_failover() -> crate::failover::Failover {
    // The numeric address prevents resolution; pinning does not open a socket.
    let profile = rtrust_profile::Profile::import(
        "hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n",
    )
    .unwrap();
    crate::failover::Failover::pin(profile, vec![], crate::failover::Pin::Ipv4)
        .await
        .unwrap()
}

async fn status(actor: &Actor) -> Response {
    tokio::time::timeout(
        Duration::from_secs(2),
        ask(actor, Command::Status { viewed: false }),
    )
    .await
    .expect("Status must remain responsive")
    .unwrap()
}

async fn expired_status(actor: &Actor) -> Response {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = status(actor).await;
            if response.message == ACCESS_EXPIRED {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the service must observe expiry independently of GUI requests")
}

// Always unblock a simulated OS command, including when an assertion panics.
struct Unblock(Option<std::sync::mpsc::Sender<()>>);
impl Unblock {
    fn finish(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}
impl Drop for Unblock {
    fn drop(&mut self) {
        self.finish();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_during_os_mutation_keeps_status_responsive_and_stop_waits_for_drain() {
    let failover = synthetic_failover().await;
    let lease = Arc::new(Mutex::new(()));
    let held = Arc::new(lease.clone().lock_owned().await);
    let (unblock, wait) = std::sync::mpsc::channel();
    let mut unblock = Unblock(Some(unblock));
    let wait = std::sync::Mutex::new(wait);
    let (entered, entry) = oneshot::channel();
    let entered = std::sync::Mutex::new(Some(entered));
    let mutations_finished = Arc::new(AtomicUsize::new(0));
    let finished = mutations_finished.clone();
    let worker = tokio::spawn(guarded_connect(
        held.clone(),
        move || {
            if let Some(entered) = entered.lock().unwrap().take() {
                let _ = entered.send(());
            }
            wait.lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "synthetic mutation was not unblocked".to_string())?;
            finished.fetch_add(1, SeqCst);
            Ok(())
        },
        std::future::pending::<Result<device::Prepared, crate::failover::Failure>>(),
    ));
    entry.await.unwrap();

    let (actor, commands) = mpsc::channel(16);
    let (_shutdown, shutdown) = tokio::sync::watch::channel(false);
    let (_power, power) = tokio::sync::watch::channel(power::State::default());
    let (initial, connected) = oneshot::channel();
    let releases = Arc::new(AtomicUsize::new(0));
    let release_count = releases.clone();
    let retries = Arc::new(AtomicUsize::new(0));
    let retry_count = retries.clone();
    let cleanup_finished = mutations_finished.clone();
    let task = tokio::spawn(super::connected(
        Control {
            freshness: finite_access(300),
            commands,
            initial: Some(initial),
            shutdown,
            probe: None,
        },
        Workers {
            transport: "synthetic",
            tunnel: None,
            reconnect: Some(worker),
        },
        false,
        power,
        failover,
        move |_, _, _| {
            retry_count.fetch_add(1, SeqCst);
        },
        move || {
            assert_eq!(cleanup_finished.load(SeqCst), 1, "cleanup preceded drain");
            release_count.fetch_add(1, SeqCst);
            drop(held);
            Ok(())
        },
    ));
    assert_eq!(connected.await.unwrap().state, State::Connected);
    assert_eq!(expired_status(&actor).await.state, State::Blocked);
    assert_eq!(mutations_finished.load(SeqCst), 0);
    assert_eq!(releases.load(SeqCst), 0);
    assert!(lease.try_lock().is_err());

    // Queue Stop explicitly so its acceptance is known, not inferred from sleep.
    let (reply, mut stopped) = oneshot::channel();
    actor
        .send(Envelope {
            command: Command::Stop,
            response: reply,
        })
        .await
        .unwrap();
    assert_eq!(status(&actor).await.state, State::Blocked);
    assert!(matches!(
        stopped.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert_eq!(releases.load(SeqCst), 0);
    assert_eq!(retries.load(SeqCst), 0);
    assert!(lease.try_lock().is_err());

    unblock.finish();
    let response = tokio::time::timeout(Duration::from_secs(3), stopped)
        .await
        .expect("Stop must finish once the mutation drains")
        .unwrap();
    assert_eq!(response.state, State::Idle);
    task.await.unwrap().unwrap();
    assert_eq!(mutations_finished.load(SeqCst), 1);
    assert_eq!(releases.load(SeqCst), 1);
    assert_eq!(retries.load(SeqCst), 0);
    assert!(lease.try_lock().is_ok());
}

struct DataplaneDropped(Option<oneshot::Sender<()>>);
impl Drop for DataplaneDropped {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

#[tokio::test]
async fn leased_gui_eof_expires_without_requests_and_wake_cannot_reconnect() {
    let failover = synthetic_failover().await;
    let lease = Arc::new(Mutex::new(()));
    let held = lease.clone().lock_owned().await;
    let (dropped, dataplane_gone) = oneshot::channel();
    let drop_signal = DataplaneDropped(Some(dropped));
    let (entered, entry) = oneshot::channel();
    let worker = tokio::spawn(async move {
        let _drop_signal = drop_signal;
        let _ = entered.send(());
        std::future::pending::<RunResult>().await
    });
    entry.await.unwrap();
    let (actor, commands) = mpsc::channel(16);
    let (_shutdown, shutdown) = tokio::sync::watch::channel(false);
    let (power, power_events) = tokio::sync::watch::channel(power::State::default());
    let (initial, connected) = oneshot::channel();
    let releases = Arc::new(AtomicUsize::new(0));
    let release_count = releases.clone();
    let retries = Arc::new(AtomicUsize::new(0));
    let retry_count = retries.clone();
    let task = tokio::spawn(super::connected(
        Control {
            freshness: finite_access(300),
            commands,
            initial: Some(initial),
            shutdown,
            probe: None,
        },
        Workers {
            transport: "synthetic",
            tunnel: Some(worker),
            reconnect: None,
        },
        false,
        power_events,
        failover,
        move |_, _, _| {
            retry_count.fetch_add(1, SeqCst);
        },
        move || {
            release_count.fetch_add(1, SeqCst);
            drop(held);
            Ok(())
        },
    ));
    assert_eq!(connected.await.unwrap().state, State::Connected);
    let (gui, service) = tokio::io::duplex(4096);
    let detached = tokio::spawn(bridge(service, actor.clone(), None));
    drop(gui);
    assert!(detached.await.unwrap().is_err());
    assert!(!task.is_finished());
    assert_eq!(releases.load(SeqCst), 0);
    assert!(lease.try_lock().is_err());

    // No Status request drives expiry: observe cancellation of the dataplane first.
    tokio::time::timeout(Duration::from_secs(5), dataplane_gone)
        .await
        .expect("GUI detach must not disable autonomous lease expiry")
        .unwrap();
    assert_eq!(releases.load(SeqCst), 0);
    assert!(lease.try_lock().is_err());
    assert_eq!(status(&actor).await.message, ACCESS_EXPIRED);
    for (generation, awake) in [(1, false), (2, true)] {
        power.send_replace(power::State { awake, generation });
        let response = status(&actor).await;
        assert_eq!(response.state, State::Blocked);
        assert_eq!(response.message, ACCESS_EXPIRED);
    }
    assert_eq!(retries.load(SeqCst), 0);
    assert_eq!(releases.load(SeqCst), 0);
    assert_eq!(ask(&actor, Command::Stop).await.unwrap().state, State::Idle);
    task.await.unwrap().unwrap();
    assert_eq!(releases.load(SeqCst), 1);
    assert!(lease.try_lock().is_ok());
}

#[tokio::test]
async fn ready_future_after_expiry_cannot_win_before_the_timer_driver_advances() {
    use std::future::Future;
    use std::task::{Context, Poll};

    let freshness = finite_access(40);
    let (ready, result) = oneshot::channel::<()>();
    let completions = Arc::new(AtomicUsize::new(0));
    let completed = completions.clone();
    let operation = freshness.during(async move {
        result
            .await
            .map_err(|_| "synthetic cancellation".to_string())?;
        completed.fetch_add(1, SeqCst);
        Ok(())
    });
    tokio::pin!(operation);
    // This independently polled expiry future has entered its 100ms timer.
    let timer = freshness.expired();
    tokio::pin!(timer);
    let waker = futures_util::task::noop_waker();
    let mut context = Context::from_waker(&waker);
    assert!(timer.as_mut().poll(&mut context).is_pending());
    assert!(operation.as_mut().poll(&mut context).is_pending());

    // Block only this current-thread test runtime. Wall/continuous time moves,
    // but there is no runtime yield to service the Tokio timer driver.
    std::thread::sleep(Duration::from_millis(140));
    ready.send(()).unwrap();
    assert!(
        timer.as_mut().poll(&mut context).is_pending(),
        "timer-gap precondition"
    );
    match operation.as_mut().poll(&mut context) {
        Poll::Ready(Err(error)) => assert_eq!(error, ACCESS_EXPIRED),
        _ => panic!("a ready stale result escaped the per-poll admission fence"),
    }
    assert_eq!(completions.load(SeqCst), 0);
}

#[tokio::test]
async fn viewed_probe_evidence_expires_and_views_cannot_restart_probes_or_transport() {
    use rtrust_control::observations::{
        Mode, Observation, Outcome, PROBE_INTERVAL_MS, SystemProbe, now_ms,
    };

    let failover = synthetic_failover().await;
    let lease = Arc::new(Mutex::new(()));
    let held = lease.clone().lock_owned().await;
    let runs = Arc::new(AtomicUsize::new(0));
    let run_count = runs.clone();
    let fake = Probe::Fake(Arc::new(move || {
        run_count.fetch_add(1, SeqCst);
        SystemProbe {
            transport_proven_at: None,
            dns: Observation::system(Outcome::Passed, Mode::Full, now_ms()),
            guard: Observation::system(Outcome::Passed, Mode::Full, now_ms()),
        }
    }));
    let (actor, commands) = mpsc::channel(16);
    let (_shutdown, shutdown) = tokio::sync::watch::channel(false);
    let (power, power_events) = tokio::sync::watch::channel(power::State::default());
    let (initial, connected) = oneshot::channel();
    let releases = Arc::new(AtomicUsize::new(0));
    let release_count = releases.clone();
    let retries = Arc::new(AtomicUsize::new(0));
    let retry_count = retries.clone();
    let task = tokio::spawn(super::connected(
        Control {
            freshness: finite_access(5_000),
            commands,
            initial: Some(initial),
            shutdown,
            probe: Some(fake),
        },
        Workers {
            transport: "synthetic",
            tunnel: Some(tokio::spawn(std::future::pending::<RunResult>())),
            reconnect: None,
        },
        true,
        power_events,
        failover,
        move |_, _, _| {
            retry_count.fetch_add(1, SeqCst);
        },
        move || {
            release_count.fetch_add(1, SeqCst);
            drop(held);
            Ok(())
        },
    ));
    assert_eq!(connected.await.unwrap().state, State::Connected);
    ask(&actor, Command::Status { viewed: true }).await.unwrap();
    let proven = tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let response = status(&actor).await;
            if response.observations.dns.outcome == Outcome::Passed
                && response.observations.guard.outcome == Outcome::Passed
            {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the viewed synthetic probe must complete before lease expiry");
    assert_eq!(runs.load(SeqCst), 1);
    let expired = expired_status(&actor).await;
    assert_eq!(expired.state, State::Blocked);
    assert!(expired.observations.generation > proven.observations.generation);
    assert_eq!(expired.observations.dns.outcome, Outcome::Stale);
    assert_eq!(expired.observations.guard.outcome, Outcome::Stale);
    assert_eq!(releases.load(SeqCst), 0);
    assert!(lease.try_lock().is_err());

    // Drive actual due/interval timers, not just immediate post-expiry requests.
    // The real wall/continuous deadline has already irreversibly expired.
    tokio::time::pause();
    for (generation, awake) in [(1, false), (2, true), (3, true)] {
        power.send_replace(power::State { awake, generation });
        let response = ask(&actor, Command::Status { viewed: true }).await.unwrap();
        assert_eq!(response.state, State::Blocked);
        tokio::time::advance(Duration::from_millis(PROBE_INTERVAL_MS + 3_000)).await;
        let response = status(&actor).await;
        assert_eq!(response.message, ACCESS_EXPIRED);
        assert_ne!(response.observations.dns.outcome, Outcome::Passed);
        assert_ne!(response.observations.guard.outcome, Outcome::Passed);
        assert_eq!(runs.load(SeqCst), 1, "expired views started a new probe");
        assert_eq!(retries.load(SeqCst), 0, "expired views restarted transport");
    }
    // Cleanup uses a real thread; never run it under paused automatic time.
    tokio::time::resume();
    assert_eq!(ask(&actor, Command::Stop).await.unwrap().state, State::Idle);
    task.await.unwrap().unwrap();
    assert_eq!(releases.load(SeqCst), 1);
    assert!(lease.try_lock().is_ok());
}

// Probe::Fake has a synchronous callback, so actor-level pending-probe injection
// would block the runtime. This checks only Runner + Freshness composition,
// separately from the actor-plan regression above; it is not native evidence.
#[tokio::test]
async fn pending_probe_is_dropped_on_freshness_expiry_and_explicit_runner_cancel() {
    use rtrust_control::observations::{Outcome, SystemProbe, now_ms};

    let deadline = finite_access(40);
    let (drop_sender, dropped) = oneshot::channel();
    let signal = DataplaneDropped(Some(drop_sender));
    let mut runner = crate::sysprobe::Runner::default();
    runner.start(7, async move {
        deadline
            .during(async move {
                let _signal = signal;
                std::future::pending::<Result<SystemProbe, String>>().await
            })
            .await
            .unwrap_or_else(|_| SystemProbe::unknown(now_ms()))
    });
    let result = tokio::time::timeout(Duration::from_secs(2), runner.next())
        .await
        .expect("pending synthetic probe must be revoked by lease expiry");
    let crate::sysprobe::Tick::Done(generation, observation) = result else {
        panic!("a running probe must not become another due tick");
    };
    assert_eq!(generation, 7);
    assert_eq!(observation.dns.outcome, Outcome::Unknown);
    assert_eq!(observation.guard.outcome, Outcome::Unknown);
    dropped.await.expect("expiry must drop pending probe work");

    let (drop_sender, mut dropped) = oneshot::channel();
    let signal = DataplaneDropped(Some(drop_sender));
    runner.start(8, async move {
        let _signal = signal;
        std::future::pending::<SystemProbe>().await
    });
    {
        let next = runner.next();
        tokio::pin!(next);
        assert!(futures_util::poll!(&mut next).is_pending());
    }
    assert!(matches!(
        dropped.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    runner.cancel();
    dropped
        .await
        .expect("Runner cancellation must drop pending probe work");
}
