use super::{
    device, events, power, routes,
    state::{self, Guard},
};
use rtrust_control::{Command, Request, Response, State, VERSION, read, write};
use std::{
    fs,
    net::Ipv4Addr,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite},
    net::UnixListener,
    sync::Mutex,
    task::JoinSet,
};

type RunResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type Lease = Arc<tokio::sync::OwnedMutexGuard<()>>;

async fn guarded_connect<T>(
    lease: Lease,
    refresh: impl Fn() -> Result<(), String>,
    connect: impl std::future::Future<Output = Result<T, String>>,
) -> Result<T, String> {
    // block_in_place lets IPC tasks run while fixed system tools execute. Unlike
    // detached spawn_blocking work, abort + join drains this task before Stop
    // releases the guard. Retain the lease even if the owning IPC task exits.
    let _lease = lease;
    tokio::task::block_in_place(&refresh)?;
    let prepared = connect.await?;
    tokio::task::block_in_place(refresh)?;
    Ok(prepared)
}
struct Workers {
    tunnel: Option<tokio::task::JoinHandle<RunResult>>,
    reconnect: Option<tokio::task::JoinHandle<Result<device::Prepared, String>>>,
}
impl Drop for Workers {
    fn drop(&mut self) {
        if let Some(task) = &self.tunnel {
            task.abort();
        }
        if let Some(task) = &self.reconnect {
            task.abort();
        }
    }
}
impl Workers {
    fn retry(
        &mut self,
        profile: &rtrust_profile::Profile,
        delay: &mut rtrust_control::recovery::Budget,
        device: Arc<tun_rs::AsyncDevice>,
        guard: &Guard,
        lease: &Lease,
    ) {
        let profile = profile.clone();
        let guard = guard.clone();
        let lease = lease.clone();
        let wait = delay.next_delay(rand::random());
        self.reconnect = Some(tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            // Darwin can discard endpoint host routes during sleep. Restore
            // them before opening a socket, or split routes send it into utun.
            guarded_connect(lease, || guard.refresh(), async {
                tokio::time::timeout(
                    Duration::from_secs(30),
                    device::Prepared::reconnect(&profile, device),
                )
                .await
                .map_err(|_| "Reconnect timed out".to_owned())?
                .map_err(|e| format!("Reconnect failed: {e}"))
            })
            .await
        }));
    }
    fn cancel(&self) {
        if let Some(task) = &self.reconnect {
            task.abort();
        }
        if let Some(task) = &self.tunnel {
            task.abort();
        }
    }
    fn idle(&self) -> bool {
        self.tunnel.is_none() && self.reconnect.is_none()
    }
    async fn stop(&mut self) {
        if let Some(task) = self.reconnect.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(task) = self.tunnel.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
pub async fn run() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("The service must run as root".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("Usage: rtrust-service ALLOWED_UID".into());
    }
    let uid: u32 = args
        .last()
        .unwrap()
        .parse()
        .map_err(|_| "Invalid allowed UID")?;
    if uid < 501 {
        return Err("Choose an unprivileged desktop UID".into());
    }
    if !std::path::Path::new("/private/var/run/rtrust").exists() {
        fs::DirBuilder::new()
            .mode(0o711)
            .create("/private/var/run/rtrust")
            .map_err(|_| "Cannot create runtime directory")?;
    }
    let metadata =
        fs::symlink_metadata("/private/var/run/rtrust").map_err(|_| "Invalid runtime directory")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("Unsafe runtime directory".into());
    }
    // launchd's 0077 umask masks DirBuilder's execute bits. The desktop user
    // needs traversal to the authenticated socket, not a directory listing.
    fs::set_permissions("/private/var/run/rtrust", fs::Permissions::from_mode(0o711))
        .map_err(|_| "Cannot set runtime directory permissions")?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/private/var/run/rtrust/service.lock")
        .map_err(|_| "Cannot open service lock")?;
    fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| "Service already running")?;
    if let Ok(metadata) = fs::symlink_metadata(rtrust_control::SOCKET) {
        use std::os::unix::fs::FileTypeExt;
        if !metadata.file_type().is_socket() || metadata.uid() != 0 {
            return Err("Unsafe socket path".into());
        }
        fs::remove_file(rtrust_control::SOCKET).map_err(|_| "Cannot replace stale socket")?;
    }
    let listener =
        UnixListener::bind(rtrust_control::SOCKET).map_err(|_| "Cannot bind service socket")?;
    fs::set_permissions(rtrust_control::SOCKET, fs::Permissions::from_mode(0o666))
        .map_err(|_| "Cannot set socket permissions")?;
    let lease = Arc::new(Mutex::new(()));
    state::directory()?;
    let power = power::Monitor::new()?;
    events::record("service_started native_power_monitor=registered");
    let mut tasks = JoinSet::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "Cannot register signal")?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| "IPC accept failed")?;
                if stream.peer_cred().map_err(|_| "IPC identity failed")?.uid() != uid || tasks.len() >= 16 { continue; }
                let lease = lease.clone();
                let power = power.events.clone();
                tasks.spawn(async move {
                    if serve(stream, uid, lease, power).await.is_err() {
                        events::record("ipc_session_ended");
                        if let Ok(error) = std::ffi::CString::new("redacted IPC failure") {
                        // launchd discards our stderr; retain redacted IPC
                        // failures in the macOS system log for diagnosis.
                        unsafe {
                            libc::syslog(libc::LOG_ERR, c"R-TrustTunnel IPC session ended: %s".as_ptr(), error.as_ptr());
                        }
                        }
                    }
                });
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            _ = terminate.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    fs::remove_file(rtrust_control::SOCKET).map_err(|_| "Cannot remove service socket")?;
    Ok(())
}
async fn reply(
    stream: &mut (impl AsyncWrite + Unpin),
    state: State,
    message: &str,
) -> Result<(), String> {
    tokio::time::timeout(
        Duration::from_secs(5),
        write(stream, &Response::new(state, message)),
    )
    .await
    .map_err(|_| "IPC write timed out")?
}
async fn reply_observed(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    state: State,
    message: &str,
    monitor: &mut rtrust_control::observations::Monitor,
    active_profile: Option<u8>,
) -> Result<(), String> {
    let mut response = Response::new(state, message);
    response.active_profile = active_profile;
    response.observations = monitor.sample(rtrust_control::observations::now_ms());
    tokio::time::timeout(Duration::from_secs(5), write(stream, &response))
        .await
        .map_err(|_| "IPC write timed out")?
}
async fn serve(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    uid: u32,
    lease: Arc<Mutex<()>>,
    mut power: tokio::sync::watch::Receiver<power::State>,
) -> Result<(), String> {
    let request: Request = tokio::time::timeout(Duration::from_secs(5), read(&mut stream))
        .await
        .map_err(|_| "IPC read timed out")??;
    if request.version != VERSION {
        return reply(&mut stream, State::Error, "IPC version mismatch").await;
    }
    if matches!(request.command, Command::Capabilities) {
        return write(&mut stream, &Response::new(State::Idle, "Capabilities")).await;
    }
    let Ok(_lease) = lease.try_lock_owned() else {
        return reply(
            &mut stream,
            State::Error,
            "Служба уже обслуживает подключение",
        )
        .await;
    };
    let held_lease = Arc::new(_lease);
    power.borrow_and_update();
    let (profile, selection, dns, split_dns, fallbacks) = match request.command {
        Command::PrepareUpdate => {
            if state::pending() {
                return reply(
                    &mut stream,
                    State::Blocked,
                    "Сначала восстановите защиту VPN; обновление отменено",
                )
                .await;
            }
            reply(
                &mut stream,
                State::Idle,
                "Служба зарезервирована для обновления",
            )
            .await?;
            let _ = read::<Request>(&mut stream).await;
            return Ok(());
        }
        Command::Recover => {
            return match state::recover(uid) {
                Ok(()) => reply(&mut stream, State::Idle, "Блокировка снята").await,
                Err(e) => reply(&mut stream, State::Blocked, &e).await,
            };
        }
        Command::Start {
            profile,
            networks,
            exclude,
            exclude_lan,
            dns,
            fallbacks,
        } => {
            let selection = rtrust_control::Selection {
                include: networks,
                exclude,
                exclude_lan,
            };
            if let Err(error) = selection.validate() {
                return reply(&mut stream, State::Error, &error).await;
            }
            (profile, selection, None, dns, fallbacks)
        }
        Command::StartFull {
            profile,
            dns,
            fallbacks,
        } => (profile, Default::default(), Some(dns), None, fallbacks),
        _ => return reply(&mut stream, State::Error, "Start or Recover required").await,
    };
    let full = dns.is_some();
    if state::pending() {
        // A retained guard blocks DNS; report it before resolving the endpoint.
        return reply(
            &mut stream,
            State::Error,
            "Recovery is required before connecting",
        )
        .await;
    }
    // Both modes pin IPv4 endpoint addresses: PF blocks selected networks
    // outside the tunnel, so the endpoint must be known and left out of them.
    // Every allowed backup is pinned now: the guard covers all candidates.
    let mut failover =
        match crate::failover::Failover::pin(*profile, fallbacks, crate::failover::Pin::Ipv4).await
        {
            Ok(failover) => failover,
            _ => {
                return reply(
                    &mut stream,
                    State::Error,
                    "Не удалось разрешить адрес VPN-сервера",
                )
                .await;
            }
        };
    let profile = failover.guard_profile();
    let endpoints = match state::endpoints(&profile) {
        Ok(e) => e,
        Err(e) => return reply(&mut stream, State::Error, &e).await,
    };
    let networks = if full {
        vec![]
    } else {
        let ips: Vec<Ipv4Addr> = endpoints.iter().map(|e| *e.ip()).collect();
        let local = if selection.exclude_lan {
            routes::local()
        } else {
            Ok(vec![])
        };
        match local.and_then(|local| selection.routes(&ips, &local)) {
            Ok(networks) => networks,
            Err(e) => return reply(&mut stream, State::Error, &e).await,
        }
    };
    // A split selection that carries the resolver (e.g. everything but the
    // LAN) gets VPN DNS too; otherwise names would leak to the LAN resolver.
    // Like Linux without systemd-resolved, split mode skips DNS when the
    // system resolver cannot take it; full mode still requires it.
    let resolver = dns.or(rtrust_control::tunneled_resolver(&networks, split_dns)
        .filter(|_| super::dns::preflight().is_ok()));
    if let Err(error) = Guard::preflight(&networks, full, resolver) {
        return reply(&mut stream, State::Error, &error).await;
    }
    if !power.borrow().awake {
        return reply(
            &mut stream,
            State::Blocked,
            "macOS ещё не завершила пробуждение",
        )
        .await;
    }
    let prepared = {
        let mut unexpected = [0];
        tokio::select! {
            result = failover.connect_initial(|profile| async move { device::Prepared::connect(&profile).await }) => match result {
                Ok(prepared) => prepared,
                _ => return reply(&mut stream, State::Error, "Не удалось открыть TUN: проверьте профиль, TLS и доступность endpoint").await,
            },
            _ = stream.read(&mut unexpected) => return Err("IPC closed during connect".into()),
        }
    };
    let guard = match Guard::install(
        uid,
        networks,
        full,
        resolver,
        endpoints,
        &failover.permits()?,
    ) {
        Ok(guard) => guard,
        Err(error) => return reply(&mut stream, State::Blocked, &error).await,
    };
    let device = prepared.device();
    let workers = Workers {
        tunnel: Some(tokio::spawn(prepared.run())),
        reconnect: None,
    };
    let retry_guard = guard.clone();
    connected(
        stream,
        workers,
        full,
        power,
        failover,
        move |workers, profile, delay| {
            workers.retry(profile, delay, device.clone(), &retry_guard, &held_lease)
        },
        move || guard.release(),
    )
    .await
}

// Keep all IPC and worker completion events in one supervisor. In particular,
// a wake must never await cancellation inside a select branch: block_in_place
// route mutations cannot be cancelled until they return.
async fn connected(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    mut workers: Workers,
    full: bool,
    mut power: tokio::sync::watch::Receiver<power::State>,
    mut failover: crate::failover::Failover,
    mut retry: impl FnMut(&mut Workers, &rtrust_profile::Profile, &mut rtrust_control::recovery::Budget),
    release: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    events::record("tunnel_connected");
    let mut retry_delay = rtrust_control::recovery::Budget::default();
    let mut connected_since = Instant::now();
    let mut monitor = rtrust_control::observations::Monitor::new(
        if full {
            rtrust_control::observations::Mode::Full
        } else {
            rtrust_control::observations::Mode::Split
        },
        rtrust_control::observations::Source::ServiceLifecycle,
        rtrust_control::observations::now_ms(),
    );
    if failover.active().is_some_and(|index| index > 0) {
        monitor.failed_over(rtrust_control::observations::now_ms());
    }
    reply_observed(
        &mut stream,
        State::Connected,
        &format!(
            "{}{}",
            if full {
                "Весь компьютер: IPv4, IPv6 и DNS через VPN"
            } else {
                "IPv4-сети подключены"
            },
            failover.note()
        ),
        &mut monitor,
        failover.active(),
    )
    .await?;
    let mut state = State::Connected;
    monitor.transition(true, rtrust_control::observations::now_ms());
    let mut netwatch = crate::netwatch::Watch::new(super::device::DEVICE);
    let mut last_failure = String::new();
    let mut restart_pending = false;
    let mut awake = power.borrow().awake;
    loop {
        let mut pending = Box::pin(read::<Request>(&mut stream));
        let request = loop {
            // Aborted block_in_place work can still own route mutations. Join
            // completion in select below, keeping Status and EOF responsive.
            if awake && workers.idle() {
                events::record("reconnect_scheduled");
                retry(&mut workers, failover.current(), &mut retry_delay);
                restart_pending = false;
            }
            tokio::select! {
                request = &mut pending => break request?,
                event = power.changed() => {
                    event.map_err(|_| "macOS power monitor stopped")?;
                    let event = *power.borrow_and_update();
                    awake = event.awake;
                    events::record(&format!("power_event awake={awake} generation={}", event.generation));
                    workers.cancel();
                    restart_pending = true;
                    state = State::Blocked;
                    last_failure = if awake { "Восстановление VPN после сна" } else { "VPN приостановлен на время сна" }.into();
                    if awake { monitor.resumed(rtrust_control::observations::now_ms()); }
                    monitor.transition(false, rtrust_control::observations::now_ms());
                }
                change = netwatch.next() => match change {
                    crate::netwatch::Change::Network => monitor.network_changed(rtrust_control::observations::now_ms()),
                    crate::netwatch::Change::Resumed => monitor.resumed(rtrust_control::observations::now_ms()),
                },
                result = async { workers.tunnel.as_mut().unwrap().await }, if workers.tunnel.is_some() => {
                    workers.tunnel = None;
                    if restart_pending { continue; }
                    last_failure = match result {
                        Ok(Err(_)) => "VPN transport stopped".into(),
                        Ok(Ok(())) => "VPN transport stopped".into(),
                        Err(_) => "VPN transport worker failed".into(),
                    };
                    events::record(&last_failure);
                    state = State::Blocked;
                    // A flapping endpoint must not reset the backoff indefinitely.
                    monitor.transition(false, rtrust_control::observations::now_ms());
                    retry_delay.disconnected(connected_since.elapsed());
                    if failover.ended(connected_since.elapsed(), Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                    }
                }
                result = async { workers.reconnect.as_mut().unwrap().await }, if workers.reconnect.is_some() => {
                    workers.reconnect = None;
                    // A task can complete just before abort. Do not resurrect
                    // its pre-wake transport even if its result was successful.
                    if restart_pending { continue; }
                    match &result {
                        Ok(Err(_)) => {
                            last_failure = "VPN reconnect failed".into();
                            events::record(&last_failure);
                        }
                        Err(_) => last_failure = "VPN reconnect worker failed".into(),
                        _ => {},
                    }
                    if let Ok(Ok(prepared)) = result {
                        workers.tunnel = Some(tokio::spawn(prepared.run()));
                        connected_since = Instant::now();
                        state = State::Connected;
                        monitor.transition(true, rtrust_control::observations::now_ms());
                        events::record("reconnect_complete");
                        continue;
                    }
                    if failover.failed(Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                    }
                }
            }
        };
        drop(pending);
        if request.version != VERSION {
            return Err("IPC version mismatch".into());
        }
        match request.command {
            Command::Status => {
                reply_observed(
                    &mut stream,
                    state.clone(),
                    if state == State::Connected {
                        if full {
                            "Весь компьютер: IPv4, IPv6 и DNS через VPN"
                        } else {
                            "Выбранные IPv4-сети подключены"
                        }
                    } else {
                        &last_failure
                    },
                    &mut monitor,
                    failover.active(),
                )
                .await?
            }
            Command::Stop => {
                events::record("stop_requested");
                workers.stop().await;
                return match release() {
                    Ok(()) => {
                        monitor.stop(rtrust_control::observations::now_ms());
                        reply_observed(&mut stream, State::Idle, "Отключено", &mut monitor, None)
                            .await
                    }
                    Err(e) => reply(&mut stream, State::Blocked, &e).await,
                };
            }
            _ => return Err("Invalid operation during lease".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn failover() -> crate::failover::Failover {
        let profile = rtrust_profile::Profile::import("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n").unwrap();
        crate::failover::Failover::pin(profile, vec![], crate::failover::Pin::Ipv4)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sleep_waits_for_powered_on_and_stop_remains_available() {
        let (power, receiver) = tokio::sync::watch::channel(power::State::default());
        let retries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts = retries.clone();
        let (mut client, server) = tokio::io::duplex(4096);
        let supervisor = tokio::spawn(connected(
            server,
            Workers {
                tunnel: Some(tokio::spawn(std::future::pending())),
                reconnect: None,
            },
            false,
            receiver,
            failover().await,
            move |workers, _, _| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                workers.reconnect = Some(tokio::spawn(std::future::pending()));
            },
            || Ok(()),
        ));
        let _: Response = read(&mut client).await.unwrap();
        power.send_modify(|s| {
            s.awake = false;
            s.generation += 1;
        });
        // Wait for the supervisor's actual observable state, not scheduler timing.
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                write(
                    &mut client,
                    &Request {
                        version: VERSION,
                        command: Command::Status,
                    },
                )
                .await
                .unwrap();
                if read::<Response>(&mut client).await.unwrap().state == State::Blocked {
                    break;
                }
            }
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        assert_eq!(retries.load(std::sync::atomic::Ordering::SeqCst), 0);
        power.send_modify(|s| {
            s.awake = true;
            s.generation += 1;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while retries.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(retries.load(std::sync::atomic::Ordering::SeqCst), 1);
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Stop,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read::<Response>(&mut client).await.unwrap().state,
            State::Idle
        );
        supervisor.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn repeated_power_events_preserve_retry_budget_and_stale_evidence() {
        let (power, receiver) = tokio::sync::watch::channel(power::State::default());
        let delays = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = delays.clone();
        let (mut client, server) = tokio::io::duplex(4096);
        let supervisor = tokio::spawn(connected(
            server,
            Workers {
                tunnel: Some(tokio::spawn(std::future::pending())),
                reconnect: None,
            },
            false,
            receiver,
            failover().await,
            move |workers, _, budget| {
                recorded.lock().unwrap().push(budget.next_delay(0));
                workers.reconnect = Some(tokio::spawn(std::future::pending()));
            },
            || Ok(()),
        ));
        let initial: Response = read(&mut client).await.unwrap();
        for attempt in 1..=9 {
            power.send_modify(|s| s.generation += 1);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    write(
                        &mut client,
                        &Request {
                            version: VERSION,
                            command: Command::Status,
                        },
                    )
                    .await
                    .unwrap();
                    let status: Response = read(&mut client).await.unwrap();
                    if delays.lock().unwrap().len() == attempt && status.state == State::Blocked {
                        assert_ne!(
                            status.observations.generation,
                            initial.observations.generation
                        );
                        assert!(!status.observations.verified());
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(
            delays.lock().unwrap()[8],
            rtrust_control::recovery::COOLDOWN
        );
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Stop,
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read::<Response>(&mut client).await.unwrap().state,
            State::Idle
        );
        supervisor.await.unwrap().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wake_during_route_refresh_keeps_real_supervisor_responsive() {
        let lease = Arc::new(Mutex::new(()));
        let held = Arc::new(lease.clone().lock_owned().await);
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let (release, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let worker = tokio::spawn(guarded_connect(
            held,
            move || {
                signal.notify_one();
                wait.lock().unwrap().recv().unwrap();
                Ok(())
            },
            std::future::pending::<Result<device::Prepared, String>>(),
        ));
        entered.notified().await;
        let retries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let attempts = retries.clone();
        let (mut client, server) = tokio::io::duplex(4096);
        let (power, power_events) = tokio::sync::watch::channel(power::State::default());
        let supervisor = tokio::spawn(connected(
            server,
            Workers {
                tunnel: None,
                reconnect: Some(worker),
            },
            false,
            power_events,
            failover().await,
            move |workers, _, _| {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                workers.reconnect = Some(tokio::spawn(std::future::pending()));
            },
            || Ok(()),
        ));
        let _: Response = read(&mut client).await.unwrap();
        power.send_modify(|s| s.generation += 1);
        // Deliver a real supervisor power event while refresh is still blocked.
        tokio::time::sleep(Duration::from_millis(30)).await;
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Status,
            },
        )
        .await
        .unwrap();
        let response =
            tokio::time::timeout(Duration::from_millis(200), read::<Response>(&mut client)).await;
        let before_release = retries.load(std::sync::atomic::Ordering::SeqCst);
        let lease_held = lease.try_lock().is_err();
        release.send(()).unwrap();
        // Always unblock the worker before asserting, including on the old code.
        let drained = tokio::time::timeout(Duration::from_secs(1), async {
            while retries.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        supervisor.abort();
        let _ = supervisor.await;
        assert!(lease_held);
        assert_eq!(before_release, 0, "must drain old mutations before retry");
        assert!(drained.is_ok());
        assert_eq!(
            response.expect("wake blocked Status IPC").unwrap().state,
            State::Blocked
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_guard_refresh_keeps_status_replies_responsive() {
        let lease = Arc::new(Mutex::new(()));
        let held = Arc::new(lease.clone().lock_owned().await);
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let (release, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let worker = tokio::spawn(guarded_connect(
            held,
            move || {
                if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 1 {
                    signal.notify_one();
                    wait.lock().unwrap().recv().unwrap();
                }
                Ok(())
            },
            async { Ok::<_, String>(()) },
        ));
        entered.notified().await;
        let (mut client, mut server) = tokio::io::duplex(4096);
        let ipc = tokio::spawn(async move {
            let request: Request = read(&mut server).await.unwrap();
            assert!(matches!(request.command, Command::Status));
            reply(&mut server, State::Blocked, "reconnecting")
                .await
                .unwrap();
        });
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Status,
            },
        )
        .await
        .unwrap();
        let response: Response =
            tokio::time::timeout(Duration::from_millis(100), read(&mut client))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(response.state, State::Blocked);
        release.send(()).unwrap();
        worker.await.unwrap().unwrap();
        ipc.await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_refresh_retains_lease_and_stop_drains_mutations() {
        let lease = Arc::new(Mutex::new(()));
        let held = Arc::new(lease.clone().lock_owned().await);
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let (release, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let mut worker = tokio::spawn(guarded_connect(
            held,
            move || {
                signal.notify_one();
                wait.lock().unwrap().recv().unwrap();
                Ok(())
            },
            std::future::pending::<Result<(), String>>(),
        ));
        entered.notified().await;
        worker.abort();
        assert!(lease.try_lock().is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut worker)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert!(worker.await.unwrap_err().is_cancelled());
        assert!(lease.try_lock().is_ok());
    }

    #[tokio::test]
    async fn capabilities_are_read_only_and_available_during_an_active_lease() {
        let lease = Arc::new(Mutex::new(()));
        let _held = lease.clone().lock_owned().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(
            server,
            501,
            lease,
            tokio::sync::watch::channel(power::State::default()).1,
        ));
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Capabilities,
            },
        )
        .await
        .unwrap();
        let response: Response = read(&mut client).await.unwrap();
        assert_eq!(response.state, State::Idle);
        assert_eq!(
            response.capabilities.observations_schema,
            rtrust_control::observations::SCHEMA
        );
        assert!(!response.capabilities.system_probes);
        assert!(!response.observations.verified());
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn rejects_wrong_version_before_any_privileged_operation() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(
            server,
            501,
            Arc::new(Mutex::new(())),
            tokio::sync::watch::channel(power::State::default()).1,
        ));
        write(
            &mut client,
            &Request {
                version: VERSION + 1,
                command: Command::Recover,
            },
        )
        .await
        .unwrap();
        let response: Response = read(&mut client).await.unwrap();
        assert_eq!(response.state, State::Error);
        assert_eq!(response.message, "IPC version mismatch");
        task.await.unwrap().unwrap();
    }
    #[tokio::test]
    async fn concurrent_recovery_cannot_steal_active_or_maintenance_lease() {
        let lease = Arc::new(Mutex::new(()));
        let held = lease.clone().lock_owned().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(
            server,
            501,
            lease,
            tokio::sync::watch::channel(power::State::default()).1,
        ));
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Recover,
            },
        )
        .await
        .unwrap();
        let response: Response = read(&mut client).await.unwrap();
        assert_eq!(response.state, State::Error);
        task.await.unwrap().unwrap();
        drop(held);
    }
}
