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
        delay: &mut u64,
        device: Arc<tun_rs::AsyncDevice>,
        guard: &Guard,
        lease: &Lease,
    ) {
        let profile = profile.clone();
        let guard = guard.clone();
        let lease = lease.clone();
        let wait = *delay;
        *delay = (*delay * 2).min(30);
        self.reconnect = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(wait)).await;
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
                    if let Err(error) = serve(stream, uid, lease, power).await {
                        events::record(&format!("ipc_session_ended: {error}"));
                        if let Ok(error) = std::ffi::CString::new(error) {
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
    let (profile, selection, dns) = match request.command {
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
        } => {
            let selection = rtrust_control::Selection {
                include: networks,
                exclude,
                exclude_lan,
            };
            if let Err(error) = selection.validate() {
                return reply(&mut stream, State::Error, &error).await;
            }
            (profile, selection, None)
        }
        Command::StartFull { profile, dns } => (profile, Default::default(), Some(dns)),
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
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut profile = profile;
        let mut addresses = Vec::new();
        for address in &profile.endpoint.addresses {
            for address in tokio::net::lookup_host(address)
                .await
                .map_err(|_| "Cannot resolve endpoint")?
            {
                if !address.is_ipv4() {
                    continue;
                }
                if addresses.len() >= 64 {
                    return Err("Too many endpoint addresses");
                }
                addresses.push(address.to_string());
            }
        }
        if addresses.is_empty() {
            return Err("Endpoint has no addresses");
        }
        profile.endpoint.addresses = addresses;
        Ok(profile)
    })
    .await;
    let profile = match result {
        Ok(Ok(profile)) => profile,
        _ => {
            return reply(
                &mut stream,
                State::Error,
                "Не удалось разрешить адрес VPN-сервера",
            )
            .await;
        }
    };
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
    if let Err(error) = Guard::preflight(&networks, dns) {
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
            result = tokio::time::timeout(Duration::from_secs(30), device::Prepared::connect(&profile)) => match result {
                Ok(Ok(prepared)) => prepared,
                _ => return reply(&mut stream, State::Error, "Не удалось открыть TUN: проверьте профиль, TLS и доступность endpoint").await,
            },
            _ = stream.read(&mut unexpected) => return Err("IPC closed during connect".into()),
        }
    };
    let guard = match Guard::install(
        uid,
        networks,
        dns,
        endpoints,
        profile.udp_transport(),
        &profile.hop_port_ranges(),
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
        move |workers, delay| {
            workers.retry(&profile, delay, device.clone(), &retry_guard, &held_lease)
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
    mut retry: impl FnMut(&mut Workers, &mut u64),
    release: impl FnOnce() -> Result<(), String>,
) -> Result<(), String> {
    events::record("tunnel_connected");
    let mut retry_delay = 2;
    let mut connected_since = Instant::now();
    reply(
        &mut stream,
        State::Connected,
        if full {
            "Весь компьютер: IPv4, IPv6 и DNS через VPN"
        } else {
            "IPv4-сети подключены"
        },
    )
    .await?;
    let mut state = State::Connected;
    let mut last_failure = String::new();
    let mut restart_pending = false;
    let mut awake = power.borrow().awake;
    loop {
        let mut pending = Box::pin(read::<Request>(&mut stream));
        let request = loop {
            // Aborted block_in_place work can still own route mutations. Join
            // completion in select below, keeping Status and EOF responsive.
            if awake && workers.idle() {
                events::record(&format!("reconnect_scheduled delay={retry_delay}"));
                retry(&mut workers, &mut retry_delay);
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
                    retry_delay = 2;
                }
                result = async { workers.tunnel.as_mut().unwrap().await }, if workers.tunnel.is_some() => {
                    workers.tunnel = None;
                    if restart_pending { continue; }
                    last_failure = match result {
                        Ok(Err(error)) => format!("VPN transport stopped: {error}"),
                        Ok(Ok(())) => "VPN transport stopped".into(),
                        Err(_) => "VPN transport worker failed".into(),
                    };
                    events::record(&last_failure);
                    state = State::Blocked;
                    // A flapping endpoint must not reset the backoff indefinitely.
                    if connected_since.elapsed() >= Duration::from_secs(30) { retry_delay = 2; }
                }
                result = async { workers.reconnect.as_mut().unwrap().await }, if workers.reconnect.is_some() => {
                    workers.reconnect = None;
                    // A task can complete just before abort. Do not resurrect
                    // its pre-wake transport even if its result was successful.
                    if restart_pending { continue; }
                    match &result {
                        Ok(Err(error)) => {
                            last_failure = format!("VPN reconnect failed: {error}");
                            events::record(&last_failure);
                        }
                        Err(_) => last_failure = "VPN reconnect worker failed".into(),
                        _ => {},
                    }
                    if let Ok(Ok(prepared)) = result {
                        workers.tunnel = Some(tokio::spawn(prepared.run()));
                        connected_since = Instant::now();
                        state = State::Connected;
                        events::record("reconnect_complete");
                        continue;
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
                reply(
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
                )
                .await?
            }
            Command::Stop => {
                events::record("stop_requested");
                workers.stop().await;
                return match release() {
                    Ok(()) => reply(&mut stream, State::Idle, "Отключено").await,
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
            move |workers, _| {
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
            move |workers, _| {
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
