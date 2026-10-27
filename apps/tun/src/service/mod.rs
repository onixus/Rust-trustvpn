mod boot;
mod broker;
mod endpoint;
mod full;
mod probe;
mod routes;
use full::FullRoutes;
enum Guard {
    Selected(Routes),
    Full(FullRoutes),
}
impl Guard {
    fn reattach(&self) -> Result<(), String> {
        match self {
            Self::Selected(r) => r.reattach(),
            Self::Full(r) => r.reattach(),
        }
    }
    fn release(&mut self) -> Result<(), String> {
        match self {
            Self::Selected(r) => r.release(),
            Self::Full(r) => r.release(),
        }
    }
}
use routes::Routes;
use rtrust_control::{Command, Request, Response, State, VERSION, read, write};
use std::{
    fs,
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
struct Workers {
    tunnel: Option<tokio::task::JoinHandle<RunResult>>,
    reconnect:
        Option<tokio::task::JoinHandle<Result<crate::linux::Prepared, crate::failover::Failure>>>,
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
        full: bool,
    ) {
        let profile = profile.clone();
        let wait = delay.next_delay(rand::random());
        let attempt = delay.attempt();
        let budget = rtrust_journal::Budget::from_cooling(delay.cooling());
        let transport = rtrust_engine::planned_transport(&profile);
        self.reconnect = Some(tokio::spawn(async move {
            tokio::time::sleep(wait).await;
            let started = Instant::now();
            let result = tokio::time::timeout(
                Duration::from_secs(30),
                crate::linux::Prepared::connect_mode(
                    &profile,
                    routes::DEVICE,
                    routes::ADDRESS.parse().unwrap(),
                    full,
                ),
            )
            .await
            .map_err(|_| crate::failover::Failure::timeout("Reconnect timed out"))
            .and_then(|r| {
                r.map_err(|e| crate::failover::Failure {
                    class: rtrust_journal::classify_boxed(e.as_ref()),
                    message: format!("Reconnect failed: {e}"),
                    record: None,
                })
            });
            result.map_err(|mut e| {
                e.record = Some(rtrust_journal::Record::failure(
                    rtrust_journal::Path::Reconnect,
                    e.class,
                    transport,
                    attempt,
                    budget,
                    started.elapsed(),
                ));
                e
            })
        }));
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
    let boot_only = args.len() == 2 && args[0] == "--boot-guard";
    if args.len() != 1 && !boot_only {
        return Err("Usage: rtrust-service ALLOWED_UID".into());
    }
    let uid: u32 = args
        .last()
        .unwrap()
        .parse()
        .map_err(|_| "Invalid allowed UID")?;
    if uid == 0 {
        return Err("Choose an unprivileged desktop UID".into());
    }
    if !std::path::Path::new("/run/rtrust").exists() {
        fs::DirBuilder::new()
            .mode(0o711)
            .create("/run/rtrust")
            .map_err(|_| "Cannot create runtime directory")?;
    }
    let metadata = fs::symlink_metadata("/run/rtrust").map_err(|_| "Invalid runtime directory")?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("Unsafe runtime directory".into());
    }
    if boot_only {
        if crate::boot_policy::exists()? {
            boot_guard(true)?;
        }
        return Ok(());
    }
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/run/rtrust/service.lock")
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
    let supervisor = crate::always_on::Supervisor::start(uid.to_string(), lease.clone())?;
    let _broker = if std::env::var_os("RTRUST_DBUS").as_deref() == Some(std::ffi::OsStr::new("1")) {
        Some(broker::start(uid, lease.clone(), supervisor.clone()).await?)
    } else {
        None
    };
    let mut tasks = JoinSet::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "Cannot register signal")?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| "IPC accept failed")?;
                if stream.peer_cred().map_err(|_| "IPC identity failed")?.uid() != uid || tasks.len() >= 16 { continue; }
                let lease = lease.clone();
                let supervisor=supervisor.clone();
                tasks.spawn(async move { let _ = serve(stream, uid, lease,Some(supervisor)).await; });
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
    response.endpoint_probe_token = endpoint::registry().current_token();
    response.observations = monitor.sample(rtrust_control::observations::now_ms());
    tokio::time::timeout(Duration::from_secs(5), write(stream, &response))
        .await
        .map_err(|_| "IPC write timed out")?
}
async fn serve(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    uid: u32,
    lease: Arc<Mutex<()>>,
    supervisor: Option<Arc<crate::always_on::Supervisor>>,
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
    if let Command::ProbeEndpoint { token } = request.command {
        return endpoint::serve(&mut stream, token, uid).await;
    }
    if let Some(ref supervisor) = supervisor {
        if matches!(request.command, Command::Stop) {
            supervisor.cancel_pending_enable();
        }
        match request.command {
            Command::AlwaysOnStatus{viewed}=>return write(&mut stream,&supervisor.status(viewed)).await,
            command @ (Command::EnableAlwaysOn{..}|Command::EnableRecovery{..}|Command::DisableAlwaysOn)=>return write(&mut stream,&supervisor.command(command).await).await,
            _ if supervisor.enabled()=>return reply(&mut stream,State::Error,"Always-on управляется системной службой. Для обслуживания сначала выключите always-on.").await,
            _=>{},
        }
    }
    let Ok(_lease) = lease.try_lock_owned() else {
        return reply(
            &mut stream,
            State::Error,
            "Служба уже обслуживает подключение",
        )
        .await;
    };
    let mut journal = crate::failover::start_journal(&request.command);
    let (mut freshness, command) = match rtrust_control::freshness::start(request.command) {
        Ok(start) => start,
        Err(error) => {
            if let Some(journal) = journal.as_mut() {
                journal.class(rtrust_journal::Class::Authentication);
            }
            return reply(&mut stream, State::Error, &error).await;
        }
    };
    let (profile, networks, dns, split_dns, fallbacks) = match command {
        Command::PrepareUpdate => {
            if FullRoutes::pending() || Routes::pending() {
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
        Command::Recover { .. } => {
            return match FullRoutes::recover(uid).and_then(|()| Routes::recover(uid)) {
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
            // Only this user's traffic is policy-routed; the service's own
            // endpoint connection never matches, so no endpoint exception.
            let selection = rtrust_control::Selection {
                include: networks,
                exclude,
                exclude_lan,
            };
            match selection
                .validate()
                .inspect_err(|_| {
                    if let Some(journal) = journal.as_mut() {
                        journal.class(rtrust_journal::Class::Profile);
                    }
                })
                .and_then(|()| {
                    selection.routes(
                        &[],
                        &if exclude_lan {
                            Routes::local()?
                        } else {
                            vec![]
                        },
                    )
                }) {
                Ok(routes) => {
                    let resolver = Routes::resolver(&routes, dns);
                    (profile, routes, None, resolver, fallbacks)
                }
                Err(error) => return reply(&mut stream, State::Error, &error).await,
            }
        }
        Command::StartFull {
            profile,
            dns,
            fallbacks,
        } => {
            if let Err(error) = rtrust_control::validate_dns(dns) {
                if let Some(journal) = journal.as_mut() {
                    journal.class(rtrust_journal::Class::Profile);
                }
                return reply(&mut stream, State::Error, &error).await;
            }
            (profile, vec![], Some(dns), None, fallbacks)
        }
        _ => return reply(&mut stream, State::Error, "Start or Recover required").await,
    };
    let mut journal = journal.unwrap_or_else(|| {
        crate::failover::journal_attempt(
            rtrust_journal::Path::Start,
            rtrust_engine::planned_transport(&profile),
            1,
            rtrust_journal::Budget::Burst,
        )
    });
    if let Err(error) = if let Some(dns) = dns {
        FullRoutes::preflight(dns)
    } else {
        Routes::preflight(&networks)
    } {
        return reply(&mut stream, State::Error, &error).await;
    }
    let full = dns.is_some();
    // Full mode pins every allowed candidate: the guard covers them all.
    // Selected mode routes only this user's traffic, so nothing is pinned.
    journal.cancelled();
    let mut failover = match crate::failover::Failover::pin(
        *profile,
        fallbacks,
        if full {
            crate::failover::Pin::All
        } else {
            crate::failover::Pin::Unresolved
        },
    )
    .await
    {
        Ok(failover) => failover,
        Err(error) => {
            journal.class(error.class());
            return reply(
                &mut stream,
                State::Error,
                "Не удалось разрешить адрес VPN-сервера",
            )
            .await;
        }
    };
    journal.cancelled();
    let prepared = {
        let mut unexpected = [0];
        tokio::select! {
            result = async {
                let mut connection_failed=false;
                let result=rtrust_control::freshness::while_valid(freshness.as_mut(), async {
                    failover.connect_initial(|profile| async move { crate::linux::Prepared::connect_mode(&profile, routes::DEVICE, routes::ADDRESS.parse().unwrap(), full).await }).await.map_err(|e| {
                        connection_failed=true;
                        e.annotate(&mut journal,|e|rtrust_journal::classify_boxed(e.as_ref()));
                        "No allowed VPN endpoint connected within the startup budget".to_owned()
                    })
                }).await;
                if result.is_err() && !connection_failed {journal.class(rtrust_journal::Class::Authentication);}
                result
            } => match result {
                Ok(prepared) => prepared,
                Err(_) => return reply(&mut stream, State::Error, "Не удалось открыть TUN: проверьте профиль, TLS и доступность endpoint").await,
            },
            _ = stream.read(&mut unexpected) => return Err("IPC closed during connect".into()),
        }
    };
    journal.class(rtrust_journal::Class::Other);
    let mut routes = match if let Some(dns) = dns {
        FullRoutes::install(uid, dns, &failover.endpoint_addresses()).map(Guard::Full)
    } else {
        Routes::install(uid, networks, split_dns).map(Guard::Selected)
    } {
        Ok(routes) => routes,
        Err(error) => return reply(&mut stream, State::Error, &error).await,
    };
    journal.success();
    let mut workers = Workers {
        tunnel: Some(tokio::spawn(prepared.run())),
        reconnect: None,
    };
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
    let endpoint_lease = endpoint::registry().publish(
        failover.current(),
        uid,
        full,
        monitor
            .sample(rtrust_control::observations::now_ms())
            .generation,
        failover.active(),
    );
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
    let mut access_expired = false;
    let mut state = State::Connected;
    monitor.transition(true, rtrust_control::observations::now_ms());
    let mut netwatch = crate::netwatch::Watch::new(routes::DEVICE);
    let plan = dns.map(|dns| probe::Plan {
        dns,
        endpoints: failover
            .endpoint_addresses()
            .iter()
            .filter_map(|a| a.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
            .collect(),
    });
    let mut probes = crate::sysprobe::Runner::default();
    let mut labels = crate::failover::RecoveryLabels::default();
    let mut attempt_path = rtrust_journal::Path::Reconnect;
    loop {
        let mut pending = Box::pin(read::<Request>(&mut stream));
        let request = loop {
            tokio::select! {
                biased;
                _=async{freshness.as_mut().unwrap().expired().await},if freshness.is_some() && !access_expired=>{endpoint_lease.suspend();workers.stop().await;access_expired=true;state=State::Blocked;monitor.transition(false,rtrust_control::observations::now_ms());probes.cancel();},
                request = &mut pending => break request?,
                change = netwatch.next() => match change {
                    crate::netwatch::Change::Network => {
                        probes.cancel();
                        monitor.network_changed(rtrust_control::observations::now_ms());
                        endpoint_lease.update(failover.current(), monitor.sample(rtrust_control::observations::now_ms()).generation, failover.active());
                    },
                    crate::netwatch::Change::Resumed => {
                        labels.resumed(state == State::Blocked);
                        probes.cancel();
                        monitor.resumed(rtrust_control::observations::now_ms());
                        endpoint_lease.update(failover.current(), monitor.sample(rtrust_control::observations::now_ms()).generation, failover.active());
                    },
                },
                result = async { workers.tunnel.as_mut().unwrap().await }, if workers.tunnel.is_some() => {
                    endpoint_lease.suspend();
                    workers.tunnel = None;
                    probes.cancel();
                    state = State::Blocked; monitor.transition(false, rtrust_control::observations::now_ms());
                    endpoint_lease.update(failover.current(), monitor.sample(rtrust_control::observations::now_ms()).generation, failover.active());
                    // A flapping endpoint must not reset the backoff indefinitely.
                    retry_delay.disconnected(connected_since.elapsed(), result.as_ref().is_ok_and(crate::dataplane::unproven));
                    if failover.ended(connected_since.elapsed(), Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                        endpoint_lease.update(failover.current(), monitor.sample(rtrust_control::observations::now_ms()).generation, failover.active());
                    }
                    attempt_path = labels.path();
                    workers.retry(failover.current(), &mut retry_delay, full);
                }
                result = async { workers.reconnect.as_mut().unwrap().await }, if workers.reconnect.is_some() => {
                    workers.reconnect = None;
                    let path = attempt_path;
                    let failure = match &result { Ok(Err(e)) => Some(e.class), Err(e) => Some(if e.is_cancelled() { rtrust_journal::Class::Cancelled } else { rtrust_journal::Class::Other }), _ => None };
                    if let Some(class) = failure {
                        let mut record = match &result { Ok(Err(e)) => e.record, _ => None }.unwrap_or_else(|| rtrust_journal::Record::failure(path, class, rtrust_engine::planned_transport(failover.current()), retry_delay.attempt(), rtrust_journal::Budget::from_cooling(retry_delay.cooling()), Duration::ZERO));
                        record.path = path;
                        crate::failover::journal_failure(record);
                    }
                    if let Ok(Err(error))=&result { eprintln!("VPN reconnect failed: {error}"); }
                    if let Ok(Ok(prepared)) = result {
                        // Route mutations stay in the lease task, never in the
                        // reconnect worker: Stop/EOF cannot race a late install.
                        let reattached=routes.reattach();
                        if let Err(error)=&reattached {
                            crate::failover::journal_failure(rtrust_journal::Record::failure(path, rtrust_journal::Class::Other, rtrust_engine::planned_transport(failover.current()), retry_delay.attempt(), rtrust_journal::Budget::from_cooling(retry_delay.cooling()), Duration::ZERO));
                            eprintln!("VPN route reattach failed: {error}");
                        }
                        if reattached.is_ok() {
                            labels.connected();
                            workers.tunnel = Some(tokio::spawn(prepared.run()));
                            endpoint_lease.resume();
                            connected_since = Instant::now();
                            probes.cancel();
                            state = State::Connected; monitor.transition(true, rtrust_control::observations::now_ms());
                            endpoint_lease.update(failover.current(), monitor.sample(rtrust_control::observations::now_ms()).generation, failover.active());
                            continue;
                        }
                    }
                    // The guard already covers every candidate.
                    if failover.failed(Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                        endpoint_lease.update(failover.current(), monitor.sample(rtrust_control::observations::now_ms()).generation, failover.active());
                    }
                    attempt_path = labels.path();
                    workers.retry(failover.current(), &mut retry_delay, full);
                }
                // Started only by this timer while connected in full mode and
                // viewed through the lease; Status never probes.
                tick = probes.next(), if plan.is_some() => match tick {
                    crate::sysprobe::Tick::Due => if state == State::Connected && !access_expired && probes.viewing() {
                        probes.start(monitor.generation(), probe::collect(plan.clone().unwrap()));
                    },
                    crate::sysprobe::Tick::Done(generation, result) => {
                        monitor.apply_system(generation, result, rtrust_control::observations::now_ms());
                    },
                },
            }
        };
        drop(pending);
        if request.version != VERSION {
            return Err("IPC version mismatch".into());
        }
        match request.command {
            Command::Status { viewed } => {
                if viewed {
                    probes.viewed(state == State::Connected && !access_expired);
                }
                endpoint_lease.update(
                    failover.current(),
                    monitor
                        .sample(rtrust_control::observations::now_ms())
                        .generation,
                    failover.active(),
                );
                reply_observed(
                &mut stream,
                state.clone(),
                if access_expired { "Access confirmation expired; protection retained. Synchronize before reconnecting." } else if state == State::Connected {
                    if full {
                        "Весь компьютер: IPv4, IPv6 и DNS через VPN"
                    } else {
                        "Выбранные IPv4-сети подключены"
                    }
                } else {
                    if full {
                        "Связь потеряна. Сеть заблокирована; выполняется переподключение."
                    } else {
                        "Связь потеряна. Выбранные сети заблокированы; выполняется переподключение."
                    }
                },
                &mut monitor,
                failover.active(),
            )
            .await?
            }
            Command::Stop => {
                if let Some(ref supervisor) = supervisor {
                    supervisor.cancel_pending_enable();
                }
                drop(endpoint_lease);
                workers.stop().await;
                return match routes.release() {
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

pub(crate) fn boot_guard(enable: bool) -> Result<(), String> {
    boot::guard(enable)
}
pub(crate) fn boot_recover(owner: &str) -> Result<(), String> {
    let uid = owner.parse().map_err(|_| "Invalid boot owner")?;
    FullRoutes::recover(uid).and_then(|()| Routes::recover(uid))
}
pub(crate) async fn boot_serve(
    stream: tokio::io::DuplexStream,
    uid: u32,
    lease: Arc<Mutex<()>>,
) -> Result<(), String> {
    serve(stream, uid, lease, None).await
}

pub(crate) fn boot_active() -> Result<bool, String> {
    boot::active()
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn plain_and_leased_start_failures_reply_and_record_once_without_os_io() {
        crate::failover::tests::assert_start_serve_failures(|server| {
            serve(server, 1000, Arc::new(Mutex::new(())), None)
        })
        .await;
    }
    #[tokio::test]
    async fn capabilities_do_not_require_or_steal_a_lease() {
        let lease = Arc::new(Mutex::new(()));
        let _held = lease.clone().lock_owned().await;
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(server, 1000, lease, None));
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
        assert!(response.capabilities.system_probes);
        task.await.unwrap().unwrap();
    }
}
