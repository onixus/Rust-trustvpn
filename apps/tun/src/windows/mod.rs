//! Windows SCM service with one SID-authorized lease and bounded IPv4 routing.
mod firewall;
mod full;
mod probe;
mod routes;
use rtrust_control::{Command, Request, Response, State, VERSION, read, write};
use rtrust_engine::Session;
use std::{ffi::OsString, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    net::windows::named_pipe::NamedPipeServer,
    sync::{Mutex, watch},
    task::JoinSet,
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
const DEVICE: &str = "RTrustTunnel";
const ADDRESS: Ipv4Addr = Ipv4Addr::new(169, 254, 254, 2);
type RunResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
define_windows_service!(ffi_service_main, service_main);
pub fn dispatch() -> Result<(), String> {
    if std::env::args().skip(1).eq(["--wfp-self-test"]) {
        return firewall::self_test();
    }
    if std::env::args().skip(1).eq(["--disable-always-on"]) {
        return full::recover()
            .and_then(|()| crate::boot_policy::remove())
            .and_then(|()| firewall::remove_boot());
    }
    if std::env::args().skip(1).eq(["--recover"]) {
        if crate::boot_policy::exists()? || firewall::boot_active()? {
            return Err("Disable always-on explicitly before recovery".into());
        }
        return full::recover();
    }

    service_dispatcher::start(rtrust_control::windows::SERVICE, ffi_service_main)
        .map_err(|e| e.to_string())
}
fn service_main(_: Vec<OsString>) {
    let (stop, receiver) = watch::channel(false);
    let handler =
        match service_control_handler::register(rtrust_control::windows::SERVICE, move |event| {
            match event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = stop.send(true);
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        }) {
            Ok(h) => h,
            Err(_) => return,
        };
    let status = |state, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    let _ = handler.set_service_status(status(ServiceState::StartPending, 0));
    let result = (|| {
        if rtrust_control::windows::process_sid(std::process::id())? != "S-1-5-18" {
            return Err("Service must run as LocalSystem".into());
        }
        let args: Vec<_> = std::env::args().skip(1).collect();
        if args.len() != 1 || !rtrust_control::windows::valid_sid(&args[0]) {
            return Err("Usage: rtrust-service DESKTOP_SID (via SCM)".to_owned());
        }
        let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        runtime.block_on(async {
            let pipe = rtrust_control::windows::listen(&args[0], true)?;
            handler
                .set_service_status(status(ServiceState::Running, 0))
                .map_err(|e| e.to_string())?;
            run(&args[0], pipe, receiver).await
        })
    })();
    let _ = handler.set_service_status(status(
        ServiceState::Stopped,
        if result.is_ok() { 0 } else { 1 },
    ));
}
async fn run(
    sid: &str,
    mut pipe: NamedPipeServer,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let lease = Arc::new(Mutex::new(()));
    let supervisor = crate::always_on::Supervisor::start(sid.to_string(), lease.clone())?;
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            result = pipe.connect() => {
                result.map_err(|_| "IPC accept failed")?;
                // Keep a server instance alive across accepts: no name-squatting gap.
                let next = rtrust_control::windows::listen(sid, false)?;
                let accepted = std::mem::replace(&mut pipe, next);
                if tasks.len() < 14 {
                    let lease = lease.clone(); let stop = stop.clone(); let supervisor=supervisor.clone();
                    tasks.spawn(async move {
                        let mut accepted = accepted;
                        if let Err(error) = serve(&mut accepted, lease, stop,Some(supervisor)).await {
                            let _ = reply(&mut accepted, State::Error, &error).await;
                        }
                    });
                }
            }
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            _ = stop.changed() => break,
        }
    }
    // Cooperative stop releases routes and awaits data-plane cancellation.
    while tasks.join_next().await.is_some() {}
    Ok(())
}
async fn reply(
    pipe: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    state: State,
    message: &str,
) -> Result<(), String> {
    reply_as(pipe, VERSION, state, message).await
}
/// Replies on the wire version and shape admitted for this request.
async fn reply_as(
    pipe: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    version: u32,
    state: State,
    message: &str,
) -> Result<(), String> {
    let response = rtrust_control::Reply::new(version, state, message);
    tokio::time::timeout(Duration::from_secs(5), write(pipe, &response))
        .await
        .map_err(|_| "IPC write timed out")?
}
/// Selected routes minus the pinned endpoint (and LAN on request), checked
/// against the current table.
fn selected_routes(
    profile: &rtrust_profile::Profile,
    selection: &rtrust_control::Selection,
) -> Result<Vec<rtrust_control::Ipv4Net>, String> {
    let endpoints: Vec<Ipv4Addr> = profile
        .endpoint
        .addresses
        .iter()
        .filter_map(|a| match a.parse() {
            Ok(std::net::SocketAddr::V4(a)) => Some(*a.ip()),
            _ => None,
        })
        .collect();
    let networks = selection.routes(&endpoints, &routes::local()?)?;
    routes::preflight(&networks)?;
    Ok(networks)
}
async fn transport(
    profile: &rtrust_profile::Profile,
) -> Result<(Session, rtrust_engine::Tunnel), crate::failover::Failure> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let session = Session::connect(profile)
            .await
            .map_err(crate::failover::Failure::from)?;
        session
            .health()
            .await
            .map_err(crate::failover::Failure::from)?;
        let udp = session
            .open_udp()
            .await
            .map_err(crate::failover::Failure::from)?;
        Ok((session, udp))
    })
    .await
    .map_err(|_| crate::failover::Failure::timeout("Endpoint connection timed out"))?
}
struct Worker(Option<tokio::task::JoinHandle<RunResult>>);
impl Worker {
    fn new(task: tokio::task::JoinHandle<RunResult>) -> Self {
        Self(Some(task))
    }
    /// True when the session ended degraded without ever delivering data.
    async fn finished(&mut self) -> bool {
        let mut unproven = false;
        if let Some(task) = self.0.as_mut() {
            unproven = task.await.as_ref().is_ok_and(crate::dataplane::unproven);
        }
        self.0 = None;
        unproven
    }
    async fn stop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
            let _ = task.await;
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
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
    pipe: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    lease: Arc<Mutex<()>>,
    mut stop: watch::Receiver<bool>,
    supervisor: Option<Arc<crate::always_on::Supervisor>>,
) -> Result<(), String> {
    let request: Request = tokio::time::timeout(Duration::from_secs(5), read(pipe))
        .await
        .map_err(|_| "IPC read timed out")??;
    // A previous-version updater may only negotiate and reserve the service,
    // and a released older updater (RELEASED_UPDATER_VERSIONS) only reserve
    // it, so a failed upgrade can still be rolled back by the old installer.
    let Some(version) = rtrust_control::admitted_version(&request) else {
        return reply(pipe, State::Error, "IPC version mismatch").await;
    };
    if matches!(request.command, Command::Capabilities) {
        return reply_as(pipe, version, State::Idle, "Capabilities").await;
    }
    if let Some(ref supervisor) = supervisor {
        if matches!(request.command, Command::Stop) {
            supervisor.cancel_pending_enable();
        }
        match request.command {
            Command::AlwaysOnStatus{viewed}=>return write(pipe,&supervisor.status(viewed)).await,
            command @ (Command::EnableAlwaysOn{..}|Command::EnableRecovery{..}|Command::DisableAlwaysOn)=>return write(pipe,&supervisor.command(command).await).await,
            _ if supervisor.enabled()=>return reply_as(pipe,version,State::Error,"Always-on управляется системной службой. Для обслуживания сначала выключите always-on.").await,
            _=>{},
        }
    }
    let Ok(_lease) = lease.try_lock_owned() else {
        return reply_as(
            pipe,
            version,
            State::Error,
            "Служба уже обслуживает подключение",
        )
        .await;
    };
    let mut journal = match &request.command {
        Command::Start { profile, .. } | Command::StartFull { profile, .. } => {
            Some(crate::failover::journal_attempt(
                rtrust_journal::Path::Start,
                rtrust_engine::planned_transport(profile),
                1,
                rtrust_journal::Budget::Burst,
            ))
        }
        _ => None,
    };
    let (mut freshness, command) = rtrust_control::freshness::start(request.command)?;
    let (profile, selection, dns, split_dns, fallbacks) = match command {
        Command::PrepareUpdate => {
            // Failures are answered in the caller's version so a previous
            // updater reports the reason; the reservation is still refused.
            match full::pending() {
                Ok(false) => {}
                Ok(true) => {
                    return reply_as(
                        pipe,
                        version,
                        State::Blocked,
                        "Сначала восстановите защиту VPN; обновление отменено",
                    )
                    .await;
                }
                Err(error) => return reply_as(pipe, version, State::Error, &error).await,
            }
            if let Err(error) = routes::settled_adapter() {
                return reply_as(pipe, version, State::Error, &error).await;
            }
            reply_as(
                pipe,
                version,
                State::Idle,
                "Служба зарезервирована для обновления",
            )
            .await?;
            tokio::select! { _=stop.changed()=>{}, _=read::<Request>(pipe)=>{} }
            return Ok(());
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
                return reply(pipe, State::Error, &error).await;
            }
            (profile, selection, None, dns, fallbacks)
        }
        Command::StartFull {
            profile,
            dns,
            fallbacks,
        } => {
            rtrust_control::validate_dns(dns)?;
            (profile, Default::default(), Some(dns), None, fallbacks)
        }
        Command::Recover { .. } => {
            full::recover()?;
            return reply(pipe, State::Idle, "Защита сброшена; маршруты восстановлены").await;
        }
        _ => return reply(pipe, State::Error, "Start required").await,
    };
    let mut journal = journal.take().expect("Start has a journal guard");
    if full::pending()? {
        return reply(
            pipe,
            State::Blocked,
            "Сохранена защита после аварии. Нажмите сброс блокировки.",
        )
        .await;
    }
    routes::settled_adapter()?;
    journal.cancelled();
    let setup = async {
        // Every allowed candidate is pinned now: the guard covers them all.
        // WFP full mode pins IPv4 endpoint exceptions: an IPv6 answer of any
        // candidate would otherwise reject the whole start.
        let mut failover = crate::failover::Failover::pin(
            *profile,
            fallbacks,
            if dns.is_some() {
                crate::failover::Pin::Ipv4
            } else {
                crate::failover::Pin::All
            },
        )
        .await
        .inspect_err(|_| journal.class(rtrust_journal::Class::EndpointUnreachable))?;
        journal.class(rtrust_journal::Class::Other);
        let networks = if dns.is_none() {
            selected_routes(&failover.guard_profile(), &selection)?
        } else {
            vec![]
        };
        journal.cancelled();
        let (session, udp) = rtrust_control::freshness::while_valid(freshness.as_mut(), async {
            failover
                .connect_initial(|profile| async move { transport(&profile).await })
                .await
                .map_err(|e| {
                    journal.metadata(e.transport, e.attempts);
                    journal.class(
                        e.last
                            .as_ref()
                            .map_or(rtrust_journal::Class::Timeout, |e| e.class),
                    );
                    "No allowed VPN endpoint connected within the startup budget".to_owned()
                })
        })
        .await?;
        journal.class(rtrust_journal::Class::Other);
        Ok::<_, String>((failover, networks, session, udp))
    };
    let setup_result = {
        use tokio::io::AsyncReadExt;
        let mut unexpected = [0];
        tokio::select! {
            r = tokio::time::timeout(Duration::from_secs(42), setup) => Some(r),
            _ = pipe.read(&mut unexpected) => None,
            _ = stop.changed() => None,
        }
    };
    let (mut failover, networks, session, udp) = match setup_result {
        Some(Ok(Ok(value))) => value,
        Some(Ok(Err(error))) => return reply(pipe, State::Error, &error).await,
        Some(Err(_)) => {
            journal.class(rtrust_journal::Class::Timeout);
            return reply(pipe, State::Error, "Endpoint connection timed out").await;
        }
        None => return Ok(()),
    };
    // Absolute DLL path inside the admin-owned service installation directory.
    let dll = std::env::current_exe()
        .map_err(|_| "Service path unavailable")?
        .with_file_name("wintun.dll");
    let device = tun_rs::DeviceBuilder::new()
        .name(DEVICE)
        .mtu(crate::packet::MTU as u16)
        .ipv4(ADDRESS, 32, None)
        .ipv6(crate::ipv6::ADDRESS, 128)
        .metric(5)
        .wintun_log(false)
        .delete_driver(false)
        .wintun_file(dll.to_str().ok_or("Invalid DLL path")?.to_owned())
        .build_async()
        .map_err(|_| "Cannot create Wintun adapter; install signed wintun.dll beside service")?;
    let device = Arc::new(device);
    routes::ready(
        device
            .if_index()
            .map_err(|_| "Wintun interface index unavailable")?,
        ADDRESS,
    )
    .await?;
    routes::ready6(
        device
            .if_index()
            .map_err(|_| "Wintun interface index unavailable")?,
    )
    .await?;
    let networks = if let Some(dns) = dns {
        let index = device
            .if_index()
            .map_err(|_| "Wintun interface index unavailable")?;
        full::install(
            index,
            &full::endpoints(&failover.guard_profile())?,
            dns,
            &failover.permits()?,
        )?;
        vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()]
    } else {
        networks
    };
    let mut routes = routes::Routes::install(
        device
            .if_index()
            .map_err(|_| "Wintun interface index unavailable")?,
        &networks,
    )?;
    // A selection that carries the resolver (e.g. everything but the LAN)
    // gets VPN DNS too; otherwise names would leak to the LAN resolver.
    let split_dns = split_dns.filter(|_| dns.is_none());
    let _dns_lock = match rtrust_control::tunneled_resolver(&networks, split_dns) {
        Some(resolver) => {
            let mut luid = Default::default();
            if unsafe {
                windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid(
                    device
                        .if_index()
                        .map_err(|_| "Wintun interface index unavailable")?,
                    &mut luid,
                )
            } != 0
            {
                return Err("Wintun interface LUID unavailable".into());
            }
            full::interface_dns(luid, resolver)?;
            Some(firewall::lock_dns(unsafe { luid.Value })?)
        }
        None => None,
    };
    if dns.is_some() {
        routes.full_ipv6(
            device
                .if_index()
                .map_err(|_| "Wintun interface index unavailable")?,
        )?;
    }
    journal.success();
    let mut worker = Worker::new(tokio::spawn(crate::dataplane::run(
        session,
        udp,
        device.clone(),
        ADDRESS,
    )));
    let result = lease_loop(
        pipe,
        &mut failover,
        device.clone(),
        &mut worker,
        &mut stop,
        dns,
        (supervisor.as_deref(), freshness),
    )
    .await;
    worker.stop().await;
    let mut cleaned = routes.release();
    drop(routes);
    drop(device);
    if dns.is_none() && cleaned.is_ok() && matches!(result, Ok(Some(_))) {
        cleaned = routes::wait_removed();
    }
    if dns.is_some() && (matches!(result, Ok(Some(_))) || *stop.borrow()) {
        cleaned.clone()?;
        full::recover()?;
    }
    if let Ok(Some(observations)) = result {
        match cleaned {
            Ok(()) => {
                let mut response = Response::new(State::Idle, "Отключено");
                response.observations = observations;
                write(pipe, &response).await
            }
            Err(e) => reply(pipe, State::Error, &e).await,
        }
    } else {
        result.map(|_| ())
    }
}
async fn lease_loop(
    pipe: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    failover: &mut crate::failover::Failover,
    device: Arc<tun_rs::AsyncDevice>,
    worker: &mut Worker,
    stop: &mut watch::Receiver<bool>,
    dns: Option<Ipv4Addr>,
    context: (
        Option<&crate::always_on::Supervisor>,
        Option<rtrust_control::freshness::Deadline>,
    ),
) -> Result<Option<rtrust_control::observations::Snapshot>, String> {
    let (supervisor, mut freshness) = context;
    let full = dns.is_some();
    let plan = match (dns, device.if_index()) {
        (Some(dns), Ok(index)) => Some(probe::Plan {
            index,
            dns,
            endpoints: failover
                .endpoint_addresses()
                .iter()
                .filter_map(|a| a.parse::<std::net::SocketAddr>().ok().map(|a| a.ip()))
                .collect(),
        }),
        _ => None,
    };
    let mut probes = crate::sysprobe::Runner::default();
    let mut access_expired = false;
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
        pipe,
        State::Connected,
        &format!(
            "{}{}",
            if full {
                "Весь компьютер: IPv4, IPv6 и DNS через Wintun"
            } else {
                "Выбранные IPv4-сети подключены через Wintun"
            },
            failover.note()
        ),
        &mut monitor,
        failover.active(),
    )
    .await?;
    let mut state = State::Connected;
    monitor.transition(true, rtrust_control::observations::now_ms());
    let mut netwatch = crate::netwatch::Watch::new(DEVICE);
    let mut retry = Box::pin(tokio::time::sleep(Duration::from_secs(2)));
    let mut budget = rtrust_control::recovery::Budget::default();
    let mut connected_since = std::time::Instant::now();
    let mut connecting = Box::pin(std::future::pending::<
        Result<(Session, rtrust_engine::Tunnel), crate::failover::Failure>,
    >())
        as std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<(Session, rtrust_engine::Tunnel), crate::failover::Failure>,
                    > + Send,
            >,
        >;
    let mut reconnecting = false;
    let mut wake_reconnect = false;
    let mut attempt_started = std::time::Instant::now();
    loop {
        // Keep partially read frames alive across heartbeat/reconnect events.
        let mut pending = Box::pin(read::<Request>(pipe));
        let request = loop {
            tokio::select! {
                biased;
                _=async{freshness.as_mut().unwrap().expired().await},if freshness.is_some() && !access_expired=>{worker.stop().await;connecting=Box::pin(std::future::pending());reconnecting=false;access_expired=true;state=State::Blocked;probes.cancel();monitor.transition(false,rtrust_control::observations::now_ms());},
                r = &mut pending => break r?,
                change = netwatch.next() => {
                    probes.cancel();
                    match change {
                        crate::netwatch::Change::Network => monitor.network_changed(rtrust_control::observations::now_ms()),
                        crate::netwatch::Change::Resumed => { wake_reconnect = true; monitor.resumed(rtrust_control::observations::now_ms()); },
                    }
                },
                _ = stop.changed() => return Ok(None),
                unproven = worker.finished(), if state == State::Connected => {
                    probes.cancel();
                    state = State::Blocked; monitor.transition(false, rtrust_control::observations::now_ms());
                    budget.disconnected(connected_since.elapsed(), unproven);
                    if failover.ended(connected_since.elapsed(), std::time::Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                    }
                    retry.as_mut().reset(tokio::time::Instant::now()+budget.next_delay(rand::random()));
                },
                _ = &mut retry, if state == State::Blocked && !reconnecting && !access_expired => {
                    attempt_started = std::time::Instant::now();
                    if full && full::refresh(device.if_index().map_err(|_| "Missing Wintun interface")?, &full::endpoints(&failover.guard_profile())?).is_err() {
                        crate::failover::journal_failure(rtrust_journal::Record::failure(if wake_reconnect { rtrust_journal::Path::WakeReconnect } else { rtrust_journal::Path::Reconnect }, rtrust_journal::Class::Other, rtrust_engine::planned_transport(failover.current()), budget.attempt(), rtrust_journal::Budget::from_cooling(budget.cooling()), attempt_started.elapsed()));
                        retry.as_mut().reset(tokio::time::Instant::now()+budget.next_delay(rand::random()));
                        continue;
                    }
                    let profile = failover.current().clone();
                    connecting = Box::pin(async move {
                        tokio::time::timeout(rtrust_control::recovery::ATTEMPT_TIMEOUT, transport(&profile))
                            .await.map_err(|_| crate::failover::Failure::timeout("Reconnect timed out"))?
                    }); reconnecting=true;
                },
                result = &mut connecting, if reconnecting => {
                    reconnecting=false;
                    match result {
                        Ok((session,udp)) => {
                            wake_reconnect = false;
                            *worker=Worker::new(tokio::spawn(crate::dataplane::run(session,udp,device.clone(),ADDRESS)));
                            probes.cancel();
                            state=State::Connected; monitor.transition(true, rtrust_control::observations::now_ms()); connected_since=std::time::Instant::now();
                        },
                        Err(error) => {
                            crate::failover::journal_failure(rtrust_journal::Record::failure(if wake_reconnect { rtrust_journal::Path::WakeReconnect } else { rtrust_journal::Path::Reconnect }, error.class, rtrust_engine::planned_transport(failover.current()), budget.attempt(), rtrust_journal::Budget::from_cooling(budget.cooling()), attempt_started.elapsed()));
                            // The guard already covers every candidate.
                            if failover.failed(std::time::Instant::now()) {
                                monitor.failed_over(rtrust_control::observations::now_ms());
                            }
                            retry.as_mut().reset(tokio::time::Instant::now()+budget.next_delay(rand::random()));
                        },
                    }
                },
                // Started only by this timer while connected in full mode and
                // viewed through the lease; Status never probes.
                tick = probes.next(), if plan.is_some() => match tick {
                    crate::sysprobe::Tick::Due => if state == State::Connected && !access_expired && probes.viewing() {
                        // Permits are re-read: the audit compares against the current candidates.
                        if let (Some(plan), Ok(permits)) = (plan.clone(), failover.permits()) {
                            probes.start(monitor.generation(), probe::collect(plan, permits));
                        } else {
                            probes.defer();
                        }
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
                reply_observed(
                    pipe,
                    state.clone(),
                    if access_expired { "Access confirmation expired; protection retained. Synchronize before reconnecting." } else if state == State::Connected {
                        "Wintun подключён"
                    } else {
                        "Переподключение; выбранные IPv4-сети удерживаются на Wintun"
                    },
                    &mut monitor,
                    failover.active(),
                )
                .await?
            }
            Command::Stop => {
                if let Some(supervisor) = supervisor {
                    supervisor.cancel_pending_enable();
                }
                monitor.stop(rtrust_control::observations::now_ms());
                return Ok(Some(monitor.sample(rtrust_control::observations::now_ms())));
            }
            _ => return Err("Invalid operation during lease".into()),
        }
    }
}

pub(crate) fn boot_guard(policy: Option<&crate::boot_policy::Policy>) -> Result<(), String> {
    let endpoints = match policy {
        Some(p) => full::endpoints(&p.profile)?,
        None => vec![],
    };
    firewall::install_boot(
        0,
        &endpoints,
        policy.is_some_and(|p| p.profile.udp_transport()),
        &policy
            .map(|p| p.profile.hop_port_ranges())
            .unwrap_or_default(),
    )
}
pub(crate) fn boot_unguard() -> Result<(), String> {
    firewall::remove_boot()
}
pub(crate) fn boot_recover() -> Result<(), String> {
    full::recover()
}
pub(crate) async fn boot_serve(
    mut stream: tokio::io::DuplexStream,
    lease: Arc<Mutex<()>>,
) -> Result<(), String> {
    let (_stop, receiver) = watch::channel(false);
    serve(&mut stream, lease, receiver, None).await
}

pub(crate) fn boot_active() -> Result<bool, String> {
    firewall::boot_active()
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn exchange(version: u32, command: Command) -> Response {
        let (mut client, mut server) = tokio::io::duplex(1 << 16);
        let (_stop, stop) = watch::channel(false);
        let service =
            tokio::spawn(
                async move { serve(&mut server, Arc::new(Mutex::new(())), stop, None).await },
            );
        write(&mut client, &Request { version, command })
            .await
            .unwrap();
        let response = read(&mut client).await.unwrap();
        drop(client);
        let _ = service.await;
        response
    }
    #[tokio::test]
    async fn previous_version_negotiates_but_cannot_control_a_session() {
        let previous = VERSION - 1;
        let response = exchange(previous, Command::Capabilities).await;
        assert_eq!((response.version, response.state), (previous, State::Idle));
        // v6 Status/AlwaysOnStatus (with or without `viewed`) are refused.
        for command in [
            Command::Stop,
            Command::Status { viewed: false },
            Command::Status { viewed: true },
            Command::Recover { owner: None },
            Command::DisableAlwaysOn,
            Command::AlwaysOnStatus { viewed: false },
        ] {
            let response = exchange(previous, command).await;
            assert_eq!(response.version, VERSION);
            assert_eq!(response.state, State::Error);
            assert_eq!(response.message, "IPC version mismatch");
        }
        let response = exchange(VERSION - 2, Command::Capabilities).await;
        assert_eq!(response.message, "IPC version mismatch");
    }
    #[tokio::test]
    async fn released_v1_updater_cannot_negotiate_or_control_a_session() {
        for &version in rtrust_control::RELEASED_UPDATER_VERSIONS {
            for command in [
                Command::Capabilities,
                Command::Stop,
                Command::Status { viewed: false },
                Command::Recover { owner: None },
                Command::DisableAlwaysOn,
                Command::AlwaysOnStatus { viewed: false },
            ] {
                let response = exchange(version, command).await;
                assert_eq!(response.version, VERSION);
                assert_eq!(response.state, State::Error);
                assert_eq!(response.message, "IPC version mismatch");
            }
        }
    }
    #[tokio::test]
    async fn stop_after_transport_failure_does_not_poll_completed_task() {
        let mut worker = Worker::new(tokio::spawn(async { Err("endpoint lost".into()) }));
        worker.finished().await;
        worker.stop().await;
        worker.stop().await;
    }

    #[tokio::test]
    async fn endpoint_is_pinned_and_cannot_be_routed_into_its_own_tunnel() {
        let mut profile = rtrust_profile::Profile::import(include_str!(
            "../../../../examples/demo.endpoint.toml"
        ))
        .unwrap();
        profile.endpoint.addresses = vec!["198.18.0.2:443".into()];
        let p = crate::failover::pin_endpoint(profile.clone(), crate::failover::Pin::All)
            .await
            .unwrap();
        let endpoint: Ipv4Addr = "198.18.0.2".parse().unwrap();
        let selection = rtrust_control::Selection::parse("198.18.0.0/24", "", false).unwrap();
        let routes = selection.routes(&[endpoint], &[]).unwrap();
        assert!(!routes.iter().any(|net| net.contains(&endpoint)));
        assert!(
            routes
                .iter()
                .any(|net| net.contains(&"198.18.0.3".parse::<Ipv4Addr>().unwrap()))
        );
        assert_eq!(p.endpoint.addresses, ["198.18.0.2:443"]);
        assert_eq!(p.endpoint.hostname, profile.endpoint.hostname);
        // HTTP/3 is pinned the same way; only the WFP permit switches to UDP.
        profile.endpoint.upstream_protocol = "http3".into();
        let p = crate::failover::pin_endpoint(profile.clone(), crate::failover::Pin::All)
            .await
            .unwrap();
        assert_eq!(p.endpoint.addresses, ["198.18.0.2:443"]);
        assert!(p.udp_transport());
    }
}
