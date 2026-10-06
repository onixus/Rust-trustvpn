//! Windows SCM service with one SID-authorized lease and bounded IPv4 routing.
mod firewall;
mod full;
mod routes;
use rtrust_control::{Command, Request, Response, State, VERSION, read, write};
use rtrust_engine::Session;
use std::{
    ffi::OsString,
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};
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
    tokio::time::timeout(
        Duration::from_secs(5),
        write(pipe, &Response::new(state, message)),
    )
    .await
    .map_err(|_| "IPC write timed out")?
}
async fn pinned(profile: &rtrust_profile::Profile) -> Result<rtrust_profile::Profile, String> {
    let mut result = profile.clone();
    let mut addresses = Vec::new();
    for address in &profile.endpoint.addresses {
        for addr in tokio::net::lookup_host(address)
            .await
            .map_err(|_| "Cannot resolve endpoint")?
        {
            if addresses.len() >= 64 {
                return Err("Too many endpoint addresses".into());
            }
            addresses.push(addr.to_string());
        }
    }
    if addresses.is_empty() {
        return Err("Endpoint has no addresses".into());
    }
    // Freeze DNS answers for this lease so reconnect cannot route into itself.
    result.endpoint.addresses = addresses;
    Ok(result)
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
) -> Result<(Session, rtrust_engine::Tunnel), String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let session = Session::connect(profile).await.map_err(|e| e.to_string())?;
        session.health().await.map_err(|e| e.to_string())?;
        let udp = session.open_udp().await.map_err(|e| e.to_string())?;
        Ok((session, udp))
    })
    .await
    .map_err(|_| "Endpoint connection timed out")?
}
struct Worker(Option<tokio::task::JoinHandle<RunResult>>);
impl Worker {
    fn new(task: tokio::task::JoinHandle<RunResult>) -> Self {
        Self(Some(task))
    }
    async fn finished(&mut self) {
        if let Some(task) = self.0.as_mut() {
            let _ = task.await;
        }
        self.0 = None;
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
async fn serve(
    pipe: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    lease: Arc<Mutex<()>>,
    mut stop: watch::Receiver<bool>,
    supervisor: Option<Arc<crate::always_on::Supervisor>>,
) -> Result<(), String> {
    let request: Request = tokio::time::timeout(Duration::from_secs(5), read(pipe))
        .await
        .map_err(|_| "IPC read timed out")??;
    if request.version != VERSION {
        return reply(pipe, State::Error, "IPC version mismatch").await;
    }
    if let Some(supervisor) = supervisor {
        match request.command {
            Command::AlwaysOnStatus=>return write(pipe,&supervisor.state()).await,
            command @ (Command::EnableAlwaysOn{..}|Command::DisableAlwaysOn)=>return write(pipe,&supervisor.command(command).await).await,
            _ if supervisor.enabled()=>return reply(pipe,State::Error,"Always-on управляется системной службой. Для обслуживания сначала выключите always-on.").await,
            _=>{},
        }
    }
    let Ok(_lease) = lease.try_lock_owned() else {
        return reply(pipe, State::Error, "Служба уже обслуживает подключение").await;
    };
    let (profile, selection, dns) = match request.command {
        Command::PrepareUpdate => {
            if full::pending()? {
                return reply(
                    pipe,
                    State::Blocked,
                    "Сначала восстановите защиту VPN; обновление отменено",
                )
                .await;
            }
            routes::settled_adapter()?;
            reply(pipe, State::Idle, "Служба зарезервирована для обновления").await?;
            tokio::select! { _=stop.changed()=>{}, _=read::<Request>(pipe)=>{} }
            return Ok(());
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
                return reply(pipe, State::Error, &error).await;
            }
            (profile, selection, None)
        }
        Command::StartFull { profile, dns } => {
            rtrust_control::validate_dns(dns)?;
            (profile, Default::default(), Some(dns))
        }
        Command::Recover => {
            full::recover()?;
            return reply(pipe, State::Idle, "Защита сброшена; маршруты восстановлены").await;
        }
        _ => return reply(pipe, State::Error, "Start required").await,
    };
    if full::pending()? {
        return reply(
            pipe,
            State::Blocked,
            "Сохранена защита после аварии. Нажмите сброс блокировки.",
        )
        .await;
    }
    routes::settled_adapter()?;
    let setup = async {
        let profile = pinned(&profile).await?;
        let networks = if dns.is_none() {
            selected_routes(&profile, &selection)?
        } else {
            vec![]
        };
        let (session, udp) = transport(&profile).await?;
        Ok::<_, String>((profile, networks, session, udp))
    };
    let (profile, networks, session, udp) = {
        use tokio::io::AsyncReadExt;
        let mut unexpected = [0];
        tokio::select! {
            r = tokio::time::timeout(Duration::from_secs(35), setup) => match r {
                Ok(Ok(v)) => v,
                Ok(Err(error)) => return reply(pipe, State::Error, &error).await,
                Err(_) => return reply(pipe, State::Error, "Endpoint connection timed out").await,
            },
            _ = pipe.read(&mut unexpected) => return Ok(()),
            _ = stop.changed() => return Ok(()),
        }
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
            &full::endpoints(&profile)?,
            dns,
            profile.udp_transport(),
            &profile.hop_port_ranges(),
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
    if dns.is_some() {
        routes.full_ipv6(
            device
                .if_index()
                .map_err(|_| "Wintun interface index unavailable")?,
        )?;
    }
    let mut worker = Worker::new(tokio::spawn(crate::dataplane::run(
        session,
        udp,
        device.clone(),
        ADDRESS,
    )));
    let result = lease_loop(
        pipe,
        &profile,
        device.clone(),
        &mut worker,
        &mut stop,
        dns.is_some(),
    )
    .await;
    worker.stop().await;
    let mut cleaned = routes.release();
    drop(routes);
    drop(device);
    if dns.is_none() && cleaned.is_ok() && matches!(result, Ok(true)) {
        cleaned = routes::wait_removed();
    }
    if dns.is_some() && (matches!(result, Ok(true)) || *stop.borrow()) {
        cleaned.clone()?;
        full::recover()?;
    }
    if matches!(result, Ok(true)) {
        match cleaned {
            Ok(()) => reply(pipe, State::Idle, "Отключено").await,
            Err(e) => reply(pipe, State::Error, &e).await,
        }
    } else {
        result.map(|_| ())
    }
}
async fn lease_loop(
    pipe: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    profile: &rtrust_profile::Profile,
    device: Arc<tun_rs::AsyncDevice>,
    worker: &mut Worker,
    stop: &mut watch::Receiver<bool>,
    full: bool,
) -> Result<bool, String> {
    reply(
        pipe,
        State::Connected,
        if full {
            "Весь компьютер: IPv4, IPv6 и DNS через Wintun"
        } else {
            "Выбранные IPv4-сети подключены через Wintun"
        },
    )
    .await?;
    let mut state = State::Connected;
    let mut retry = Box::pin(tokio::time::sleep(Duration::from_secs(2)));
    let mut delay = 2;
    let mut connected_since = std::time::Instant::now();
    let mut connecting = Box::pin(std::future::pending::<
        Result<(Session, rtrust_engine::Tunnel), String>,
    >())
        as std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<(Session, rtrust_engine::Tunnel), String>>
                    + Send,
            >,
        >;
    let mut reconnecting = false;
    loop {
        // Keep partially read frames alive across heartbeat/reconnect events.
        let mut pending = Box::pin(read::<Request>(pipe));
        let request = loop {
            tokio::select! {
                r = &mut pending => break r?,
                _ = stop.changed() => return Ok(false),
                _ = worker.finished(), if state == State::Connected => {
                    state = State::Blocked;
                    if connected_since.elapsed() >= Duration::from_secs(30) { delay=2; }
                    retry.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(delay));
                },
                _ = &mut retry, if state == State::Blocked && !reconnecting => {
                    if full && full::refresh(device.if_index().map_err(|_| "Missing Wintun interface")?, &full::endpoints(profile)?).is_err() {
                        delay=(delay*2).min(30);
                        retry.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(delay));
                        continue;
                    }
                    connecting = Box::pin(transport(profile)); reconnecting=true;
                },
                result = &mut connecting, if reconnecting => {
                    reconnecting=false;
                    match result {
                        Ok((session,udp)) => {
                            *worker=Worker::new(tokio::spawn(crate::dataplane::run(session,udp,device.clone(),ADDRESS)));
                            state=State::Connected; connected_since=std::time::Instant::now();
                        },
                        Err(_) => { delay=(delay*2).min(30); retry.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(delay)); },
                    }
                },
            }
        };
        drop(pending);
        if request.version != VERSION {
            return Err("IPC version mismatch".into());
        }
        match request.command {
            Command::Status => {
                reply(
                    pipe,
                    state.clone(),
                    if state == State::Connected {
                        "Wintun подключён"
                    } else {
                        "Переподключение; выбранные IPv4-сети удерживаются на Wintun"
                    },
                )
                .await?
            }
            Command::Stop => return Ok(true),
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
        assert!(
            pinned(&profile, &["198.18.0.0/24".parse().unwrap()])
                .await
                .is_err()
        );
        let p = pinned(&profile, &["10.231.243.2/32".parse().unwrap()])
            .await
            .unwrap();
        assert_eq!(p.endpoint.addresses, ["198.18.0.2:443"]);
        assert_eq!(p.endpoint.hostname, profile.endpoint.hostname);
        // HTTP/3 is pinned the same way; only the WFP permit switches to UDP.
        profile.endpoint.upstream_protocol = "http3".into();
        let p = pinned(&profile, &["10.231.243.2/32".parse().unwrap()])
            .await
            .unwrap();
        assert_eq!(p.endpoint.addresses, ["198.18.0.2:443"]);
        assert!(p.udp_transport());
    }
}
