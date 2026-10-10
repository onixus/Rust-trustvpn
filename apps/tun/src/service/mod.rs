mod boot;
mod broker;
mod full;
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
    reconnect: Option<tokio::task::JoinHandle<Result<crate::linux::Prepared, String>>>,
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
    fn retry(&mut self, profile: &rtrust_profile::Profile, delay: &mut u64, full: bool) {
        let profile = profile.clone();
        let wait = *delay;
        *delay = (*delay * 2).min(30);
        self.reconnect = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            tokio::time::timeout(
                Duration::from_secs(30),
                crate::linux::Prepared::connect_mode(
                    &profile,
                    routes::DEVICE,
                    routes::ADDRESS.parse().unwrap(),
                    full,
                ),
            )
            .await
            .map_err(|_| "Reconnect timed out".to_owned())?
            .map_err(|e| format!("Reconnect failed: {e}"))
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
) -> Result<(), String> {
    let mut response = Response::new(state, message);
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
    if let Some(supervisor) = supervisor {
        match request.command {
            Command::AlwaysOnStatus=>return write(&mut stream,&supervisor.state()).await,
            command @ (Command::EnableAlwaysOn{..}|Command::DisableAlwaysOn)=>return write(&mut stream,&supervisor.command(command).await).await,
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
    let (profile, networks, dns, split_dns) = match request.command {
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
        Command::Recover => {
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
        } => {
            // Only this user's traffic is policy-routed; the service's own
            // endpoint connection never matches, so no endpoint exception.
            let selection = rtrust_control::Selection {
                include: networks,
                exclude,
                exclude_lan,
            };
            match selection.validate().and_then(|()| {
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
                    (profile, routes, None, resolver)
                }
                Err(error) => return reply(&mut stream, State::Error, &error).await,
            }
        }
        Command::StartFull { profile, dns } => (profile, vec![], Some(dns), None),
        _ => return reply(&mut stream, State::Error, "Start or Recover required").await,
    };
    if let Err(error) = if let Some(dns) = dns {
        FullRoutes::preflight(dns)
    } else {
        Routes::preflight(&networks)
    } {
        return reply(&mut stream, State::Error, &error).await;
    }
    let full = dns.is_some();
    let profile = if full {
        let result = tokio::time::timeout(Duration::from_secs(10), async {
            let mut profile = profile;
            let mut addresses = Vec::new();
            for address in &profile.endpoint.addresses {
                for address in tokio::net::lookup_host(address)
                    .await
                    .map_err(|_| "Cannot resolve endpoint")?
                {
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
        match result {
            Ok(Ok(profile)) => profile,
            _ => {
                return reply(
                    &mut stream,
                    State::Error,
                    "Не удалось разрешить адрес VPN-сервера",
                )
                .await;
            }
        }
    } else {
        profile
    };
    let prepared = {
        let mut unexpected = [0];
        tokio::select! {
            result = crate::linux::Prepared::connect_mode(&profile, routes::DEVICE, routes::ADDRESS.parse().unwrap(), full) => match result {
                Ok(prepared) => prepared,
                Err(_) => return reply(&mut stream, State::Error, "Не удалось открыть TUN: проверьте профиль, TLS и доступность endpoint").await,
            },
            _ = stream.read(&mut unexpected) => return Err("IPC closed during connect".into()),
        }
    };
    let mut routes = match if let Some(dns) = dns {
        FullRoutes::install(uid, dns, &profile.endpoint.addresses).map(Guard::Full)
    } else {
        Routes::install(uid, networks, split_dns).map(Guard::Selected)
    } {
        Ok(routes) => routes,
        Err(error) => return reply(&mut stream, State::Error, &error).await,
    };
    let mut workers = Workers {
        tunnel: Some(tokio::spawn(prepared.run())),
        reconnect: None,
    };
    let mut retry_delay = 2;
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
    reply_observed(
        &mut stream,
        State::Connected,
        if full {
            "Весь компьютер: IPv4, IPv6 и DNS через VPN"
        } else {
            "IPv4-сети подключены"
        },
        &mut monitor,
    )
    .await?;
    let mut state = State::Connected;
    monitor.transition(true, rtrust_control::observations::now_ms());
    loop {
        let mut pending = Box::pin(read::<Request>(&mut stream));
        let request = loop {
            tokio::select! {
                request = &mut pending => break request?,
                _ = async { workers.tunnel.as_mut().unwrap().await }, if workers.tunnel.is_some() => {
                    workers.tunnel = None;
                    state = State::Blocked; monitor.transition(false, rtrust_control::observations::now_ms());
                    // A flapping endpoint must not reset the backoff indefinitely.
                    if connected_since.elapsed() >= Duration::from_secs(30) { retry_delay = 2; }
                    workers.retry(&profile, &mut retry_delay, full);
                }
                result = async { workers.reconnect.as_mut().unwrap().await }, if workers.reconnect.is_some() => {
                    workers.reconnect = None;
                    if let Ok(Err(error))=&result { eprintln!("VPN reconnect failed: {error}"); }
                    if let Ok(Ok(prepared)) = result {
                        // Route mutations stay in the lease task, never in the
                        // reconnect worker: Stop/EOF cannot race a late install.
                        let reattached=routes.reattach();
                        if let Err(error)=&reattached { eprintln!("VPN route reattach failed: {error}"); }
                        if reattached.is_ok() {
                            workers.tunnel = Some(tokio::spawn(prepared.run()));
                            connected_since = Instant::now();
                            state = State::Connected; monitor.transition(true, rtrust_control::observations::now_ms());
                            continue;
                        }
                    }
                    workers.retry(&profile, &mut retry_delay, full);
                }
            }
        };
        drop(pending);
        if request.version != VERSION {
            return Err("IPC version mismatch".into());
        }
        match request.command {
            Command::Status => reply_observed(
                &mut stream,
                state.clone(),
                if state == State::Connected {
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
            )
            .await?,
            Command::Stop => {
                workers.stop().await;
                return match routes.release() {
                    Ok(()) => {
                        monitor.stop(rtrust_control::observations::now_ms());
                        reply_observed(&mut stream, State::Idle, "Отключено", &mut monitor).await
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
        assert!(!response.capabilities.system_probes);
        task.await.unwrap().unwrap();
    }
}
