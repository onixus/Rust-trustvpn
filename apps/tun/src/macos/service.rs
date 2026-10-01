use super::{
    device,
    state::{self, Guard},
};
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
    ) {
        let profile = profile.clone();
        let wait = *delay;
        *delay = (*delay * 2).min(30);
        self.reconnect = Some(tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(wait)).await;
            tokio::time::timeout(
                Duration::from_secs(30),
                device::Prepared::reconnect(&profile, device),
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
    let mut tasks = JoinSet::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "Cannot register signal")?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| "IPC accept failed")?;
                if stream.peer_cred().map_err(|_| "IPC identity failed")?.uid() != uid || tasks.len() >= 16 { continue; }
                let lease = lease.clone();
                tasks.spawn(async move { let _ = serve(stream, uid, lease).await; });
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
    let (profile, networks, dns) = match request.command {
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
        Command::Start { profile, networks } => (profile, networks, None),
        Command::StartFull { profile, dns } => (profile, vec![], Some(dns)),
        _ => return reply(&mut stream, State::Error, "Start or Recover required").await,
    };
    if let Err(error) = Guard::preflight(&networks, dns) {
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
    let endpoints = match state::endpoints(&profile) {
        Ok(e) => e,
        Err(e) => return reply(&mut stream, State::Error, &e).await,
    };
    let prepared = {
        let mut unexpected = [0];
        tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(30), device::Prepared::connect(&profile)) => match result {
                Ok(Ok(prepared)) => prepared,
                _ => return reply(&mut stream, State::Error, "Не удалось открыть TUN: проверьте профиль HTTP/2, TLS и доступность endpoint").await,
            },
            _ = stream.read(&mut unexpected) => return Err("IPC closed during connect".into()),
        }
    };
    let guard = match Guard::install(uid, networks, dns, endpoints) {
        Ok(guard) => guard,
        Err(error) => return reply(&mut stream, State::Blocked, &error).await,
    };
    let device = prepared.device();
    let mut workers = Workers {
        tunnel: Some(tokio::spawn(prepared.run())),
        reconnect: None,
    };
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
    loop {
        let mut pending = Box::pin(read::<Request>(&mut stream));
        let request = loop {
            tokio::select! {
                request = &mut pending => break request?,
                result = async { workers.tunnel.as_mut().unwrap().await }, if workers.tunnel.is_some() => {
                    last_failure = match result {
                        Ok(Err(error)) => format!("VPN transport stopped: {error}"),
                        Ok(Ok(())) => "VPN transport stopped".into(),
                        Err(_) => "VPN transport worker failed".into(),
                    };
                    workers.tunnel = None;
                    state = State::Blocked;
                    // A flapping endpoint must not reset the backoff indefinitely.
                    if connected_since.elapsed() >= Duration::from_secs(30) { retry_delay = 2; }
                    workers.retry(&profile, &mut retry_delay, device.clone());
                }
                result = async { workers.reconnect.as_mut().unwrap().await }, if workers.reconnect.is_some() => {
                    workers.reconnect = None;
                    if let Ok(Err(error))=&result { eprintln!("VPN reconnect failed: {error}"); }
                    if let Ok(Ok(prepared)) = result && guard.refresh().is_ok() {
                            workers.tunnel = Some(tokio::spawn(prepared.run()));
                            connected_since = Instant::now();
                            state = State::Connected;
                            continue;
                    }
                    workers.retry(&profile, &mut retry_delay, device.clone());
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
                workers.stop().await;
                return match guard.release() {
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
    async fn rejects_wrong_version_before_any_privileged_operation() {
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(serve(server, 501, Arc::new(Mutex::new(()))));
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
        let task = tokio::spawn(serve(server, 501, lease));
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
