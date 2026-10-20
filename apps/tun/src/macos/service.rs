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
    sync::{Mutex, mpsc, oneshot},
    task::JoinSet,
};

type RunResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;
type Lease = Arc<tokio::sync::OwnedMutexGuard<()>>;

type Actor = mpsc::Sender<Envelope>;
#[derive(Clone)]
struct Session {
    actor: Actor,
    finished: tokio::sync::watch::Receiver<bool>,
    shutdown: tokio::sync::watch::Sender<bool>,
    // Capability returned to the Start caller. Recover of this live session
    // from a new connection must present it; Status never needs it.
    owner: Owner,
}
use rtrust_control::owner::Owner;
// Fail closed: without a CSPRNG value no session is admitted.
fn new_owner() -> Result<Owner, String> {
    use rand::TryRngCore;
    let mut bytes = zeroize::Zeroizing::new([0; rtrust_control::owner::LEN]);
    rand::rngs::OsRng
        .try_fill_bytes(bytes.as_mut())
        .map_err(|_| "Session owner unavailable")?;
    Ok(Owner::from_bytes(*bytes))
}
use rtrust_control::owner::NOT_OWNER;
// Synchronous lock: the actor drop guard must clear it during unwind or
// cancellation, where it cannot await. Never held across an await.
type Registry = Arc<std::sync::Mutex<Option<Session>>>;
fn registry_slot(registry: &Registry) -> std::sync::MutexGuard<'_, Option<Session>> {
    registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
// Forget only this actor's entry; a replacement session stays registered.
fn forget(registry: &Registry, identity: &Actor) {
    let mut current = registry_slot(registry);
    if current
        .as_ref()
        .is_some_and(|current| current.actor.same_channel(identity))
    {
        *current = None;
    }
}
// Owned by the actor future, so it runs on normal return, panic unwind,
// cancellation and drop before first poll. It only forgets IPC bookkeeping:
// the network Guard has no Drop, so PF, routes and DNS stay installed until an
// explicit Stop or Recover releases them.
struct Finish {
    registry: Registry,
    identity: Actor,
    lease: Option<Lease>,
    finished: tokio::sync::watch::Sender<bool>,
}
impl Drop for Finish {
    fn drop(&mut self) {
        forget(&self.registry, &self.identity);
        drop(self.lease.take());
        self.finished.send_replace(true);
    }
}
fn supervise(
    finish: Finish,
    actor: impl std::future::Future<Output = ()> + Send + 'static,
) -> ActorTask {
    Box::pin(async move {
        let _finish = finish;
        actor.await;
    })
}
struct Control {
    commands: mpsc::Receiver<Envelope>,
    initial: Option<oneshot::Sender<Response>>,
    shutdown: tokio::sync::watch::Receiver<bool>,
    /// Whole-computer sessions only; tests never probe the host.
    probe: Option<Probe>,
}
/// What a due probe tick runs: the host probe, or a synthetic one in tests.
#[derive(Clone)]
enum Probe {
    Host(super::probe::Plan),
    #[cfg(test)]
    Fake(Arc<dyn Fn() -> rtrust_control::observations::SystemProbe + Send + Sync>),
}
impl Probe {
    fn collect(
        &self,
    ) -> impl std::future::Future<Output = rtrust_control::observations::SystemProbe> + Send + 'static
    {
        let probe = self.clone();
        async move {
            match probe {
                Probe::Host(plan) => super::probe::collect(plan).await,
                #[cfg(test)]
                Probe::Fake(collect) => collect(),
            }
        }
    }
}
type ActorTask = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>;
struct Envelope {
    command: Command,
    response: oneshot::Sender<Response>,
}

const SESSION_ENDED: &str = "Tunnel session ended";
async fn ask(actor: &Actor, command: Command) -> Result<Response, String> {
    let (response, receive) = oneshot::channel();
    tokio::time::timeout(
        Duration::from_secs(5),
        actor.send(Envelope { command, response }),
    )
    .await
    .map_err(|_| "Supervisor queue timed out")?
    .map_err(|_| SESSION_ENDED)?;
    tokio::time::timeout(Duration::from_secs(45), receive)
        .await
        .map_err(|_| "Supervisor response timed out")?
        .map_err(|_| SESSION_ENDED.into())
}
// Durable state, independent of the bounded IPC command queue. Losing the
// service owner also requests fail-closed shutdown, even before first poll.
fn shutdown_requested(shutdown: &tokio::sync::watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}
async fn shutting_down(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    loop {
        if shutdown_requested(shutdown) {
            return;
        }
        if shutdown.changed().await.is_err() {
            return;
        }
    }
}

async fn write_response(
    stream: &mut (impl AsyncWrite + Unpin),
    response: &Response,
) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(5), write(stream, response))
        .await
        .map_err(|_| "IPC write timed out")?
}
async fn publish(
    initial: &mut Option<oneshot::Sender<Response>>,
    state: State,
    message: &str,
) -> Result<(), String> {
    if let Some(response) = initial.take() {
        // A vanished GUI is not a reason to stop service-owned work.
        let _ = response.send(Response::new(state, message));
    }
    Ok(())
}

/// How long after a (re)connect the data-plane counters are summarised.
const SUMMARY_DELAY: Duration = Duration::from_secs(30);
fn summary_after(
    after: &'static str,
) -> (tokio::time::Instant, &'static str, crate::stats::Snapshot) {
    (
        tokio::time::Instant::now() + SUMMARY_DELAY,
        after,
        crate::stats::snapshot(),
    )
}
fn millis(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}
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
            let started = Instant::now();
            let refresh_ms = std::sync::atomic::AtomicU64::new(0);
            // Darwin can discard endpoint host routes during sleep. Restore
            // them before opening a socket, or split routes send it into utun.
            let result = guarded_connect(
                lease,
                || {
                    let refresh = Instant::now();
                    let result = guard.refresh();
                    refresh_ms.fetch_add(millis(refresh), std::sync::atomic::Ordering::Relaxed);
                    result
                },
                async {
                    tokio::time::timeout(
                        Duration::from_secs(30),
                        device::Prepared::reconnect(&profile, device),
                    )
                    .await
                    .map_err(|_| "Reconnect timed out".to_owned())?
                    .map_err(|e| format!("Reconnect failed: {e}"))
                },
            )
            .await;
            // Durations only: no endpoint, route or profile data.
            events::record(&format!(
                "reconnect_timing wait_ms={} route_refresh_ms={} total_ms={} ok={}",
                wait.as_millis(),
                refresh_ms.into_inner(),
                millis(started),
                result.is_ok()
            ));
            result
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
    let mut actors = JoinSet::new();
    let registry: Registry = Arc::new(std::sync::Mutex::new(None));
    let (spawn, mut spawned) = mpsc::channel::<ActorTask>(16);
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| "Cannot register signal")?;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.map_err(|_| "IPC accept failed")?;
                if stream.peer_cred().map_err(|_| "IPC identity failed")?.uid() != uid || tasks.len() >= 16 { continue; }
                let lease = lease.clone();
                let power = power.events.clone();
                let registry = registry.clone();
                let spawn = spawn.clone();
                tasks.spawn(async move {
                    if serve(stream, uid, lease, power, registry, spawn).await.is_err() {
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
            task = spawned.recv() => { if let Some(task) = task { actors.spawn(task); } },
            _ = actors.join_next(), if !actors.is_empty() => {},
            _ = terminate.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    // Start may have queued its actor immediately before termination. Register
    // those futures too, then drain workers without releasing the network guard.
    while let Ok(task) = spawned.try_recv() {
        actors.spawn(task);
    }
    let current = registry_slot(&registry).clone();
    if let Some(actor) = current {
        actor.shutdown.send_replace(true);
    }
    while actors.join_next().await.is_some() {}
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
    power: tokio::sync::watch::Receiver<power::State>,
    registry: Registry,
    spawn: mpsc::Sender<ActorTask>,
) -> Result<(), String> {
    let request: Request = tokio::time::timeout(Duration::from_secs(5), read(&mut stream))
        .await
        .map_err(|_| "IPC read timed out")??;
    if request.version != VERSION {
        return reply(&mut stream, State::Error, "IPC version mismatch").await;
    }
    if matches!(request.command, Command::Capabilities) {
        return reply(&mut stream, State::Idle, "Capabilities").await;
    }
    let current = registry_slot(&registry).clone();
    if matches!(
        request.command,
        Command::Status { .. } | Command::Recover { .. }
    ) && let Some(session) = current
    {
        let stopping = matches!(request.command, Command::Recover { .. });
        if let Command::Recover { owner } = &request.command
            && !owner
                .as_ref()
                .is_some_and(|owner| session.owner.matches(owner))
        {
            if !*session.finished.borrow() {
                // Missing or wrong owner: the live session and its guard stay.
                events::record("recover_rejected reason=not_owner");
                return reply(&mut stream, State::Blocked, NOT_OWNER).await;
            }
            // The actor already ended; its guard is released only through
            // the journal path below, which needs no owner.
            forget(&registry, &session.actor);
        } else {
            // Only the lease connection reports views: a Status from any
            // other local connection never enables the system probes.
            let command = if stopping {
                Command::Stop
            } else {
                Command::Status { viewed: false }
            };
            match ask(&session.actor, command).await {
                Ok(response) => {
                    if stopping && let Err(error) = wait_finished(session.finished).await {
                        return reply(&mut stream, State::Error, &error).await;
                    }
                    // Status is read-only and does not adopt the active session.
                    return write_response(&mut stream, &response).await;
                }
                // A live but unresponsive actor keeps its lease and guard.
                Err(error) if error != SESSION_ENDED => {
                    return reply(&mut stream, State::Error, &error).await;
                }
                // The actor ended (returned, panicked or was cancelled) before it
                // answered. Wait for its cleanup, then answer like no session is
                // registered: the lease still serialises any recovery below.
                Err(_) => {
                    if let Err(error) = wait_finished(session.finished).await {
                        return reply(&mut stream, State::Error, &error).await;
                    }
                    forget(&registry, &session.actor);
                }
            }
        }
    }
    let Ok(held) = lease.try_lock_owned() else {
        return reply(
            &mut stream,
            State::Error,
            "Служба уже обслуживает подключение",
        )
        .await;
    };
    match request.command {
        Command::Status { .. } => {
            return reply(
                &mut stream,
                if state::pending() {
                    State::Blocked
                } else {
                    State::Idle
                },
                "Нет активной сессии VPN",
            )
            .await;
        }
        Command::Recover { .. } => {
            return match state::recover(uid) {
                Ok(()) => reply(&mut stream, State::Idle, "Блокировка снята").await,
                Err(e) => reply(&mut stream, State::Blocked, &e).await,
            };
        }
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
        Command::Start { .. } | Command::StartFull { .. } => {}
        _ => return reply(&mut stream, State::Error, "Start or Recover required").await,
    }
    let owner = match new_owner() {
        Ok(owner) => owner,
        Err(error) => return reply(&mut stream, State::Error, &error).await,
    };
    let held_lease = Arc::new(held);
    let (actor, commands) = mpsc::channel(16);
    let (shutdown_signal, shutdown_events) = tokio::sync::watch::channel(false);
    let (initial, response) = oneshot::channel();
    let (finished, completion) = tokio::sync::watch::channel(false);
    *registry_slot(&registry) = Some(Session {
        actor: actor.clone(),
        finished: completion.clone(),
        shutdown: shutdown_signal,
        owner: owner.clone(),
    });
    let finish = Finish {
        registry: registry.clone(),
        identity: actor.clone(),
        lease: Some(held_lease.clone()),
        finished,
    };
    let task = supervise(finish, async move {
        let _ = start(
            request,
            uid,
            held_lease,
            power,
            Control {
                commands,
                initial: Some(initial),
                shutdown: shutdown_events,
                probe: None,
            },
        )
        .await;
    });
    // A rejected task is dropped here; its Finish forgets the registration.
    if spawn.send(task).await.is_err() {
        return Err("Service is stopping".into());
    }
    let mut unexpected = [0];
    let initial = tokio::select! {
        response = response => response.map_err(|_| "Tunnel startup stopped")?,
        _ = stream.read(&mut unexpected) => return Err("IPC closed during connect".into()),
    };
    let initial = admitted_reply(initial, owner);
    let active = initial.state == State::Connected;
    write_response(&mut stream, &initial).await?;
    if !active {
        return Ok(());
    }
    bridge(stream, actor, Some(completion)).await
}

// Only the admitted caller learns the owner, and only once the session is
// Connected; it is never logged or included in later replies.
fn admitted_reply(mut initial: Response, owner: Owner) -> Response {
    initial.owner = (initial.state == State::Connected).then_some(owner);
    initial
}

async fn wait_finished(mut completion: tokio::sync::watch::Receiver<bool>) -> Result<(), String> {
    tokio::time::timeout(Duration::from_secs(45), async {
        while !*completion.borrow_and_update() {
            completion
                .changed()
                .await
                .map_err(|_| "Supervisor completion lost")?;
        }
        Ok(())
    })
    .await
    .map_err(|_| "Supervisor completion timed out")?
}

async fn bridge(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    actor: Actor,
    completion: Option<tokio::sync::watch::Receiver<bool>>,
) -> Result<(), String> {
    loop {
        let request: Request = read(&mut stream).await?;
        if request.version != VERSION {
            return Err("IPC version mismatch".into());
        }
        if !matches!(request.command, Command::Status { .. } | Command::Stop) {
            return Err("Invalid operation during lease".into());
        }
        let stop = matches!(request.command, Command::Stop);
        let response = ask(&actor, request.command).await?;
        if stop && let Some(completion) = completion.clone() {
            wait_finished(completion).await?;
        }
        write_response(&mut stream, &response).await?;
        if stop {
            return Ok(());
        }
    }
}

// Before guard installation the caller can still cancel Start. Recovery can
// also cancel this preparation without waiting for endpoint/TLS deadlines.
async fn prepare<T>(
    future: impl std::future::Future<Output = Result<T, String>>,
    initial: &mut oneshot::Sender<Response>,
    commands: &mut mpsc::Receiver<Envelope>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<T, String> {
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            _ = shutting_down(shutdown) => return Err("Service is stopping".into()),
            _ = initial.closed() => return Err("Start cancelled".into()),
            result = &mut future => return result,
            command = commands.recv() => match command {
                Some(Envelope { command: Command::Stop, response, .. }) => {
                    let _ = response.send(Response::new(State::Idle, "Подключение отменено"));
                    return Err("Start cancelled".into());
                }
                Some(command) => { let _ = command.response.send(Response::new(State::Blocked, "Подключение подготавливается")); }
                None => return Err("Service is stopping".into()),
            }
        }
    }
}

async fn start(
    request: Request,
    uid: u32,
    held_lease: Lease,
    mut power: tokio::sync::watch::Receiver<power::State>,
    control: Control,
) -> Result<(), String> {
    let Control {
        mut commands,
        mut initial,
        mut shutdown,
        probe: _,
    } = control;
    if shutdown_requested(&shutdown) {
        return Ok(());
    }
    power.borrow_and_update();
    let (profile, selection, dns, split_dns, fallbacks) = match request.command {
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
                return publish(&mut initial, State::Error, &error).await;
            }
            (profile, selection, None, dns, fallbacks)
        }
        Command::StartFull {
            profile,
            dns,
            fallbacks,
        } => (profile, Default::default(), Some(dns), None, fallbacks),
        _ => return publish(&mut initial, State::Error, "Start or Recover required").await,
    };
    let full = dns.is_some();
    if state::pending() {
        // A retained guard blocks DNS; report it before resolving the endpoint.
        return publish(
            &mut initial,
            State::Error,
            "Recovery is required before connecting",
        )
        .await;
    }
    // Both modes pin IPv4 endpoint addresses: PF blocks selected networks
    // outside the tunnel, so the endpoint must be known and left out of them.
    // Every allowed backup is pinned now: the guard covers all candidates.
    let mut failover = match prepare(
        crate::failover::Failover::pin(*profile, fallbacks, crate::failover::Pin::Ipv4),
        initial.as_mut().unwrap(),
        &mut commands,
        &mut shutdown,
    )
    .await
    {
        Ok(failover) => failover,
        _ => {
            return publish(
                &mut initial,
                State::Error,
                "Не удалось разрешить адрес VPN-сервера",
            )
            .await;
        }
    };
    let profile = failover.guard_profile();
    let endpoints = match state::endpoints(&profile) {
        Ok(e) => e,
        Err(e) => return publish(&mut initial, State::Error, &e).await,
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
            Err(e) => return publish(&mut initial, State::Error, &e).await,
        }
    };
    // A split selection that carries the resolver (e.g. everything but the
    // LAN) gets VPN DNS too; otherwise names would leak to the LAN resolver.
    // Like Linux without systemd-resolved, split mode skips DNS when the
    // system resolver cannot take it; full mode still requires it.
    let resolver = dns.or(rtrust_control::tunneled_resolver(&networks, split_dns)
        .filter(|_| super::dns::preflight().is_ok()));
    if let Err(error) = Guard::preflight(&networks, full, resolver) {
        return publish(&mut initial, State::Error, &error).await;
    }
    if !power.borrow().awake {
        return publish(
            &mut initial,
            State::Blocked,
            "macOS ещё не завершила пробуждение",
        )
        .await;
    }
    let prepared = match prepare(
        async {
            failover
                .connect_initial(|profile| async move { device::Prepared::connect(&profile).await })
                .await
                .map_err(|_| "Initial connection failed".to_owned())
        },
        initial.as_mut().unwrap(),
        &mut commands,
        &mut shutdown,
    )
    .await
    {
        Ok(prepared) => prepared,
        _ => {
            return publish(
                &mut initial,
                State::Error,
                "Не удалось открыть TUN: проверьте профиль, TLS и доступность endpoint",
            )
            .await;
        }
    };
    if shutdown_requested(&shutdown) || initial.as_ref().is_some_and(oneshot::Sender::is_closed) {
        return Ok(());
    }
    let permits = failover.permits()?;
    let probe = resolver.filter(|_| full).map(|dns| {
        Probe::Host(super::probe::Plan {
            uid,
            dns,
            permits: permits.clone(),
            endpoints: endpoints.iter().map(|e| (*e.ip()).into()).collect(),
        })
    });
    let guard = match Guard::install(uid, networks, full, resolver, endpoints, &permits) {
        Ok(guard) => guard,
        Err(error) => return publish(&mut initial, State::Blocked, &error).await,
    };
    let device = prepared.device();
    let workers = Workers {
        tunnel: Some(tokio::spawn(prepared.run())),
        reconnect: None,
    };
    let retry_guard = guard.clone();
    let release_lease = held_lease.clone();
    connected(
        Control {
            commands,
            initial,
            shutdown,
            probe,
        },
        workers,
        full,
        power,
        failover,
        move |workers, profile, delay| {
            workers.retry(profile, delay, device.clone(), &retry_guard, &held_lease)
        },
        move || {
            let _lease = release_lease;
            guard.release()
        },
    )
    .await
}

// An actor may be cancelled or unwind. Join the owned OS worker on Drop too,
// rather than detach an already-started spawn_blocking task. The worker owns
// its lease and has bounded system commands; dropping IPC never frees it early.
struct CleanupThread(Option<std::thread::JoinHandle<()>>);
impl Drop for CleanupThread {
    fn drop(&mut self) {
        if let Some(worker) = self.0.take() {
            let _ = worker.join();
        }
    }
}

// Bounded Stop waiters share one cleanup. Status describes stopping without
// claiming enforcement or restoration; no reconnect can start in this phase.
fn stopping_reply(request: Envelope, waiters: &mut Vec<oneshot::Sender<Response>>) {
    match request.command {
        Command::Stop if waiters.len() < 16 => waiters.push(request.response),
        Command::Status { .. } | Command::Stop => {
            let _ = request.response.send(Response::new(
                State::Blocked,
                "Отключение VPN; восстановление состояния ОС",
            ));
        }
        _ => {
            let _ = request
                .response
                .send(Response::new(State::Error, "Invalid supervisor operation"));
        }
    }
}

// Keep all actor commands and worker completion events in one supervisor. In particular,
// a wake must never await cancellation inside a select branch: block_in_place
// route mutations cannot be cancelled until they return.
async fn connected(
    control: Control,
    mut workers: Workers,
    full: bool,
    mut power: tokio::sync::watch::Receiver<power::State>,
    mut failover: crate::failover::Failover,
    mut retry: impl FnMut(&mut Workers, &rtrust_profile::Profile, &mut rtrust_control::recovery::Budget),
    release: impl FnOnce() -> Result<(), String> + Send + 'static,
) -> Result<(), String> {
    let Control {
        mut commands,
        mut initial,
        mut shutdown,
        probe: plan,
    } = control;
    if shutdown_requested(&shutdown) {
        workers.stop().await;
        return Ok(());
    }
    events::record("tunnel_connected");
    // Numbers only: a bounded data-plane summary after each (re)connect so a
    // session that proxies nothing is visible without raw traffic capture.
    let mut summary: Option<(tokio::time::Instant, &'static str, crate::stats::Snapshot)> =
        Some(summary_after("connect"));
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
    let mut response = Response::new(
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
    );
    response.active_profile = failover.active();
    response.observations = monitor.sample(rtrust_control::observations::now_ms());
    if let Some(initial) = initial.take() {
        let _ = initial.send(response);
    }
    let mut state = State::Connected;
    monitor.transition(true, rtrust_control::observations::now_ms());
    let mut netwatch = crate::netwatch::Watch::new(super::device::DEVICE);
    let mut last_failure = String::new();
    let mut restart_pending = false;
    let mut awake = power.borrow().awake;
    let mut probes = crate::sysprobe::Runner::default();
    loop {
        let request = loop {
            // Aborted block_in_place work can still own route mutations. Join
            // completion in select below, keeping Status and EOF responsive.
            if shutdown_requested(&shutdown) {
                workers.stop().await;
                return Ok(());
            }
            if awake && workers.idle() {
                events::record("reconnect_scheduled");
                retry(&mut workers, failover.current(), &mut retry_delay);
                restart_pending = false;
            }
            tokio::select! {
                _ = shutting_down(&mut shutdown) => {
                    workers.stop().await;
                    return Ok(());
                },
                event = power.changed() => {
                    event.map_err(|_| "macOS power monitor stopped")?;
                    let event = *power.borrow_and_update();
                    awake = event.awake;
                    events::record(&format!("power_event awake={awake} generation={}", event.generation));
                    summary = None;
                    if !awake {
                        // Sleep after a stable session restores the budget as a
                        // natural disconnect would; a pending attempt it cancels
                        // is refunded. Wake-to-wake flapping keeps the backoff.
                        if workers.tunnel.is_some() {
                            retry_delay.disconnected(connected_since.elapsed(), false);
                        } else if workers.reconnect.is_some() {
                            retry_delay.interrupted();
                        }
                    }
                    workers.cancel();
                    probes.cancel();
                    restart_pending = true;
                    state = State::Blocked;
                    last_failure = if awake { "Восстановление VPN после сна" } else { "VPN приостановлен на время сна" }.into();
                    if awake { monitor.resumed(rtrust_control::observations::now_ms()); }
                    monitor.transition(false, rtrust_control::observations::now_ms());
                }
                change = netwatch.next() => {
                    probes.cancel();
                    match change {
                        crate::netwatch::Change::Network => monitor.network_changed(rtrust_control::observations::now_ms()),
                        crate::netwatch::Change::Resumed => monitor.resumed(rtrust_control::observations::now_ms()),
                    }
                },
                result = async { workers.tunnel.as_mut().unwrap().await }, if workers.tunnel.is_some() => {
                    workers.tunnel = None;
                    probes.cancel();
                    summary = None;
                    if restart_pending { continue; }
                    let degraded = result.as_ref().ok().and_then(crate::dataplane::degraded);
                    if let Some(proven) = degraded { events::record(&format!("transport_degraded proven={proven}")); }
                    last_failure = match result {
                        Ok(Err(_)) => "VPN transport stopped".into(),
                        Ok(Ok(())) => "VPN transport stopped".into(),
                        Err(_) => "VPN transport worker failed".into(),
                    };
                    events::record(&last_failure);
                    state = State::Blocked;
                    // A flapping endpoint must not reset the backoff indefinitely.
                    monitor.transition(false, rtrust_control::observations::now_ms());
                    retry_delay.disconnected(connected_since.elapsed(), degraded == Some(false));
                    if failover.ended(connected_since.elapsed(), Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                    }
                }
                result = async { workers.reconnect.as_mut().unwrap().await }, if workers.reconnect.is_some() => {
                    workers.reconnect = None;
                    if shutdown_requested(&shutdown) { workers.stop().await; return Ok(()); }
                    // A task can complete just before abort. Do not resurrect
                    // its pre-wake transport even if its result was successful.
                    if restart_pending { continue; }
                    match &result {
                        Ok(Err(error)) => {
                            last_failure = "VPN reconnect failed".into();
                            // Fixed reason strings from device.rs only; no endpoint data.
                            events::record(&format!("{last_failure}: {error}"));
                        }
                        Err(_) => last_failure = "VPN reconnect worker failed".into(),
                        _ => {},
                    }
                    if let Ok(Ok(prepared)) = result {
                        // Baseline before the data plane runs: its backlog
                        // discard must land inside the summary window.
                        summary = Some(summary_after("reconnect"));
                        workers.tunnel = Some(tokio::spawn(prepared.run()));
                        connected_since = Instant::now();
                        state = State::Connected;
                        probes.cancel();
                        monitor.transition(true, rtrust_control::observations::now_ms());
                        events::record("reconnect_complete");
                        continue;
                    }
                    if failover.failed(Instant::now()) {
                        monitor.failed_over(rtrust_control::observations::now_ms());
                    }
                }
                request = commands.recv() => {
                    if let Some(request) = request { break request; }
                    return Err("Service supervisor stopped".into());
                },
                _ = tokio::time::sleep_until(summary.map(|s| s.0).unwrap_or_else(tokio::time::Instant::now)), if summary.is_some() => {
                    let (_, after, base) = summary.take().unwrap();
                    events::record(&format!(
                        "dataplane_summary after={after} window_s={} {}",
                        SUMMARY_DELAY.as_secs(),
                        crate::stats::snapshot().since(&base).render()
                    ));
                },
                // Started only by this timer while awake, connected and viewed
                // through the lease; Status never probes.
                tick = probes.next(), if plan.is_some() => match tick {
                    crate::sysprobe::Tick::Due => if awake && state == State::Connected && probes.viewing() {
                        probes.start(monitor.generation(), plan.as_ref().unwrap().collect());
                    },
                    crate::sysprobe::Tick::Done(generation, result) => {
                        monitor.apply_system(generation, result, rtrust_control::observations::now_ms());
                    },
                },
            }
        };
        if shutdown_requested(&shutdown) {
            workers.stop().await;
            return Ok(());
        }
        match request.command {
            Command::Status { viewed } => {
                if viewed {
                    probes.viewed(awake && state == State::Connected);
                }
                let mut response = Response::new(
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
                );
                response.active_profile = failover.active();
                response.observations = monitor.sample(rtrust_control::observations::now_ms());
                let _ = request.response.send(response);
            }
            Command::Stop => {
                events::record("stop_requested");
                let stop_started = Instant::now();
                probes.cancel();
                monitor.transition(false, rtrust_control::observations::now_ms());
                let mut waiters = vec![request.response];
                {
                    let stopping = workers.stop();
                    tokio::pin!(stopping);
                    loop {
                        tokio::select! {
                            _ = &mut stopping => break,
                            request = commands.recv(), if !commands.is_closed() => {
                                if let Some(request) = request { stopping_reply(request, &mut waiters); }
                            }
                        }
                    }
                }
                // The retry closure retains the persistent utun Arc. Drop it
                // after workers drain, before reporting successful restoration.
                drop(retry);
                let drain_ms = millis(stop_started);
                if shutdown_requested(&shutdown) {
                    for waiter in waiters {
                        let _ = waiter.send(Response::new(
                            State::Blocked,
                            "Служба остановлена; защита сохранена",
                        ));
                    }
                    return Ok(());
                }
                // Join blocking release even on shutdown: abandoning OS
                // mutations would allow a competing recovery. The production
                // release closure retains the lease until this task completes.
                let (complete, mut cleanup) = oneshot::channel();
                let worker = std::thread::Builder::new()
                    .name("rtrust-cleanup".into())
                    .spawn(move || {
                        let _ = complete.send(release());
                    });
                let worker = match worker {
                    Ok(worker) => CleanupThread(Some(worker)),
                    Err(_) => {
                        for waiter in waiters {
                            let _ = waiter.send(Response::new(
                                State::Blocked,
                                "Не удалось начать восстановление состояния ОС",
                            ));
                        }
                        return Ok(());
                    }
                };
                let result = loop {
                    tokio::select! {
                        result = &mut cleanup => break result,
                        request = commands.recv(), if !commands.is_closed() => {
                            if let Some(request) = request { stopping_reply(request, &mut waiters); }
                        }
                    }
                };
                drop(worker);
                // Durations only. The utun is released at drain; release covers
                // the owned routes, DNS and PF restored from the journal.
                events::record(&format!(
                    "stop_timing drain_ms={drain_ms} release_ms={} total_ms={} ok={}",
                    millis(stop_started).saturating_sub(drain_ms),
                    millis(stop_started),
                    matches!(result, Ok(Ok(())))
                ));
                let response = match result {
                    Ok(Ok(())) => {
                        monitor.stop(rtrust_control::observations::now_ms());
                        let mut response = Response::new(State::Idle, "Отключено");
                        response.observations =
                            monitor.sample(rtrust_control::observations::now_ms());
                        response
                    }
                    Ok(Err(e)) => Response::new(State::Blocked, &e),
                    Err(_) => Response::new(
                        State::Blocked,
                        "Восстановление состояния ОС не подтверждено",
                    ),
                };
                for waiter in waiters {
                    let _ = waiter.send(response.clone());
                }
                return Ok(());
            }
            _ => {
                let _ = request
                    .response
                    .send(Response::new(State::Error, "Invalid supervisor operation"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_owner() -> Owner {
        Owner::from_bytes([0x3c; rtrust_control::owner::LEN])
    }
    use tokio::io::AsyncWriteExt;

    async fn connected(
        mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        workers: Workers,
        full: bool,
        power: tokio::sync::watch::Receiver<power::State>,
        failover: crate::failover::Failover,
        retry: impl FnMut(&mut Workers, &rtrust_profile::Profile, &mut rtrust_control::recovery::Budget)
        + Send
        + 'static,
        release: impl FnOnce() -> Result<(), String> + Send + 'static,
    ) -> Result<(), String> {
        let (actor, commands) = mpsc::channel(16);
        let (_shutdown_signal, shutdown_events) = tokio::sync::watch::channel(false);
        let (initial, response) = oneshot::channel();
        let supervisor = tokio::spawn(super::connected(
            Control {
                commands,
                initial: Some(initial),
                shutdown: shutdown_events,
                probe: None,
            },
            workers,
            full,
            power,
            failover,
            retry,
            release,
        ));
        write_response(&mut stream, &response.await.unwrap()).await?;
        let result = bridge(stream, actor, None).await;
        if result.is_err() {
            supervisor.abort();
        }
        let _ = supervisor.await;
        result
    }

    async fn serve(
        stream: impl AsyncRead + AsyncWrite + Unpin,
        uid: u32,
        lease: Arc<Mutex<()>>,
        power: tokio::sync::watch::Receiver<power::State>,
    ) -> Result<(), String> {
        let (spawn, _spawned) = mpsc::channel(16);
        super::serve(
            stream,
            uid,
            lease,
            power,
            Arc::new(std::sync::Mutex::new(None)),
            spawn,
        )
        .await
    }

    struct TestActor {
        actor: Actor,
        initial: oneshot::Receiver<Response>,
        task: tokio::task::JoinHandle<Result<(), String>>,
        power: tokio::sync::watch::Sender<power::State>,
        lease: Arc<Mutex<()>>,
        released: Arc<std::sync::atomic::AtomicBool>,
        dropped: Arc<std::sync::atomic::AtomicBool>,
        retries: Arc<std::sync::atomic::AtomicUsize>,
        shutdown: tokio::sync::watch::Sender<bool>,
    }
    struct Dropped(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    async fn test_actor() -> TestActor {
        let lease = Arc::new(Mutex::new(()));
        let held = lease.clone().lock_owned().await;
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = released.clone();
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drop_signal = Dropped(dropped.clone());
        let (ready, entered) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let _drop_signal = drop_signal;
            let _ = ready.send(());
            std::future::pending::<RunResult>().await
        });
        entered.await.unwrap();
        let (power, receiver) = tokio::sync::watch::channel(power::State::default());
        let (actor, commands) = mpsc::channel(16);
        let (shutdown_signal, shutdown_events) = tokio::sync::watch::channel(false);
        let (initial, response) = oneshot::channel();
        let retries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let retry_count = retries.clone();
        let task = tokio::spawn(super::connected(
            Control {
                commands,
                initial: Some(initial),
                shutdown: shutdown_events,
                probe: None,
            },
            Workers {
                tunnel: Some(worker),
                reconnect: None,
            },
            false,
            receiver,
            failover().await,
            move |workers, _, _| {
                retry_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                workers.reconnect = Some(tokio::spawn(std::future::pending()));
            },
            move || {
                drop(held);
                release.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        ));
        TestActor {
            actor,
            initial: response,
            task,
            power,
            lease,
            released,
            dropped,
            retries,
            shutdown: shutdown_signal,
        }
    }

    #[tokio::test]
    async fn vanished_initial_reply_and_eof_do_not_drop_workers_or_lease() {
        let fixture = test_actor().await;
        drop(fixture.initial);
        let (client, server) = tokio::io::duplex(4096);
        let bridge = tokio::spawn(super::bridge(server, fixture.actor.clone(), None));
        drop(client);
        assert!(bridge.await.unwrap().is_err());
        assert_eq!(
            ask(&fixture.actor, Command::Status { viewed: false })
                .await
                .unwrap()
                .state,
            State::Connected
        );
        assert!(!fixture.task.is_finished());
        assert!(fixture.lease.try_lock().is_err());
        assert!(!fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!fixture.released.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            ask(&fixture.actor, Command::Stop).await.unwrap().state,
            State::Idle
        );
        fixture.task.await.unwrap().unwrap();
        assert!(fixture.lease.try_lock().is_ok());
        assert!(fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn malformed_version_command_and_oversized_frames_only_detach_ipc() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        for bad in 0..4 {
            let (mut client, server) = tokio::io::duplex(4096);
            let bridge = tokio::spawn(super::bridge(server, fixture.actor.clone(), None));
            match bad {
                0 => write(
                    &mut client,
                    &Request {
                        version: VERSION + 1,
                        command: Command::Stop,
                    },
                )
                .await
                .unwrap(),
                1 => write(
                    &mut client,
                    &Request {
                        version: VERSION,
                        command: Command::Recover { owner: None },
                    },
                )
                .await
                .unwrap(),
                2 => {
                    client.write_all(&[0, 0, 0, 1, b'{']).await.unwrap();
                }
                _ => {
                    client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
                }
            }
            assert!(bridge.await.unwrap().is_err());
            assert_eq!(
                ask(&fixture.actor, Command::Status { viewed: false })
                    .await
                    .unwrap()
                    .state,
                State::Connected
            );
            assert!(fixture.lease.try_lock().is_err());
            assert!(!fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
        }
        ask(&fixture.actor, Command::Stop).await.unwrap();
        fixture.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn failed_status_write_and_read_only_observer_cannot_end_actor() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        let (mut client, server) = tokio::io::duplex(4096);
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Status { viewed: false },
            },
        )
        .await
        .unwrap();
        drop(client);
        assert!(
            super::bridge(server, fixture.actor.clone(), None)
                .await
                .is_err()
        );
        let (_finished, completion) = tokio::sync::watch::channel(false);
        let registry = Arc::new(std::sync::Mutex::new(Some(Session {
            actor: fixture.actor.clone(),
            finished: completion,
            shutdown: fixture.shutdown.clone(),
            owner: test_owner(),
        })));
        let (spawn, _spawned) = mpsc::channel(16);
        let (mut observer, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(super::serve(
            server,
            501,
            fixture.lease.clone(),
            fixture.power.subscribe(),
            registry,
            spawn,
        ));
        write(
            &mut observer,
            &Request {
                version: VERSION,
                command: Command::Status { viewed: false },
            },
        )
        .await
        .unwrap();
        assert_eq!(
            read::<Response>(&mut observer).await.unwrap().state,
            State::Connected
        );
        task.await.unwrap().unwrap();
        // The observer socket has no adopted mutation rights.
        assert!(
            write(
                &mut observer,
                &Request {
                    version: VERSION,
                    command: Command::Stop
                }
            )
            .await
            .is_err()
        );
        assert_eq!(
            ask(&fixture.actor, Command::Status { viewed: false })
                .await
                .unwrap()
                .state,
            State::Connected
        );
        assert!(fixture.lease.try_lock().is_err());
        ask(&fixture.actor, Command::Stop).await.unwrap();
        fixture.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn frozen_reader_does_not_block_detached_power_recovery() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        let (mut client, server) = tokio::io::duplex(64);
        let bridge = tokio::spawn(super::bridge(server, fixture.actor.clone(), None));
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Status { viewed: false },
            },
        )
        .await
        .unwrap();
        fixture.power.send_modify(|state| {
            state.awake = false;
            state.generation += 1;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while ask(&fixture.actor, Command::Status { viewed: false })
                .await
                .unwrap()
                .state
                != State::Blocked
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        fixture.power.send_modify(|state| {
            state.awake = true;
            state.generation += 1;
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while fixture.retries.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(fixture.lease.try_lock().is_err());
        assert!(!fixture.released.load(std::sync::atomic::Ordering::SeqCst));
        // Do not consume the response: exercise the actual five-second write deadline.
        assert!(
            tokio::time::timeout(Duration::from_secs(6), bridge)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        ask(&fixture.actor, Command::Stop).await.unwrap();
        fixture.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn stale_sender_cannot_stop_replacement_session() {
        let old = test_actor().await;
        old.initial.await.unwrap();
        let captured = old.actor.clone();
        ask(&old.actor, Command::Stop).await.unwrap();
        old.task.await.unwrap().unwrap();
        let new = test_actor().await;
        new.initial.await.unwrap();
        assert!(ask(&captured, Command::Stop).await.is_err());
        assert_eq!(
            ask(&new.actor, Command::Status { viewed: false })
                .await
                .unwrap()
                .state,
            State::Connected
        );
        assert!(!new.dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(new.lease.try_lock().is_err());
        ask(&new.actor, Command::Stop).await.unwrap();
        new.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn preparation_cancellation_never_commits_abandoned_start() {
        let (initial, response) = oneshot::channel();
        let mut initial = initial;
        let (_actor, mut commands) = mpsc::channel(16);
        let (_shutdown_signal, mut shutdown_events) = tokio::sync::watch::channel(false);
        drop(response);
        assert!(
            prepare(
                std::future::pending::<Result<(), String>>(),
                &mut initial,
                &mut commands,
                &mut shutdown_events
            )
            .await
            .is_err()
        );
        let (initial, _response) = oneshot::channel();
        let mut initial = initial;
        let (actor, mut commands) = mpsc::channel(16);
        let (_shutdown_signal, mut shutdown_events) = tokio::sync::watch::channel(false);
        let stopping = tokio::spawn(async move { ask(&actor, Command::Stop).await });
        assert!(
            prepare(
                std::future::pending::<Result<(), String>>(),
                &mut initial,
                &mut commands,
                &mut shutdown_events
            )
            .await
            .is_err()
        );
        assert_eq!(stopping.await.unwrap().unwrap().state, State::Idle);
    }

    #[tokio::test]
    async fn normal_service_shutdown_drains_workers_and_retains_guard() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        fixture.shutdown.send_replace(true);
        fixture.task.await.unwrap().unwrap();
        assert!(fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(!fixture.released.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn active_actor_blocks_start_and_update_without_adoption() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        let (_finished, completion) = tokio::sync::watch::channel(false);
        let registry = Arc::new(std::sync::Mutex::new(Some(Session {
            actor: fixture.actor.clone(),
            finished: completion,
            shutdown: fixture.shutdown.clone(),
            owner: test_owner(),
        })));
        let profile = rtrust_profile::Profile::import("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n").unwrap();
        for command in [
            Command::PrepareUpdate,
            Command::StartFull {
                profile: Box::new(profile),
                dns: "192.0.2.53".parse().unwrap(),
                fallbacks: vec![],
            },
        ] {
            let (spawn, _spawned) = mpsc::channel(16);
            let (mut client, server) = tokio::io::duplex(4096);
            let task = tokio::spawn(super::serve(
                server,
                501,
                fixture.lease.clone(),
                fixture.power.subscribe(),
                registry.clone(),
                spawn,
            ));
            write(
                &mut client,
                &Request {
                    version: VERSION,
                    command,
                },
            )
            .await
            .unwrap();
            assert_eq!(
                read::<Response>(&mut client).await.unwrap().state,
                State::Error
            );
            task.await.unwrap().unwrap();
        }
        assert!(!fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
        ask(&fixture.actor, Command::Stop).await.unwrap();
        fixture.task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn saturated_command_queue_has_deadline_and_does_not_retarget_stop() {
        let (actor, mut commands) = mpsc::channel(1);
        let (response, _receive) = oneshot::channel();
        actor
            .send(Envelope {
                command: Command::Status { viewed: false },
                response,
            })
            .await
            .unwrap();
        assert_eq!(
            ask(&actor, Command::Stop).await.unwrap_err(),
            "Supervisor queue timed out"
        );
        assert!(matches!(
            commands.recv().await.unwrap().command,
            Command::Status { .. }
        ));
        assert!(
            commands.try_recv().is_err(),
            "timed-out Stop must not enter the queue later"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actor_stop_and_shutdown_drain_inflight_route_mutations() {
        for shutdown in [false, true] {
            let lease = Arc::new(Mutex::new(()));
            let held = Arc::new(lease.clone().lock_owned().await);
            let entered = Arc::new(tokio::sync::Notify::new());
            let signal = entered.clone();
            let (unblock, wait) = std::sync::mpsc::channel();
            let wait = std::sync::Mutex::new(wait);
            let worker = tokio::spawn(guarded_connect(
                held.clone(),
                move || {
                    signal.notify_one();
                    wait.lock().unwrap().recv().unwrap();
                    Ok(())
                },
                std::future::pending::<Result<device::Prepared, String>>(),
            ));
            entered.notified().await;
            let (actor, commands) = mpsc::channel(16);
            let (shutdown_signal, shutdown_events) = tokio::sync::watch::channel(false);
            let (initial, response) = oneshot::channel();
            let (power, receiver) = tokio::sync::watch::channel(power::State::default());
            let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let release = released.clone();
            let task = tokio::spawn(super::connected(
                Control {
                    commands,
                    initial: Some(initial),
                    shutdown: shutdown_events,
                    probe: None,
                },
                Workers {
                    tunnel: None,
                    reconnect: Some(worker),
                },
                false,
                receiver,
                failover().await,
                |_, _, _| panic!("must drain before retry"),
                move || {
                    drop(held);
                    release.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            ));
            response.await.unwrap();
            let stopping = if shutdown {
                shutdown_signal.send_replace(true);
                None
            } else {
                let actor = actor.clone();
                Some(tokio::spawn(
                    async move { ask(&actor, Command::Stop).await },
                ))
            };
            tokio::time::sleep(Duration::from_millis(30)).await;
            let ack_before_drain =
                stopping.as_ref().is_some_and(|task| task.is_finished()) || task.is_finished();
            let lease_before_drain = lease.try_lock().is_err();
            let released_before_drain = released.load(std::sync::atomic::Ordering::SeqCst);
            let status = if !shutdown {
                Some(
                    tokio::time::timeout(
                        Duration::from_millis(200),
                        ask(&actor, Command::Status { viewed: false }),
                    )
                    .await,
                )
            } else {
                None
            };
            unblock.send(()).unwrap();
            let result = if let Some(stopping) = stopping {
                Some(stopping.await.unwrap().unwrap())
            } else {
                None
            };
            task.await.unwrap().unwrap();
            drop(power);
            assert!(!ack_before_drain);
            assert!(lease_before_drain);
            assert!(!released_before_drain);
            if let Some(status) = status {
                assert_eq!(
                    status.expect("Status blocked during drain").unwrap().state,
                    State::Blocked
                );
            }
            if let Some(result) = result {
                assert_eq!(result.state, State::Idle);
            }
            assert_eq!(
                released.load(std::sync::atomic::Ordering::SeqCst),
                !shutdown
            );
            assert!(lease.try_lock().is_ok());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopping_status_duplicate_stop_and_shutdown_join_delayed_release() {
        for failure in [false, true] {
            let lease = Arc::new(Mutex::new(()));
            let held = lease.clone().lock_owned().await;
            let entered = Arc::new(tokio::sync::Notify::new());
            let signal = entered.clone();
            let (unblock, wait) = std::sync::mpsc::channel();
            let (actor, commands) = mpsc::channel(16);
            let (shutdown, shutdown_events) = tokio::sync::watch::channel(false);
            let (initial, response) = oneshot::channel();
            let (_power, receiver) = tokio::sync::watch::channel(power::State::default());
            let device_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let retry_device = Dropped(device_dropped.clone());
            let release_device = device_dropped.clone();
            let task = tokio::spawn(super::connected(
                Control {
                    commands,
                    initial: Some(initial),
                    shutdown: shutdown_events,
                    probe: None,
                },
                Workers {
                    tunnel: Some(tokio::spawn(std::future::pending())),
                    reconnect: None,
                },
                false,
                receiver,
                failover().await,
                move |_, _, _| {
                    let _ = &retry_device;
                    panic!("must not retry during Stop");
                },
                move || {
                    let _lease = held;
                    assert!(
                        release_device.load(std::sync::atomic::Ordering::SeqCst),
                        "device retained past drain"
                    );
                    signal.notify_one();
                    wait.recv().unwrap();
                    if failure {
                        Err("synthetic restoration failure".into())
                    } else {
                        Ok(())
                    }
                },
            ));
            response.await.unwrap();
            let first_actor = actor.clone();
            let first = tokio::spawn(async move { ask(&first_actor, Command::Stop).await });
            entered.notified().await;
            let second_actor = actor.clone();
            let second = tokio::spawn(async move { ask(&second_actor, Command::Stop).await });
            let status = tokio::time::timeout(
                Duration::from_millis(200),
                ask(&actor, Command::Status { viewed: false }),
            )
            .await;
            shutdown.send_replace(true);
            tokio::time::sleep(Duration::from_millis(20)).await;
            let held_during_release = lease.try_lock().is_err();
            let finished_early = task.is_finished() || first.is_finished() || second.is_finished();
            unblock.send(()).unwrap();
            let expected = if failure { State::Blocked } else { State::Idle };
            assert_eq!(first.await.unwrap().unwrap().state, expected);
            assert_eq!(second.await.unwrap().unwrap().state, expected);
            task.await.unwrap().unwrap();
            assert_eq!(
                status
                    .expect("Status blocked during release")
                    .unwrap()
                    .state,
                State::Blocked
            );
            assert!(held_during_release);
            assert!(!finished_early);
            assert!(lease.try_lock().is_ok());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn actor_cancellation_joins_owned_cleanup_before_releasing_lease() {
        let lease = Arc::new(Mutex::new(()));
        let held = lease.clone().lock_owned().await;
        let (unblock, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _lease = held;
            wait.recv().unwrap();
        });
        let (entered, ready) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _cleanup = CleanupThread(Some(worker));
            let _ = entered.send(());
            std::future::pending::<()>().await;
        });
        ready.await.unwrap();
        task.abort();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let held_during_cancel = lease.try_lock().is_err();
        let completed_early = task.is_finished();
        unblock.send(()).unwrap();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(held_during_cancel);
        assert!(!completed_early);
        assert!(lease.try_lock().is_ok());
    }

    #[test]
    fn repeated_stop_waiters_are_bounded() {
        let mut waiters = vec![];
        let mut replies = vec![];
        for _ in 0..32 {
            let (response, reply) = oneshot::channel();
            stopping_reply(
                Envelope {
                    command: Command::Stop,
                    response,
                },
                &mut waiters,
            );
            replies.push(reply);
        }
        assert_eq!(waiters.len(), 16);
        for reply in &mut replies[16..] {
            assert_eq!(reply.try_recv().unwrap().state, State::Blocked);
        }
    }

    #[tokio::test]
    async fn shutdown_cancels_ready_and_pending_preparation_even_without_owner() {
        for already_set in [false, true] {
            let (signal, mut shutdown) = tokio::sync::watch::channel(already_set);
            let (initial, _response) = oneshot::channel();
            let mut initial = initial;
            let (_actor, mut commands) = mpsc::channel(16);
            if already_set {
                assert!(
                    prepare(
                        async { Ok::<_, String>(()) },
                        &mut initial,
                        &mut commands,
                        &mut shutdown
                    )
                    .await
                    .is_err()
                );
            } else {
                let task = tokio::spawn(async move {
                    prepare(
                        std::future::pending::<Result<(), String>>(),
                        &mut initial,
                        &mut commands,
                        &mut shutdown,
                    )
                    .await
                });
                signal.send_replace(true);
                assert!(
                    tokio::time::timeout(Duration::from_secs(1), task)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
            }
        }
        let (signal, mut shutdown) = tokio::sync::watch::channel(false);
        drop(signal);
        let (initial, _response) = oneshot::channel();
        let mut initial = initial;
        let (_actor, mut commands) = mpsc::channel(16);
        assert!(
            prepare(
                async { Ok::<_, String>(()) },
                &mut initial,
                &mut commands,
                &mut shutdown
            )
            .await
            .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_before_first_poll_bypasses_full_queue_and_drains_owned_workers() {
        let lease = Arc::new(Mutex::new(()));
        let held = Arc::new(lease.clone().lock_owned().await);
        let owner = held.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let (unblock, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let worker = tokio::spawn(guarded_connect(
            held.clone(),
            move || {
                signal.notify_one();
                wait.lock().unwrap().recv().unwrap();
                Ok(())
            },
            std::future::pending::<Result<device::Prepared, String>>(),
        ));
        entered.notified().await;
        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let drop_signal = Dropped(dropped.clone());
        let tunnel = tokio::spawn(async move {
            let _drop_signal = drop_signal;
            std::future::pending::<RunResult>().await
        });
        let (actor, commands) = mpsc::channel(16);
        let mut replies = Vec::new();
        for index in 0..16 {
            let (response, receive) = oneshot::channel();
            actor
                .send(Envelope {
                    command: if index == 0 {
                        Command::Stop
                    } else {
                        Command::Status { viewed: false }
                    },
                    response,
                })
                .await
                .unwrap();
            replies.push(receive);
        }
        let (shutdown, shutdown_events) = tokio::sync::watch::channel(false);
        let (power, receiver) = tokio::sync::watch::channel(power::State::default());
        power.send_modify(|state| state.generation += 1);
        let (initial, response) = oneshot::channel();
        let (started, startup) = oneshot::channel();
        let (finished, completion) = tokio::sync::watch::channel(false);
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = released.clone();
        let failover = failover().await;
        let task = tokio::spawn(async move {
            startup.await.unwrap();
            let result = super::connected(
                Control {
                    commands,
                    initial: Some(initial),
                    shutdown: shutdown_events,
                    probe: None,
                },
                Workers {
                    tunnel: Some(tunnel),
                    reconnect: Some(worker),
                },
                false,
                receiver,
                failover,
                |_, _, _| panic!("shutdown must outrank retry and pending power event"),
                move || {
                    drop(held);
                    release.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok(())
                },
            )
            .await;
            drop(owner);
            finished.send_replace(true);
            result
        });
        // Exceed the obsolete enqueue deadline while the actor is still queued.
        shutdown.send_replace(true);
        tokio::time::sleep(Duration::from_millis(5100)).await;
        assert_eq!(actor.capacity(), 0);
        started.send(()).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let completed_before_drain = task.is_finished();
        let lease_before_drain = lease.try_lock().is_err();
        let release_before_drain = released.load(std::sync::atomic::Ordering::SeqCst);
        unblock.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        wait_finished(completion).await.unwrap();
        assert!(!completed_before_drain);
        assert!(lease_before_drain);
        assert!(!release_before_drain);
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(lease.try_lock().is_ok());
        assert!(
            response.await.is_err(),
            "shutdown must not report Connected"
        );
        for reply in replies {
            assert!(
                reply.await.is_err(),
                "queued requests must not defeat shutdown"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_admitted_stop_drain_retains_guard_and_reports_blocked() {
        let lease = Arc::new(Mutex::new(()));
        let held = Arc::new(lease.clone().lock_owned().await);
        let entered = Arc::new(tokio::sync::Notify::new());
        let signal = entered.clone();
        let (unblock, wait) = std::sync::mpsc::channel();
        let wait = std::sync::Mutex::new(wait);
        let worker_lease = held.clone();
        let tunnel = tokio::spawn(async move {
            let _lease = worker_lease;
            tokio::task::block_in_place(|| {
                signal.notify_one();
                wait.lock().unwrap().recv().unwrap();
            });
            std::future::pending::<RunResult>().await
        });
        entered.notified().await;
        struct StopEntered(Arc<tokio::sync::Notify>);
        impl Drop for StopEntered {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let cancelled = Arc::new(tokio::sync::Notify::new());
        let stop_entered = StopEntered(cancelled.clone());
        let reconnect = tokio::spawn(async move {
            let _stop_entered = stop_entered;
            std::future::pending::<Result<device::Prepared, String>>().await
        });
        let (actor, commands) = mpsc::channel(16);
        let (shutdown, shutdown_events) = tokio::sync::watch::channel(false);
        let (_power, receiver) = tokio::sync::watch::channel(power::State::default());
        let (initial, response) = oneshot::channel();
        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = released.clone();
        let task = tokio::spawn(super::connected(
            Control {
                commands,
                initial: Some(initial),
                shutdown: shutdown_events,
                probe: None,
            },
            Workers {
                tunnel: Some(tunnel),
                reconnect: Some(reconnect),
            },
            false,
            receiver,
            failover().await,
            |_, _, _| panic!("must drain before retry"),
            move || {
                drop(held);
                release.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok(())
            },
        ));
        response.await.unwrap();
        let (response, stopped) = oneshot::channel();
        actor
            .send(Envelope {
                command: Command::Stop,
                response,
            })
            .await
            .unwrap();
        // Workers::stop first aborts and joins reconnect. Its destructor is
        // observable proof that Stop entered worker drain, rather than merely
        // dequeuing a command before a competing shutdown branch won.
        let admitted = tokio::time::timeout(Duration::from_secs(1), cancelled.notified()).await;
        shutdown.send_replace(true);
        let lease_before_drain = lease.try_lock().is_err();
        unblock.send(()).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), stopped)
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap().unwrap();
        assert!(admitted.is_ok());
        assert!(lease_before_drain);
        assert_eq!(response.state, State::Blocked);
        assert!(!released.load(std::sync::atomic::Ordering::SeqCst));
        assert!(lease.try_lock().is_ok());
    }

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
                        command: Command::Status { viewed: false },
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
                            command: Command::Status { viewed: false },
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

    #[tokio::test]
    async fn sleep_during_a_pending_reconnect_refunds_the_attempt() {
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
        let _: Response = read(&mut client).await.unwrap();
        async fn settle(
            delays: &Arc<std::sync::Mutex<Vec<Duration>>>,
            expected: usize,
            client: &mut tokio::io::DuplexStream,
        ) {
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    write(
                        client,
                        &Request {
                            version: VERSION,
                            command: Command::Status { viewed: false },
                        },
                    )
                    .await
                    .unwrap();
                    let status: Response = read(client).await.unwrap();
                    if delays.lock().unwrap().len() == expected && status.state == State::Blocked {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        }
        // Wake while connected: the first attempt is scheduled.
        for round in 1..=3 {
            power.send_modify(|s| {
                s.awake = true;
                s.generation += 1;
            });
            settle(&delays, round, &mut client).await;
            // Sleep again while that attempt is still pending: it is refunded.
            power.send_modify(|s| {
                s.awake = false;
                s.generation += 1;
            });
            settle(&delays, round, &mut client).await;
        }
        let delays = delays.lock().unwrap().clone();
        assert_eq!(
            delays,
            vec![Duration::from_secs(2); 3],
            "refunded attempts restart at the base delay"
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
                command: Command::Status { viewed: false },
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
            assert!(matches!(request.command, Command::Status { .. }));
            reply(&mut server, State::Blocked, "reconnecting")
                .await
                .unwrap();
        });
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Status { viewed: false },
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
        assert!(response.capabilities.system_probes);
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
                command: Command::Recover { owner: None },
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
                command: Command::Recover { owner: None },
            },
        )
        .await
        .unwrap();
        let response: Response = read(&mut client).await.unwrap();
        assert_eq!(response.state, State::Error);
        task.await.unwrap().unwrap();
        drop(held);
    }

    async fn serve_once(
        registry: &Registry,
        lease: &Arc<Mutex<()>>,
        command: Command,
    ) -> (Option<Response>, Result<(), String>) {
        let (spawn, _spawned) = mpsc::channel(16);
        let (mut client, server) = tokio::io::duplex(4096);
        let task = tokio::spawn(super::serve(
            server,
            501,
            lease.clone(),
            tokio::sync::watch::channel(power::State::default()).1,
            registry.clone(),
            spawn,
        ));
        write(
            &mut client,
            &Request {
                version: VERSION,
                command,
            },
        )
        .await
        .unwrap();
        let response = read::<Response>(&mut client).await.ok();
        (response, task.await.unwrap())
    }

    #[tokio::test]
    async fn registered_recover_drains_actor_then_falls_back_to_journal_path() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        let (finished, completion) = tokio::sync::watch::channel(false);
        let registry: Registry = Arc::new(std::sync::Mutex::new(Some(Session {
            actor: fixture.actor.clone(),
            finished: completion,
            shutdown: fixture.shutdown.clone(),
            owner: test_owner(),
        })));
        let task = fixture.task;
        let supervisor = tokio::spawn(supervise(
            Finish {
                registry: registry.clone(),
                identity: fixture.actor.clone(),
                lease: None,
                finished,
            },
            async move { task.await.unwrap().unwrap() },
        ));
        let (response, result) = serve_once(
            &registry,
            &fixture.lease,
            Command::Recover {
                owner: Some(test_owner()),
            },
        )
        .await;
        assert_eq!(response.unwrap().state, State::Idle);
        result.unwrap();
        // Idle is acknowledged only after Stop released the guard and drained workers.
        assert!(fixture.released.load(std::sync::atomic::Ordering::SeqCst));
        assert!(fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(registry_slot(&registry).is_none());
        supervisor.await.unwrap();
        // The next Recover takes the no-session path, which needs the lease
        // before state::recover; hold it so the test never touches host state.
        let held = fixture.lease.clone().try_lock_owned().unwrap();
        let (response, result) =
            serve_once(&registry, &fixture.lease, Command::Recover { owner: None }).await;
        let response = response.unwrap();
        assert_eq!(response.state, State::Error);
        assert_eq!(response.message, "Служба уже обслуживает подключение");
        result.unwrap();
        drop(held);
    }

    #[tokio::test]
    async fn panicked_actor_is_forgotten_and_recover_status_start_still_answer() {
        let lease = Arc::new(Mutex::new(()));
        let held: Lease = Arc::new(lease.clone().lock_owned().await);
        let (actor, commands) = mpsc::channel::<Envelope>(16);
        let (finished, completion) = tokio::sync::watch::channel(false);
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let session = Session {
            actor: actor.clone(),
            finished: completion,
            shutdown,
            owner: test_owner(),
        };
        let registry: Registry = Arc::new(std::sync::Mutex::new(Some(session.clone())));
        let (trigger, fired) = oneshot::channel::<()>();
        let task = tokio::spawn(supervise(
            Finish {
                registry: registry.clone(),
                identity: actor.clone(),
                lease: Some(held),
                finished,
            },
            async move {
                let _commands = commands;
                let _ = fired.await;
                panic!("synthetic actor panic");
            },
        ));
        trigger.send(()).unwrap();
        assert!(task.await.unwrap_err().is_panic());
        assert!(registry_slot(&registry).is_none());
        assert!(*session.finished.borrow());
        assert!(lease.try_lock().is_ok());
        // Recreate the window between actor exit and registry cleanup: a dead
        // registration must still produce an answer, never an IPC EOF.
        for command in [
            Command::Recover { owner: None },
            Command::Status { viewed: false },
        ] {
            *registry_slot(&registry) = Some(session.clone());
            let held = lease.clone().try_lock_owned().unwrap();
            let (response, result) = serve_once(&registry, &lease, command).await;
            let response = response.expect("dead actor must not cause EOF");
            assert_eq!(response.state, State::Error);
            assert_eq!(response.message, "Служба уже обслуживает подключение");
            result.unwrap();
            assert!(registry_slot(&registry).is_none());
            drop(held);
        }
        // Read-only Status with a free lease reports the journal state.
        let (response, result) =
            serve_once(&registry, &lease, Command::Status { viewed: false }).await;
        assert!(matches!(
            response.unwrap().state,
            State::Idle | State::Blocked
        ));
        result.unwrap();
        // Start is admitted again: not rejected by a stale registration or lease.
        let profile = rtrust_profile::Profile::import("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n").unwrap();
        let (spawn, mut spawned) = mpsc::channel(16);
        let (mut client, server) = tokio::io::duplex(4096);
        let serving = tokio::spawn(super::serve(
            server,
            501,
            lease.clone(),
            tokio::sync::watch::channel(power::State::default()).1,
            registry.clone(),
            spawn,
        ));
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::StartFull {
                    profile: Box::new(profile),
                    dns: "192.0.2.53".parse().unwrap(),
                    fallbacks: vec![],
                },
            },
        )
        .await
        .unwrap();
        let admitted = spawned.recv().await.unwrap();
        assert!(registry_slot(&registry).is_some());
        assert!(lease.try_lock().is_err());
        // Dropping the unpolled actor still runs its cleanup.
        drop(admitted);
        assert!(serving.await.unwrap().is_err());
        assert!(registry_slot(&registry).is_none());
        assert!(lease.try_lock().is_ok());
    }

    #[tokio::test]
    async fn recover_of_live_session_requires_its_owner() {
        let fixture = test_actor().await;
        fixture.initial.await.unwrap();
        let (finished, completion) = tokio::sync::watch::channel(false);
        let registry: Registry = Arc::new(std::sync::Mutex::new(Some(Session {
            actor: fixture.actor.clone(),
            finished: completion,
            shutdown: fixture.shutdown.clone(),
            owner: test_owner(),
        })));
        let task = fixture.task;
        let supervisor = tokio::spawn(supervise(
            Finish {
                registry: registry.clone(),
                identity: fixture.actor.clone(),
                lease: None,
                finished,
            },
            async move { task.await.unwrap().unwrap() },
        ));
        let canary = test_owner().to_hex();
        let mut wrong = [0x3c; rtrust_control::owner::LEN];
        wrong[7] ^= 0x80;
        let presented = Owner::from_bytes(wrong);
        let presented_hex = presented.to_hex();
        for command in [
            Command::Recover { owner: None },
            Command::Recover {
                owner: Some(presented),
            },
            // A new connection cannot Stop: the live session holds the lease.
            Command::Stop,
        ] {
            let stop = matches!(command, Command::Stop);
            let (response, result) = serve_once(&registry, &fixture.lease, command).await;
            let response = response.expect("rejection must be answered");
            result.unwrap();
            if stop {
                assert_eq!(response.state, State::Error);
            } else {
                assert_eq!(response.state, State::Blocked);
                assert_eq!(response.message, NOT_OWNER);
            }
            assert!(response.owner.is_none());
            let wire = serde_json::to_string(&response).unwrap();
            assert!(!wire.contains(canary.as_str()));
            assert!(!wire.contains(presented_hex.as_str()));
            assert!(!format!("{response:?}").contains(canary.as_str()));
            // Session, workers, lease and guard all stay.
            assert!(registry_slot(&registry).is_some());
            assert!(!fixture.released.load(std::sync::atomic::Ordering::SeqCst));
            assert!(!fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
            assert!(fixture.lease.try_lock().is_err());
            assert_eq!(
                ask(&fixture.actor, Command::Status { viewed: false })
                    .await
                    .unwrap()
                    .state,
                State::Connected
            );
        }
        // Read-only Status from a new connection needs no owner.
        let (response, result) =
            serve_once(&registry, &fixture.lease, Command::Status { viewed: false }).await;
        let response = response.unwrap();
        assert_eq!(response.state, State::Connected);
        assert!(response.owner.is_none());
        result.unwrap();
        // The owner stops the session; Idle only after the guard is released.
        let (response, result) = serve_once(
            &registry,
            &fixture.lease,
            Command::Recover {
                owner: Some(test_owner()),
            },
        )
        .await;
        assert_eq!(response.unwrap().state, State::Idle);
        result.unwrap();
        assert!(fixture.released.load(std::sync::atomic::Ordering::SeqCst));
        assert!(fixture.dropped.load(std::sync::atomic::Ordering::SeqCst));
        assert!(registry_slot(&registry).is_none());
        supervisor.await.unwrap();
        // With no live session, Recover reaches the journal path without an
        // owner (stopped at the lease here so host state is never touched).
        let held = fixture.lease.clone().try_lock_owned().unwrap();
        let (response, result) =
            serve_once(&registry, &fixture.lease, Command::Recover { owner: None }).await;
        assert_eq!(
            response.unwrap().message,
            "Служба уже обслуживает подключение"
        );
        result.unwrap();
        drop(held);
    }

    #[tokio::test]
    async fn dead_actor_recover_ignores_a_wrong_owner_and_uses_the_journal_path() {
        let lease = Arc::new(Mutex::new(()));
        let (actor, commands) = mpsc::channel::<Envelope>(16);
        drop(commands);
        let (finished, completion) = tokio::sync::watch::channel(false);
        finished.send_replace(true);
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let registry: Registry = Arc::new(std::sync::Mutex::new(Some(Session {
            actor,
            finished: completion,
            shutdown,
            owner: test_owner(),
        })));
        let held = lease.clone().try_lock_owned().unwrap();
        let (response, result) = serve_once(
            &registry,
            &lease,
            Command::Recover {
                owner: Some(Owner::from_bytes([1; rtrust_control::owner::LEN])),
            },
        )
        .await;
        assert_eq!(
            response.unwrap().message,
            "Служба уже обслуживает подключение"
        );
        result.unwrap();
        assert!(registry_slot(&registry).is_none());
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn lease_probes_run_only_while_a_user_interface_views_the_session() {
        use rtrust_control::observations::{Mode, Observation, Outcome, SystemProbe, now_ms};
        let runs = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = runs.clone();
        let fake = Probe::Fake(Arc::new(move || {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            SystemProbe {
                transport_proven_at: None,
                dns: Observation::system(Outcome::Passed, Mode::Full, now_ms()),
                guard: Observation::system(Outcome::Passed, Mode::Full, now_ms()),
            }
        }));
        let (_power, receiver) = tokio::sync::watch::channel(power::State::default());
        let (actor, commands) = mpsc::channel(16);
        let (_shutdown_signal, shutdown_events) = tokio::sync::watch::channel(false);
        let (initial, response) = oneshot::channel();
        let supervisor = tokio::spawn(super::connected(
            Control {
                commands,
                initial: Some(initial),
                shutdown: shutdown_events,
                probe: Some(fake),
            },
            Workers {
                tunnel: Some(tokio::spawn(std::future::pending())),
                reconnect: None,
            },
            true,
            receiver,
            failover().await,
            |workers, _, _| workers.reconnect = Some(tokio::spawn(std::future::pending())),
            // A real, slow release (as on a loaded host) keeps Stop waiting
            // on the cleanup thread rather than finishing before it parks.
            || {
                std::thread::sleep(Duration::from_millis(20));
                Ok(())
            },
        ));
        assert_eq!(response.await.unwrap().state, State::Connected);
        let count = || runs.load(std::sync::atomic::Ordering::SeqCst);
        let status = |viewed| ask(&actor, Command::Status { viewed });
        // A minute of plain keepalives (no user interface): no run at all,
        // and nothing claims DNS or guard evidence.
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let response = status(false).await.unwrap();
            assert_eq!(response.state, State::Connected);
            assert_ne!(response.observations.dns.outcome, Outcome::Passed);
            assert_ne!(response.observations.guard.outcome, Outcome::Passed);
        }
        assert_eq!(count(), 0, "keepalives alone must not probe");
        // A viewed keepalive wakes the idle runner after the settle; the
        // Status itself never probes synchronously.
        status(true).await.unwrap();
        assert_eq!(count(), 0);
        tokio::time::sleep(Duration::from_secs(3)).await;
        let response = status(true).await.unwrap();
        assert_eq!(count(), 1);
        assert_eq!(response.observations.dns.outcome, Outcome::Passed);
        assert_eq!(response.observations.guard.outcome, Outcome::Passed);
        // The view ends: the next interval tick falls outside the window.
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            status(false).await.unwrap();
        }
        assert_eq!(count(), 1, "probes stop once nobody views");
        // A stream of viewed keepalives probes at most once per interval.
        let start = tokio::time::Instant::now();
        while start.elapsed() < Duration::from_secs(61) {
            status(true).await.unwrap();
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let viewed_runs = count() - 1;
        assert!(
            (4..=5).contains(&viewed_runs),
            "one run per {} ms at most: {viewed_runs}",
            rtrust_control::observations::PROBE_INTERVAL_MS
        );
        // Stop joins `release` on a std::thread the paused clock cannot see:
        // an idle runtime would auto-advance past the 45 s bound instantly.
        tokio::time::resume();
        assert_eq!(ask(&actor, Command::Stop).await.unwrap().state, State::Idle);
        supervisor.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_status_from_another_connection_cannot_mark_a_view() {
        let lease = Arc::new(Mutex::new(()));
        let (actor, mut commands) = mpsc::channel::<Envelope>(16);
        let (_finished, completion) = tokio::sync::watch::channel(false);
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let registry: Registry = Arc::new(std::sync::Mutex::new(Some(Session {
            actor,
            finished: completion,
            shutdown,
            owner: test_owner(),
        })));
        let observer = tokio::spawn(async move {
            let request = commands.recv().await.unwrap();
            let forwarded = matches!(request.command, Command::Status { viewed: false });
            let _ = request
                .response
                .send(Response::new(State::Connected, "observed"));
            forwarded
        });
        let (response, result) =
            serve_once(&registry, &lease, Command::Status { viewed: true }).await;
        assert_eq!(response.unwrap().state, State::Connected);
        result.unwrap();
        assert!(
            observer.await.unwrap(),
            "only the lease connection may report a view"
        );
    }

    #[test]
    fn owner_is_returned_only_with_a_connected_start_reply() {
        let connected = admitted_reply(Response::new(State::Connected, "ok"), test_owner());
        assert!(connected.owner.as_ref().unwrap().matches(&test_owner()));
        for state in [State::Error, State::Blocked, State::Idle] {
            assert!(
                admitted_reply(Response::new(state, "no"), test_owner())
                    .owner
                    .is_none()
            );
        }
        let first = new_owner().unwrap();
        assert!(!first.matches(&new_owner().unwrap()));
        assert!(!format!("{first:?}").contains(first.to_hex().as_str()));
    }
}

/// Independent tester coverage for issue #99 (dataplane_summary timer,
/// criterion 7). `events::record` is a no-op without root, so the timer is
/// checked for not disturbing the supervisor, and the line format separately.
#[cfg(test)]
mod tester_summary_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn failover() -> crate::failover::Failover {
        let profile = rtrust_profile::Profile::import("hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='synthetic'\n").unwrap();
        crate::failover::Failover::pin(profile, vec![], crate::failover::Pin::Ipv4)
            .await
            .unwrap()
    }
    /// Same harness as `tests::connected` (private there): a supervisor
    /// bridged to a duplex stream, with no probe plan and no shutdown signal.
    async fn connected(
        mut stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
        workers: Workers,
        power: tokio::sync::watch::Receiver<power::State>,
        failover: crate::failover::Failover,
        retry: impl FnMut(&mut Workers, &rtrust_profile::Profile, &mut rtrust_control::recovery::Budget)
        + Send
        + 'static,
    ) -> Result<(), String> {
        let (actor, commands) = mpsc::channel(16);
        let (_shutdown_signal, shutdown_events) = tokio::sync::watch::channel(false);
        let (initial, response) = oneshot::channel();
        let supervisor = tokio::spawn(super::connected(
            Control {
                commands,
                initial: Some(initial),
                shutdown: shutdown_events,
                probe: None,
            },
            workers,
            false,
            power,
            failover,
            retry,
            || Ok(()),
        ));
        write_response(&mut stream, &response.await.unwrap()).await?;
        let result = bridge(stream, actor, None).await;
        if result.is_err() {
            supervisor.abort();
        }
        let _ = supervisor.await;
        result
    }

    #[test]
    fn summary_is_scheduled_thirty_seconds_ahead_and_renders_numbers_only() {
        let before = tokio::time::Instant::now();
        let (due, after, base) = summary_after("connect");
        assert_eq!(after, "connect");
        assert!(due - before >= SUMMARY_DELAY);
        assert!(due - before <= SUMMARY_DELAY + Duration::from_secs(1));
        // Counters are process-wide: parallel tests may advance them between
        // the two snapshots, so the baseline is a lower bound, never equal.
        let now = crate::stats::snapshot();
        let delta = now.since(&base);
        assert!(delta.syn_accepted <= now.syn_accepted && delta.udp_evicted <= now.udp_evicted);
        let line = format!(
            "dataplane_summary after={after} window_s={} {}",
            SUMMARY_DELAY.as_secs(),
            crate::stats::snapshot().since(&base).render()
        );
        assert!(line.starts_with("dataplane_summary after=connect window_s=30 syn_accepted="));
        // Every token after the event name is key=number; no addresses,
        // hosts, ports or profile material can appear.
        for token in line.split(' ').skip(1) {
            let (key, value) = token.split_once('=').expect("key=value token");
            assert!(
                key.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{key}"
            );
            assert!(
                key == "after" && value == "connect" || value.chars().all(|c| c.is_ascii_digit()),
                "{token}"
            );
        }
        assert!(!line.contains('.') && !line.contains(':'));
    }

    /// The 30 s summary timer fires inside the supervisor loop without
    /// blocking Status, and a power event followed by Stop still works
    /// whether the timer has fired or was cancelled.
    #[tokio::test(start_paused = true)]
    async fn summary_timer_does_not_block_status_power_or_stop() {
        let (power, receiver) = tokio::sync::watch::channel(power::State::default());
        let (mut client, server) = tokio::io::duplex(4096);
        let supervisor = tokio::spawn(connected(
            server,
            Workers {
                tunnel: Some(tokio::spawn(std::future::pending())),
                reconnect: None,
            },
            receiver,
            failover().await,
            |workers, _, _| {
                workers.reconnect = Some(tokio::spawn(std::future::pending()));
            },
        ));
        let initial: Response = read(&mut client).await.unwrap();
        assert_eq!(initial.state, State::Connected);
        // Past the summary deadline: the timer branch runs and disarms.
        tokio::time::advance(SUMMARY_DELAY + Duration::from_secs(1)).await;
        for _ in 0..3 {
            write(
                &mut client,
                &Request {
                    version: VERSION,
                    command: Command::Status { viewed: false },
                },
            )
            .await
            .unwrap();
            let status: Response = tokio::time::timeout(Duration::from_secs(5), read(&mut client))
                .await
                .expect("Status answered after the summary timer")
                .unwrap();
            assert_eq!(status.state, State::Connected);
        }
        // Sleep cancels any pending summary; Stop must still be served.
        power.send_modify(|s| {
            s.awake = false;
            s.generation += 1;
        });
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::advance(SUMMARY_DELAY).await;
        write(
            &mut client,
            &Request {
                version: VERSION,
                command: Command::Stop,
            },
        )
        .await
        .unwrap();
        let stopped: Response = tokio::time::timeout(Duration::from_secs(5), read(&mut client))
            .await
            .expect("Stop answered")
            .unwrap();
        assert_eq!(stopped.state, State::Idle);
        client.shutdown().await.unwrap();
        supervisor.await.unwrap().unwrap();
    }
}
