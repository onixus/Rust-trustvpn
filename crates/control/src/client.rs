#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::net::UnixStream;
#[cfg(any(target_os = "linux", target_os = "macos"))]
type Pipe = UnixStream;
#[cfg(target_os = "windows")]
type Pipe = tokio::net::windows::named_pipe::NamedPipeClient;
#[cfg(target_os = "windows")]
async fn socket() -> Result<Pipe, String> {
    super::windows::connect()
}
use super::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

struct Inner {
    stop: mpsc::Sender<oneshot::Sender<Result<(), String>>>,
    status: Arc<Mutex<Response>>,
    /// Monotonic time a user interface last showed this session's status.
    viewed_at: Arc<Mutex<Option<tokio::time::Instant>>>,
    owner: Option<owner::Owner>,
    abort: tokio::task::AbortHandle,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.abort.abort();
    }
}
#[derive(Clone)]
pub struct Client(Arc<Inner>);
#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn socket() -> Result<UnixStream, String> {
    #[cfg(target_os = "linux")]
    if std::env::var_os("FLATPAK_ID").is_some() {
        return super::broker::connect().await;
    }
    let stream = UnixStream::connect(SOCKET)
        .await
        .map_err(|_| "Служба R-TrustTunnel недоступна. Установите и запустите системную службу.")?;
    if stream
        .peer_cred()
        .map_err(|_| "IPC identity unavailable")?
        .uid()
        != 0
    {
        return Err("IPC server must run as root".into());
    }
    Ok(stream)
}
async fn exchange(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    command: Command,
    seconds: u64,
) -> Result<Response, String> {
    #[cfg(target_os = "macos")]
    let mut suspend = super::suspend::Watch::default();
    exchange_with_resume(stream, command, Duration::from_secs(seconds), || {
        #[cfg(target_os = "macos")]
        {
            suspend.resumed()
        }
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
    })
    .await
}
async fn exchange_with_resume(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    command: Command,
    deadline: Duration,
    mut resumed: impl FnMut() -> bool,
) -> Result<Response, String> {
    let operation = async {
        write(
            stream,
            &Request {
                version: VERSION,
                command,
            },
        )
        .await?;
        let response: Response = read(stream).await?;
        if response.version != VERSION
            || response.capabilities.observations_schema != observations::SCHEMA
            || response.observations.schema != observations::SCHEMA
            || response.observations.events.len() > observations::MAX_EVENTS
        {
            return Err("IPC version mismatch".into());
        }
        Ok(response)
    };
    tokio::pin!(operation);
    let mut extended = false;
    loop {
        let result = tokio::time::timeout(deadline, &mut operation).await;
        if result.is_err() && !extended && resumed() {
            extended = true;
            // Continue the same framed exchange: resending Status or losing a
            // partial response would desynchronize IPC and abandon the guard.
            continue;
        }
        return result.map_err(|_| "Служба не отвечает")?;
    }
}
// Negotiate on a separate authenticated connection before sending credentials or mutating.
async fn negotiate() -> Result<Capabilities, String> {
    let mut pipe = socket().await?;
    let response = exchange(&mut pipe, Command::Capabilities, 5).await?;
    if !response.capabilities.lifecycle_observations || response.state != State::Idle {
        return Err("IPC capabilities unavailable; update the UI and service together".into());
    }
    Ok(response.capabilities)
}
fn current_endpoint_result(
    result: &endpoint::Result,
    captured: &Response,
    current: &Response,
) -> bool {
    captured.endpoint_probe_token == Some(result.token)
        && current.endpoint_probe_token == captured.endpoint_probe_token
        && result.active_profile == captured.active_profile
        && current.active_profile == captured.active_profile
        && matches!(current.state, State::Connected)
}
fn validate_fallbacks(fallbacks: &[rtrust_profile::Profile]) -> Result<(), String> {
    if fallbacks.len() > MAX_FALLBACKS {
        return Err(format!("Не больше {MAX_FALLBACKS} резервных профилей"));
    }
    Ok(())
}
/// Holding this connection reserves an idle service for installer maintenance.
pub struct MaintenancePermit {
    _pipe: Pipe,
}
impl Client {
    pub async fn always_on(mut command: Command) -> Result<Response, String> {
        if !matches!(
            command,
            Command::EnableAlwaysOn { .. }
                | Command::EnableRecovery { .. }
                | Command::DisableAlwaysOn
                | Command::AlwaysOnStatus { .. }
        ) {
            return Err("Invalid always-on operation".into());
        }
        let capabilities = negotiate().await?;
        if matches!(command, Command::EnableRecovery { .. }) && !capabilities.automatic_recovery {
            return Err(
                "Служба не поддерживает автоматическое восстановление на этой платформе".into(),
            );
        }
        if let Command::EnableAlwaysOn { generation, .. }
        | Command::EnableRecovery { generation, .. } = &mut command
        {
            // Receive the fence before opening the mutation connection. An aborted
            // caller cannot leave a complete old Enable carrying a post-Disable fence.
            let mut status_pipe = socket().await?;
            // The fence read is not a view: it never enables probes.
            let status = exchange(
                &mut status_pipe,
                Command::AlwaysOnStatus { viewed: false },
                5,
            )
            .await?;
            *generation = Some(status.always_on_generation.ok_or(
                "Always-on cancellation fence unavailable; update UI and service together",
            )?);
        }
        let mut pipe = socket().await?;
        exchange(&mut pipe, command, 60).await
    }

    /// Check only the profile currently owned by this authenticated service lease.
    /// Dropping this future closes its independent IPC channel and cancels the check.
    pub async fn probe_endpoint(&self) -> Result<endpoint::Result, String> {
        let status = self.status();
        if !status.capabilities.endpoint_probes {
            return Err(
                "Независимая проверка endpoint службой не поддерживается на этой платформе".into(),
            );
        }
        let token = status
            .endpoint_probe_token
            .ok_or("Активный профиль службы не подтверждён")?;
        let mut pipe = socket().await?;
        let response = exchange(&mut pipe, Command::ProbeEndpoint { token }, 15).await?;
        let result = response
            .endpoint_probe
            .ok_or("Служба не вернула результат проверки endpoint")?;
        let current = self.status();
        if !current_endpoint_result(&result, &status, &current) {
            return Err("Устаревший результат проверки endpoint".into());
        }
        Ok(result)
    }

    pub async fn prepare_update() -> Result<MaintenancePermit, String> {
        negotiate().await?;
        let mut stream = socket().await?;
        let response = exchange(&mut stream, Command::PrepareUpdate, 5).await?;
        if response.state != State::Idle {
            return Err(response.message);
        }
        Ok(MaintenancePermit { _pipe: stream })
    }

    pub async fn start(
        profile: rtrust_profile::Profile,
        fallbacks: Vec<rtrust_profile::Profile>,
        selection: Selection,
        dns: Option<std::net::Ipv4Addr>,
    ) -> Result<Self, String> {
        selection.validate()?;
        validate_fallbacks(&fallbacks)?;
        if let Some(dns) = dns {
            validate_dns(dns)?;
        }
        Self::start_command(Command::Start {
            profile: Box::new(profile),
            networks: selection.include,
            exclude: selection.exclude,
            exclude_lan: selection.exclude_lan,
            dns,
            fallbacks,
        })
        .await
    }
    pub async fn start_full(
        profile: rtrust_profile::Profile,
        fallbacks: Vec<rtrust_profile::Profile>,
        dns: std::net::Ipv4Addr,
    ) -> Result<Self, String> {
        validate_dns(dns)?;
        validate_fallbacks(&fallbacks)?;
        Self::start_command(Command::StartFull {
            profile: Box::new(profile),
            dns,
            fallbacks,
        })
        .await
    }
    pub async fn start_managed(
        profile: rtrust_profile::Profile,
        fallbacks: Vec<rtrust_profile::Profile>,
        selection: Option<Selection>,
        dns: std::net::Ipv4Addr,
        lease: crate::freshness::Lease,
    ) -> Result<Self, String> {
        validate_fallbacks(&fallbacks)?;
        validate_dns(dns)?;
        lease.validate_at(crate::freshness::now())?;
        let command = match selection {
            Some(selection) => {
                selection.validate()?;
                Command::Start {
                    profile: Box::new(profile),
                    networks: selection.include,
                    exclude: selection.exclude,
                    exclude_lan: selection.exclude_lan,
                    dns: Some(dns),
                    fallbacks,
                }
            }
            None => Command::StartFull {
                profile: Box::new(profile),
                dns,
                fallbacks,
            },
        };
        Self::start_command(Command::StartLeased {
            lease,
            command: Box::new(command),
        })
        .await
    }
    async fn start_command(command: Command) -> Result<Self, String> {
        let capabilities = negotiate().await?;
        if matches!(&command, Command::StartLeased { .. }) && !capabilities.managed_access_freshness
        {
            return Err("Service freshness capability required; update the service".into());
        }
        let inspected = match &command {
            Command::StartLeased { command, .. } => command.as_ref(),
            other => other,
        };
        if let Command::Start { fallbacks, .. } | Command::StartFull { fallbacks, .. } = inspected
            && !fallbacks.is_empty()
            && !capabilities.failover
        {
            return Err("Служба не поддерживает резервные профили; обновите службу".into());
        }
        let mut stream = socket().await?;
        let response = exchange(&mut stream, command, 45).await?;
        if response.state != State::Connected {
            return Err(response.message);
        }
        Ok(Self::poll(stream, response))
    }
    /// Keep the admitted session's connection as the service lease: poll
    /// Status every 2 s until Stop. Each poll reports whether a user
    /// interface marked the session viewed within `CLIENT_VIEW_MS`.
    fn poll(
        mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
        mut response: Response,
    ) -> Self {
        // Kept apart from the shared status so snapshots never carry it.
        let owner = response.owner.take();
        let status = Arc::new(Mutex::new(response));
        let shared = status.clone();
        let viewed_at = Arc::new(Mutex::new(None::<tokio::time::Instant>));
        let viewed_shared = viewed_at.clone();
        let (stop, mut receiver) = mpsc::channel::<oneshot::Sender<Result<(), String>>>(1);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    reply = receiver.recv() => {
                        if let Some(reply) = reply {
                            let result = exchange(&mut stream, Command::Stop, 45).await.and_then(|r| {
                                let result = if r.state == State::Idle { Ok(()) } else { Err(r.message.clone()) };
                                *shared.lock().unwrap() = r;
                                result
                            });
                            if result.is_err() {
                                let mut r = shared.lock().unwrap();
                                r.state = State::Blocked;
                                r.observations.invalidate(observations::Reason::ControlLost, observations::EventKind::ControlLost, observations::now_ms());
                            }
                            let _ = reply.send(result);
                        }
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {
                        let viewed = recently_viewed(*viewed_shared.lock().unwrap(), tokio::time::Instant::now());
                        // Darwin's root service can resume later than the GUI.
                        // Keep the same framed exchange alive through that gap.
                        let seconds = if cfg!(target_os = "macos") { 30 } else { 5 };
                        match exchange(&mut stream, Command::Status { viewed }, seconds).await {
                            Ok(response) => *shared.lock().unwrap() = response,
                            Err(_) => {
                                let mut response = shared.lock().unwrap();
                                response.state = State::Blocked;
                                response.message = "Связь со службой потеряна; состояние защиты не подтверждено".into();
                                response.observations.invalidate(observations::Reason::ControlLost, observations::EventKind::ControlLost, observations::now_ms());
                                break;
                            }
                        }
                    }
                }
            }
        });
        Self(Arc::new(Inner {
            stop,
            status,
            viewed_at,
            owner,
            abort: task.abort_handle(),
        }))
    }
    /// A user interface is showing this session's status now. The next
    /// keepalives (within `CLIENT_VIEW_MS`) ask the service to keep its
    /// system probes running. Status reads alone never mark a view.
    pub fn mark_viewed(&self) {
        *self.0.viewed_at.lock().unwrap() = Some(tokio::time::Instant::now());
    }
    pub fn status(&self) -> Response {
        let mut response = self.0.status.lock().unwrap().clone();
        response.owner = None;
        response.observations.expire(observations::now_ms());
        response
    }
    pub async fn close(self) -> Result<(), String> {
        let (tx, rx) = oneshot::channel();
        self.0
            .stop
            .send(tx)
            .await
            .map_err(|_| "Связь со службой потеряна; используйте сброс блокировки")?;
        rx.await.map_err(|_| "Отключение службы не подтверждено")?
    }
    /// Capability to Recover this session from a new connection after the
    /// GUI restarts. Persist it only in the OS credential store.
    pub fn owner(&self) -> Option<owner::Owner> {
        self.0.owner.clone()
    }
    /// A live session is stopped only with its `owner`; without a live
    /// session the service releases a retained guard from its journal.
    pub async fn recover(owner: Option<owner::Owner>) -> Result<(), String> {
        negotiate().await?;
        let mut stream = socket().await?;
        let response = exchange(&mut stream, Command::Recover { owner }, 45).await?;
        if response.state == State::Idle {
            Ok(())
        } else {
            Err(response.message)
        }
    }
}

fn recently_viewed(at: Option<tokio::time::Instant>, now: tokio::time::Instant) -> bool {
    at.is_some_and(|at| {
        now.saturating_duration_since(at) < Duration::from_millis(observations::CLIENT_VIEW_MS)
    })
}

#[cfg(test)]
mod resume_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn wake_timeout_keeps_partial_response_and_sends_request_once() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let (partial, ready) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let task = tokio::spawn(async move {
            let request: Request = read(&mut server).await.unwrap();
            assert!(matches!(request.command, Command::Status { viewed: false }));
            let response = Response::new(State::Connected, "restored");
            let (mut encoder, mut bytes) = tokio::io::duplex(4096);
            write(&mut encoder, &response).await.unwrap();
            drop(encoder);
            let mut frame = Vec::new();
            bytes.read_to_end(&mut frame).await.unwrap();
            server.write_all(&frame[..6]).await.unwrap();
            partial.send(()).unwrap();
            resumed.await.unwrap();
            server.write_all(&frame[6..]).await.unwrap();
            let mut duplicate = [0];
            assert_eq!(server.read(&mut duplicate).await.unwrap(), 0);
        });
        let mut resume = Some(resume);
        let result = exchange_with_resume(
            &mut client,
            Command::Status { viewed: false },
            Duration::from_millis(50),
            || {
                resume.take().unwrap().send(()).unwrap();
                true
            },
        )
        .await
        .unwrap();
        ready.await.unwrap();
        assert_eq!(result.state, State::Connected);
        assert_eq!(result.message, "restored");
        drop(client);
        task.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_reports_viewed_only_within_the_client_window() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let (seen_tx, mut seen) = mpsc::unbounded_channel();
        let service = tokio::spawn(async move {
            while let Ok(request) = read::<Request>(&mut server).await {
                let Command::Status { viewed } = request.command else {
                    panic!("keepalive must be Status");
                };
                seen_tx.send(viewed).unwrap();
                write(&mut server, &Response::new(State::Connected, "up"))
                    .await
                    .unwrap();
            }
        });
        let session = Client::poll(client, Response::new(State::Connected, "up"));
        // Service-side readers (diagnostics, endpoint checks) are not views.
        let _ = session.status();
        assert!(!seen.recv().await.unwrap());
        let _ = session.status();
        assert!(!seen.recv().await.unwrap());
        session.mark_viewed();
        assert!(seen.recv().await.unwrap(), "2 s after the mark");
        assert!(seen.recv().await.unwrap(), "4 s after the mark");
        assert!(!seen.recv().await.unwrap(), "6 s: the client window passed");
        assert!(!seen.recv().await.unwrap());
        session.mark_viewed();
        assert!(seen.recv().await.unwrap());
        drop(session);
        service.await.unwrap();
    }

    #[test]
    fn view_window_is_bounded_and_monotonic() {
        let now = tokio::time::Instant::now();
        let window = Duration::from_millis(observations::CLIENT_VIEW_MS);
        assert!(!recently_viewed(None, now));
        assert!(recently_viewed(Some(now), now));
        assert!(recently_viewed(
            Some(now),
            now + window - Duration::from_millis(1)
        ));
        assert!(!recently_viewed(Some(now), now + window));
        // A mark "from the future" (clock reordering) counts as now.
        assert!(recently_viewed(Some(now + window * 4), now));
    }

    #[tokio::test]
    async fn repeated_resume_cannot_extend_a_dead_service_forever() {
        let (mut client, _server) = tokio::io::duplex(4096);
        let result = tokio::time::timeout(
            Duration::from_millis(200),
            exchange_with_resume(
                &mut client,
                Command::Status { viewed: false },
                Duration::from_millis(10),
                || true,
            ),
        )
        .await
        .expect("resume extension must be bounded");
        assert_eq!(result.unwrap_err(), "Служба не отвечает");
    }

    #[tokio::test]
    async fn unresponsive_service_still_times_out_without_resume() {
        let (mut client, _server) = tokio::io::duplex(4096);
        let error = exchange_with_resume(
            &mut client,
            Command::Status { viewed: false },
            Duration::from_millis(10),
            || false,
        )
        .await
        .unwrap_err();
        assert_eq!(error, "Служба не отвечает");
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn incompatible_schema_and_old_response_are_rejected() {
        for schema in [0, observations::SCHEMA + 1] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let task = tokio::spawn(async move {
                let request: Request = read(&mut server).await.unwrap();
                assert!(matches!(request.command, Command::Capabilities));
                let mut response = Response::new(State::Idle, "caps");
                response.capabilities.observations_schema = schema;
                write(&mut server, &response).await.unwrap();
            });
            assert!(
                exchange(&mut client, Command::Capabilities, 1)
                    .await
                    .is_err()
            );
            task.await.unwrap();
        }
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            let _: Request = read(&mut server).await.unwrap();
            write(
                &mut server,
                &serde_json::json!({"version":1,"state":"Idle","message":"old"}),
            )
            .await
            .unwrap();
        });
        assert!(
            exchange(&mut client, Command::Capabilities, 1)
                .await
                .is_err()
        );
        task.await.unwrap();
    }
    #[test]
    fn valid_backup_cooldown_is_a_current_reply_instead_of_a_stale_session() {
        let token = endpoint::Token {
            lease: [7; 16],
            generation: 3,
        };
        let mut status = Response::new(State::Connected, "backup active");
        status.active_profile = Some(2);
        status.endpoint_probe_token = Some(token);
        let mut result = endpoint::Result::unknown(
            token,
            endpoint::Outcome::RateLimited,
            endpoint::Reason::Cooldown,
        );
        result.active_profile = Some(2);
        assert!(current_endpoint_result(&result, &status, &status));
        result.active_profile = None;
        assert!(!current_endpoint_result(&result, &status, &status));
        result.active_profile = Some(2);
        let mut changed = status.clone();
        changed.active_profile = Some(1);
        assert!(!current_endpoint_result(&result, &status, &changed));
        changed = status.clone();
        changed.endpoint_probe_token.as_mut().unwrap().generation += 1;
        assert!(!current_endpoint_result(&result, &status, &changed));
    }
    #[tokio::test]
    async fn ipc_three_service_is_rejected_during_capability_negotiation() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(async move {
            let request: Request = read(&mut server).await.unwrap();
            assert!(matches!(request.command, Command::Capabilities));
            let mut response = Response::new(State::Idle, "old service");
            response.version = 3;
            write(&mut server, &response).await.unwrap();
        });
        assert!(
            exchange(&mut client, Command::Capabilities, 1)
                .await
                .is_err()
        );
        task.await.unwrap();
    }
    #[tokio::test]
    async fn response_timeout_is_bounded() {
        let (mut client, _server) = UnixStream::pair().unwrap();
        assert!(
            exchange(&mut client, Command::Capabilities, 0)
                .await
                .is_err()
        );
    }
}
