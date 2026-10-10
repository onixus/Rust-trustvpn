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
async fn exchange(stream: &mut Pipe, command: Command, seconds: u64) -> Result<Response, String> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
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
    })
    .await
    .map_err(|_| "Служба не отвечает")?
}
// Negotiate on a separate authenticated connection before sending credentials or mutating.
async fn negotiate() -> Result<(), String> {
    let mut pipe = socket().await?;
    let response = exchange(&mut pipe, Command::Capabilities, 5).await?;
    if !response.capabilities.lifecycle_observations || response.state != State::Idle {
        return Err("IPC capabilities unavailable; update the UI and service together".into());
    }
    Ok(())
}
/// Holding this connection reserves an idle service for installer maintenance.
pub struct MaintenancePermit {
    _pipe: Pipe,
}
impl Client {
    pub async fn always_on(command: Command) -> Result<Response, String> {
        if !matches!(
            command,
            Command::EnableAlwaysOn { .. } | Command::DisableAlwaysOn | Command::AlwaysOnStatus
        ) {
            return Err("Invalid always-on operation".into());
        }
        negotiate().await?;
        let mut pipe = socket().await?;
        exchange(&mut pipe, command, 60).await
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
        selection: Selection,
        dns: Option<std::net::Ipv4Addr>,
    ) -> Result<Self, String> {
        selection.validate()?;
        if let Some(dns) = dns {
            validate_dns(dns)?;
        }
        Self::start_command(Command::Start {
            profile: Box::new(profile),
            networks: selection.include,
            exclude: selection.exclude,
            exclude_lan: selection.exclude_lan,
            dns,
        })
        .await
    }
    pub async fn start_full(
        profile: rtrust_profile::Profile,
        dns: std::net::Ipv4Addr,
    ) -> Result<Self, String> {
        validate_dns(dns)?;
        Self::start_command(Command::StartFull {
            profile: Box::new(profile),
            dns,
        })
        .await
    }
    async fn start_command(command: Command) -> Result<Self, String> {
        negotiate().await?;
        let mut stream = socket().await?;
        let response = exchange(&mut stream, command, 45).await?;
        if response.state != State::Connected {
            return Err(response.message);
        }
        let status = Arc::new(Mutex::new(response));
        let shared = status.clone();
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
                        match exchange(&mut stream, Command::Status, 5).await {
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
        Ok(Self(Arc::new(Inner {
            stop,
            status,
            abort: task.abort_handle(),
        })))
    }
    pub fn status(&self) -> Response {
        let mut response = self.0.status.lock().unwrap().clone();
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
    pub async fn recover() -> Result<(), String> {
        negotiate().await?;
        let mut stream = socket().await?;
        let response = exchange(&mut stream, Command::Recover, 45).await?;
        if response.state == State::Idle {
            Ok(())
        } else {
            Err(response.message)
        }
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
