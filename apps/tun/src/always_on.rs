//! Own the boot VPN independently of GUI IPC. Platform guards bracket every restart.
use crate::boot_policy::{self, Policy};
use rtrust_control::{Command, Request, Response, State, VERSION, read, write};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::DuplexStream,
    sync::{Mutex, mpsc, oneshot, watch},
};
pub struct Supervisor {
    owner: String,
    enabled: AtomicBool,
    state: watch::Receiver<Response>,
    events: mpsc::Sender<(Command, oneshot::Sender<Response>)>,
}
impl Supervisor {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    pub fn state(&self) -> Response {
        let mut response = self.state.borrow().clone();
        response.always_on = Some(self.enabled());
        response
    }
    pub async fn command(&self, command: Command) -> Response {
        let (tx, rx) = oneshot::channel();
        if self.events.send((command, tx)).await.is_err() {
            return Response::new(State::Blocked, "Always-on supervisor unavailable");
        }
        rx.await
            .unwrap_or_else(|_| Response::new(State::Blocked, "Always-on operation failed"))
    }
    pub fn start(owner: String, lease: Arc<Mutex<()>>) -> Result<Arc<Self>, String> {
        let enabled = boot_policy::exists()? || platform_active()?;
        let policy = boot_policy::load(&owner);
        if enabled {
            platform_guard(policy.as_ref().ok().and_then(|p| p.as_ref()))?;
        }
        let initial = Response::new(
            if enabled { State::Blocked } else { State::Idle },
            if enabled && !matches!(policy, Ok(Some(_))) {
                "Always-on: политика отсутствует или повреждена; сеть защищена. Выключите always-on для восстановления"
            } else if enabled {
                "Always-on запускается; сеть защищена"
            } else {
                "Always-on выключен"
            },
        );
        let (state_tx, state) = watch::channel(initial);
        let (events, mut rx) = mpsc::channel::<(Command, oneshot::Sender<Response>)>(8);
        let this = Arc::new(Self {
            owner,
            enabled: AtomicBool::new(enabled),
            state,
            events,
        });
        let task = this.clone();
        tokio::spawn(async move {
            let mut active = policy
                .ok()
                .flatten()
                .map(|p| launch(p, lease.clone(), state_tx.clone()));
            while let Some((command, reply)) = rx.recv().await {
                let result = match command {
                    Command::EnableAlwaysOn { profile, dns } => {
                        if task.enabled() {
                            Err("Сначала выключите действующий always-on".into())
                        } else if let Ok(reservation) = lease.clone().try_lock_owned() {
                            let mut policy = Policy {
                                version: 1,
                                owner: task.owner.clone(),
                                profile: *profile,
                                dns,
                            };
                            let result =
                                tokio::time::timeout(Duration::from_secs(45), prepare(&mut policy))
                                    .await
                                    .map_err(|_| "Always-on preparation timed out".to_string())
                                    .and_then(|r| r);
                            if result.is_ok() {
                                // Persist before installing protection: a crash must retain intent.
                                if let Err(e) = boot_policy::save(&policy) {
                                    Err(e)
                                } else {
                                    task.enabled.store(true, Ordering::Release);
                                    match platform_guard(Some(&policy)) {
                                        Ok(()) => {
                                            drop(reservation);
                                            active = Some(launch(
                                                policy,
                                                lease.clone(),
                                                state_tx.clone(),
                                            ));
                                            Ok(())
                                        }
                                        Err(e) => Err(e),
                                    }
                                }
                            } else {
                                result
                            }
                        } else {
                            Err("Сначала отключите текущее соединение".into())
                        }
                    }
                    Command::DisableAlwaysOn if !task.enabled() => Ok(()),
                    Command::DisableAlwaysOn => {
                        if let Some((stop, handle)) = active.take() {
                            let _ = stop.send(true);
                            let _ = handle.await;
                        }
                        let result = platform_recover(&task.owner)
                            .and_then(|()| boot_policy::remove())
                            .and_then(|()| platform_unguard());
                        if result.is_ok() {
                            task.enabled.store(false, Ordering::Release);
                        }
                        result
                    }
                    _ => Err("Invalid always-on command".into()),
                };
                let mut response = match result {
                    Ok(()) => Response::new(
                        if task.enabled() {
                            State::Blocked
                        } else {
                            State::Idle
                        },
                        if task.enabled() {
                            "Always-on включён; подключается системная служба"
                        } else {
                            "Always-on выключен; маршруты восстановлены"
                        },
                    ),
                    Err(e) => Response::new(State::Error, &e),
                };
                response.always_on = Some(task.enabled());
                state_tx.send_replace(response.clone());
                let _ = reply.send(response);
            }
        });
        Ok(this)
    }
}
async fn prepare(policy: &mut Policy) -> Result<(), String> {
    policy.profile.validate().map_err(|_| "Invalid profile")?;
    let mut addresses = vec![];
    for address in &policy.profile.endpoint.addresses {
        for value in tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host(address))
            .await
            .map_err(|_| "Endpoint resolution timed out")?
            .map_err(|_| "Cannot resolve endpoint")?
        {
            if addresses.len() >= 64 {
                return Err("Too many endpoint addresses".into());
            }
            #[cfg(target_os = "windows")]
            if value.is_ipv6() {
                continue;
            }
            addresses.push(value.to_string());
        }
    }
    policy.profile.endpoint.addresses = addresses;
    policy.validate(&policy.owner)?;
    let session = tokio::time::timeout(
        Duration::from_secs(30),
        rtrust_engine::Session::connect(&policy.profile),
    )
    .await
    .map_err(|_| "Endpoint timeout")?
    .map_err(|_| "Cannot authenticate endpoint")?;
    session
        .health()
        .await
        .map_err(|_| "Endpoint health check failed".into())
}
type Active = (watch::Sender<bool>, tokio::task::JoinHandle<()>);
fn launch(policy: Policy, lease: Arc<Mutex<()>>, state: watch::Sender<Response>) -> Active {
    let (stop, mut stopped) = watch::channel(false);
    let task = tokio::spawn(async move {
        loop {
            if *stopped.borrow() {
                break;
            }
            let mut failure = platform_guard(Some(&policy))
                .and_then(|()| platform_recover(&policy.owner))
                .err();
            if failure.is_none() {
                let (mut client, server) = tokio::io::duplex(rtrust_control::LIMIT + 1024);
                let serving = platform_serve(server, &policy.owner, lease.clone());
                let mut exchange_stop = stopped.clone();
                let exchange = async {
                    write(
                        &mut client,
                        &Request {
                            version: VERSION,
                            command: Command::StartFull {
                                profile: Box::new(policy.profile.clone()),
                                dns: policy.dns,
                            },
                        },
                    )
                    .await?;
                    let response: Response = tokio::select! {
                        response = read(&mut client) => response?,
                        _ = exchange_stop.changed() => return Ok::<(), String>(()),
                    };
                    if response.state != State::Connected {
                        return Err(response.message);
                    }
                    state.send_replace(response);
                    loop {
                        tokio::select! {
                            _=exchange_stop.changed()=>{
                                write(&mut client,&Request{version:VERSION,command:Command::Stop}).await?;
                                let response:Response=read(&mut client).await?;
                                state.send_replace(response);return Ok::<(),String>(());
                            }
                            _=tokio::time::sleep(Duration::from_secs(1))=>{
                                write(&mut client,&Request{version:VERSION,command:Command::Status}).await?;
                                let response:Response=read(&mut client).await?;state.send_replace(response);
                            }
                        }
                    }
                };
                // Closing/cancelling the internal lease retains the full guard, just like a GUI crash.
                failure = session_exchange(exchange, serving).await.err();
                drop(client);
            }
            if *stopped.borrow() {
                break;
            }
            state.send_replace(Response::new(
                State::Blocked,
                &format!(
                    "Always-on: {}; повторное подключение",
                    failure.as_deref().unwrap_or("сеть защищена")
                ),
            ));
            tokio::select! {_=stopped.changed()=>{},_=tokio::time::sleep(Duration::from_secs(3))=>{}}
        }
    });
    (stop, task)
}
#[cfg(target_os = "linux")]
fn platform_guard(_: Option<&Policy>) -> Result<(), String> {
    crate::service::boot_guard(true)
}
#[cfg(target_os = "linux")]
fn platform_unguard() -> Result<(), String> {
    crate::service::boot_guard(false)
}
#[cfg(target_os = "linux")]
fn platform_recover(owner: &str) -> Result<(), String> {
    crate::service::boot_recover(owner)
}
#[cfg(target_os = "linux")]
fn platform_serve(
    stream: DuplexStream,
    owner: &str,
    lease: Arc<Mutex<()>>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    let uid = owner.parse().expect("validated service UID");
    tokio::spawn(crate::service::boot_serve(stream, uid, lease))
}
#[cfg(target_os = "windows")]
fn platform_guard(policy: Option<&Policy>) -> Result<(), String> {
    crate::windows::boot_guard(policy)
}
#[cfg(target_os = "windows")]
fn platform_unguard() -> Result<(), String> {
    crate::windows::boot_unguard()
}
#[cfg(target_os = "windows")]
fn platform_recover(_: &str) -> Result<(), String> {
    crate::windows::boot_recover()
}
#[cfg(target_os = "windows")]
fn platform_serve(
    stream: DuplexStream,
    _: &str,
    lease: Arc<Mutex<()>>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    tokio::spawn(crate::windows::boot_serve(stream, lease))
}

#[cfg(target_os = "linux")]
fn platform_active() -> Result<bool, String> {
    crate::service::boot_active()
}
#[cfg(target_os = "windows")]
fn platform_active() -> Result<bool, String> {
    crate::windows::boot_active()
}

/// A finished JoinHandle must never be polled again: a setup error races IPC EOF.
async fn session_exchange(
    exchange: impl std::future::Future<Output = Result<(), String>>,
    mut serving: tokio::task::JoinHandle<Result<(), String>>,
) -> Result<(), String> {
    let (result, finished) = tokio::select! {
        result=exchange => (result, false),
        result=&mut serving => (result.unwrap_or_else(|_| Err("VPN service task failed".into())), true),
    };
    if !finished {
        serving.abort();
        let _ = serving.await;
    }
    result
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn setup_error_before_ipc_response_can_be_retried_without_double_poll_panic() {
        let server = tokio::spawn(async { Err("adapter not ready".to_owned()) });
        let result = session_exchange(std::future::pending(), server).await;
        assert_eq!(result, Err("adapter not ready".into()));
        let server = tokio::spawn(async { Ok(()) });
        assert!(
            session_exchange(std::future::pending(), server)
                .await
                .is_ok()
        );
    }
    #[tokio::test]
    async fn completed_client_cancels_and_joins_server() {
        let (started, ready) = oneshot::channel();
        let (dropped, done) = oneshot::channel();
        struct Notify(Option<oneshot::Sender<()>>);
        impl Drop for Notify {
            fn drop(&mut self) {
                let _ = self.0.take().unwrap().send(());
            }
        }
        let server = tokio::spawn(async {
            let _notify = Notify(Some(dropped));
            let _ = started.send(());
            std::future::pending::<Result<(), String>>().await
        });
        ready.await.unwrap();
        assert!(session_exchange(async { Ok(()) }, server).await.is_ok());
        done.await.unwrap();
    }
}
