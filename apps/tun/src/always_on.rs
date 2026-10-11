//! Own the boot VPN independently of GUI IPC. Platform guards bracket every restart.
use crate::boot_policy::{self, Policy};
use rtrust_control::{Command, Request, Response, State, VERSION, read, write};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
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
    generation: AtomicU64,
    observation_epochs: Arc<AtomicU64>,
    state: watch::Receiver<Response>,
    events: mpsc::Sender<(Command, u64, oneshot::Sender<Response>)>,
}
impl Supervisor {
    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }
    pub fn state(&self) -> Response {
        let mut response = self.state.borrow().clone();
        response
            .observations
            .expire(rtrust_control::observations::now_ms());
        response.always_on = Some(self.enabled());
        response.always_on_generation = Some(self.generation.load(Ordering::Acquire));
        response
    }
    /// Cancel pending setup only. Running/persisted always-on intent is unchanged.
    pub fn cancel_pending_enable(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }
    pub async fn command(&self, command: Command) -> Response {
        let (tx, rx) = oneshot::channel();
        let generation = if matches!(command, Command::DisableAlwaysOn) {
            self.generation.fetch_add(1, Ordering::AcqRel) + 1
        } else if let Command::EnableAlwaysOn { generation, .. }
        | Command::EnableRecovery { generation, .. } = &command
        {
            match generation {
                Some(expected) if *expected == self.generation.load(Ordering::Acquire) => *expected,
                _ => {
                    return Response::new(
                        State::Error,
                        "Always-on setup cancelled; refresh status before enabling",
                    );
                }
            }
        } else {
            self.generation.load(Ordering::Acquire)
        };
        if self.events.send((command, generation, tx)).await.is_err() {
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
        let (events, mut rx) = mpsc::channel::<(Command, u64, oneshot::Sender<Response>)>(8);
        let this = Arc::new(Self {
            owner,
            enabled: AtomicBool::new(enabled),
            generation: AtomicU64::new(0),
            observation_epochs: Arc::new(AtomicU64::new(0)),
            state,
            events,
        });
        let task = this.clone();
        tokio::spawn(async move {
            let mut active = policy.ok().flatten().map(|p| {
                launch(
                    p,
                    lease.clone(),
                    state_tx.clone(),
                    task.observation_epochs.clone(),
                )
            });
            while let Some((command, generation, reply)) = rx.recv().await {
                // Normalize both explicit opt-ins to the same guarded setup path.
                let (command, backups) = match command {
                    Command::EnableRecovery {
                        profile,
                        dns,
                        backups,
                        generation,
                    } => (
                        Command::EnableAlwaysOn {
                            profile,
                            dns,
                            generation,
                        },
                        Some(backups),
                    ),
                    command => (command, None),
                };
                let result = match command {
                    Command::EnableAlwaysOn { profile, dns, .. } => {
                        if generation != task.generation.load(Ordering::Acquire) {
                            Err("Настройка отменена отключением".into())
                        } else if backups.as_ref().is_some_and(|p| {
                            p.is_empty() || p.len() > rtrust_control::recovery::MAX_BACKUPS
                        }) {
                            Err("Выберите от 1 до 3 резервных профилей".into())
                        } else if task.enabled() {
                            Err("Сначала выключите действующий always-on".into())
                        } else if let Ok(reservation) = lease.clone().try_lock_owned() {
                            let mut policy = Policy {
                                version: 1,
                                owner: task.owner.clone(),
                                profile: *profile,
                                dns,
                                backups: backups.unwrap_or_default(),
                            };
                            let result =
                                tokio::time::timeout(Duration::from_secs(45), prepare(&mut policy))
                                    .await
                                    .map_err(|_| "Always-on preparation timed out".to_string())
                                    .and_then(|r| r);
                            let result = if generation != task.generation.load(Ordering::Acquire) {
                                Err("Настройка отменена отключением".into())
                            } else {
                                result
                            };
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
                                                task.observation_epochs.clone(),
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
    if !policy.backups.is_empty() {
        rtrust_control::recovery::Planner::new(policy.backups.len())?;
    }
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
    // Pin every permitted endpoint before protection. No later DNS lookup can
    // escape the full guard or silently expand the endpoint allowlist.
    for profile in &mut policy.backups {
        profile.validate().map_err(|_| "Invalid backup profile")?;
        let mut pinned = vec![];
        for endpoint in &profile.endpoint.addresses {
            let resolved =
                tokio::time::timeout(Duration::from_secs(5), tokio::net::lookup_host(endpoint))
                    .await
                    .map_err(|_| "Backup resolution timed out")?
                    .map_err(|_| "Cannot resolve backup endpoint")?;
            for value in resolved {
                #[cfg(target_os = "windows")]
                if value.is_ipv6() {
                    continue;
                }
                if pinned.len() >= 64 {
                    return Err("Too many backup addresses".into());
                }
                pinned.push(value.to_string());
            }
        }
        profile.endpoint.addresses = pinned;
    }
    policy.validate(&policy.owner)?;
    if !policy.backups.is_empty() {
        return Ok(());
    }
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
fn launch(
    mut policy: Policy,
    lease: Arc<Mutex<()>>,
    state: watch::Sender<Response>,
    observation_epochs: Arc<AtomicU64>,
) -> Active {
    let (stop, mut stopped) = watch::channel(false);
    let task = tokio::spawn(async move {
        let mut planner = if policy.backups.is_empty() {
            None
        } else {
            Some(
                rtrust_control::recovery::Planner::new(policy.backups.len())
                    .expect("validated backups"),
            )
        };
        let mut observations = rtrust_control::recovery::Observations::new(
            state.borrow().observations.clone(),
            observation_epochs,
        );
        let mut profiles = vec![policy.profile.clone()];
        profiles.extend(policy.backups.clone());
        loop {
            if *stopped.borrow() {
                break;
            }
            let attempt = observations.begin(rtrust_control::observations::now_ms());
            if let Some(planner) = planner.as_mut() {
                let Some(index) = planner.begin() else {
                    let mut response = Response::new(
                        State::Blocked,
                        "Автовосстановление: бюджет попыток исчерпан; VPN не подключён. Проверьте состояние защиты, выключите и настройте режим заново",
                    );
                    response.recovery = Some(planner.status());
                    response.observations = observations.snapshot();
                    state.send_replace(response);
                    let _ = stopped.changed().await;
                    break;
                };
                policy.profile = profiles[index].clone();
                let mut response = Response::new(
                    State::Blocked,
                    "Автовосстановление: подготовка разрешённого профиля; подключение ещё не подтверждено",
                );
                response.recovery = Some(planner.status());
                response.observations = observations.snapshot();
                state.send_replace(response);
            }
            let connected_at = Arc::new(Mutex::new(None::<std::time::Instant>));
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
                                fallbacks: vec![],
                            },
                        },
                    )
                    .await?;
                    let mut response: Response = tokio::select! {
                        response = tokio::time::timeout(Duration::from_secs(rtrust_control::recovery::ATTEMPT_TIMEOUT_SECS), read(&mut client)) => response.map_err(|_| "Recovery attempt timed out")??,
                        _ = exchange_stop.changed() => return Ok::<(), String>(()),
                    };
                    if response.state != State::Connected {
                        return Err(response.message);
                    }
                    *connected_at.lock().await = Some(std::time::Instant::now());
                    response.recovery = planner.as_ref().map(|p| p.status());
                    if !observations.accept(attempt, response.observations) {
                        return Err("Stale service observation".into());
                    }
                    response.observations = observations.snapshot();
                    state.send_replace(response);
                    loop {
                        tokio::select! {
                            _=exchange_stop.changed()=>{
                                write(&mut client,&Request{version:VERSION,command:Command::Stop}).await?;
                                let mut response:Response=tokio::time::timeout(Duration::from_secs(10),read(&mut client)).await.map_err(|_| "Stop timed out")??;
                                if !observations.accept(attempt, response.observations) { return Err("Stale stop observation".into()); }
                                response.observations = observations.snapshot();
                                state.send_replace(response);return Ok::<(),String>(());
                            }
                            _=tokio::time::sleep(Duration::from_secs(1))=>{
                                write(&mut client,&Request{version:VERSION,command:Command::Status}).await?;
                                let mut response:Response=tokio::time::timeout(Duration::from_secs(10),read(&mut client)).await.map_err(|_| "Status timed out")??;
                                response.recovery = planner.as_ref().map(|p| p.status());
                                if !observations.accept(attempt, response.observations) { return Err("Stale status observation".into()); }
                                response.observations = observations.snapshot();
                                if response.state != State::Connected { return Err("Подключение утрачено; повторная проверка резервного профиля".into()); }
                                state.send_replace(response);
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
            let mut response = Response::new(
                State::Blocked,
                &format!(
                    "Always-on: {}; повторное подключение",
                    failure.as_deref().unwrap_or("подключение отсутствует")
                ),
            );
            let connected_seconds = connected_at
                .lock()
                .await
                .map(|t| t.elapsed().as_secs().max(1))
                .unwrap_or(0);
            let delay = planner
                .as_mut()
                .map(|p| p.failed(rand::random(), connected_seconds))
                .unwrap_or(3);
            response.recovery = planner.as_ref().map(|p| p.status());
            observations.begin(rtrust_control::observations::now_ms());
            response.observations = observations.snapshot();
            state.send_replace(response);
            tokio::select! {_=stopped.changed()=>{},_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
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
    #[tokio::test]
    async fn automatic_policy_can_be_prepared_with_an_unreachable_primary() {
        let profile = |host: &str, ip: &str| {
            rtrust_profile::Profile::import(&format!(
                "hostname='{host}'\naddresses=['{ip}:443']\nusername='u'\npassword='p'\n"
            ))
            .unwrap()
        };
        let mut policy = Policy {
            version: 1,
            owner: "1000".into(),
            profile: profile("primary.example", "192.0.2.1"),
            dns: "1.1.1.1".parse().unwrap(),
            backups: vec![profile("backup.example", "192.0.2.2")],
        };
        tokio::time::timeout(Duration::from_secs(2), prepare(&mut policy))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(policy.backups.len(), 1);
        policy.validate("1000").unwrap();
    }
    #[tokio::test]
    async fn disable_invalidates_pending_configuration_generation_before_it_is_queued() {
        let (_, state) = watch::channel(Response::new(State::Idle, "off"));
        let (events, mut requests) = mpsc::channel(8);
        let supervisor = Arc::new(Supervisor {
            owner: "1000".into(),
            enabled: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            observation_epochs: Arc::new(AtomicU64::new(0)),
            state,
            events,
        });
        let previous = supervisor.generation.load(Ordering::Acquire);
        let task = supervisor.clone();
        let pending = tokio::spawn(async move { task.command(Command::DisableAlwaysOn).await });
        let (command, generation, reply) = requests.recv().await.unwrap();
        assert!(matches!(command, Command::DisableAlwaysOn));
        assert_ne!(previous, generation);
        assert_eq!(generation, supervisor.generation.load(Ordering::Acquire));
        reply.send(Response::new(State::Idle, "off")).unwrap();
        pending.await.unwrap();
    }
    type QueuedCommand = (Command, u64, oneshot::Sender<Response>);
    fn queued_supervisor() -> (Arc<Supervisor>, mpsc::Receiver<QueuedCommand>) {
        let (_, state) = watch::channel(Response::new(State::Idle, "off"));
        let (events, requests) = mpsc::channel(8);
        (
            Arc::new(Supervisor {
                owner: "1000".into(),
                enabled: AtomicBool::new(false),
                generation: AtomicU64::new(0),
                observation_epochs: Arc::new(AtomicU64::new(0)),
                state,
                events,
            }),
            requests,
        )
    }
    fn enable(generation: Option<u64>, recovery: bool) -> Command {
        let profile = Box::new(profile("primary.example", "192.0.2.1"));
        let dns = "1.1.1.1".parse().unwrap();
        if recovery {
            Command::EnableRecovery {
                profile,
                dns,
                generation,
                backups: vec![profile_for_backup()],
            }
        } else {
            Command::EnableAlwaysOn {
                profile,
                dns,
                generation,
            }
        }
    }
    fn profile(host: &str, ip: &str) -> rtrust_profile::Profile {
        rtrust_profile::Profile::import(&format!(
            "hostname='{host}'\naddresses=['{ip}:443']\nusername='u'\npassword='p'\n"
        ))
        .unwrap()
    }
    fn profile_for_backup() -> rtrust_profile::Profile {
        profile("backup.example", "192.0.2.2")
    }
    #[tokio::test]
    async fn buffered_enable_after_completed_disable_cannot_acquire_new_generation() {
        for recovery in [false, true] {
            let (supervisor, mut requests) = queued_supervisor();
            let old = supervisor.state().always_on_generation;
            // A complete Enable frame already in the pipe before UI cancellation.
            let buffered = serde_json::to_vec(&Request {
                version: VERSION,
                command: enable(old, recovery),
            })
            .unwrap();
            let task = supervisor.clone();
            let disable = tokio::spawn(async move { task.command(Command::DisableAlwaysOn).await });
            let (_, _, reply) = requests.recv().await.unwrap();
            reply.send(Response::new(State::Idle, "off")).unwrap();
            disable.await.unwrap();
            let delayed: Request = serde_json::from_slice(&buffered).unwrap();
            assert_eq!(
                supervisor.command(delayed.command).await.state,
                State::Error
            );
            assert!(
                requests.try_recv().is_err(),
                "stale enable must never enter the actor"
            );
            assert_eq!(
                supervisor.command(enable(None, recovery)).await.state,
                State::Error
            );
            // A new deliberate request obtains the new fence and can be queued.
            let fresh = supervisor.state().always_on_generation;
            let task = supervisor.clone();
            let pending = tokio::spawn(async move { task.command(enable(fresh, recovery)).await });
            let (_, captured, reply) = requests.recv().await.unwrap();
            assert_eq!(Some(captured), fresh);
            supervisor.cancel_pending_enable();
            assert_ne!(captured, supervisor.generation.load(Ordering::Acquire));
            // This is the captured token used by both actor preparation checks.
            reply
                .send(Response::new(State::Error, "cancelled"))
                .unwrap();
            pending.await.unwrap();
        }
    }
    #[tokio::test]
    async fn stop_cancels_pending_fence_without_disabling_persisted_intent() {
        let (supervisor, mut requests) = queued_supervisor();
        let old = supervisor.state().always_on_generation;
        supervisor.enabled.store(true, Ordering::Release);
        supervisor.cancel_pending_enable();
        assert!(supervisor.enabled());
        assert_ne!(old, supervisor.state().always_on_generation);
        assert_eq!(
            supervisor.command(enable(old, true)).await.state,
            State::Error
        );
        assert!(requests.try_recv().is_err());
    }
}
