use jni::{
    Env, JValue, JavaVM, jni_sig, jni_str, native_method,
    objects::{JObject, JString},
    sys::{jboolean, jint, jlong},
};
use rtrust_engine::{Session, SocketProtector};
use rtrust_profile::Profile;
use std::{
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};
use tokio::sync::watch;
use zeroize::Zeroizing;

struct Runner {
    session: u64,
    policy: rtrust_tun::policy::Controller,
    cancel: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
}
static RUNNER: Mutex<Option<Runner>> = Mutex::new(None);
static FLOWS: std::sync::LazyLock<Mutex<rtrust_mobile::flows::Capture>> =
    std::sync::LazyLock::new(|| Mutex::new(rtrust_mobile::flows::Capture::default()));
static STATE: AtomicU8 = AtomicU8::new(0);
static MESSAGE: Mutex<String> = Mutex::new(String::new());
static OBSERVATIONS: std::sync::LazyLock<Mutex<rtrust_mobile::Observations>> =
    std::sync::LazyLock::new(|| Mutex::new(rtrust_mobile::Observations::default()));
fn state(value: u8, message: &str) {
    OBSERVATIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .transition(value);
    *MESSAGE.lock().unwrap_or_else(|p| p.into_inner()) = message.into();
    STATE.store(value, Ordering::SeqCst);
}
fn input(env: &mut Env<'_>, value: &JString<'_>) -> jni::errors::Result<Zeroizing<String>> {
    let len = env
        .call_method(value, jni_str!("length"), jni_sig!("()I"), &[])?
        .i()?;
    if len < 0 || len as usize > rtrust_profile::MAX_INPUT {
        return Err(jni::errors::Error::NullPtr(
            "Input exceeds profile size limit",
        ));
    }
    let value = Zeroizing::new(value.try_to_string(env)?);
    if value.len() > rtrust_profile::MAX_INPUT {
        return Err(jni::errors::Error::NullPtr(
            "Input exceeds profile size limit",
        ));
    }
    Ok(value)
}
fn codec_result<'a>(
    env: &mut Env<'a>,
    result: Result<Zeroizing<String>, String>,
) -> jni::errors::Result<JString<'a>> {
    let output = result.unwrap_or_else(|message| {
        Zeroizing::new(serde_json::json!({"ok":false,"message":message}).to_string())
    });
    JString::new(env, &*output)
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn parse(raw:JString)->JString,};
fn parse<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
) -> jni::errors::Result<JString<'a>> {
    let raw = input(env, &raw)?;
    codec_result(env, super::import_profile(&raw))
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn export(raw:JString,format:jint)->JString,};
fn export<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
    format: jint,
) -> jni::errors::Result<JString<'a>> {
    let raw = input(env, &raw)?;
    codec_result(env, super::export_profile(&raw, format))
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn start(raw:JString,fd:jint,protector:JObject)->jboolean,};
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn plan(raw:JString)->JString,};
fn plan<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
) -> jni::errors::Result<JString<'a>> {
    let raw = input(env, &raw)?;
    codec_result(
        env,
        (|| {
            let profile = Profile::import(&raw).map_err(|e| e.to_string())?;
            let (profile, plan) = super::prepare(profile)?;
            Ok(Zeroizing::new(
                serde_json::json!({"ok":true,"profile":profile,"plan":plan}).to_string(),
            ))
        })(),
    )
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",name="planManaged",extern fn plan_managed(raw:JString,group:JString)->JString,};
fn plan_managed<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
    group: JString<'a>,
) -> jni::errors::Result<JString<'a>> {
    let raw = input(env, &raw)?;
    let group = input(env, &group)?;
    codec_result(
        env,
        (|| {
            if group.len() > 16384 {
                return Err("Managed group exceeds size limit".into());
            }
            let group: rtrust_mobile::managed::Group =
                serde_json::from_str(&group).map_err(|_| "Invalid managed group")?;
            let profile = Profile::import(&raw).map_err(|e| e.to_string())?;
            let (profile, plan) = rtrust_mobile::managed::prepare_group(profile, &group)?;
            Ok(Zeroizing::new(
                serde_json::json!({"ok":true,"profile":profile,"plan":plan}).to_string(),
            ))
        })(),
    )
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",name="planManagedOnNetwork",extern fn plan_managed_on_network(raw:JString,group:JString,local:JString)->JString,};
fn plan_managed_on_network<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
    group: JString<'a>,
    local: JString<'a>,
) -> jni::errors::Result<JString<'a>> {
    let raw = input(env, &raw)?;
    let group = input(env, &group)?;
    let local = input(env, &local)?;
    codec_result(
        env,
        (|| {
            if group.len() > 16384 || local.len() > 8192 {
                return Err("Policy exceeds size limit".into());
            }
            let group: rtrust_mobile::managed::Group =
                serde_json::from_str(&group).map_err(|_| "Invalid group")?;
            let local: Option<Vec<ipnet::Ipv4Net>> =
                serde_json::from_str(&local).map_err(|_| "Invalid local prefixes")?;
            let profile = Profile::import(&raw).map_err(|e| e.to_string())?;
            let (profile, plan) = rtrust_mobile::managed::prepare_group_on_network(
                profile,
                &group,
                local.as_deref(),
            )?;
            Ok(Zeroizing::new(
                serde_json::json!({"ok":true,"profile":profile,"plan":plan}).to_string(),
            ))
        })(),
    )
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixSelection {
    routes: Vec<ipnet::IpNet>,
    ipv6: bool,
    context: rtrust_profile::routing::Context,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Candidates {
    profiles: Vec<serde_json::Value>,
    #[serde(default)]
    unavailable: Vec<usize>,
    logical_session: u64,
    selection: Option<PrefixSelection>,
}
type RecoveryBudget = Arc<Mutex<rtrust_mobile::reserves::Planner>>;
static RECOVERY: Mutex<Option<(u64, usize, RecoveryBudget)>> = Mutex::new(None);
static NEXT_FIXED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn start<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
    fd: jint,
    protector: JObject<'a>,
) -> jni::errors::Result<jboolean> {
    let raw = input(env, &raw)?;
    let Ok(profile) = Profile::import(&raw) else {
        return Ok(false);
    };
    start_candidates(
        env,
        vec![profile],
        vec![false],
        None,
        NEXT_FIXED.fetch_add(1, Ordering::SeqCst),
        fd,
        protector,
    )
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",name="startProfiles",extern fn start_profiles(raw:JString,fd:jint,protector:JObject)->jboolean,};
fn start_profiles<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
    fd: jint,
    protector: JObject<'a>,
) -> jni::errors::Result<jboolean> {
    let raw = input(env, &raw)?;
    let Ok(set) = serde_json::from_str::<Candidates>(&raw) else {
        return Ok(false);
    };
    if set.logical_session == 0
        || !(1..=4).contains(&set.profiles.len())
        || set.unavailable.iter().any(|i| *i >= set.profiles.len())
    {
        return Ok(false);
    }
    let mut profiles = Vec::new();
    for value in set.profiles {
        let Ok(profile) = Profile::import(&value.to_string()) else {
            return Ok(false);
        };
        profiles.push(profile);
    }
    let unavailable = (0..profiles.len())
        .map(|i| set.unavailable.contains(&i))
        .collect();
    start_candidates(
        env,
        profiles,
        unavailable,
        set.selection,
        set.logical_session,
        fd,
        protector,
    )
}
fn start_candidates<'a>(
    env: &mut Env<'a>,
    profiles: Vec<Profile>,
    unavailable: Vec<bool>,
    selection: Option<PrefixSelection>,
    logical_session: u64,
    fd: jint,
    protector: JObject<'a>,
) -> jni::errors::Result<jboolean> {
    let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_some() || fd < 0 {
        return Ok(false);
    }
    let mut prepared = Vec::new();
    let mut baseline = None;
    for (i, profile) in profiles.into_iter().enumerate() {
        let Ok((profile, plan)) = super::prepare(profile) else {
            return Ok(false);
        };
        if !unavailable[i]
            && profile
                .endpoint
                .addresses
                .iter()
                .any(|a| a.parse::<std::net::SocketAddr>().is_err())
        {
            return Ok(false);
        }
        if rtrust_engine::check_capabilities(&profile).is_err() {
            return Ok(false);
        }
        let encoded =
            serde_json::to_value(&plan).map_err(|_| jni::errors::Error::NullPtr("Invalid plan"))?;
        if baseline.as_ref().is_some_and(|old| old != &encoded) {
            return Ok(false);
        }
        baseline = Some(encoded);
        prepared.push(profile);
    }
    let policy: rtrust_engine::routing::Policy = serde_json::from_value(prepared[0].policy.clone())
        .map_err(|_| jni::errors::Error::NullPtr("Invalid flow policy"))?;
    let local = env
        .call_method(&protector, jni_str!("hasLocalSource"), jni_sig!("()Z"), &[])?
        .z()?;
    let mutable = env
        .call_method(
            &protector,
            jni_str!("allowPolicyMutation"),
            jni_sig!("()Z"),
            &[],
        )?
        .z()?;
    let mut router = policy
        .compile_with_context(rtrust_profile::routing::Context {
            source: if mutable {
                rtrust_profile::routing::Source::EmbeddedProfile
            } else if local {
                rtrust_profile::routing::Source::Local
            } else {
                rtrust_profile::routing::Source::ManagedUnknown
            },
            revision: None,
        })
        .map_err(|_| jni::errors::Error::NullPtr("Invalid flow policy"))?;
    if let Some(selected) = selection {
        router = router
            .with_prefix_selection(selected.routes, selected.ipv6, selected.context)
            .map_err(|_| jni::errors::Error::NullPtr("Invalid prefix selection"))?;
    }
    let router = Arc::new(router);
    let budget = {
        let mut cache = RECOVERY.lock().unwrap_or_else(|p| p.into_inner());
        if cache
            .as_ref()
            .is_none_or(|(id, _, _)| *id != logical_session)
        {
            *cache = Some((
                logical_session,
                prepared.len(),
                Arc::new(Mutex::new(
                    rtrust_mobile::reserves::Planner::new(prepared.len())
                        .map_err(|_| jni::errors::Error::NullPtr("Invalid candidates"))?,
                )),
            ));
        }
        let (_, count, budget) = cache.as_ref().unwrap();
        if *count != prepared.len() {
            return Ok(false);
        }
        budget.clone()
    };
    let protector = env.new_global_ref(protector)?;
    // Java retains its own ParcelFileDescriptor. Rust owns only this duplicate.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Ok(false);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let access = env.new_global_ref(&protector)?;
    let valid: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
        JavaVM::singleton()
            .and_then(|vm| {
                vm.attach_current_thread(|env| {
                    env.call_method(&access, jni_str!("accessValid"), jni_sig!("()Z"), &[])?
                        .z()
                })
            })
            .unwrap_or(false)
    });
    let protect: SocketProtector = Arc::new(move |fd| {
        let accepted = JavaVM::singleton()
            .and_then(|vm| {
                vm.attach_current_thread(|env| {
                    env.call_method(
                        &protector,
                        jni_str!("protectSocket"),
                        jni_sig!("(I)Z"),
                        &[JValue::Int(fd)],
                    )?
                    .z()
                })
            })
            .unwrap_or(false);
        if accepted {
            Ok(())
        } else {
            Err(std::io::ErrorKind::PermissionDenied.into())
        }
    });
    let (cancel, receiver) = watch::channel(false);
    let (policy_control, policy_receiver) = rtrust_tun::policy::Controller::new(router.clone());
    let session = FLOWS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .attach(router.clone());
    state(1, "Connecting securely");
    let thread = std::thread::Builder::new()
        .name("rtrust-android".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?;
                runtime.block_on(run(
                    RecoveryInputs {
                        profiles: prepared,
                        unavailable,
                        budget,
                        valid,
                    },
                    owned,
                    protect,
                    receiver,
                    router,
                    session,
                    policy_receiver,
                ))
            }));
            FLOWS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .detach_session(session);
            if !matches!(result, Ok(Ok(()))) {
                state(
                    4,
                    "VPN worker stopped; traffic remains blocked until Disconnect",
                );
            }
        });
    match thread {
        Ok(thread) => {
            *slot = Some(Runner {
                session,
                policy: policy_control,
                cancel,
                thread,
            });
            Ok(true)
        }
        Err(_) => {
            FLOWS
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .detach_session(session);
            state(4, "Cannot start VPN worker");
            Ok(false)
        }
    }
}
const _: jni::NativeMethod =
    native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn stop(),};
fn stop(_env: &mut Env<'_>, _this: JObject<'_>) -> jni::errors::Result<()> {
    let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    FLOWS.lock().unwrap_or_else(|p| p.into_inner()).detach();
    if let Some(runner) = slot.take() {
        let _ = runner.cancel.send(true);
        let _ = runner.thread.join();
    }
    state(0, "");
    Ok(())
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",name="networkChanged",extern fn network_changed(),};
fn network_changed(_env: &mut Env<'_>, _this: JObject<'_>) -> jni::errors::Result<()> {
    OBSERVATIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .network_changed();
    Ok(())
}
const _: jni::NativeMethod =
    native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn resumed(),};
fn resumed(_env: &mut Env<'_>, _this: JObject<'_>) -> jni::errors::Result<()> {
    OBSERVATIONS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .resumed();
    Ok(())
}
const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",name="flowCapture",extern fn flow_capture(session:jlong,capture:jlong,operation:jint)->JString,};
fn flow_capture<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    session: jlong,
    capture: jlong,
    operation: jint,
) -> jni::errors::Result<JString<'a>> {
    let mut flows = FLOWS.lock().unwrap_or_else(|p| p.into_inner());
    let token = rtrust_mobile::flows::Token {
        session: session as u64,
        capture: capture as u64,
    };
    let result = if operation == 0 {
        Ok(flows.snapshot())
    } else if session < 0 || capture < 0 {
        Err("Invalid flow capture token")
    } else {
        match operation {
            1 => flows.observe(token, true),
            2 => flows.observe(token, false),
            3 => flows.poll(token),
            _ => Err("Invalid flow capture operation"),
        }
    };
    let value = match result {
        Ok(snapshot) => serde_json::to_value(snapshot).unwrap_or_default(),
        Err(message) => serde_json::json!({"error":message}),
    };
    JString::new(env, value.to_string())
}
const _: jni::NativeMethod =
    native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn status()->JString,};
fn status<'a>(env: &mut Env<'a>, _this: JObject<'a>) -> jni::errors::Result<JString<'a>> {
    FLOWS.lock().unwrap_or_else(|p| p.into_inner()).expire();
    let message = MESSAGE.lock().unwrap_or_else(|p| p.into_inner());
    JString::new(
        env,
        serde_json::json!({"state":STATE.load(Ordering::SeqCst),"message":&*message,"recovery":RECOVERY.lock().unwrap_or_else(|p|p.into_inner()).as_ref().map(|(_,_,p)|{let p=p.lock().unwrap_or_else(|p|p.into_inner());serde_json::json!({"selected_index":p.selected(),"attempts":p.attempts(),"limit":rtrust_mobile::reserves::LIMIT})}),"observations":OBSERVATIONS.lock().unwrap_or_else(|p| p.into_inner()).snapshot()}).to_string(),
    )
}

const _: jni::NativeMethod = native_method! {java_type="org.rtrusttunnel.android.NativeCore",name="flowPolicy",extern fn flow_policy(raw:JString)->JString,};
fn flow_policy<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
) -> jni::errors::Result<JString<'a>> {
    #[derive(serde::Deserialize)]
    #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
    enum Mutation {
        Version,
        Preview {
            session: u64,
            expected: rtrust_engine::routing::PolicyVersion,
            policy: rtrust_engine::routing::Policy,
            destination: String,
        },
        Apply {
            session: u64,
            expected: rtrust_engine::routing::PolicyVersion,
            policy: rtrust_engine::routing::Policy,
        },
        Rollback {
            session: u64,
            expected: rtrust_engine::routing::PolicyVersion,
            previous_revision: String,
        },
    }
    let result = (|| {
        let raw = input(env, &raw).map_err(|_| "Invalid policy request")?;
        if raw.len() > 40 * 1024 {
            return Err("Policy request too large");
        }
        let mutation: Mutation =
            serde_json::from_str(&raw).map_err(|_| "Invalid policy request")?;
        let (session, controller) = RUNNER
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|r| (r.session, r.policy.clone()))
            .ok_or("Policy session unavailable")?;
        let requested_session = match &mutation {
            Mutation::Version => session,
            Mutation::Preview { session, .. }
            | Mutation::Apply { session, .. }
            | Mutation::Rollback { session, .. } => *session,
        };
        if requested_session != session {
            return Err("Policy session changed; reopen the dialog");
        }
        if STATE.load(Ordering::SeqCst) != 2 {
            return Err("Wait for the connected policy session");
        }
        if let Mutation::Preview {
            expected,
            policy,
            destination,
            ..
        } = &mutation
        {
            let destination = destination
                .parse()
                .map_err(|_| "Preview requires numeric IP:port")?;
            let decision = controller
                .preview(expected, policy, destination)
                .map_err(|_| "Policy preview unavailable or unauthorized")?;
            return Ok(
                serde_json::json!({"ok":true,"session":session,"version":controller.version(),"decision":decision}),
            );
        }
        let version = match mutation {
            Mutation::Version => controller.version(),
            mutation => {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .map_err(|_| "Policy executor unavailable")?;
                let version = runtime
                    .block_on(async {
                        match mutation {
                            Mutation::Apply {
                                expected, policy, ..
                            } => {
                                controller
                                    .apply(
                                        expected,
                                        policy,
                                        rtrust_profile::routing::Context::default(),
                                    )
                                    .await
                            }
                            Mutation::Rollback {
                                expected,
                                previous_revision,
                                ..
                            } => controller.rollback(expected, previous_revision).await,
                            Mutation::Version | Mutation::Preview { .. } => unreachable!(),
                        }
                    })
                    .map_err(
                        |_| "Policy changed, unsupported or unavailable; refresh its version",
                    )?;
                OBSERVATIONS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .policy_changed();
                version
            }
        };
        Ok(
            serde_json::json!({"ok":true,"session":session,"version":version,"scope":"flow_policy_only_os_configuration_unchanged"}),
        )
    })();
    let value = match result {
        Ok(value) => value,
        Err(message) => serde_json::json!({"ok":false,"message":message}),
    };
    JString::new(env, value.to_string())
}

struct RecoveryInputs {
    profiles: Vec<Profile>,
    unavailable: Vec<bool>,
    budget: RecoveryBudget,
    valid: Arc<dyn Fn() -> bool + Send + Sync>,
}
async fn run(
    inputs: RecoveryInputs,
    fd: OwnedFd,
    protect: SocketProtector,
    mut cancel: watch::Receiver<bool>,
    router: Arc<rtrust_engine::routing::Router>,
    runner_session: u64,
    mut policy: rtrust_tun::policy::Receiver,
) -> std::io::Result<()> {
    let RecoveryInputs {
        profiles,
        unavailable,
        budget,
        valid,
    } = inputs;
    // VpnService configured addresses, DNS and routes before handing over the FD.
    let device = Arc::new(unsafe { tun_rs::AsyncDevice::from_fd(fd.into_raw_fd()) }?);
    let dns = rtrust_engine::dns::encrypted(&profiles[0].endpoint.dns_upstreams)
        .map_err(std::io::Error::other)?
        .unwrap_or_default();
    let routing = Some((router, protect.clone()));
    loop {
        let index = budget.lock().unwrap_or_else(|p| p.into_inner()).begin();
        let Some(index) = index else {
            state(
                4,
                "Recovery budget exhausted or all permitted candidates denied; traffic blocked",
            );
            let _ = cancel.changed().await;
            break;
        };
        let profile = &profiles[index];
        let wait_expiry = async {
            loop {
                if !valid() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        };
        let mut connected_for = std::time::Duration::ZERO;
        let mut fatal = false;
        let connected = tokio::select! {
            biased;
            _=cancel.changed()=>break,
            _=wait_expiry=>{state(4,"Access refresh required; traffic blocked");let _=cancel.changed().await;break;},
            result=tokio::time::timeout(rtrust_mobile::recovery::ATTEMPT_TIMEOUT, async {
                if unavailable[index]{return Err(rtrust_engine::Error::ConnectIo(std::io::ErrorKind::NotConnected));}
                let session=Session::connect_protected(profile,&protect).await?;
                session.health().await?;
                let tunnel=session.open_udp().await?;
                Ok::<_,rtrust_engine::Error>((session,tunnel))
            })=>result.unwrap_or(Err(rtrust_engine::Error::Timeout)),
        };
        match connected {
            Ok((session, tunnel)) => {
                FLOWS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .transport_ready(runner_session);
                state(
                    2,
                    if profile.endpoint.has_ipv6 {
                        "Transport connected · IPv4/IPv6 configured; check system DNS/HTTPS"
                    } else {
                        "Transport connected · IPv4 configured; check system DNS/HTTPS"
                    },
                );
                let started = std::time::Instant::now();
                tokio::select! {
                    biased;
                    _=cancel.changed()=>break,
                    _=async{loop{if !valid(){break;}tokio::time::sleep(std::time::Duration::from_millis(100)).await;}}=>{state(4,"Access refresh required; traffic blocked");let _=cancel.changed().await;break;},
                    _=rtrust_tun::run_with_policy(session,tunnel,device.clone(),"169.254.254.2".parse().unwrap(),dns.clone(),routing.clone(),Some(&mut policy))=>{},
                }
                FLOWS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .transport_lost(runner_session);
                connected_for = started.elapsed();
                state(3, "Connection lost; traffic blocked while reconnecting");
            }
            Err(error) => {
                FLOWS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .transport_lost(runner_session);
                state(3, &error.to_string());
                fatal = matches!(
                    error,
                    rtrust_engine::Error::Authentication
                        | rtrust_engine::Error::Tls
                        | rtrust_engine::Error::Trust
                        | rtrust_engine::Error::Unsupported(_)
                        | rtrust_engine::Error::Profile
                );
            }
        }
        let delay = budget.lock().unwrap_or_else(|p| p.into_inner()).failed(
            fatal,
            connected_for,
            rand::random(),
        );
        tokio::select! {_=cancel.changed()=>break,_=tokio::time::sleep(delay)=>{}}
    }
    Ok(())
}
