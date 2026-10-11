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
fn start<'a>(
    env: &mut Env<'a>,
    _this: JObject<'a>,
    raw: JString<'a>,
    fd: jint,
    protector: JObject<'a>,
) -> jni::errors::Result<jboolean> {
    let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    if slot.is_some() || fd < 0 {
        return Ok(false);
    }
    let raw = input(env, &raw)?;
    let Ok(profile) = Profile::import(&raw) else {
        return Ok(false);
    };
    let Ok((profile, _plan)) = super::prepare(profile) else {
        state(4, "Unsupported mobile routing or DNS policy");
        return Ok(false);
    };
    if profile
        .endpoint
        .addresses
        .iter()
        .any(|a| a.parse::<std::net::SocketAddr>().is_err())
    {
        return Ok(false);
    }
    if let Err(error) = rtrust_engine::check_capabilities(&profile) {
        state(4, &error.to_string());
        return Ok(false);
    }
    let policy: rtrust_engine::routing::Policy = serde_json::from_value(profile.policy.clone())
        .map_err(|_| jni::errors::Error::NullPtr("Invalid flow policy"))?;
    let local = env
        .call_method(
            &protector,
            jni_str!("allowPolicyMutation"),
            jni_sig!("()Z"),
            &[],
        )?
        .z()?;
    let router = Arc::new(
        policy
            .compile_with_context(rtrust_profile::routing::Context {
                source: if local {
                    rtrust_profile::routing::Source::EmbeddedProfile
                } else {
                    rtrust_profile::routing::Source::ManagedUnknown
                },
                revision: None,
            })
            .map_err(|_| jni::errors::Error::NullPtr("Invalid flow policy"))?,
    );
    let protector = env.new_global_ref(protector)?;
    // Java retains its own ParcelFileDescriptor. Rust owns only this duplicate.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Ok(false);
    }
    let owned = unsafe { OwnedFd::from_raw_fd(duplicate) };
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
                    profile,
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
        serde_json::json!({"state":STATE.load(Ordering::SeqCst),"message":&*message,"observations":OBSERVATIONS.lock().unwrap_or_else(|p| p.into_inner()).snapshot()}).to_string(),
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
            expected: rtrust_engine::routing::PolicyVersion,
            policy: rtrust_engine::routing::Policy,
            destination: String,
        },
        Apply {
            expected: rtrust_engine::routing::PolicyVersion,
            policy: rtrust_engine::routing::Policy,
        },
        Rollback {
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
        let controller = RUNNER
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|r| r.policy.clone())
            .ok_or("Policy session unavailable")?;
        if STATE.load(Ordering::SeqCst) != 2 {
            return Err("Wait for the connected policy session");
        }
        if let Mutation::Preview {
            expected,
            policy,
            destination,
        } = &mutation
        {
            let destination = destination
                .parse()
                .map_err(|_| "Preview requires numeric IP:port")?;
            let decision = controller
                .preview(expected, policy, destination)
                .map_err(|_| "Policy preview unavailable or unauthorized")?;
            return Ok(
                serde_json::json!({"ok":true,"version":controller.version(),"decision":decision}),
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
                            Mutation::Apply { expected, policy } => {
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
            serde_json::json!({"ok":true,"version":version,"scope":"flow_policy_only_os_configuration_unchanged"}),
        )
    })();
    let value = match result {
        Ok(value) => value,
        Err(message) => serde_json::json!({"ok":false,"message":message}),
    };
    JString::new(env, value.to_string())
}

async fn run(
    profile: Profile,
    fd: OwnedFd,
    protect: SocketProtector,
    mut cancel: watch::Receiver<bool>,
    router: Arc<rtrust_engine::routing::Router>,
    runner_session: u64,
    mut policy: rtrust_tun::policy::Receiver,
) -> std::io::Result<()> {
    // VpnService configured addresses, DNS and routes before handing over the FD.
    let device = Arc::new(unsafe { tun_rs::AsyncDevice::from_fd(fd.into_raw_fd()) }?);
    let dns = rtrust_engine::dns::encrypted(&profile.endpoint.dns_upstreams)
        .map_err(std::io::Error::other)?
        .unwrap_or_default();
    let routing = Some((router, protect.clone()));
    let mut budget = rtrust_mobile::recovery::Budget::default();
    loop {
        let connected = tokio::select! {
            _=cancel.changed()=>break,
            result=tokio::time::timeout(rtrust_mobile::recovery::ATTEMPT_TIMEOUT, async {
                let session=Session::connect_protected(&profile,&protect).await?;
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
                        "Connected · IPv4, IPv6 and DNS"
                    } else {
                        "Connected · IPv4 and DNS"
                    },
                );
                let started = std::time::Instant::now();
                tokio::select! {
                    _=cancel.changed()=>break,
                    _=rtrust_tun::run_with_policy(session,tunnel,device.clone(),"169.254.254.2".parse().unwrap(),dns.clone(),routing.clone(),Some(&mut policy))=>{},
                }
                FLOWS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .transport_lost(runner_session);
                budget.disconnected(started.elapsed());
                state(3, "Connection lost; traffic blocked while reconnecting");
            }
            Err(error) => {
                FLOWS
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .transport_lost(runner_session);
                state(3, &error.to_string());
                if matches!(
                    error,
                    rtrust_engine::Error::Authentication
                        | rtrust_engine::Error::Tls
                        | rtrust_engine::Error::Trust
                        | rtrust_engine::Error::Unsupported(_)
                        | rtrust_engine::Error::Profile
                ) {
                    state(4, &error.to_string());
                    let _ = cancel.changed().await;
                    break;
                }
            }
        }
        let delay = budget.next_delay(rand::random());
        tokio::select! {_=cancel.changed()=>break,_=tokio::time::sleep(delay)=>{}}
    }
    Ok(())
}
