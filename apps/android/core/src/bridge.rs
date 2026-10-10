use jni::{
    Env, JValue, JavaVM, jni_sig, jni_str, native_method,
    objects::{JObject, JString},
    sys::{jboolean, jint},
};
use rtrust_engine::{Session, SocketProtector};
use rtrust_profile::Profile;
use std::{
    os::fd::{FromRawFd, IntoRawFd, OwnedFd},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::watch;
use zeroize::Zeroizing;

struct Runner {
    cancel: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
}
static RUNNER: Mutex<Option<Runner>> = Mutex::new(None);
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
    state(1, "Connecting securely");
    let thread = std::thread::Builder::new()
        .name("rtrust-android".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()?;
                runtime.block_on(run(profile, owned, protect, receiver))
            }));
            if !matches!(result, Ok(Ok(()))) {
                state(
                    4,
                    "VPN worker stopped; traffic remains blocked until Disconnect",
                );
            }
        });
    match thread {
        Ok(thread) => {
            *slot = Some(Runner { cancel, thread });
            Ok(true)
        }
        Err(_) => {
            state(4, "Cannot start VPN worker");
            Ok(false)
        }
    }
}
const _: jni::NativeMethod =
    native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn stop(),};
fn stop(_env: &mut Env<'_>, _this: JObject<'_>) -> jni::errors::Result<()> {
    let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(runner) = slot.take() {
        let _ = runner.cancel.send(true);
        let _ = runner.thread.join();
    }
    state(0, "");
    Ok(())
}
const _: jni::NativeMethod =
    native_method! {java_type="org.rtrusttunnel.android.NativeCore",extern fn status()->JString,};
fn status<'a>(env: &mut Env<'a>, _this: JObject<'a>) -> jni::errors::Result<JString<'a>> {
    let message = MESSAGE.lock().unwrap_or_else(|p| p.into_inner());
    JString::new(
        env,
        serde_json::json!({"state":STATE.load(Ordering::SeqCst),"message":&*message,"observations":OBSERVATIONS.lock().unwrap_or_else(|p| p.into_inner()).snapshot()}).to_string(),
    )
}
async fn run(
    profile: Profile,
    fd: OwnedFd,
    protect: SocketProtector,
    mut cancel: watch::Receiver<bool>,
) -> std::io::Result<()> {
    // VpnService configured addresses, DNS and routes before handing over the FD.
    let device = Arc::new(unsafe { tun_rs::AsyncDevice::from_fd(fd.into_raw_fd()) }?);
    let dns = rtrust_engine::dns::encrypted(&profile.endpoint.dns_upstreams)
        .map_err(std::io::Error::other)?
        .unwrap_or_default();
    let policy: rtrust_engine::routing::Policy =
        serde_json::from_value(profile.policy.clone()).map_err(std::io::Error::other)?;
    let routing = Some((
        Arc::new(policy.compile().map_err(std::io::Error::other)?),
        protect.clone(),
    ));
    let mut delay = 1;
    loop {
        let connected = tokio::select! {
            _=cancel.changed()=>break,
            result=async {
                let session=Session::connect_protected(&profile,&protect).await?;
                session.health().await?;
                let tunnel=session.open_udp().await?;
                Ok::<_,rtrust_engine::Error>((session,tunnel))
            }=>result,
        };
        match connected {
            Ok((session, tunnel)) => {
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
                    _=rtrust_tun::run_android(session,tunnel,device.clone(),"169.254.254.2".parse().unwrap(),dns.clone(),routing.clone())=>{},
                }
                if started.elapsed() > Duration::from_secs(30) {
                    delay = 1;
                }
                state(3, "Connection lost; traffic blocked while reconnecting");
            }
            Err(error) => {
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
        tokio::select! {_=cancel.changed()=>break,_=tokio::time::sleep(Duration::from_secs(delay))=>{}}
        delay = (delay * 2).min(30);
    }
    Ok(())
}
