//! C ABI for NEPacketTunnelFlow. No private utun file descriptor access.
use rtrust_profile::{Format, Profile};
use std::{
    ffi::{CString, c_char},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

const PACKET_LIMIT: usize = 65535;
const QUEUE: usize = 64;
static RUNNER: Mutex<Option<Runner>> = Mutex::new(None);
static STATE: AtomicU8 = AtomicU8::new(0); // idle, connecting, connected, reconnecting, failed
struct Runner {
    input: mpsc::Sender<Vec<u8>>,
    output: mpsc::Receiver<Vec<u8>>,
    cancel: watch::Sender<bool>,
    thread: std::thread::JoinHandle<()>,
}
struct Device {
    input: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    output: mpsc::Sender<Vec<u8>>,
}
impl rtrust_tun::PacketDevice for Device {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let packet = self
            .input
            .lock()
            .await
            .recv()
            .await
            .ok_or(std::io::ErrorKind::BrokenPipe)?;
        if packet.len() > buffer.len() {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        buffer[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        // Drop under pressure, as an IP interface does; never grow unbounded.
        match self.output.try_send(packet.to_vec()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(packet.len()),
            Err(_) => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }
}
fn prepare(raw: &str) -> Result<Profile, &'static str> {
    let p = Profile::import(raw).map_err(|_| "Invalid profile")?;
    rtrust_engine::check_capabilities(&p).map_err(|_| "Unsupported endpoint security settings")?;
    let (_, plan) =
        rtrust_mobile::prepare(p.clone()).map_err(|_| "Unsupported routing or DNS policy")?;
    if plan.require_lockdown {
        return Err("Android lockdown policy requires managed-device support on iOS");
    }
    Ok(p)
}
// All input buffers are borrowed only for the duration of the call.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Result<&'a str, &'static str> {
    if ptr.is_null() || len == 0 || len > rtrust_profile::MAX_INPUT {
        return Err("Invalid input size");
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) })
        .map_err(|_| "Invalid UTF-8")
}
/// Returns owned JSON (including credentials on success); release with rtrust_ios_free.
/// # Safety
/// ptr must reference len readable bytes for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtrust_ios_prepare(ptr: *const u8, len: usize) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        let p = prepare(unsafe { input(ptr, len) }?)?;
        let canonical = p
            .export(Format::Json)
            .map_err(|_| "Cannot encode profile")?;
        let (_, plan) =
            rtrust_mobile::prepare(p.clone()).map_err(|_| "Unsupported routing or DNS policy")?;
        Ok::<_, &'static str>(serde_json::json!({"ok":true,"profile":&*canonical.content,
            "hostname":p.endpoint.hostname,"name":p.name,"dns":plan.dns,
            "routes":plan.routes,"mtu":plan.mtu,"ipv6":plan.ipv6}))
    });
    let value = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => serde_json::json!({"ok":false,"message":e}),
        Err(_) => serde_json::json!({"ok":false,"message":"Core failure"}),
    };
    CString::new(value.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
/// Export preserves codec loss warnings for explicit UI confirmation.
/// # Safety
/// ptr must reference len readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtrust_ios_export(ptr: *const u8, len: usize, format: i32) -> *mut c_char {
    let result = std::panic::catch_unwind(|| {
        let p = Profile::import(unsafe { input(ptr, len) }?).map_err(|_| "Invalid profile")?;
        let format = match format {
            0 => Format::Json,
            1 => Format::EndpointToml,
            2 => Format::CliToml,
            3 => Format::Link,
            4 => Format::Conf,
            _ => return Err("Unknown format"),
        };
        let export = p.export(format).map_err(|_| "Cannot export this format")?;
        Ok::<_, &'static str>(
            serde_json::json!({"ok":true,"content":&*export.content,"losses":export.losses}),
        )
    });
    let value = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => serde_json::json!({"ok":false,"message":e}),
        Err(_) => serde_json::json!({"ok":false,"message":"Core failure"}),
    };
    CString::new(value.to_string())
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}
/// # Safety
/// ptr must be null or an unfreed pointer returned by rtrust_ios_prepare.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtrust_ios_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        let bytes = unsafe { CString::from_raw(ptr) }.into_bytes_with_nul();
        drop(Zeroizing::new(bytes));
    }
}
/// # Safety
/// ptr must reference len readable bytes during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtrust_ios_start(ptr: *const u8, len: usize) -> bool {
    std::panic::catch_unwind(|| {
        let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
        if slot.is_some() {
            return false;
        }
        let Ok(raw) = (unsafe { input(ptr, len) }) else {
            return false;
        };
        let Ok(original) = prepare(raw) else {
            return false;
        };
        let Ok((profile, _)) = rtrust_mobile::prepare(original) else {
            return false;
        };
        let (input, incoming) = mpsc::channel(QUEUE);
        let (outgoing, output) = mpsc::channel(QUEUE);
        let device = Arc::new(Device {
            input: tokio::sync::Mutex::new(incoming),
            output: outgoing,
        });
        let (cancel, receiver) = watch::channel(false);
        STATE.store(1, Ordering::Release);
        let thread = std::thread::Builder::new()
            .name("rtrust-ios".into())
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?;
                    runtime.block_on(run(profile, device, receiver));
                    Ok::<_, std::io::Error>(())
                }));
                if !matches!(result, Ok(Ok(()))) {
                    STATE.store(4, Ordering::Release);
                }
            });
        match thread {
            Ok(thread) => {
                *slot = Some(Runner {
                    input,
                    output,
                    cancel,
                    thread,
                });
                true
            }
            Err(_) => {
                STATE.store(4, Ordering::Release);
                false
            }
        }
    })
    .unwrap_or(false)
}
async fn run(profile: Profile, device: Arc<Device>, mut cancel: watch::Receiver<bool>) {
    let dns = match rtrust_engine::dns::encrypted(&profile.endpoint.dns_upstreams) {
        Ok(dns) => dns.unwrap_or_default(),
        Err(_) => {
            STATE.store(4, Ordering::Release);
            return;
        }
    };
    let policy: rtrust_engine::routing::Policy =
        match serde_json::from_value(profile.policy.clone()) {
            Ok(p) => p,
            Err(_) => {
                STATE.store(4, Ordering::Release);
                return;
            }
        };
    let router = match policy.compile() {
        Ok(r) => Arc::new(r),
        Err(_) => {
            STATE.store(4, Ordering::Release);
            return;
        }
    };
    // NEPacketTunnelProvider's BSD sockets use the physical network. Unlike Android,
    // iOS needs no VpnService.protect call; includeAllNetworks is intentionally not used.
    let bypass: rtrust_engine::SocketProtector = Arc::new(|_| Ok(()));
    let routing = Some((router, bypass));
    let mut delay = 1;
    loop {
        let attempt = tokio::select! {
            _ = cancel.changed() => return,
            result = async {
                let session = rtrust_engine::Session::connect(&profile).await?;
                session.health().await?;
                let tunnel = session.open_udp().await?;
                Ok::<_,rtrust_engine::Error>((session,tunnel))
            } => result,
        };
        match attempt {
            Ok((session, tunnel)) => {
                STATE.store(2, Ordering::Release);
                let started = std::time::Instant::now();
                tokio::select! {
                    _ = cancel.changed() => return,
                    _ = rtrust_tun::run_packet_flow(session,tunnel,device.clone(),"169.254.254.2".parse().unwrap(),dns.clone(),routing.clone()) => {}
                }
                if started.elapsed() > Duration::from_secs(30) {
                    delay = 1;
                }
            }
            Err(
                rtrust_engine::Error::Authentication
                | rtrust_engine::Error::Tls
                | rtrust_engine::Error::Trust
                | rtrust_engine::Error::Profile
                | rtrust_engine::Error::Unsupported(_),
            ) => {
                STATE.store(4, Ordering::Release);
                let _ = cancel.changed().await;
                return;
            }
            Err(_) => {}
        }
        STATE.store(3, Ordering::Release);
        tokio::select! { _ = cancel.changed() => return, _ = tokio::time::sleep(Duration::from_secs(delay)) => {} }
        delay = (delay * 2).min(30);
    }
}
#[unsafe(no_mangle)]
pub extern "C" fn rtrust_ios_status() -> u8 {
    STATE.load(Ordering::Acquire)
}
#[unsafe(no_mangle)]
pub extern "C" fn rtrust_ios_stop() {
    // Serialize start with shutdown so a previous worker cannot overwrite new state.
    let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    if let Some(runner) = slot.take() {
        let _ = runner.cancel.send(true);
        let _ = runner.thread.join();
    }
    STATE.store(0, Ordering::Release);
}
/// # Safety
/// ptr must reference len readable bytes during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtrust_ios_push(ptr: *const u8, len: usize) -> bool {
    if ptr.is_null() || !(20..=PACKET_LIMIT).contains(&len) {
        return false;
    }
    let packet = unsafe { std::slice::from_raw_parts(ptr, len) };
    if !matches!(packet[0] >> 4, 4 | 6) {
        return false;
    }
    let slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    slot.as_ref()
        .is_some_and(|r| r.input.try_send(packet.to_vec()).is_ok())
}
/// Nonblocking, returns zero when empty. Buffer must have capacity >= 65535.
/// # Safety
/// ptr must reference capacity writable bytes during this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rtrust_ios_pop(ptr: *mut u8, capacity: usize) -> usize {
    if ptr.is_null() || capacity < PACKET_LIMIT {
        return 0;
    }
    let mut slot = RUNNER.lock().unwrap_or_else(|p| p.into_inner());
    let Some(r) = slot.as_mut() else {
        return 0;
    };
    let Ok(packet) = r.output.try_recv() else {
        return 0;
    };
    unsafe {
        std::ptr::copy_nonoverlapping(packet.as_ptr(), ptr, packet.len());
    }
    packet.len()
}
#[cfg(test)]
mod tests {
    use super::*;
    const PROFILE: &str = "hostname='test.example'\naddresses=['192.0.2.1:443']\nusername='test'\npassword='ios-secret-canary'\n";
    #[test]
    fn rejects_policy_and_invalid_inputs_without_leaking_secrets() {
        let mut p = Profile::import(PROFILE).unwrap();
        p.policy = serde_json::json!({"kill_switch":"always_on"});
        assert!(prepare(&p.export(Format::Json).unwrap().content).is_err());
        assert!(prepare(&PROFILE.replace("192.0.2.1:443", "test.example:443")).is_ok());
        assert!(prepare(PROFILE).is_ok());
        unsafe {
            let output = rtrust_ios_prepare(std::ptr::null(), usize::MAX);
            let text = std::ffi::CStr::from_ptr(output).to_str().unwrap();
            assert!(text.contains("false"));
            assert!(!text.contains("canary"));
            rtrust_ios_free(output);
            assert!(!rtrust_ios_push(std::ptr::null(), 20));
        }
    }
    #[test]
    fn ffi_roundtrip_and_cancelled_worker_can_restart() {
        unsafe {
            let pointer = rtrust_ios_prepare(PROFILE.as_ptr(), PROFILE.len());
            let response: serde_json::Value =
                serde_json::from_str(std::ffi::CStr::from_ptr(pointer).to_str().unwrap()).unwrap();
            let canonical = response["profile"].as_str().unwrap();
            assert!(prepare(canonical).is_ok());
            assert_eq!(response["dns"], serde_json::json!(["1.1.1.1"]));
            rtrust_ios_free(pointer);
            let local = PROFILE.replace("192.0.2.1:443", "127.0.0.1:9");
            for _ in 0..2 {
                assert!(rtrust_ios_start(local.as_ptr(), local.len()));
                assert!(!rtrust_ios_start(local.as_ptr(), local.len()));
                rtrust_ios_stop();
                assert_eq!(rtrust_ios_status(), 0);
            }
            rtrust_ios_stop();
        }
    }
    #[test]
    fn portable_policy_is_preserved_while_runtime_plan_is_adapted() {
        let mut p = Profile::import(PROFILE).unwrap();
        p.policy = serde_json::json!({"mode":"selective","exclusions":["*.example.com:443"],"included_routes":["10.0.0.0/8"],"dns_upstreams":["https://dns.example/dns-query"]});
        let raw = p.export(Format::Json).unwrap();
        let preserved = prepare(&raw.content).unwrap();
        assert_eq!(preserved.policy, p.policy);
        let (runtime, plan) = rtrust_mobile::prepare(preserved).unwrap();
        assert!(plan.routes.contains(&"198.18.0.53/32".to_owned()));
        assert_eq!(plan.dns, ["198.18.0.53"]);
        assert_eq!(runtime.policy["mode"], "selective");
        assert!(!plan.require_lockdown);
    }
    #[test]
    fn ffi_export_roundtrips_and_retains_loss_warnings() {
        unsafe {
            for format in 0..4 {
                let pointer = rtrust_ios_export(PROFILE.as_ptr(), PROFILE.len(), format);
                let value: serde_json::Value =
                    serde_json::from_str(std::ffi::CStr::from_ptr(pointer).to_str().unwrap())
                        .unwrap();
                assert_eq!(value["ok"], true);
                let restored = Profile::import(value["content"].as_str().unwrap()).unwrap();
                assert_eq!(restored.endpoint.password.expose(), "ios-secret-canary");
                assert!(value["losses"].is_array());
                rtrust_ios_free(pointer);
            }
        }
    }
    #[tokio::test]
    async fn packets_preserve_boundaries_and_queues_apply_backpressure() {
        use rtrust_tun::PacketDevice;
        let (tx, rx) = mpsc::channel(1);
        let (out, mut replies) = mpsc::channel(1);
        let device = Device {
            input: tokio::sync::Mutex::new(rx),
            output: out,
        };
        tx.try_send(vec![1, 2, 3]).unwrap();
        assert!(tx.try_send(vec![4]).is_err());
        let mut buffer = [0; 8];
        assert_eq!(device.recv(&mut buffer).await.unwrap(), 3);
        assert_eq!(&buffer[..3], &[1, 2, 3]);
        device.send(&[5, 6]).await.unwrap();
        device.send(&[7]).await.unwrap();
        assert_eq!(replies.recv().await.unwrap(), vec![5, 6]);
        assert!(replies.try_recv().is_err());
    }
}
