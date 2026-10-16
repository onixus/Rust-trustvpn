//! Linux laboratory harness for issue #32: the mobile flow dataplane on a TUN
//! inside a disposable network namespace. Not packaged and not a product path.
//!
//! Usage (root, inside the test namespace only):
//!   flow-lab PROFILE TUN_NAME BIND_INTERFACE
//!
//! The router comes from `rtrust_mobile::prepare`, the dataplane is
//! `rtrust_tun::run_with_policy` (as Android) and direct sockets are protected
//! with SO_BINDTODEVICE on the physical interface. Observations go through the
//! mobile redaction boundary (`rtrust_mobile::flows::Capture`): output lines
//! contain decisions and SHA-256 revision digests, never destinations or names.
//! The harness never adds routes, DNS or firewall rules; its caller does.
//!
//! stdin commands, one per line, each answered by one or more JSON lines:
//!   observe on|off       explicit opt-in to flow observations (default off)
//!   poll                 drain observed events
//!   version              current redacted policy version
//!   apply-local POLICY   hot local revision through `policy::Controller`
//!                        (prepare_local, drain, commit_local)
#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
fn line(value: serde_json::Value) {
    // Rust stdout is line buffered: each answer reaches the harness at once.
    println!("{value}");
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use rtrust_mobile::flows::Capture;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [profile, name, bind] = args.as_slice() else {
        return Err("Usage: flow-lab PROFILE TUN_NAME BIND_INTERFACE".into());
    };
    for interface in [name, bind] {
        if interface.is_empty()
            || interface.len() > 15
            || !interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err("Invalid interface name".into());
        }
    }
    if std::path::Path::new("/sys/class/net").join(name).exists() {
        return Err("Interface already exists".into());
    }
    let bytes =
        rtrust_store::read_bounded(std::path::Path::new(profile), rtrust_profile::MAX_INPUT)?;
    let profile = rtrust_profile::Profile::import(std::str::from_utf8(&bytes)?)?;
    // Same strict adapter and compiled policy as `rtrust-inspect --explain-mobile-flow`.
    let (profile, plan) = rtrust_mobile::prepare(profile)?;
    let router = Arc::new(
        plan.flow
            .compile_with_context(rtrust_profile::routing::Context::default())?,
    );
    let interface = std::ffi::CString::new(bind.as_str())?;
    let protect: rtrust_engine::SocketProtector = Arc::new(move |fd| {
        let bytes = interface.as_bytes_with_nul();
        // SAFETY: fd is a live socket owned by the engine; the option value is
        // a NUL-terminated interface name that outlives this call.
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                bytes.as_ptr().cast(),
                bytes.len() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    });
    let session = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        rtrust_engine::Session::connect_protected(&profile, &protect),
    )
    .await
    .map_err(|_| "Transport connect timeout")??;
    session.health().await?;
    let tunnel = session.open_udp().await?;
    let address: std::net::Ipv4Addr = "169.254.254.2".parse()?;
    let device = Arc::new(
        tun_rs::DeviceBuilder::new()
            .name(name)
            .mtu(rtrust_tun::packet::MTU as u16)
            .ipv4(address, 32, None)
            .ipv6(rtrust_tun::ipv6::ADDRESS, 128)
            .build_async()?,
    );
    let dns = rtrust_engine::dns::encrypted(&profile.endpoint.dns_upstreams)?.unwrap_or_default();
    let ipv6 = session.ipv6();
    let capture = Arc::new(Mutex::new(Capture::default()));
    let runner = {
        let mut capture = capture.lock().unwrap();
        let runner = capture.attach(router.clone());
        capture.transport_ready(runner);
        runner
    };
    let (controller, mut updates) = rtrust_tun::policy::Controller::new(router.clone());
    line(json!({
        "ready": true,
        "ipv6": ipv6,
        "version": capture.lock().unwrap().snapshot().version,
    }));
    // stdin is blocking; a bounded channel keeps the command queue finite.
    let (commands, mut input) = tokio::sync::mpsc::channel::<String>(8);
    std::thread::spawn(move || {
        for command in std::io::stdin().lines().map_while(Result::ok) {
            if commands.blocking_send(command).is_err() {
                break;
            }
        }
    });
    // Commands run beside the dataplane: apply waits for the dataplane drain.
    let handler = {
        let capture = capture.clone();
        tokio::spawn(async move {
            while let Some(command) = input.recv().await {
                let (verb, argument) = command.split_once(' ').unwrap_or((command.as_str(), ""));
                match verb {
                    "observe" => {
                        let mut capture = capture.lock().unwrap();
                        let token = capture.snapshot().token;
                        match capture.observe(token, argument == "on") {
                            Ok(snapshot) => line(json!({"observe": snapshot.enabled})),
                            Err(error) => line(json!({"error": error})),
                        }
                    }
                    "poll" => {
                        let mut capture = capture.lock().unwrap();
                        let token = capture.snapshot().token;
                        match capture.poll(token) {
                            Ok(snapshot) => {
                                for event in &snapshot.events {
                                    line(json!({"event": event}));
                                }
                                line(json!({
                                    "polled": snapshot.events.len(),
                                    "lagged": snapshot.lagged,
                                    "discarded_stale": snapshot.discarded_stale,
                                    "discarded_oversize": snapshot.discarded_oversize,
                                    "version": snapshot.version,
                                }));
                            }
                            Err(error) => line(json!({"error": error})),
                        }
                    }
                    "version" => {
                        line(json!({"version": capture.lock().unwrap().snapshot().version}))
                    }
                    "apply-local" => {
                        let result = match serde_json::from_str(argument) {
                            Ok(policy) => {
                                controller
                                    .apply(
                                        controller.version(),
                                        policy,
                                        rtrust_profile::routing::Context::default(),
                                    )
                                    .await
                            }
                            Err(_) => Err("Invalid policy JSON".into()),
                        };
                        match result {
                            Ok(_) => line(json!({
                                "applied": capture.lock().unwrap().snapshot().version,
                            })),
                            Err(error) => line(json!({"error": error})),
                        }
                    }
                    _ => line(json!({"error": "Unknown command"})),
                }
            }
        })
    };
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        ended = rtrust_tun::run_with_policy(session, tunnel, device, address, dns, Some((router, protect)), Some(&mut updates)) => ended,
        _ = terminate.recv() => Ok(()),
        _ = tokio::signal::ctrl_c() => Ok(()),
    };
    handler.abort();
    capture.lock().unwrap().detach_session(runner);
    if result.is_err() {
        line(json!({"ended": true, "degraded": rtrust_tun::degraded(&result)}));
    }
    result
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("flow-lab requires Linux");
    std::process::exit(1);
}
