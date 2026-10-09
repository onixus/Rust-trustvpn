#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if args.first().is_some_and(|s| s == "--recover-service") {
        rtrust_control::Client::recover().await?;
        println!("SERVICE recovered");
        return Ok(());
    }
    let path = args
        .first()
        .ok_or("Usage: rtrust-inspect FILE [--probe-http HOST:PORT]")?;
    let bytes = rtrust_store::read_bounded(std::path::Path::new(path), rtrust_profile::MAX_INPUT)?;
    let p = rtrust_profile::Profile::import(
        std::str::from_utf8(&bytes).map_err(|_| "Input must be UTF-8")?,
    )?;
    println!(
        "Valid profile. Addresses: {}. Transport: {}. Credentials: [REDACTED]",
        p.endpoint.addresses.len(),
        p.endpoint.upstream_protocol
    );
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    if args.get(1).is_some_and(|s| {
        s == "--serve-tun"
            || (cfg!(any(target_os = "linux", target_os = "macos")) && s == "--serve-full")
    }) {
        use std::io::Write;
        let argument = args
            .get(2)
            .and_then(|s| s.to_str())
            .ok_or("Requires CIDRs or DNS address")?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let client = if args[1] == "--serve-full" {
            rtrust_control::Client::start_full(p, argument.parse()?).await?
        } else {
            rtrust_control::Client::start(
                p,
                rtrust_control::Selection {
                    include: rtrust_control::networks(argument)?,
                    ..Default::default()
                },
            )
            .await?
        };
        #[cfg(target_os = "windows")]
        let client = rtrust_control::Client::start(
            p,
            rtrust_control::Selection {
                include: rtrust_control::networks(argument)?,
                ..Default::default()
            },
        )
        .await?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let terminated = async move {
            terminate.recv().await;
        };
        #[cfg(target_os = "windows")]
        let terminated = std::future::pending::<()>();
        tokio::pin!(terminated);
        println!("SERVICE connected");
        std::io::stdout().flush()?;
        let mut last_state = rtrust_control::State::Connected;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = &mut terminated => break,
                _ = tokio::signal::ctrl_c() => break,
                _ = tick.tick() => {
                    let state = client.status().state;
                    if state != last_state {
                        println!("SERVICE {}", if state == rtrust_control::State::Connected { "connected" } else { "blocked" });
                        std::io::stdout().flush()?;
                        last_state = state;
                    }
                }
            }
        }
        client.close().await?;
        println!("SERVICE stopped");
        return Ok(());
    }
    if args.get(1).is_some_and(|s| s == "--explain-mobile-flow") {
        let destination: std::net::SocketAddr = args
            .get(2)
            .and_then(|s| s.to_str())
            .ok_or("Explain requires IP:PORT; it performs no DNS lookup")?
            .parse()?;
        let (_, plan) = rtrust_mobile::prepare(p)?;
        let decision = plan.flow.compile()?.decide(destination);
        println!("{}", serde_json::to_string(&decision)?);
    } else if args.get(1).is_some_and(|s| s == "--probe-http") {
        let target = args
            .get(2)
            .and_then(|s| s.to_str())
            .ok_or("Probe requires HOST:PORT")?;
        println!("{}", rtrust_engine::probe_http(&p, target).await?);
    } else if args.get(1).is_some_and(|s| s == "--probe-udp") {
        use tokio::io::AsyncWriteExt;
        let destination = args
            .get(2)
            .and_then(|s| s.to_str())
            .ok_or("UDP probe requires IP:PORT")?
            .parse()?;
        tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let session = rtrust_engine::Session::connect(&p).await?;
            session.health().await?;
            let mut stream = session.open_udp().await?;
            let packet = rtrust_engine::udp::Datagram {
                source: "10.0.0.2:42100".parse().unwrap(),
                destination,
                payload: b"rtrust-loopback-echo".to_vec(),
            };
            stream
                .write_all(&rtrust_engine::udp::encode(&packet, "rtrust-inspect")?)
                .await?;
            let reply = rtrust_engine::udp::read(&mut stream).await?;
            if reply.payload != packet.payload
                || reply.source != destination
                || reply.destination != packet.source
            {
                return Err(rtrust_engine::Error::Protocol);
            }
            Ok::<_, rtrust_engine::Error>(())
        })
        .await??;
        println!(
            "UDP echo passed through {} / _udp2",
            p.endpoint.upstream_protocol
        );
    } else if args.get(1).is_some_and(|s| s == "--serve-socks") {
        use std::io::Write;
        let port = args
            .get(2)
            .and_then(|s| s.to_str())
            .ok_or("Requires a local port (0 = automatic)")?
            .parse()?;
        let proxy = rtrust_engine::proxy::Proxy::start(&p, port).await?;
        println!("SOCKS5 {}", proxy.address());
        std::io::stdout().flush()?;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            if let Err(error) = proxy.health().await {
                proxy.stop();
                return Err(error.into());
            }
        }
    } else if args.len() > 1 {
        return Err("Unknown operation".into());
    }
    Ok(())
}
