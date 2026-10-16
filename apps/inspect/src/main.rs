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
        // A live session needs the owner a desktop client stored; without
        // it only a guard retained after the session ended is released.
        #[cfg(target_os = "macos")]
        let owner = tokio::task::spawn_blocking(rtrust_store::load_session_owner).await?;
        #[cfg(not(target_os = "macos"))]
        let owner = None;
        rtrust_control::Client::recover(owner).await?;
        println!("SERVICE recovered");
        return Ok(());
    }
    if args.first().is_some_and(|s| s == "--explain-selected") {
        let (decision, routes) = explain_selected(&args[1..])?;
        println!("{decision}");
        println!("{routes}");
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
        // Optional allowed backups: `--fallback FILE`, repeated, in order.
        let mut fallbacks = Vec::new();
        let mut rest = args[3..].iter();
        while let Some(flag) = rest.next() {
            if flag != "--fallback" {
                return Err("Unknown argument; expected --fallback FILE".into());
            }
            let file = rest.next().ok_or("--fallback requires FILE")?;
            let bytes =
                rtrust_store::read_bounded(std::path::Path::new(file), rtrust_profile::MAX_INPUT)?;
            fallbacks.push(rtrust_profile::Profile::import(
                std::str::from_utf8(&bytes).map_err(|_| "Input must be UTF-8")?,
            )?);
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let client = if args[1] == "--serve-full" {
            rtrust_control::Client::start_full(p, fallbacks, argument.parse()?).await?
        } else {
            rtrust_control::Client::start(
                p,
                fallbacks,
                rtrust_control::Selection {
                    include: rtrust_control::networks(argument)?,
                    ..Default::default()
                },
                None,
            )
            .await?
        };
        #[cfg(target_os = "windows")]
        let client = rtrust_control::Client::start(
            p,
            fallbacks,
            rtrust_control::Selection {
                include: rtrust_control::networks(argument)?,
                ..Default::default()
            },
            None,
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
        if let Some(index) = client.status().active_profile.filter(|&index| index > 0) {
            println!("SERVICE active {index}");
        }
        println!("SERVICE connected");
        std::io::stdout().flush()?;
        let mut last_state = rtrust_control::State::Connected;
        let mut last_active = client.status().active_profile;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(1));
        loop {
            tokio::select! {
                _ = &mut terminated => break,
                _ = tokio::signal::ctrl_c() => break,
                _ = tick.tick() => {
                    let status = client.status();
                    if status.active_profile != last_active {
                        println!("SERVICE active {}", status.active_profile.unwrap_or(0));
                        last_active = status.active_profile;
                    }
                    let state = status.state;
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

const EXPLAIN_SELECTED: &str = "Usage: rtrust-inspect --explain-selected IP --include CIDRS \
[--exclude CIDRS] [--exclude-lan | --lan CIDRS] [--endpoints IPS]";

fn ipv4_list<T: std::str::FromStr>(text: &str) -> Result<Vec<T>, String> {
    text.split([',', ' '])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse().map_err(|_| "Invalid IPv4 list".to_owned()))
        .collect()
}

/// Offline desktop selected-IPv4 prediction using the installation subtraction.
/// No profile, socket, resolver or route change. Returns the decision JSON and,
/// when every runtime input is known, the prefix set `Selection::routes` would
/// install. Neither line contains the destination.
fn explain_selected(
    args: &[std::ffi::OsString],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let mut args = args.iter().map(|a| a.to_str().ok_or(EXPLAIN_SELECTED));
    let destination: std::net::IpAddr = args.next().ok_or(EXPLAIN_SELECTED)??.parse()?;
    let mut include = None;
    let mut exclude = "";
    let mut exclude_lan = false;
    let mut local: Option<Vec<rtrust_control::Ipv4Net>> = None;
    let mut endpoints: Option<Vec<std::net::Ipv4Addr>> = None;
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(EXPLAIN_SELECTED);
        match flag? {
            "--include" => include = Some(value()??),
            "--exclude" => exclude = value()??,
            // Requested but unobserved local networks: the prediction is unknown.
            "--exclude-lan" => exclude_lan = true,
            // Observed local networks, as the service reads them before Start.
            "--lan" => {
                let networks: Vec<rtrust_control::Ipv4Net> = ipv4_list(value()??)?;
                if networks.iter().any(|n| n.trunc() != *n) {
                    return Err("Local networks must be canonical CIDRs".into());
                }
                exclude_lan = true;
                local = Some(networks);
            }
            "--endpoints" => endpoints = Some(ipv4_list(value()??)?),
            _ => return Err(EXPLAIN_SELECTED.into()),
        }
    }
    let selection =
        rtrust_control::Selection::parse(include.ok_or(EXPLAIN_SELECTED)?, exclude, exclude_lan)?;
    // Linux policy-routes only the desktop UID, so the root service's endpoint
    // needs no exception (as Native offline explain). Elsewhere it is unknown
    // unless the caller states the endpoint addresses.
    let endpoints = endpoints.or_else(|| cfg!(target_os = "linux").then(Vec::new));
    let context = rtrust_profile::routing::Context {
        source: rtrust_profile::routing::Source::Local,
        revision: None,
    };
    let decision =
        selection.explain(destination, endpoints.as_deref(), local.as_deref(), context)?;
    let routes = match (&endpoints, &local) {
        (Some(endpoints), _) if !exclude_lan => Some(selection.routes(endpoints, &[])?),
        (Some(endpoints), Some(local)) => Some(selection.routes(endpoints, local)?),
        _ => None,
    };
    Ok((
        serde_json::to_string(&decision)?,
        serde_json::json!({ "routes": routes }).to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::explain_selected;
    fn run(args: &[&str]) -> (serde_json::Value, serde_json::Value) {
        let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
        let (decision, routes) = explain_selected(&args).unwrap();
        assert!(!decision.contains("198.18.1.1") && !decision.contains("2001:db8"));
        (
            serde_json::from_str(&decision).unwrap(),
            serde_json::from_str(&routes).unwrap(),
        )
    }
    const A: [&str; 4] = [
        "--include",
        "198.18.0.0/16,10.0.0.0/8",
        "--exclude",
        "198.18.2.0/24",
    ];
    #[test]
    fn requested_lan_without_observation_is_unknown_and_has_no_route_set() {
        let mut args = vec!["198.18.1.1"];
        args.extend(A);
        args.extend(["--exclude-lan", "--endpoints", ""]);
        let (decision, routes) = run(&args);
        assert_eq!(decision["action"], "unknown");
        assert_eq!(decision["reason"], "local_networks_unobserved");
        assert!(routes["routes"].is_null());
    }
    #[test]
    fn observed_inputs_predict_and_return_installation_prefixes() {
        for (destination, action, reason) in [
            ("198.18.1.1", "tunnel", "selected_prefix"),
            ("198.18.2.1", "direct", "excluded_prefix"),
            ("10.99.0.1", "direct", "local_network_bypass"),
            ("203.0.113.1", "direct", "outside_selection"),
            ("169.254.1.1", "direct", "reserved_address"),
            ("2001:db8::1", "unknown", "unsupported_family"),
        ] {
            let mut args = vec![destination];
            args.extend(A);
            args.extend(["--lan", "10.99.0.0/30", "--endpoints", ""]);
            let (decision, routes) = run(&args);
            assert_eq!(decision["action"], action, "{destination}");
            assert_eq!(decision["reason"], reason, "{destination}");
            assert_eq!(decision["prediction"], true);
            let routes = routes["routes"].as_array().unwrap();
            assert!(routes.iter().any(|r| r == "198.18.0.0/23"));
            assert!(!routes.iter().any(|r| r == "10.99.0.0/30"));
        }
    }
    #[test]
    fn missing_or_invalid_inputs_are_rejected() {
        for args in [
            vec!["198.18.1.1"],
            vec!["not-an-ip", "--include", "198.18.0.0/16"],
            vec!["198.18.1.1", "--include", "198.18.0.1/16"],
            vec![
                "198.18.1.1",
                "--include",
                "198.18.0.0/16",
                "--lan",
                "10.99.0.1/30",
            ],
            vec!["198.18.1.1", "--include", "198.18.0.0/16", "--unknown"],
        ] {
            let args: Vec<std::ffi::OsString> = args.iter().map(Into::into).collect();
            assert!(explain_selected(&args).is_err());
        }
    }
}
