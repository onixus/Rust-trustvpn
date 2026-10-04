use rtrust_engine::{Session, udp};
use rtrust_profile::Profile;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
#[ignore = "run through ci/hysteria_interop.py"]
async fn official_server_tcp_payload_udp_fragmentation_and_multiplexing() {
    let path = std::env::var("RTRUST_HYSTERIA_FIXTURE").unwrap();
    let input = zeroize::Zeroizing::new(std::fs::read_to_string(path).unwrap());
    let profile = Profile::import(&input).unwrap();
    let session = Session::connect(&profile).await.unwrap();
    let tcp_port = std::env::var("RTRUST_HYSTERIA_TCP").unwrap();
    let udp_port = std::env::var("RTRUST_HYSTERIA_UDP").unwrap();
    let mut tcp = session
        .open_tcp(&format!("127.0.0.1:{tcp_port}"))
        .await
        .unwrap();
    let payload: Vec<_> = (0..512 * 1024).map(|n| n as u8).collect();
    tcp.write_u32(payload.len() as u32).await.unwrap();
    tcp.write_all(&payload).await.unwrap();
    let mut response = vec![];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tcp.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response,
        format!("{:x}", Sha256::digest(&payload)).as_bytes()
    );
    let mut first = session.open_udp().await.unwrap();
    let mut second = session.open_udp().await.unwrap();
    let max_udp: usize = std::env::var("RTRUST_HYSTERIA_MAX_UDP")
        .unwrap()
        .parse()
        .unwrap();
    for size in [1, 1472, 4000, 5000, 8192, 60000, 65507]
        .into_iter()
        .filter(|n| *n <= max_udp)
    {
        let a = udp::Datagram {
            source: "10.0.0.2:12000".parse().unwrap(),
            destination: format!("127.0.0.1:{udp_port}").parse().unwrap(),
            payload: (0..size).map(|n| n as u8).collect(),
        };
        let b = udp::Datagram {
            source: "10.0.0.3:12001".parse().unwrap(),
            destination: a.destination,
            payload: vec![77; size],
        };
        first
            .write_all(&udp::encode(&a, "first").unwrap())
            .await
            .unwrap();
        second
            .write_all(&udp::encode(&b, "second").unwrap())
            .await
            .unwrap();
        let (ra, rb) = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            tokio::try_join!(udp::read(&mut first), udp::read(&mut second))
        })
        .await
        .unwrap_or_else(|_| panic!("UDP timeout for payload {size}"))
        .unwrap();
        // Official Hysteria 2.12.3 reads replies into a 4096-byte buffer.
        // Large outbound requests are verified by a small length+hash reply.
        let expected = |payload: &[u8]| {
            if payload.len() <= 4000 {
                payload.to_vec()
            } else {
                format!("SHA256:{}:{:x}", payload.len(), Sha256::digest(payload)).into_bytes()
            }
        };
        assert_eq!(ra.payload, expected(&a.payload));
        assert_eq!(rb.payload, expected(&b.payload));
        assert_eq!(ra.destination, a.source);
        assert_eq!(rb.destination, b.source);
    }
    // pinSHA256 is checked on the leaf certificate in addition to CA validation.
    let leaf = rustls_pemfile::certs(&mut profile.endpoint.certificate.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let pin = format!("{:x}", Sha256::digest(leaf.as_ref()));
    let mut pinned = profile.clone();
    pinned.hysteria2.as_mut().unwrap().pin_sha256 = pin.clone();
    let session = Session::connect(&pinned).await.unwrap();
    session.health().await.unwrap();
    let mut wrong = pinned.clone();
    wrong.hysteria2.as_mut().unwrap().pin_sha256 = "00".repeat(32);
    assert!(matches!(
        Session::connect(&wrong).await,
        Err(rtrust_engine::Error::Tls)
    ));
    // A matching pin never replaces chain validation.
    wrong = pinned;
    wrong.endpoint.certificate.clear();
    assert!(Session::connect(&wrong).await.is_err());
    let mut wrong = profile.clone();
    wrong.endpoint.password = rtrust_profile::Secret::new("wrong-password");
    assert!(Session::connect(&wrong).await.is_err());
    wrong = profile.clone();
    wrong.endpoint.certificate.clear();
    assert!(Session::connect(&wrong).await.is_err());
    wrong = profile;
    wrong.hysteria2.as_mut().unwrap().salamander =
        rtrust_profile::Secret::new("wrong-obfuscation-password");
    assert!(Session::connect(&wrong).await.is_err());
}

/// Exchanges `payload` with the fixture's length-prefixed SHA-256 echo.
async fn digest_exchange(session: &Session, target: &str, payload: &[u8]) {
    let mut tcp = session.open_tcp(target).await.unwrap();
    tcp.write_u32(payload.len() as u32).await.unwrap();
    tcp.write_all(payload).await.unwrap();
    let mut response = vec![];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tcp.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        response,
        format!("{:x}", Sha256::digest(payload)).as_bytes()
    );
}
#[tokio::test]
#[ignore = "run through ci/hysteria_interop.py"]
async fn official_server_port_hopping_bandwidth_and_quic_options() {
    let path = std::env::var("RTRUST_HYSTERIA_HOP_FIXTURE").unwrap();
    let input = zeroize::Zeroizing::new(std::fs::read_to_string(path).unwrap());
    let profile = Profile::import(&input).unwrap();
    assert!(!profile.hysteria2.as_ref().unwrap().hop_ports.is_empty());
    let session = Session::connect(&profile).await.unwrap();
    let target = format!(
        "127.0.0.1:{}",
        std::env::var("RTRUST_HYSTERIA_TCP").unwrap()
    );
    let udp_port = std::env::var("RTRUST_HYSTERIA_UDP").unwrap();
    // One stream stays open across several 5-second hops.
    let chunk: Vec<u8> = (0..16 * 1024).map(|n| (n * 7) as u8).collect();
    let rounds = 7;
    let mut long = session.open_tcp(&target).await.unwrap();
    long.write_u32((chunk.len() * rounds) as u32).await.unwrap();
    let mut digest = Sha256::new();
    for round in 0..rounds {
        long.write_all(&chunk).await.unwrap();
        digest.update(&chunk);
        let payload: Vec<u8> = (0..256 * 1024).map(|n| (n + round) as u8).collect();
        digest_exchange(&session, &target, &payload).await;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let mut response = vec![];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        long.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, format!("{:x}", digest.finalize()).as_bytes());
    let mut udp_tunnel = session.open_udp().await.unwrap();
    let datagram = udp::Datagram {
        source: "10.0.0.2:12000".parse().unwrap(),
        destination: format!("127.0.0.1:{udp_port}").parse().unwrap(),
        payload: vec![42; 3000],
    };
    udp_tunnel
        .write_all(&udp::encode(&datagram, "hop").unwrap())
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        udp::read(&mut udp_tunnel),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply.payload, datagram.payload);
    // Brutal at 20 Mbit/s (quinn paces 1.25x) bounds a 5 MB upload to well over
    // a second; loopback without the negotiated rate finishes far sooner.
    let bulk: Vec<u8> = (0..5_000_000).map(|n| n as u8).collect();
    let started = std::time::Instant::now();
    digest_exchange(&session, &target, &bulk).await;
    let elapsed = started.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(1200),
        "{elapsed:?}"
    );
    assert!(elapsed <= std::time::Duration::from_secs(8), "{elapsed:?}");
    session.health().await.unwrap();
}
#[tokio::test]
#[ignore = "run through ci/hysteria_interop.py"]
async fn official_server_gecko_obfuscation_and_mutual_tls() {
    let read = |name: &str| {
        let path = std::env::var(name).unwrap();
        let input = zeroize::Zeroizing::new(std::fs::read_to_string(path).unwrap());
        Profile::import(&input).unwrap()
    };
    let profile = read("RTRUST_HYSTERIA_GECKO_FIXTURE");
    assert!(profile.hysteria2.as_ref().unwrap().gecko.is_some());
    let session = Session::connect(&profile).await.unwrap();
    let target = format!(
        "127.0.0.1:{}",
        std::env::var("RTRUST_HYSTERIA_TCP").unwrap()
    );
    let payload: Vec<u8> = (0..512 * 1024).map(|n| (n * 3) as u8).collect();
    digest_exchange(&session, &target, &payload).await;
    let mut udp_tunnel = session.open_udp().await.unwrap();
    let datagram = udp::Datagram {
        source: "10.0.0.2:12000".parse().unwrap(),
        destination: format!(
            "127.0.0.1:{}",
            std::env::var("RTRUST_HYSTERIA_UDP").unwrap()
        )
        .parse()
        .unwrap(),
        payload: vec![7; 1400],
    };
    udp_tunnel
        .write_all(&udp::encode(&datagram, "gecko").unwrap())
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        udp::read(&mut udp_tunnel),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply.payload, datagram.payload);
    // The server requires the client certificate.
    let mut anonymous = profile.clone();
    let options = anonymous.hysteria2.as_mut().unwrap();
    assert!(!options.client_certificate.is_empty());
    options.client_certificate.clear();
    options.client_key = rtrust_profile::Secret::new("");
    assert!(Session::connect(&anonymous).await.is_err());
    // Gecko and Salamander are not interchangeable in either direction.
    let mut plain = profile.clone();
    plain.hysteria2.as_mut().unwrap().gecko = None;
    assert!(Session::connect(&plain).await.is_err());
    let mut mismatch = read("RTRUST_HYSTERIA_FIXTURE");
    mismatch.hysteria2.as_mut().unwrap().gecko = profile.hysteria2.unwrap().gecko;
    assert!(Session::connect(&mismatch).await.is_err());
}
