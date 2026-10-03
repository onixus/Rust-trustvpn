use rtrust_engine::{Session, udp};
use rtrust_profile::Profile;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|n| (n as u8).wrapping_mul(31) ^ seed)
        .collect()
}
/// Length-prefixed upload answered by the SHA-256 of the payload.
async fn digest(session: &Session, target: &str, data: &[u8], pause: Duration) {
    let mut tcp = session.open_tcp(target).await.unwrap();
    tcp.write_u32(data.len() as u32).await.unwrap();
    let (first, second) = data.split_at(data.len() / 2);
    tcp.write_all(first).await.unwrap();
    tokio::time::sleep(pause).await;
    tcp.write_all(second).await.unwrap();
    let mut response = vec![];
    tokio::time::timeout(Duration::from_secs(20), tcp.read_to_end(&mut response))
        .await
        .unwrap_or_else(|_| panic!("TCP timeout for {target}"))
        .unwrap();
    assert_eq!(response, format!("{:x}", Sha256::digest(data)).as_bytes());
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/amneziawg_interop.py"]
async fn reference_peer_tcp_udp_dns_and_rekey() {
    let path = std::env::var("RTRUST_AMNEZIAWG_FIXTURE").unwrap();
    let input = zeroize::Zeroizing::new(std::fs::read_to_string(&path).unwrap());
    let profile = Profile::import(&input).unwrap();
    assert_eq!(profile.transport_name(), "AmneziaWG");
    let session = Session::connect(&profile).await.unwrap();
    session.health().await.unwrap();
    assert!(session.ipv6());

    // Payload integrity over IPv4, IPv6 and a name resolved inside the tunnel.
    for target in ["10.8.1.1:8080", "[fd00:8::1]:8080", "fixture.test:8080"] {
        digest(&session, target, &payload(512 * 1024, 1), Duration::ZERO).await;
    }
    // Parallel streams share the tunnel without corrupting each other.
    let streams = (0..8u8).map(|n| {
        let session = session.clone();
        tokio::spawn(async move {
            digest(
                &session,
                "10.8.1.1:8080",
                &payload(1024 * 1024, n),
                Duration::ZERO,
            )
            .await
        })
    });
    for stream in streams.collect::<Vec<_>>() {
        stream.await.unwrap();
    }
    // A refused port fails instead of hanging.
    assert!(session.open_tcp("10.8.1.1:81").await.is_err());

    // Independent UDP streams; replies return to the right application source.
    let mut first = session.open_udp().await.unwrap();
    let mut second = session.open_udp().await.unwrap();
    for size in [1, 512, 1232] {
        let a = udp::Datagram {
            source: "10.0.0.2:12000".parse().unwrap(),
            destination: "10.8.1.1:7".parse().unwrap(),
            payload: payload(size, 2),
        };
        let b = udp::Datagram {
            source: "[fd00::3]:12001".parse().unwrap(),
            destination: "[fd00:8::1]:7".parse().unwrap(),
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
        let (ra, rb) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::try_join!(udp::read(&mut first), udp::read(&mut second))
        })
        .await
        .unwrap_or_else(|_| panic!("UDP timeout for payload {size}"))
        .unwrap();
        assert_eq!(
            (ra.payload, ra.source, ra.destination),
            (a.payload, a.destination, a.source)
        );
        assert_eq!(
            (rb.payload, rb.source, rb.destination),
            (b.payload, b.destination, b.source)
        );
    }

    // A stream held open across key rotations; the fixture sets short timers.
    if std::env::var("RTRUST_AMNEZIAWG_REKEY").is_ok() {
        digest(
            &session,
            "10.8.1.1:8080",
            &payload(256 * 1024, 3),
            Duration::from_secs(12),
        )
        .await;
        session.health().await.unwrap();
        digest(
            &session,
            "[fd00:8::1]:8080",
            &payload(64 * 1024, 4),
            Duration::ZERO,
        )
        .await;
    }

    // Same obfuscation, wrong preshared key: the peer never answers.
    let rejected = zeroize::Zeroizing::new(std::fs::read_to_string(path + ".rejected").unwrap());
    let started = std::time::Instant::now();
    assert!(
        Session::connect(&Profile::import(&rejected).unwrap())
            .await
            .is_err()
    );
    assert!(started.elapsed() < Duration::from_secs(21));
}
