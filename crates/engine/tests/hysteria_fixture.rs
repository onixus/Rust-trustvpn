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
