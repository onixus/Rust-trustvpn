//! Opt-in production interop. No credentials or endpoint names are printed.
use rtrust_engine::{Session, dns, udp};
use rtrust_profile::{Profile, Protocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[tokio::test]
#[ignore = "requires RTRUST_HYSTERIA_TEST_PROFILE pointing to a private authorized config"]
async fn hysteria_authenticated_tcp_udp_and_encrypted_dns() {
    let path = std::env::var("RTRUST_HYSTERIA_TEST_PROFILE").expect("private config path");
    let input = zeroize::Zeroizing::new(std::fs::read_to_string(path).unwrap());
    let profile = Profile::import(&input).unwrap();
    assert_eq!(profile.protocol, Protocol::Hysteria2);
    let session = Session::connect(&profile).await.unwrap();
    session.health().await.unwrap();
    let mut tcp = session.open_tcp("api.ipify.org:80").await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = vec![];
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tcp.take(32768).read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    let query = [
        0x72, 0x74, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 1, 0, 1,
    ];
    let mut tunnel = session.open_udp().await.unwrap();
    let packet = udp::Datagram {
        source: "10.42.0.2:53000".parse().unwrap(),
        destination: "1.1.1.1:53".parse().unwrap(),
        payload: query.to_vec(),
    };
    tunnel
        .write_all(&udp::encode(&packet, "interop").unwrap())
        .await
        .unwrap();
    let answer = tokio::time::timeout(std::time::Duration::from_secs(10), udp::read(&mut tunnel))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer.destination, packet.source);
    assert_eq!(answer.source, packet.destination);
    assert_eq!(&answer.payload[..2], &query[..2]);
    assert!(answer.payload.len() > query.len());
    let resolver = dns::Resolver::parse("https://cloudflare-dns.com/dns-query").unwrap();
    let encrypted = dns::exchange(&[resolver], &session, &query).await.unwrap();
    assert!(encrypted.len() > query.len());
    let mut wrong = profile.clone();
    wrong.endpoint.password = rtrust_profile::Secret::new("invalid-test-credential");
    assert!(Session::connect(&wrong).await.is_err());
}
