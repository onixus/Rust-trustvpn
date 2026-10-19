//! Independent tester coverage for issue #99, end to end through a real
//! HTTP/3 session and the public `Session::health`: quiet TCP flows behind a
//! few live ones end as `Degraded { proven: false }`. Synthetic endpoint,
//! certificate and targets; real time (the grace period is 10 s).
use bytes::{Buf, Bytes};
use rtrust_engine::{Error, Session};
use rtrust_profile::Profile;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Answers every CONNECT with 200 and echoes the request body only after the
/// client's FIN, so a flow that writes without closing never hears back.
async fn endpoint() -> (Profile, tokio::task::JoinHandle<()>) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key.into())
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(512u32.into());
    config.transport_config(Arc::new(transport));
    let server = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = server.local_addr().unwrap();
    let p = Profile::import(&format!(
        "hostname='localhost'\naddresses=['{address}']\nusername='test'\npassword='secret'\nupstream_protocol='http3'\ncertificate='''{}'''\n",
        certified.cert.pem()
    ))
    .unwrap();
    let task = tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let mut h3: h3::server::Connection<_, Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    tokio::spawn(async move {
                        let Ok((_, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        if stream
                            .send_response(http::Response::builder().status(200).body(()).unwrap())
                            .await
                            .is_err()
                        {
                            return;
                        }
                        let mut body = Vec::new();
                        while let Ok(Some(mut data)) = stream.recv_data().await {
                            while data.has_remaining() {
                                let chunk = data.chunk();
                                body.extend_from_slice(chunk);
                                let n = chunk.len();
                                data.advance(n);
                            }
                        }
                        if !body.is_empty() {
                            let _ = stream.send_data(Bytes::from(body)).await;
                        }
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    (p, task)
}

async fn echo(session: &Session, target: &str) {
    let mut flow = session.open_tcp(target).await.unwrap();
    flow.write_all(b"ping").await.unwrap();
    flow.shutdown().await.unwrap();
    let mut back = Vec::new();
    flow.read_to_end(&mut back).await.unwrap();
    assert_eq!(back, b"ping");
}

/// Polls health for up to `limit`, keeping inbound bytes flowing on an
/// unwatched port so verdict A (any inbound byte answers it) never fires.
async fn first_error(session: &Session, limit: Duration) -> (Option<Error>, Duration) {
    let start = Instant::now();
    while start.elapsed() < limit {
        tokio::time::sleep(Duration::from_millis(500)).await;
        echo(session, "192.0.2.1:7").await;
        if let Err(error) = session.health().await {
            return (Some(error), start.elapsed());
        }
    }
    (None, start.elapsed())
}

#[tokio::test(flavor = "multi_thread")]
async fn quiet_tls_opens_behind_live_flows_degrade_the_session_unproven() {
    let (p, server) = endpoint().await;
    let session = Session::connect(&p).await.unwrap();
    session.health().await.unwrap();
    let before = rtrust_engine::flow_counters();
    for i in 0..3 {
        echo(&session, &format!("live{i}.example.invalid:443")).await;
    }
    let mut quiet = Vec::new();
    for i in 0..36 {
        let mut flow = session
            .open_tcp(&format!("q{}.example.invalid:443", i % 12))
            .await
            .unwrap();
        // A ClientHello-like first write that never gets a byte back.
        flow.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        quiet.push(flow);
    }
    let (error, after) = first_error(&session, Duration::from_secs(30)).await;
    assert!(
        matches!(error, Some(Error::Degraded { proven: false })),
        "{error:?} after {after:?}"
    );
    // Not before the slot of the writes matured (>= 10 s grace).
    assert!(after >= Duration::from_secs(9), "{after:?}");
    drop(quiet);
    let counted = rtrust_engine::flow_counters();
    assert!(counted.tcp_opened - before.tcp_opened >= 39);
    assert!(counted.tcp_answered - before.tcp_answered >= 3);
    assert!(counted.tcp_quiet - before.tcp_quiet >= 36);
    // A new session on the same endpoint inherits none of it.
    let fresh = Session::connect(&p).await.unwrap();
    fresh.health().await.unwrap();
    echo(&fresh, "live0.example.invalid:443").await;
    fresh.health().await.unwrap();
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn quiet_flows_on_unwatched_ports_or_without_writes_stay_healthy() {
    let (p, server) = endpoint().await;
    let session = Session::connect(&p).await.unwrap();
    session.health().await.unwrap();
    let mut held = Vec::new();
    for i in 0..36 {
        // Server-first or idle protocols: written, never answered.
        let mut flow = session
            .open_tcp(&format!("q{}.example.invalid:6881", i % 12))
            .await
            .unwrap();
        flow.write_all(b"x").await.unwrap();
        held.push(flow);
        // Watched port, opened but never written.
        held.push(
            session
                .open_tcp(&format!("idle{}.example.invalid:443", i % 12))
                .await
                .unwrap(),
        );
    }
    let _udp = session.open_udp().await.unwrap();
    let (error, after) = first_error(&session, Duration::from_secs(22)).await;
    assert!(error.is_none(), "{error:?} after {after:?}");
    server.abort();
}
