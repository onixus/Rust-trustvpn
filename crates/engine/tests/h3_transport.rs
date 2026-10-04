use bytes::{Buf, Bytes};
use rtrust_engine::{Error, Session};
use rtrust_profile::Profile;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// In-process HTTP/3 CONNECT endpoint: the first `_check` answers 200, any
/// other target echoes the request body after the client's FIN. Like endpoint
/// 1.1.0 with a blocked stream, it finishes `lost.invalid` and every later
/// `_check` without a response.
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
    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(quic)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let address = server.local_addr().unwrap();
    let p = Profile::import(&format!(
        "hostname='localhost'\naddresses=['{address}']\nusername='test'\npassword='secret'\nupstream_protocol='http3'\ncertificate='''{}'''\n",
        certified.cert.pem()
    ))
    .unwrap();
    let task = tokio::spawn(async move {
        while let Some(incoming) = server.accept().await {
            // Counted per connection: each session's first check is answered.
            let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let mut h3: h3::server::Connection<_, Bytes> =
                    h3::server::Connection::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                while let Ok(Some(resolver)) = h3.accept().await {
                    let checks = checks.clone();
                    tokio::spawn(async move {
                        let (request, mut stream) = resolver.resolve_request().await.unwrap();
                        assert_eq!(request.method(), "CONNECT");
                        if request
                            .headers()
                            .get("proxy-authorization")
                            .map(|x| x.as_bytes())
                            != Some(b"Basic dGVzdDpzZWNyZXQ=".as_slice())
                        {
                            let _ = stream
                                .send_response(
                                    http::Response::builder().status(407).body(()).unwrap(),
                                )
                                .await;
                            let _ = stream.finish().await;
                            return;
                        }
                        let authority = request.uri().authority().unwrap().as_str().to_owned();
                        let lost = authority == "lost.invalid:1"
                            || (authority == "_check"
                                && checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0);
                        if lost {
                            let _ = stream.finish().await;
                            return;
                        }
                        stream
                            .send_response(http::Response::builder().status(200).body(()).unwrap())
                            .await
                            .unwrap();
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

#[tokio::test(flavor = "multi_thread")]
async fn http3_half_close_reaches_the_endpoint() {
    let (p, server) = endpoint().await;
    let session = Session::connect(&p).await.unwrap();
    session.health().await.unwrap();
    for body in [&b""[..], b"x", &[7u8; 300_000]] {
        let mut tunnel = session.open_tcp("192.0.2.1:7").await.unwrap();
        tunnel.write_all(body).await.unwrap();
        tunnel.shutdown().await.unwrap();
        let mut echoed = Vec::new();
        tunnel.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, body);
    }
    let mut wrong = p.clone();
    wrong.endpoint.password = rtrust_profile::Secret::new("incorrect");
    let session = Session::connect(&wrong).await.unwrap();
    assert!(matches!(session.health().await, Err(Error::Authentication)));
    server.abort();
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn protected_http3_transport_invokes_hook_before_first_packet_and_fails_closed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (mut profile, server) = endpoint().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let protect: rtrust_engine::SocketProtector = Arc::new(move |fd| {
        use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd};
        // Inspect a duplicate, never close the descriptor owned by the engine.
        let copy = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
        let socket = unsafe { std::net::UdpSocket::from_raw_fd(copy.into_raw_fd()) };
        assert!(socket.local_addr()?.ip().is_unspecified());
        count.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let session = Session::connect_protected(&profile, &protect)
        .await
        .unwrap();
    session.health().await.unwrap();
    drop(session);
    let session = Session::connect_protected(&profile, &protect)
        .await
        .unwrap();
    session.health().await.unwrap();
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "reconnect must protect a fresh socket"
    );
    drop(session);
    let refused_calls = Arc::new(AtomicUsize::new(0));
    let count = refused_calls.clone();
    let denied: rtrust_engine::SocketProtector = Arc::new(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    });
    profile
        .endpoint
        .addresses
        .push(profile.endpoint.addresses[0].clone());
    assert!(matches!(
        Session::connect_protected(&profile, &denied).await,
        Err(Error::ConnectIo(std::io::ErrorKind::PermissionDenied))
    ));
    assert_eq!(refused_calls.load(Ordering::SeqCst), 2);
    profile.endpoint.addresses = vec!["localhost:443".into()];
    assert!(matches!(
        Session::connect_protected(&profile, &protect).await,
        Err(Error::Unsupported(_))
    ));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        2,
        "must reject unprotected DNS resolution"
    );
    server.abort();
}

#[tokio::test(flavor = "multi_thread")]
async fn lost_response_fails_only_its_stream() {
    let (p, server) = endpoint().await;
    let session = Session::connect(&p).await.unwrap();
    // A lost first check cannot prove the credentials; the fixture answers it.
    session.health().await.unwrap();
    let mut active = session.open_tcp("192.0.2.1:7").await.unwrap();
    active.write_all(b"before").await.unwrap();
    assert!(matches!(
        session.open_tcp("lost.invalid:1").await,
        Err(Error::Protocol)
    ));
    // Later checks lose their response; the session stays usable.
    session.health().await.unwrap();
    active.write_all(b" after").await.unwrap();
    active.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    active.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(echoed, b"before after");
    server.abort();
}
