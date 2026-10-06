use bytes::Bytes;
use rtrust_engine::{Error, Session};
use rtrust_profile::Profile;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

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
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let p=Profile::import(&format!("hostname='localhost'\naddresses=['{address}']\nusername='test'\npassword='secret'\ncertificate='''{}'''\n",certified.cert.pem())).unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut conn = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((req, mut response))) = conn.accept().await {
                    tokio::spawn(async move {
                        assert_eq!(req.method(), "CONNECT");
                        if req
                            .headers()
                            .get("proxy-authorization")
                            .map(|x| x.as_bytes())
                            != Some(b"Basic dGVzdDpzZWNyZXQ=".as_slice())
                        {
                            let _ = response.send_response(
                                http::Response::builder().status(407).body(()).unwrap(),
                                true,
                            );
                            return;
                        }
                        let check = req.uri().authority().unwrap().as_str() == "_check";
                        let mut out = response
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                check,
                            )
                            .unwrap();
                        if check {
                            return;
                        }
                        let mut incoming = req.into_body();
                        while let Some(Ok(mut data)) = incoming.data().await {
                            incoming
                                .flow_control()
                                .release_capacity(data.len())
                                .unwrap();
                            while !data.is_empty() {
                                out.reserve_capacity(data.len());
                                let Some(Ok(cap)) =
                                    std::future::poll_fn(|cx| out.poll_capacity(cx)).await
                                else {
                                    return;
                                };
                                if cap == 0 {
                                    continue;
                                }
                                let n = cap.min(data.len());
                                if out.send_data(data.split_to(n), false).is_err() {
                                    return;
                                }
                            }
                        }
                        let _ = out.send_data(Bytes::new(), true);
                    });
                }
            });
        }
    });
    (p, task)
}
#[tokio::test]
async fn authenticated_tls_connect_bidirectional_flow_control() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (p, server) = endpoint().await;
        let session = Session::connect(&p).await.unwrap();
        session.health().await.unwrap();
        let stream = session.open_tcp("example.com:443").await.unwrap();
        let (mut r, mut w) = tokio::io::split(stream);
        let payload = vec![0x5a; 512 * 1024];
        let expected = payload.clone();
        let upload = async move {
            w.write_all(&payload).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let download = async move {
            let mut output = vec![];
            r.read_to_end(&mut output).await.unwrap();
            assert_eq!(output, expected);
        };
        tokio::join!(upload, download);
        server.abort();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn wrong_password_rejected() {
    let (mut p, server) = endpoint().await;
    p.endpoint.password = rtrust_profile::Secret::new("wrong");
    let session = Session::connect(&p).await.unwrap();
    assert!(matches!(session.health().await, Err(Error::Authentication)));
    server.abort();
}
#[tokio::test]
async fn certificate_identity_is_enforced() {
    let (mut p, server) = endpoint().await;
    p.endpoint.hostname = "different.example".into();
    assert!(matches!(Session::connect(&p).await, Err(Error::Tls)));
    server.abort();
}
#[tokio::test]
async fn unsupported_security_flags_never_downgrade() {
    let (mut p, server) = endpoint().await;
    p.endpoint.skip_verification = true;
    assert!(matches!(
        Session::connect(&p).await,
        Err(Error::Unsupported(_))
    ));
    p.endpoint.skip_verification = false;
    p.endpoint.client_random_prefix = "aa".into();
    assert!(matches!(
        Session::connect(&p).await,
        Err(Error::Unsupported(_))
    ));
    server.abort();
}

async fn socks(proxy: &rtrust_engine::proxy::Proxy) -> tokio::net::TcpStream {
    let mut socket = tokio::net::TcpStream::connect(proxy.address())
        .await
        .unwrap();
    // Fragmented greeting must also work.
    for byte in [5, 1, 0] {
        socket.write_all(&[byte]).await.unwrap();
    }
    let mut selection = [0; 2];
    socket.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 0]);
    socket
}
#[tokio::test]
async fn socks_remote_dns_duplex_half_close_stats_and_disconnect() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (p, server) = endpoint().await;
        let proxy = rtrust_engine::proxy::Proxy::start(&p, 0).await.unwrap();
        assert!(proxy.address().ip().is_loopback());
        let mut socket = socks(&proxy).await;
        // A name that cannot resolve locally. The echo endpoint still accepts the CONNECT.
        let name = b"remote-resolution.invalid";
        let mut request = vec![5, 1, 0, 3, name.len() as u8];
        request.extend(name);
        request.extend(443u16.to_be_bytes());
        socket.write_all(&request).await.unwrap();
        let mut response = [0; 10];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0);
        let (mut r, mut w) = socket.into_split();
        let data = vec![77; 512 * 1024];
        let expected = data.clone();
        let upload = async move {
            w.write_all(&data).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let download = async move {
            let mut data = vec![];
            r.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, expected);
        };
        tokio::join!(upload, download);
        assert_eq!(proxy.stats().uploaded, 512 * 1024);
        assert_eq!(proxy.stats().downloaded, 512 * 1024);
        let mut active = socks(&proxy).await;
        active.write_all(&request).await.unwrap();
        active.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 0);
        proxy.stop();
        let closed = active.read_u8().await;
        assert!(closed.is_err());
        assert!(proxy.health().await.is_err());
        // Once the abort has run, the port must be reusable.
        let _listener = TcpListener::bind(proxy.address()).await.unwrap();
        server.abort();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn socks_rejects_unsupported_auth_command_and_malformed_domain() {
    let (p, server) = endpoint().await;
    let proxy = rtrust_engine::proxy::Proxy::start(&p, 0).await.unwrap();
    let mut raw = tokio::net::TcpStream::connect(proxy.address())
        .await
        .unwrap();
    raw.write_all(&[5, 1, 2]).await.unwrap();
    let mut response = [0; 2];
    raw.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 255]);
    for (request, code) in [
        (vec![5, 2, 0, 1], 7),
        (vec![5, 1, 0, 3, 3, b'a', b'@', b'b', 0, 80], 8),
        (vec![5, 1, 0, 3, 1, 255, 0, 80], 8),
        (vec![5, 1, 0, 9], 8),
    ] {
        let mut socket = socks(&proxy).await;
        socket.write_all(&request).await.unwrap();
        let mut response = [0; 10];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], code);
    }
    proxy.stop();
    server.abort();
}
#[tokio::test]
async fn http_connect_and_absolute_form_share_the_socks_port() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (p, server) = endpoint().await;
        let proxy = rtrust_engine::proxy::Proxy::start(&p, 0).await.unwrap();
        // CONNECT with a ClientHello-like prefix pipelined behind the head.
        let mut socket = tokio::net::TcpStream::connect(proxy.address())
            .await
            .unwrap();
        socket
            .write_all(b"CONNECT remote-resolution.invalid:443 HTTP/1.1\r\nHost: remote-resolution.invalid:443\r\n\r\n\x16\x03\x01early")
            .await
            .unwrap();
        let established = b"HTTP/1.1 200 Connection established\r\n\r\n";
        let mut response = vec![0; established.len()];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(response, established);
        let mut echoed = [0; 8];
        socket.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"\x16\x03\x01early");
        let (mut r, mut w) = socket.into_split();
        let data = vec![9; 64 * 1024];
        let expected = data.clone();
        let upload = async move {
            w.write_all(&data).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let download = async move {
            let mut data = vec![];
            r.read_to_end(&mut data).await.unwrap();
            assert_eq!(data, expected);
        };
        tokio::join!(upload, download);
        assert_eq!(proxy.stats().uploaded, 8 + 64 * 1024);
        assert_eq!(proxy.stats().errors, 0);

        // Absolute-form: the echo endpoint returns exactly what reached the origin.
        let mut socket = tokio::net::TcpStream::connect(proxy.address())
            .await
            .unwrap();
        socket
            .write_all(b"POST http://plain.invalid/form?a=1 HTTP/1.1\r\nHost: plain.invalid\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic c2VjcmV0\r\nContent-Length: 4\r\n\r\nbody")
            .await
            .unwrap();
        let origin = b"POST /form?a=1 HTTP/1.1\r\nHost: plain.invalid\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody";
        let mut response = vec![0; origin.len()];
        socket.read_exact(&mut response).await.unwrap();
        assert_eq!(response, origin);
        // A second request on the same connection never reaches that origin.
        socket
            .write_all(b"GET http://other.invalid/ HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut extra = [0; 1];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), socket.read(&mut extra))
                .await
                .is_err()
        );
        drop(socket);

        // Malformed and https absolute-form requests get a status, not a tunnel.
        for (request, status) in [
            (&b"GET https://plain.invalid/ HTTP/1.1\r\n\r\n"[..], "400"),
            (b"CONNECT bad_host:443 HTTP/1.1\r\n\r\n", "400"),
            (b"TRACE http://plain.invalid/ HTTP/1.1\r\n\r\n", "501"),
        ] {
            let mut socket = tokio::net::TcpStream::connect(proxy.address())
                .await
                .unwrap();
            socket.write_all(request).await.unwrap();
            let mut response = String::new();
            socket.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {status} ")), "{response}");
            assert!(!response.contains("plain.invalid") && !response.contains("bad_host"));
        }
        // Neither SOCKS5 nor HTTP: closed (EOF or reset) without a reply.
        let mut socket = tokio::net::TcpStream::connect(proxy.address())
            .await
            .unwrap();
        socket.write_all(b"\x04\x01\x00\x50").await.unwrap();
        let mut response = vec![];
        let _ = socket.read_to_end(&mut response).await;
        assert!(response.is_empty());
        proxy.stop();
        server.abort();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn socks_port_conflict_and_auth_failure_do_not_leave_listener() {
    let (mut p, server) = endpoint().await;
    let busy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = busy.local_addr().unwrap().port();
    assert!(matches!(
        rtrust_engine::proxy::Proxy::start(&p, port).await,
        Err(Error::LocalBind)
    ));
    drop(busy);
    p.endpoint.password = rtrust_profile::Secret::new("incorrect");
    assert!(matches!(
        rtrust_engine::proxy::Proxy::start(&p, port).await,
        Err(Error::Authentication)
    ));
    let _again = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .unwrap();
    server.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn protected_transport_invokes_hook_before_connect_and_fails_closed() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let (mut profile, server) = endpoint().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let protect: rtrust_engine::SocketProtector = Arc::new(move |fd| {
        use std::os::fd::{BorrowedFd, FromRawFd, IntoRawFd};
        // Inspect a duplicate, never close the descriptor owned by the engine.
        let copy = unsafe { BorrowedFd::borrow_raw(fd) }.try_clone_to_owned()?;
        let socket = unsafe { std::net::TcpStream::from_raw_fd(copy.into_raw_fd()) };
        assert!(socket.peer_addr().is_err(), "protect ran after connect");
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

#[tokio::test]
async fn interrupted_tls_handshake_is_retryable_but_certificate_failures_are_not() {
    let (mut profile, original) = endpoint().await;
    original.abort();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    profile.endpoint.addresses = vec![listener.local_addr().unwrap().to_string()];
    let interrupted = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut hello = [0; 4096];
        let _ = stream.read(&mut hello).await;
        // A restarting endpoint closes an otherwise valid socket before TLS completes.
    });
    let result = Session::connect(&profile).await;
    assert!(
        matches!(result, Err(Error::ConnectIo(_))),
        "Interrupted TLS must remain retryable"
    );
    interrupted.await.unwrap();
    let (mut profile, endpoint) = endpoint().await;
    profile.endpoint.hostname = "wrong.example".into();
    assert!(matches!(Session::connect(&profile).await, Err(Error::Tls)));
    endpoint.abort();
}
