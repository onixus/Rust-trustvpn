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
