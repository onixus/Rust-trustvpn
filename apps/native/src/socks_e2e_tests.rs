//! End to end on loopback: a real SOCKS proxy admitted through a TLS/h2
//! endpoint, then a degraded health verdict through `update`. Proves the
//! proxy stops before the wait (fail-closed) and that the retry targets the
//! same profile and port. No system network state is touched.
use super::*;
use std::sync::Arc;

/// Synthetic TLS endpoint, authenticates CONNECT (including `_check`).
async fn endpoint() -> Profile {
    endpoint_status(200).await
}
async fn endpoint_status(status: u16) -> Profile {
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(tls).await else {
                    return;
                };
                while let Some(Ok((request, mut response))) = conn.accept().await {
                    let status = if request
                        .headers()
                        .get("proxy-authorization")
                        .map(|value| value.as_bytes())
                        == Some(b"Basic ZGVtbzpzeW50aGV0aWM=".as_slice())
                    {
                        status
                    } else {
                        407
                    };
                    let _ = response.send_response(
                        http::Response::builder().status(status).body(()).unwrap(),
                        true,
                    );
                }
            });
        }
    });
    Profile::import(&format!(
        "hostname='localhost'\naddresses=['{address}']\nusername='demo'\npassword='synthetic'\ncertificate='''{}'''\n",
        certified.cert.pem()
    ))
    .unwrap()
}

#[test]
fn journal_metadata_from_real_loopback_failures_and_epoch_fencing() {
    use rtrust_journal::{Budget, Class, Path, Transport};
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    runtime.block_on(async {
        let profile = endpoint().await;
        let retry = socks_recovery::Retry {
            delay: std::time::Duration::ZERO,
            cooling: true,
            attempt: 1,
        };
        let mut wrong = profile.clone();
        wrong.endpoint.password = rtrust_profile::Secret::new("token-canary");
        let authentication = socks_recovery::attempt_with_metadata(wrong, 0, retry)
            .await
            .err()
            .unwrap();
        assert_eq!(authentication.class, Class::Authentication);
        let record = authentication.record.unwrap();
        assert_eq!(
            (record.path, record.transport, record.attempt, record.budget),
            (Path::SocksRecovery, Transport::H2, 1, Budget::Cooldown)
        );
        let mut wrong = profile.clone();
        wrong.endpoint.hostname = "sni-canary.invalid".into();
        assert_eq!(
            socks_recovery::attempt_with_metadata(wrong, 0, retry)
                .await
                .err()
                .unwrap()
                .class,
            Class::Tls
        );
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert_eq!(
            socks_recovery::attempt_with_metadata(
                profile.clone(),
                occupied.local_addr().unwrap().port(),
                retry
            )
            .await
            .err()
            .unwrap()
            .class,
            Class::LocalBind
        );
        let mut unreachable = profile.clone();
        unreachable.endpoint.addresses = vec![occupied.local_addr().unwrap().to_string()];
        drop(occupied);
        assert_eq!(
            socks_recovery::attempt_with_metadata(unreachable, 0, retry)
                .await
                .err()
                .unwrap()
                .class,
            Class::EndpointUnreachable
        );
        let rejected = endpoint_status(503).await;
        assert_eq!(
            socks_recovery::attempt_with_metadata(rejected, 0, retry)
                .await
                .err()
                .unwrap()
                .class,
            Class::Protocol
        );
        let mut invalid = profile.clone();
        invalid.endpoint.skip_verification = true;
        assert_eq!(
            socks_recovery::attempt_with_metadata(invalid, 0, retry)
                .await
                .err()
                .unwrap()
                .class,
            Class::Profile
        );

        let mut app = tests::app();
        app.mode = Mode::Socks;
        app.connecting = true;
        app.socks_recovery = Some(socks_recovery::Recovery::new(profile, 0));
        let epoch = app.connection_epoch;
        socks_recovery::take_records();
        let _ = app.update(Message::SocksAttempt(
            epoch.wrapping_sub(1),
            Err(authentication.clone()),
        ));
        assert!(socks_recovery::take_records().is_empty());
        let _ = app.update(Message::SocksAttempt(epoch, Err(authentication.clone())));
        assert_eq!(socks_recovery::take_records(), vec![record]);
        let _ = app.update(Message::SocksAttempt(epoch, Err(authentication)));
        assert!(socks_recovery::take_records().is_empty());
        app.disconnect();
    });
}

#[test]
fn a_degraded_verdict_stops_the_real_proxy_before_the_retry_wait() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime.enter();
    let profile = runtime.block_on(endpoint());
    let session = runtime
        .block_on(Session::start(
            profile.clone(),
            Vec::new(),
            Mode::Socks,
            0,
            Default::default(),
            String::new(),
        ))
        .unwrap();
    let proxy = session.proxy().unwrap().clone();
    let port = proxy.address().port();
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_ok());

    let mut app = tests::app();
    app.profiles[0] = profile.clone();
    app.mode = Mode::Socks;
    app.socks_recovery = Some(socks_recovery::Recovery::new(profile.clone(), port));
    app.connecting = true;
    let epoch = app.connection_epoch;
    let _ = app.update(Message::Connected(epoch, Ok(session)));
    assert!(app.session.is_some() && !app.connecting);

    let _ = app.update(Message::Health(
        app.connection_epoch,
        Err(rtrust_engine::Error::Degraded {
            proven: false,
            kind: rtrust_engine::Stall::Quiet,
        }
        .into()),
    ));
    // The old proxy is stopped and refuses clients during the wait.
    assert!(app.session.is_none() && app.connecting);
    assert!(matches!(
        runtime.block_on(proxy.health()),
        Err(rtrust_engine::Error::Io)
    ));
    runtime.block_on(tokio::time::sleep(std::time::Duration::from_millis(100)));
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    // The retry targets exactly what the user started.
    let (target, target_port) = app.socks_recovery.as_ref().unwrap().target();
    assert_eq!(
        (target.name.as_str(), target_port),
        (profile.name.as_str(), port)
    );
    assert!(app.status.contains("Переподключение через"));

    // The automatic attempt itself rebinds the same port through the tunnel.
    let again = runtime
        .block_on(socks_recovery::attempt(target, target_port))
        .unwrap();
    assert_eq!(again.proxy().unwrap().address().port(), port);
    let _ = app.update(Message::SocksAttempt(app.connection_epoch, Ok(again)));
    assert!(app.session.is_some() && !app.connecting && app.last_error.is_none());
    assert!(!app.socks_recovery.as_ref().unwrap().retrying());
    app.disconnect();
}
