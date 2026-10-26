//! A closed HTTP/2 connection surfaces its reason class through
//! `Session::health`, so the service can log why the transport stopped.
#![cfg(unix)]
use rtrust_engine::{Close, Error, Session};
use rtrust_profile::Profile;
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};

#[derive(Clone, Copy)]
enum Ending {
    /// GOAWAY(NO_ERROR), then close once idle.
    Graceful,
    /// GOAWAY with ENHANCE_YOUR_CALM (0xb).
    Abrupt,
    /// Close TCP (FIN) without any GOAWAY.
    Drop,
}

/// Synthetic endpoint on loopback: answers `_check` until `end` fires.
async fn endpoint(ending: Ending) -> (Profile, oneshot::Sender<()>) {
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
    let profile = Profile::import(&format!(
        "hostname='localhost'\naddresses=['{address}']\nusername='synthetic'\npassword='synthetic'\ncertificate='''{}'''\n",
        certified.cert.pem()
    ))
    .unwrap();
    let (end, mut ended) = oneshot::channel();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let fd = std::os::fd::AsRawFd::as_raw_fd(&tcp);
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut conn = h2::server::handshake(tls).await.unwrap();
        loop {
            tokio::select! {
                request = conn.accept() => {
                    let Some(Ok((_, mut response))) = request else { return };
                    let _ = response.send_response(
                        http::Response::builder().status(200).body(()).unwrap(),
                        true,
                    );
                }
                _ = &mut ended => break,
            }
        }
        match ending {
            Ending::Graceful => conn.graceful_shutdown(),
            Ending::Abrupt => conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM),
            // FIN without TLS close_notify or GOAWAY; keep reading so
            // unread client frames cannot turn it into a reset.
            Ending::Drop => {
                // Borrowed: the TLS stream still owns and closes the socket.
                let tcp = std::mem::ManuallyDrop::new(unsafe {
                    <std::net::TcpStream as std::os::fd::FromRawFd>::from_raw_fd(fd)
                });
                tcp.shutdown(std::net::Shutdown::Write).unwrap();
            }
        }
        while conn.accept().await.is_some() {}
    });
    (profile, end)
}

async fn closed_after(ending: Ending) -> Close {
    let (profile, end) = endpoint(ending).await;
    let session = Session::connect(&profile).await.unwrap();
    session.health().await.unwrap();
    assert_eq!(session.closed(), None);
    assert_eq!(session.transport_name(), "h2");
    end.send(()).unwrap();
    // No request in flight: unread data would turn the endpoint's close into
    // a TCP reset, which is reported as `io_error` instead.
    let close = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(close) = session.closed() {
                return close;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(matches!(session.health().await, Err(Error::Closed(c)) if c == close));
    close
}

#[tokio::test]
async fn graceful_goaway_is_reported_with_its_code() {
    assert_eq!(
        closed_after(Ending::Graceful).await,
        Close::GoAway {
            code: 0,
            remote: true
        }
    );
}

#[tokio::test]
async fn abrupt_goaway_is_reported_with_its_code() {
    assert_eq!(
        closed_after(Ending::Abrupt).await,
        Close::GoAway {
            code: 0xb,
            remote: true
        }
    );
}

#[tokio::test]
async fn dropped_connection_is_peer_closed() {
    assert_eq!(closed_after(Ending::Drop).await, Close::PeerClosed);
}

#[test]
fn close_fields_are_classes_and_numbers_only() {
    assert_eq!(Close::PeerClosed.fields(), "reason=peer_closed");
    assert_eq!(
        Close::GoAway {
            code: 0xb,
            remote: true
        }
        .fields(),
        "reason=goaway code=11 by=peer"
    );
    assert_eq!(
        Close::QuicTransport {
            code: 0x128,
            remote: false
        }
        .fields(),
        "reason=tls_error alert=40 by=local"
    );
    assert_eq!(
        Close::Io(std::io::ErrorKind::NetworkUnreachable).fields(),
        "reason=io_error kind=network_unreachable"
    );
}

/// Synthetic HTTP/3 endpoint that closes the QUIC connection with an
/// application code and a reason phrase the client must not keep.
#[tokio::test(flavor = "multi_thread")]
async fn quic_application_close_is_reported_with_its_code() {
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
    let profile = Profile::import(&format!(
        "hostname='localhost'\naddresses=['{address}']\nusername='synthetic'\npassword='synthetic'\nupstream_protocol='http3'\ncertificate='''{}'''\n",
        certified.cert.pem()
    ))
    .unwrap();
    let (end, ended) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let connection = server.accept().await.unwrap().await.unwrap();
        let _ = ended.await;
        connection.close(0x100u32.into(), b"synthetic 192.0.2.1 vpn.example");
        server.wait_idle().await;
    });
    let session = Session::connect(&profile).await.unwrap();
    assert_eq!(session.transport_name(), "h3");
    end.send(()).unwrap();
    let close = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Err(Error::Closed(close)) = session.health().await {
                return close;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(close, Close::QuicApplication(0x100));
    assert_eq!(
        close.fields(),
        "reason=quic_close layer=app code=256 by=peer"
    );
}
