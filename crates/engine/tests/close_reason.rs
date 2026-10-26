//! A closed connection surfaces its reason class through `Session::health`,
//! so the service can log why the transport stopped, while answers the
//! endpoint gave (407, other statuses) keep their own error.
#![cfg(unix)]
use rtrust_engine::{Close, Error, Session};
use rtrust_profile::Profile;
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};

#[derive(Clone, Copy, Debug)]
enum Ending {
    /// GOAWAY(NO_ERROR), then close once idle.
    Graceful,
    /// GOAWAY with ENHANCE_YOUR_CALM (0xb).
    Abrupt,
    /// Close TCP (FIN) without any GOAWAY.
    Drop,
}

fn certified() -> (rcgen::CertifiedKey<rcgen::KeyPair>, rustls::ServerConfig) {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certified.cert.der().clone()], key.into())
        .unwrap();
    (certified, tls)
}

/// Synthetic endpoint on loopback. Every `_check` gets `status`; the
/// connection ends with `ending` when `end` fires, or right after the first
/// answer when `immediate`: the GOAWAY then follows at once, except that an
/// abrupt or dropped close first lets a rejection reach the client.
async fn endpoint(
    status: u16,
    ending: Ending,
    immediate: bool,
    hold: bool,
) -> (Profile, oneshot::Sender<()>) {
    let (certified, mut tls) = certified();
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
        // A duplicate descriptor outlives the TLS stream: the endpoint sends
        // FIN and drains the client, so unread client frames never turn its
        // close into a reset that would discard the GOAWAY in flight.
        let spare = std::mem::ManuallyDrop::new(unsafe {
            <std::net::TcpStream as std::os::fd::FromRawFd>::from_raw_fd(
                std::os::fd::AsRawFd::as_raw_fd(&tcp),
            )
        })
        .try_clone()
        .unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut conn = h2::server::handshake(tls).await.unwrap();
        let mut held = Vec::new();
        loop {
            tokio::select! {
                request = conn.accept() => {
                    let Some(Ok((_, mut response))) = request else { return };
                    if hold && !held.is_empty() {
                        held.push(response);
                        break;
                    }
                    if hold {
                        held.push(response);
                        let response = held.last_mut().unwrap();
                        let _ = response.send_response(
                            http::Response::builder().status(status).body(()).unwrap(),
                            true,
                        );
                        continue;
                    }
                    let _ = response.send_response(
                        http::Response::builder().status(status).body(()).unwrap(),
                        true,
                    );
                    if immediate { break; }
                }
                _ = &mut ended => break,
            }
        }
        if status != 200 && !matches!(ending, Ending::Graceful) {
            // Let the rejection leave first: an abrupt GOAWAY or a drop
            // discards stream frames still queued, and the client would never
            // see an answer. A graceful GOAWAY flushes the answer with it, so
            // both arrive in one read: the case that must keep the answer.
            let _ = tokio::time::timeout(Duration::from_millis(100), conn.accept()).await;
        }
        match ending {
            Ending::Graceful => conn.graceful_shutdown(),
            Ending::Abrupt => conn.abrupt_shutdown(h2::Reason::ENHANCE_YOUR_CALM),
            Ending::Drop => {}
        }
        if !matches!(ending, Ending::Drop) {
            while conn.accept().await.is_some() {}
        }
        drop(conn);
        let _ = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut spare = spare;
            // Fails harmlessly once the client already reset the socket.
            let _ = spare.set_nonblocking(false);
            let _ = spare.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = spare.shutdown(std::net::Shutdown::Write);
            let mut sink = [0; 4096];
            while matches!(spare.read(&mut sink), Ok(n) if n > 0) {}
        })
        .await;
    });
    (profile, end)
}

async fn wait_closed(session: &Session) -> Close {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(close) = session.closed() {
                return close;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

async fn closed_after(ending: Ending) -> Close {
    let (profile, end) = endpoint(200, ending, false, false).await;
    let session = Session::connect(&profile).await.unwrap();
    session.health().await.unwrap();
    assert_eq!(session.closed(), None);
    assert_eq!(session.transport_name(), "h2");
    end.send(()).unwrap();
    let close = wait_closed(&session).await;
    assert!(matches!(session.health().await, Err(Error::Closed(c)) if c == close));
    close
}

/// GOAWAY (or FIN) right behind the first answer.
async fn closed_right_after_answer(ending: Ending) -> Close {
    let (profile, _end) = endpoint(200, ending, true, false).await;
    let session = Session::connect(&profile).await.unwrap();
    let _ = session.health().await;
    wait_closed(&session).await
}

/// An answered rejection stays a rejection although the connection closed
/// right behind it; mobile and SOCKS callers treat it as permanent.
async fn rejected_then_closed(status: u16, ending: Ending) -> rtrust_engine::Result<()> {
    let (profile, _end) = endpoint(status, ending, true, false).await;
    let session = Session::connect(&profile).await.unwrap();
    let checked = session.health().await;
    let _ = wait_closed(&session).await;
    checked
}

/// The endpoint takes a second `_check` without answering, then ends: the
/// open stream fails with the EOF behind the GOAWAY.
async fn closed_with_check_in_flight(ending: Ending) -> (Close, rtrust_engine::Result<()>) {
    let (profile, _end) = endpoint(200, ending, false, true).await;
    let session = Session::connect(&profile).await.unwrap();
    session.health().await.unwrap();
    let checked = session.health().await;
    (wait_closed(&session).await, checked)
}

/// Dropping the last session handle still ends the connection: the driver,
/// which holds a sender clone for close reasons, is aborted with it.
async fn connection_ends_when_the_session_drops() {
    let (certified, mut tls) = certified();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let profile = Profile::import(&format!(
        "hostname='localhost'\naddresses=['{address}']\nusername='synthetic'\npassword='synthetic'\ncertificate='''{}'''\n",
        certified.cert.pem()
    ))
    .unwrap();
    let server = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = acceptor.accept(tcp).await.unwrap();
        let mut conn = h2::server::handshake(tls).await.unwrap();
        while let Some(Ok((_, mut response))) = conn.accept().await {
            let _ = response.send_response(
                http::Response::builder().status(200).body(()).unwrap(),
                true,
            );
        }
    });
    let session = Session::connect(&profile).await.unwrap();
    session.health().await.unwrap();
    drop(session);
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("connection stayed open after the session dropped")
        .unwrap();
}

macro_rules! both_runtimes {
    ($($name:ident => $body:block)*) => {
        mod current_thread {
            use super::*;
            $(#[tokio::test(flavor = "current_thread")] async fn $name() $body)*
        }
        mod multi_thread {
            use super::*;
            $(#[tokio::test(flavor = "multi_thread")] async fn $name() $body)*
        }
    };
}

both_runtimes! {
    graceful_goaway_is_reported_with_its_code => {
        assert_eq!(
            closed_after(Ending::Graceful).await,
            Close::GoAway { code: 0, remote: true }
        );
    }
    abrupt_goaway_is_reported_with_its_code => {
        assert_eq!(
            closed_after(Ending::Abrupt).await,
            Close::GoAway { code: 0xb, remote: true }
        );
    }
    dropped_connection_is_peer_closed => {
        assert_eq!(closed_after(Ending::Drop).await, Close::PeerClosed);
    }
    goaway_right_after_an_answer_keeps_its_code => {
        assert_eq!(
            closed_right_after_answer(Ending::Abrupt).await,
            Close::GoAway { code: 0xb, remote: true }
        );
        assert_eq!(
            closed_right_after_answer(Ending::Graceful).await,
            Close::GoAway { code: 0, remote: true }
        );
        assert_eq!(closed_right_after_answer(Ending::Drop).await, Close::PeerClosed);
    }
    dropping_the_session_ends_the_connection => {
        connection_ends_when_the_session_drops().await;
    }
    goaway_with_a_check_in_flight_keeps_its_code => {
        let (close, checked) = closed_with_check_in_flight(Ending::Abrupt).await;
        assert_eq!(close, Close::GoAway { code: 0xb, remote: true });
        assert!(matches!(checked, Err(Error::Closed(c)) if c == close), "{checked:?}");
        let (close, _) = closed_with_check_in_flight(Ending::Drop).await;
        assert_eq!(close, Close::PeerClosed);
    }
    rejections_survive_a_close_behind_them => {
        for ending in [Ending::Abrupt, Ending::Graceful, Ending::Drop] {
            let checked = rejected_then_closed(407, ending).await;
            assert!(matches!(checked, Err(Error::Authentication)), "{ending:?}: {checked:?}");
            let checked = rejected_then_closed(503, ending).await;
            assert!(matches!(checked, Err(Error::Rejected(503))), "{ending:?}: {checked:?}");
        }
    }
    quic_application_close_is_reported_with_its_code => {
        let (profile, end) = quic_endpoint(200).await;
        let session = Session::connect(&profile).await.unwrap();
        assert_eq!(session.transport_name(), "h3");
        session.health().await.unwrap();
        end.send(()).unwrap();
        let close = wait_closed(&session).await;
        assert_eq!(close, Close::QuicApplication(0x100));
        assert!(matches!(session.health().await, Err(Error::Closed(c)) if c == close));
        assert_eq!(close.fields(), "reason=quic_close layer=app code=256 by=peer");
    }
    quic_rejection_survives_connection_close => {
        let (profile, _end) = quic_endpoint(407).await;
        let session = Session::connect(&profile).await.unwrap();
        let checked = session.health().await;
        let _ = wait_closed(&session).await;
        assert!(matches!(checked, Err(Error::Authentication)), "{checked:?}");
    }
}

/// Synthetic HTTP/3 endpoint: answers the first `_check` with `status`, then
/// closes the QUIC connection with H3_NO_ERROR and a reason phrase the
/// client must not keep. A 200 waits for `end`; any other status closes at
/// once.
async fn quic_endpoint(status: u16) -> (Profile, oneshot::Sender<()>) {
    let (certified, mut tls) = certified();
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
        let mut h3: h3::server::Connection<_, bytes::Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        if let Ok(Some(resolver)) = h3.accept().await {
            let (_, mut stream) = resolver.resolve_request().await.unwrap();
            let _ = stream
                .send_response(http::Response::builder().status(status).body(()).unwrap())
                .await;
            let _ = stream.finish().await;
        }
        if status == 200 {
            let _ = ended.await;
        } else {
            // CONNECTION_CLOSE discards unsent stream data: deliver the answer.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        connection.close(0x100u32.into(), b"synthetic 192.0.2.1 vpn.example");
        server.wait_idle().await;
    });
    (profile, end)
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
