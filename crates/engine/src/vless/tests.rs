//! Loopback VLESS/WebSocket endpoint: TLS from rcgen, a hand-written upgrade
//! and frame layer, TCP and UDP echo. No traffic leaves 127.0.0.1.
use super::*;
use crate::{Session, udp::Datagram};
use std::sync::atomic::{AtomicU8, AtomicUsize};
use tokio::net::TcpListener;

const UUID: &str = "11111111-2222-4333-8444-555555555555";
const PATH: &str = "/CanaryPath7f3abcdef";
const HOST: &str = "cdn.example.com";

const ECHO: u8 = 0;
const NOT_FOUND: u8 = 1;
const REDIRECT: u8 = 2;
const BAD_ACCEPT: u8 = 3;
/// Reads the upgrade request and never answers.
const HANG: u8 = 4;
/// Answers 1.5 s after the client finished sending, then closes.
const LATE: u8 = 5;
/// Answers the upgrade after 300 ms, then echoes.
const SLOW: u8 = 6;

#[derive(Debug)]
struct Request {
    command: u8,
    port: u16,
    address: Vec<u8>,
}
struct Endpoint {
    profile: Profile,
    mode: Arc<AtomicU8>,
    accepted: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Request>>>,
    /// One signal per connection the server saw end.
    closed: tokio::sync::mpsc::UnboundedReceiver<()>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn endpoint(names: &[&str], alpn: &[&[u8]]) -> Endpoint {
    let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
    let certified = rcgen::generate_simple_self_signed(names).unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![certified.cert.der().clone()], key.into())
    .unwrap();
    tls.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut profile = Profile::import(&format!(
        "vless://{UUID}@{address}?encryption=none&security=tls&sni={HOST}&type=ws&path=%2FCanaryPath7f3abcdef#Test"
    ))
    .unwrap();
    profile.endpoint.certificate = certified.cert.pem();
    let mode = Arc::new(AtomicU8::new(ECHO));
    let accepted = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(Mutex::new(vec![]));
    let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
    let task = {
        let (mode, accepted, requests) = (mode.clone(), accepted.clone(), requests.clone());
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let (acceptor, mode, requests, closed) = (
                    acceptor.clone(),
                    mode.load(Ordering::SeqCst),
                    requests.clone(),
                    closed_tx.clone(),
                );
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let _ = serve(tls, mode, requests).await;
                    let _ = closed.send(());
                });
            }
        })
    };
    Endpoint {
        profile,
        mode,
        accepted,
        requests,
        closed,
        task,
    }
}

type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;
async fn serve(
    mut tls: ServerTls,
    mode: u8,
    requests: Arc<Mutex<Vec<Request>>>,
) -> std::io::Result<()> {
    let mut head = vec![];
    while !head.ends_with(b"\r\n\r\n") {
        let byte = tls.read_u8().await?;
        head.push(byte);
    }
    let head = String::from_utf8(head).unwrap();
    let key = head
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .unwrap()
        .to_owned();
    assert!(head.contains(&format!("Host: {HOST}\r\n")));
    if mode == SLOW {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let reply = match mode {
        HANG => {
            // Wait for the client to go away.
            let _ = tls.read_u8().await;
            return Ok(());
        }
        NOT_FOUND => {
            "HTTP/1.1 404 Not Found /CanaryPath7f3abcdef\r\nContent-Length: 0\r\n\r\n".into()
        }
        REDIRECT => {
            "HTTP/1.1 301 Moved\r\nLocation: http://cdn.example.com/CanaryPath7f3abcdef\r\n\r\n"
                .into()
        }
        _ if !head.starts_with(&format!("GET {PATH} HTTP/1.1\r\n")) => {
            "HTTP/1.1 404 Not Found\r\n\r\n".into()
        }
        _ => format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            if mode == BAD_ACCEPT {
                ws::accept("other")
            } else {
                ws::accept(&key)
            }
        ),
    };
    tls.write_all(reply.as_bytes()).await?;
    if !reply.starts_with("HTTP/1.1 101") || mode == BAD_ACCEPT {
        return Ok(());
    }
    let mut data = vec![];
    let mut answered = false;
    let mut command = None;
    loop {
        let Some((opcode, payload)) = client_frame(&mut tls).await? else {
            return Ok(());
        };
        match opcode {
            ws::CLOSE => {
                tls.write_all(&server_frame(ws::CLOSE, &[])).await?;
                return Ok(());
            }
            ws::PING => tls.write_all(&server_frame(ws::PONG, &payload)).await?,
            ws::BINARY => data.extend(payload),
            _ => panic!("unexpected opcode"),
        }
        if command.is_none() {
            let Some((parsed, used)) = parse_request(&data) else {
                continue;
            };
            data.drain(..used);
            command = Some(parsed.command);
            requests.lock().unwrap().push(parsed);
        }
        let mut out = vec![];
        if command == Some(header::TCP) {
            if data.is_empty() {
                continue;
            }
            if mode == LATE {
                tokio::time::sleep(Duration::from_millis(1500)).await;
            }
            out.extend(std::mem::take(&mut data));
        } else {
            while data.len() >= 2 {
                let len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if data.len() < 2 + len {
                    break;
                }
                out.extend(data.drain(..2 + len));
            }
            if out.is_empty() {
                continue;
            }
        }
        if !answered {
            // Response header with two bytes of addons, then the echo.
            out.splice(0..0, [0, 2, 7, 7]);
            answered = true;
        }
        // Split the answer over two frames, the second with one byte.
        let last = out.split_off(out.len() - 1);
        tls.write_all(&server_frame(ws::BINARY, &out)).await?;
        tls.write_all(&server_frame(ws::BINARY, &last)).await?;
        if mode == LATE {
            tls.write_all(&server_frame(ws::CLOSE, &[])).await?;
        }
    }
}
fn parse_request(data: &[u8]) -> Option<(Request, usize)> {
    if data.len() < 22 {
        return None;
    }
    assert_eq!(data[0], 0);
    let uuid: String = data[1..17].iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(uuid, UUID.replace('-', ""));
    assert_eq!(data[17], 0);
    let port = u16::from_be_bytes([data[19], data[20]]);
    let len = match data[21] {
        1 => 4,
        3 => 16,
        2 => 1 + *data.get(22)? as usize,
        _ => panic!("address type"),
    };
    let address = data.get(22..22 + len)?.to_vec();
    Some((
        Request {
            command: data[18],
            port,
            address,
        },
        22 + len,
    ))
}
async fn client_frame(tls: &mut ServerTls) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 2];
    if tls.read_exact(&mut head).await.is_err() {
        return Ok(None);
    }
    assert_eq!(head[0] & 0xf0, 0x80, "FIN without RSV");
    assert_ne!(head[1] & 0x80, 0, "client frames are masked");
    let len = match head[1] & 0x7f {
        126 => tls.read_u16().await? as usize,
        127 => tls.read_u64().await? as usize,
        n => n as usize,
    };
    let mut mask = [0u8; 4];
    tls.read_exact(&mut mask).await?;
    let mut payload = vec![0; len];
    tls.read_exact(&mut payload).await?;
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    Ok(Some((head[0] & 0x0f, payload)))
}
fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | opcode];
    if payload.len() < 126 {
        out.push(payload.len() as u8);
    } else {
        out.push(126);
        out.extend((payload.len() as u16).to_be_bytes());
    }
    out.extend(payload);
    out
}
fn canaries(error: &Error) {
    let text = format!("{error} {error:?}");
    assert!(
        !text.contains("CanaryPath") && !text.contains("5555"),
        "{text}"
    );
}

#[tokio::test]
async fn tcp_flows_carry_data_with_the_vless_header() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    assert!(!session.ipv6());
    let connections = e.accepted.load(Ordering::SeqCst);
    // A recent upgrade answers health without a new connection.
    session.health().await.unwrap();
    assert_eq!(e.accepted.load(Ordering::SeqCst), connections);
    for target in ["192.0.2.1:443", "[2001:db8::1]:80", "example.com:8080"] {
        let mut tunnel = session.open_tcp(target).await.unwrap();
        tunnel.write_all(b"hello").await.unwrap();
        let mut answer = [0u8; 5];
        tunnel.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"hello");
        // Large writes span several frames.
        let big = vec![7u8; 100_000];
        tunnel.write_all(&big).await.unwrap();
        let mut back = vec![0u8; big.len()];
        tunnel.read_exact(&mut back).await.unwrap();
        assert_eq!(back, big);
    }
    {
        let requests = e.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|r| r.command == header::TCP));
        assert_eq!(requests[0].port, 443);
        assert_eq!(requests[0].address, [192, 0, 2, 1]);
        assert_eq!(requests[1].address.len(), 16);
        assert_eq!(&requests[2].address[1..], b"example.com");
    }
    assert!(matches!(
        session.open_icmp().await,
        Err(Error::Unsupported(_))
    ));
}

#[tokio::test]
async fn a_finished_upload_still_receives_the_late_answer() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(LATE, Ordering::SeqCst);
    let mut tunnel = session.open_tcp("192.0.2.1:80").await.unwrap();
    tunnel.write_all(b"request").await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut answer = vec![];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut answer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer, b"request");
}

#[tokio::test]
async fn upgrade_failures_fail_closed_without_leaking_the_path() {
    for (mode, expected) in [
        (NOT_FOUND, Error::Rejected(404)),
        (REDIRECT, Error::Rejected(301)),
        (BAD_ACCEPT, Error::Protocol),
    ] {
        let e = endpoint(&[HOST], &[b"http/1.1"]).await;
        e.mode.store(mode, Ordering::SeqCst);
        let error = Session::connect(&e.profile).await.err().unwrap();
        assert_eq!(format!("{error:?}"), format!("{expected:?}"));
        canaries(&error);
        // A redirect is not followed and nothing is retried.
        assert_eq!(e.accepted.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn tls_identity_and_alpn_are_enforced() {
    let e = endpoint(&["other.example.com"], &[b"http/1.1"]).await;
    let error = Session::connect(&e.profile).await.err().unwrap();
    assert!(matches!(error, Error::Tls), "{error:?}");
    canaries(&error);
    // One TLS attempt, no plaintext retry.
    assert_eq!(e.accepted.load(Ordering::SeqCst), 1);
    let e = endpoint(&[HOST], &[b"h2"]).await;
    let error = Session::connect(&e.profile).await.err().unwrap();
    assert!(matches!(error, Error::Tls | Error::Protocol), "{error:?}");
    assert_eq!(e.accepted.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_dropped_open_closes_its_connection() {
    let mut e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), e.closed.recv())
        .await
        .unwrap();
    e.mode.store(HANG, Ordering::SeqCst);
    assert!(
        tokio::time::timeout(Duration::from_millis(500), session.open_tcp("192.0.2.1:80"))
            .await
            .is_err()
    );
    // The server sees the abandoned connection close.
    tokio::time::timeout(Duration::from_secs(2), e.closed.recv())
        .await
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn every_flow_socket_is_protected() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let protector: SocketProtector = Arc::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    let session = Session::connect_protected(&e.profile, &protector)
        .await
        .unwrap();
    for _ in 0..2 {
        let mut tunnel = session.open_tcp("192.0.2.1:80").await.unwrap();
        tunnel.write_all(b"x").await.unwrap();
        tunnel.read_u8().await.unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 3);
    assert_eq!(e.accepted.load(Ordering::SeqCst), 3);
    // A failing protector fails the open; nothing connects unprotected.
    let refuse: SocketProtector = Arc::new(|_| Err(std::io::Error::other("refused")));
    assert!(
        Session::connect_protected(&e.profile, &refuse)
            .await
            .is_err()
    );
    assert_eq!(e.accepted.load(Ordering::SeqCst), 3);
}

async fn send_udp(tunnel: &mut Tunnel, source: &str, destination: &str, payload: Vec<u8>) {
    let d = Datagram {
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
        payload,
    };
    tunnel
        .write_all(&crate::udp::encode(&d, "app").unwrap())
        .await
        .unwrap();
}

#[tokio::test]
async fn udp_flows_echo_and_respect_limits() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    let mut tunnel = session.open_udp().await.unwrap();
    for size in [1, 1200, udp::VLESS_UDP_MAX] {
        send_udp(&mut tunnel, "10.0.0.2:5000", "192.0.2.53:53", vec![9; size]).await;
        let answer = tokio::time::timeout(Duration::from_secs(5), crate::udp::read(&mut tunnel))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer.source, "192.0.2.53:53".parse().unwrap());
        assert_eq!(answer.destination, "10.0.0.2:5000".parse().unwrap());
        assert_eq!(answer.payload.len(), size);
    }
    // One flow for that pair, opened with command 2.
    {
        let requests = e.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!((requests[0].command, requests[0].port), (header::UDP, 53));
    }
    let before = udp::OVERSIZE.load(Ordering::Relaxed);
    send_udp(
        &mut tunnel,
        "10.0.0.2:5000",
        "192.0.2.53:53",
        vec![1; udp::VLESS_UDP_MAX + 1],
    )
    .await;
    // Many destinations: no more flows than the per-tunnel limit open.
    for port in 1000..1100 {
        send_udp(
            &mut tunnel,
            "10.0.0.2:5000",
            &format!("192.0.2.9:{port}"),
            vec![1],
        )
        .await;
    }
    let mut answers = 0;
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_secs(2), crate::udp::read(&mut tunnel)).await
    {
        answers += 1;
    }
    assert!(udp::OVERSIZE.load(Ordering::Relaxed) > before);
    assert_eq!(answers, udp::TUNNEL_FLOWS - 1);
    assert_eq!(e.requests.lock().unwrap().len(), udp::TUNNEL_FLOWS);
}

#[tokio::test]
async fn xhttp_and_other_protocols_never_reach_this_transport() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let mut p = e.profile.clone();
    p.vless.as_mut().unwrap().transport = "xhttp".into();
    assert!(matches!(
        Session::connect(&p).await,
        Err(Error::Unsupported("VLESS XHTTP transport"))
    ));
    assert!(matches!(
        H2Session::connect(&e.profile).await,
        Err(Error::Unsupported(_))
    ));
    assert_eq!(e.accepted.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn udp_flows_expire_when_idle_and_drop_on_a_full_queue() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    let mut tunnel = session.open_udp().await.unwrap();
    // The handshake is slow: only a queue's worth of the burst survives.
    e.mode.store(SLOW, Ordering::SeqCst);
    for _ in 0..100 {
        send_udp(&mut tunnel, "10.0.0.2:5000", "192.0.2.53:53", vec![1]).await;
    }
    let mut answers = 0;
    while let Ok(Ok(_)) =
        tokio::time::timeout(Duration::from_secs(2), crate::udp::read(&mut tunnel)).await
    {
        answers += 1;
    }
    assert_eq!(answers, udp::QUEUE);
    assert_eq!(e.requests.lock().unwrap().len(), 1);
    // The 2 s of silence above outlived the idle limit: the next packet opens a new flow.
    e.mode.store(ECHO, Ordering::SeqCst);
    send_udp(&mut tunnel, "10.0.0.2:5000", "192.0.2.53:53", vec![2]).await;
    tokio::time::timeout(Duration::from_secs(5), crate::udp::read(&mut tunnel))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(e.requests.lock().unwrap().len(), 2);
}
