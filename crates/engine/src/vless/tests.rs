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
/// Echoes the first payload, then neither reads nor answers, and never closes.
const SILENT: u8 = 7;
/// UDP: answers every packet with a 65535-byte packet first, then echoes.
const BIG: u8 = 8;
/// Upgrades, then closes at once without a byte, as Xray does for an unknown UUID.
const REVOKED: u8 = 9;
/// TCP: a target that reads at [`SINK_RATE`] and stays silent until it got
/// [`SINK_TOTAL`] bytes; pings are answered only when read, as Xray does.
const SINK: u8 = 10;
const SINK_RATE: f64 = 256.0 * 1024.0;
const SINK_TOTAL: usize = 1024 * 1024;
/// UDP: takes the request and every packet but never answers, as Xray now and
/// then does on a fresh connection; the socket stays open.
const MUTE: u8 = 11;

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
    /// Most connections the server held open at once.
    peak: Arc<AtomicUsize>,
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
    let (open, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let requests = Arc::new(Mutex::new(vec![]));
    let (closed_tx, closed) = tokio::sync::mpsc::unbounded_channel();
    let task = {
        let (mode, accepted, requests) = (mode.clone(), accepted.clone(), requests.clone());
        let peak = peak.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                peak.fetch_max(open.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                let open = open.clone();
                let (acceptor, mode, requests, closed) = (
                    acceptor.clone(),
                    mode.load(Ordering::SeqCst),
                    requests.clone(),
                    closed_tx.clone(),
                );
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        let _ = serve(tls, mode, requests).await;
                        let _ = closed.send(());
                    }
                    open.fetch_sub(1, Ordering::SeqCst);
                });
            }
        })
    };
    Endpoint {
        profile,
        mode,
        accepted,
        peak,
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
    if mode == REVOKED {
        tls.write_all(&server_frame(ws::CLOSE, &[3, 232])).await?;
        return Ok(());
    }
    let mut data = vec![];
    let mut answered = false;
    let mut command = None;
    let mut sunk = 0;
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
            ws::BINARY if mode == SINK => {
                tokio::time::sleep(Duration::from_secs_f64(payload.len() as f64 / SINK_RATE)).await;
                sunk += payload.len();
                if sunk >= SINK_TOTAL && !answered {
                    answered = true;
                    tls.write_all(&server_frame(ws::BINARY, b"\0\0done"))
                        .await?;
                }
                continue;
            }
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
        if mode == MUTE {
            data.clear();
            continue;
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
        if mode == BIG && command == Some(header::UDP) {
            let mut big = vec![0xff, 0xff];
            big.resize(2 + 65535, 1);
            out.splice(0..0, big);
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
        if mode == SILENT {
            // A path that died without FIN or RST: the socket stays open.
            std::future::pending::<()>().await;
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
    } else if payload.len() <= 0xffff {
        out.push(126);
        out.extend((payload.len() as u16).to_be_bytes());
    } else {
        out.push(127);
        out.extend((payload.len() as u64).to_be_bytes());
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
    send_udp(&mut tunnel, "10.0.0.2:5000", "192.0.2.53:53", vec![5]).await;
    // Only the small datagram comes back: the oversized one never left.
    let answer = tokio::time::timeout(Duration::from_secs(5), crate::udp::read(&mut tunnel))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(answer.payload, [5]);
    assert!(udp::OVERSIZE.load(Ordering::Relaxed) > before);
}

async fn answer(tunnel: &mut Tunnel) -> Option<Datagram> {
    tokio::time::timeout(Duration::from_secs(5), crate::udp::read(tunnel))
        .await
        .ok()
        .and_then(|d| d.ok())
}

#[tokio::test]
async fn fresh_source_ports_never_exhaust_the_flow_table() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    let mut tunnel = session.open_udp().await.unwrap();
    // A stub resolver uses a new source port per query; so may any other client.
    for (destination, ports) in [
        ("192.0.2.53:53", 20000..20200),
        ("192.0.2.9:5353", 30000..30200),
    ] {
        for port in ports {
            send_udp(
                &mut tunnel,
                &format!("10.0.0.2:{port}"),
                destination,
                vec![7],
            )
            .await;
            let d = answer(&mut tunnel).await.expect("every query is answered");
            assert_eq!(d.destination.port(), port);
        }
    }
    assert_eq!(e.requests.lock().unwrap().len(), 400);
    // Evicted flows close: the server never held many more than the table size.
    let peak = e.peak.load(Ordering::SeqCst);
    assert!(peak <= udp::TUNNEL_FLOWS + 8, "{peak}");
}

#[tokio::test]
async fn a_silent_udp_path_is_replaced_by_a_new_flow() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(SILENT, Ordering::SeqCst);
    let mut tunnel = session.open_udp().await.unwrap();
    send_udp(&mut tunnel, "10.0.0.2:6000", "192.0.2.9:6000", vec![1]).await;
    assert!(answer(&mut tunnel).await.is_some());
    // The client keeps sending into a path that no longer answers.
    let mut answers = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    while tokio::time::Instant::now() < deadline {
        send_udp(&mut tunnel, "10.0.0.2:6000", "192.0.2.9:6000", vec![2]).await;
        if let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(100), crate::udp::read(&mut tunnel)).await
        {
            answers += 1;
        }
    }
    // Each replacement flow answers its first packet once.
    assert!(e.requests.lock().unwrap().len() >= 2);
    assert!(answers >= 1);
}

/// Nothing comes back within the first-answer window and a bit more.
async fn quiet(tunnel: &mut Tunnel) -> bool {
    tokio::time::timeout(Duration::from_millis(400), crate::udp::read(tunnel))
        .await
        .is_err()
}

#[tokio::test]
async fn a_fresh_flow_without_any_answer_is_reopened_once() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(MUTE, Ordering::SeqCst);
    let mut tunnel = session.open_udp().await.unwrap();
    let pair = ("10.0.0.2:7000", "192.0.2.9:7000");
    send_udp(&mut tunnel, pair.0, pair.1, vec![1]).await;
    assert!(quiet(&mut tunnel).await);
    // Past the first-answer window the next datagram reopens the flow, once:
    // a target that stays silent costs one extra connection, not one per packet.
    for _ in 0..3 {
        send_udp(&mut tunnel, pair.0, pair.1, vec![2]).await;
        assert!(quiet(&mut tunnel).await);
    }
    let requests = |e: &Endpoint| e.requests.lock().unwrap().len();
    assert_eq!(requests(&e), 2);
    // An answered flow is never reopened for silence.
    e.mode.store(ECHO, Ordering::SeqCst);
    let pair = ("10.0.0.2:7001", "192.0.2.9:7001");
    for _ in 0..2 {
        send_udp(&mut tunnel, pair.0, pair.1, vec![3]).await;
        assert!(answer(&mut tunnel).await.is_some());
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    assert_eq!(requests(&e), 3);
}

#[tokio::test]
async fn a_silent_tcp_path_ends_the_flow() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(SILENT, Ordering::SeqCst);
    // Idle flow: the ping after the server's silence goes unanswered.
    let mut tunnel = session.open_tcp("192.0.2.1:80").await.unwrap();
    tunnel.write_all(b"a").await.unwrap();
    assert_eq!(tunnel.read_u8().await.unwrap(), b'a');
    let mut rest = vec![];
    let ended = tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "idle flow still open");
    // Uploading flow: the server stops reading, the uplink stops moving.
    let tunnel = session.open_tcp("192.0.2.1:80").await.unwrap();
    let (mut read, mut write) = tokio::io::split(tunnel);
    write.write_all(b"a").await.unwrap();
    assert_eq!(read.read_u8().await.unwrap(), b'a');
    let writer = tokio::spawn(async move {
        let chunk = vec![0u8; 64 * 1024];
        while write.write_all(&chunk).await.is_ok() {}
    });
    let ended = tokio::time::timeout(Duration::from_secs(10), read.read_to_end(&mut rest)).await;
    assert!(ended.is_ok(), "stalled flow still open");
    writer.abort();
}

#[tokio::test]
async fn a_slow_silent_target_keeps_its_upload() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(SINK, Ordering::SeqCst);
    let started = std::time::Instant::now();
    let tunnel = session.open_tcp("192.0.2.1:80").await.unwrap();
    let (mut read, mut write) = tokio::io::split(tunnel);
    let upload = tokio::spawn(async move {
        write.write_all(&vec![7u8; SINK_TOTAL]).await.unwrap();
        write
    });
    // The server is silent for far longer than a ping and its answer window,
    // and answers the ping only after reading the data queued before it.
    let mut done = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(20), read.read_exact(&mut done))
        .await
        .expect("answer in time")
        .expect("flow kept open");
    assert_eq!(&done, b"done");
    assert!(started.elapsed() > KEEPALIVE + PONG_WAIT * 2);
    drop(upload.await.unwrap());
}

#[tokio::test]
async fn refused_flows_back_off_across_the_session() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(REVOKED, Ordering::SeqCst);
    let before = e.accepted.load(Ordering::SeqCst);
    let mut tunnel = session.open_udp().await.unwrap();
    // A resolver: a new source port for every query.
    for port in 0..100 {
        send_udp(
            &mut tunnel,
            &format!("10.0.0.2:{}", 40000 + port),
            "192.0.2.9:9000",
            vec![1],
        )
        .await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let dials = e.accepted.load(Ordering::SeqCst) - before;
    // The streak (8 varied pairs) plus at most a couple in flight.
    assert!(dials <= 10, "{dials}");
    // A recent upgrade does not make the session look healthy.
    assert!(matches!(session.health().await, Err(Error::Unanswered)));
    // Once the server answers again, flows work after the backoff window.
    e.mode.store(ECHO, Ordering::SeqCst);
    tokio::time::sleep(BACKOFF_MAX + Duration::from_millis(300)).await;
    send_udp(&mut tunnel, "10.0.0.2:39000", "192.0.2.9:9000", vec![2]).await;
    assert_eq!(answer(&mut tunnel).await.expect("answered").payload, [2]);
    session.health().await.unwrap();
}

#[tokio::test]
async fn oversized_answers_are_dropped_alone() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(BIG, Ordering::SeqCst);
    let mut tunnel = session.open_udp().await.unwrap();
    let before = udp::OVERSIZE.load(Ordering::Relaxed);
    for port in [7000, 7001] {
        send_udp(
            &mut tunnel,
            "10.0.0.2:7000",
            &format!("192.0.2.9:{port}"),
            vec![3],
        )
        .await;
        let d = answer(&mut tunnel).await.expect("the small answer arrives");
        assert_eq!((d.source.port(), d.payload.as_slice()), (port, &[3][..]));
    }
    assert!(udp::OVERSIZE.load(Ordering::Relaxed) >= before + 2);
    // The first flow is still usable.
    send_udp(&mut tunnel, "10.0.0.2:7000", "192.0.2.9:7000", vec![4]).await;
    assert_eq!(answer(&mut tunnel).await.unwrap().payload, [4]);
}

#[tokio::test]
async fn refused_flows_back_off_instead_of_redialing_per_packet() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(REVOKED, Ordering::SeqCst);
    let before = e.accepted.load(Ordering::SeqCst);
    let mut tunnel = session.open_udp().await.unwrap();
    for _ in 0..100 {
        send_udp(&mut tunnel, "10.0.0.2:8000", "192.0.2.9:8000", vec![1]).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let dials = e.accepted.load(Ordering::SeqCst) - before;
    assert!((1..=2).contains(&dials), "{dials}");
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

async fn refused_tcp(session: &Session, target: &str) {
    let mut tunnel = session.open_tcp(target).await.unwrap();
    tunnel.write_all(b"x").await.unwrap();
    let mut rest = vec![];
    tokio::time::timeout(Duration::from_secs(5), tunnel.read_to_end(&mut rest))
        .await
        .unwrap()
        .unwrap();
    assert!(rest.is_empty());
}

#[tokio::test]
async fn a_few_refusing_targets_do_not_stop_the_session() {
    // Xray closes a flow to an unreachable target without a byte, as for a revoked UUID.
    for targets in [
        vec!["192.0.2.1:80", "192.0.2.2:80", "192.0.2.3:80"],
        vec!["192.0.2.4:80"; 12],
    ] {
        let e = endpoint(&[HOST], &[b"http/1.1"]).await;
        let session = Session::connect(&e.profile).await.unwrap();
        e.mode.store(REVOKED, Ordering::SeqCst);
        for target in targets {
            refused_tcp(&session, target).await;
        }
        session.health().await.unwrap();
        // New flows are dialed at once.
        e.mode.store(ECHO, Ordering::SeqCst);
        let mut tunnel = session.open_tcp("192.0.2.5:80").await.unwrap();
        tunnel.write_all(b"y").await.unwrap();
        assert_eq!(tunnel.read_u8().await.unwrap(), b'y');
    }
}

#[tokio::test]
async fn varied_refusing_tcp_targets_back_off_the_session() {
    let e = endpoint(&[HOST], &[b"http/1.1"]).await;
    let session = Session::connect(&e.profile).await.unwrap();
    e.mode.store(REVOKED, Ordering::SeqCst);
    for n in 0..8 {
        refused_tcp(&session, &format!("192.0.2.{}:80", 1 + n % 4)).await;
    }
    assert!(matches!(session.health().await, Err(Error::Unanswered)));
    assert!(matches!(
        session.open_tcp("192.0.2.9:80").await,
        Err(Error::Unanswered)
    ));
}
