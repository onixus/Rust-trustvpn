//! VLESS over WebSocket + TLS against the official Xray-core on loopback.
//! Run through `ci/vless_interop.py`, which starts the server, the echo
//! targets and passes the synthetic link and CA in the environment.
use rtrust_engine::{Error, Session, Tunnel, udp};
use rtrust_profile::{Format, Profile};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}
fn mode() -> String {
    env("RTRUST_VLESS_MODE")
}
fn payload(size: usize, seed: u8) -> Vec<u8> {
    (0..size)
        .map(|n| (n as u8).wrapping_mul(31) ^ seed ^ (n >> 8) as u8)
        .collect()
}
/// The link with the fixture CA; the certificate never travels in a link.
fn profile(link: &str) -> Profile {
    let mut p = Profile::import(link).unwrap();
    p.endpoint.certificate = std::fs::read_to_string(env("RTRUST_VLESS_CA")).unwrap();
    p
}
/// The UUID and path of the link, which no error or Debug output may show.
fn secrets(link: &str) -> Vec<String> {
    let uuid = link["vless://".len()..link.find('@').unwrap()].to_owned();
    let path = query(link, "path").trim_start_matches("%2F").to_owned();
    vec![uuid.clone(), uuid.replace('-', ""), path]
}
fn query(link: &str, key: &str) -> String {
    let start = link.find(&format!("{key}=")).unwrap() + key.len() + 1;
    let end = link[start..]
        .find(['&', '#'])
        .map_or(link.len(), |n| start + n);
    link[start..end].to_owned()
}
fn replace_query(link: &str, key: &str, value: &str) -> String {
    link.replacen(
        &format!("{key}={}", query(link, key)),
        &format!("{key}={value}"),
        1,
    )
}
fn assert_no_secret(text: &str, link: &str) {
    for secret in secrets(link) {
        assert!(!secret.is_empty());
        assert!(
            !text.contains(&secret),
            "a link secret appears in output of length {}",
            text.len()
        );
    }
}
fn canary(error: &Error, link: &str) {
    assert_no_secret(&format!("{error} {error:?}"), link);
}

/// Writes and reads concurrently: the tunnel buffers are smaller than the payload.
async fn echo(tunnel: Tunnel, data: &[u8]) -> Vec<u8> {
    let (mut read, mut write) = tokio::io::split(tunnel);
    let mut back = vec![0; data.len()];
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::try_join!(write.write_all(data), read.read_exact(&mut back))
    })
    .await
    .expect("TCP echo timeout")
    .unwrap();
    back
}
async fn tcp_echo(session: &Session, target: &str, data: &[u8]) {
    let tunnel = session.open_tcp(target).await.unwrap();
    let back = echo(tunnel, data).await;
    assert_eq!(
        Sha256::digest(&back),
        Sha256::digest(data),
        "{} bytes",
        data.len()
    );
}
fn datagram(source: &str, destination: &str, payload: Vec<u8>) -> udp::Datagram {
    udp::Datagram {
        source: source.parse().unwrap(),
        destination: destination.parse().unwrap(),
        payload,
    }
}
async fn send(tunnel: &mut Tunnel, d: &udp::Datagram) {
    tunnel
        .write_all(&udp::encode(d, "fixture").unwrap())
        .await
        .unwrap();
}
async fn receive(tunnel: &mut Tunnel, wait: Duration) -> Option<udp::Datagram> {
    tokio::time::timeout(wait, udp::read(tunnel))
        .await
        .ok()
        .map(|r| r.unwrap())
}
/// Descriptors of this process; a leaked flow keeps its socket.
fn descriptors() -> usize {
    std::fs::read_dir(if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    })
    .unwrap()
    .count()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn open_mode_tcp_udp_and_icmp() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let tcp = format!("127.0.0.1:{}", env("RTRUST_VLESS_TCP"));
    let udp_target = format!("127.0.0.1:{}", env("RTRUST_VLESS_UDP"));
    let udp_second = format!("127.0.0.1:{}", env("RTRUST_VLESS_UDP2"));
    let p = profile(&link);
    assert_eq!(p.transport_name(), "VLESS WS");
    assert_no_secret(&format!("{p:?} {:?}", p.vless), &link);
    let session = Session::connect(&p).await.unwrap();
    session.health().await.unwrap();

    // Small and large payloads, compared by digest.
    tcp_echo(&session, &tcp, b"hello").await;
    tcp_echo(&session, &tcp, &payload(512 * 1024, 1)).await;
    tcp_echo(&session, &tcp, &payload(2 * 1024 * 1024 + 7, 2)).await;
    // Parallel flows, each its own TLS connection, do not mix bytes.
    let streams: Vec<_> = (0..8u8)
        .map(|n| {
            let (session, tcp) = (session.clone(), tcp.clone());
            tokio::spawn(
                async move { tcp_echo(&session, &tcp, &payload(256 * 1024, n + 10)).await },
            )
        })
        .collect();
    for stream in streams {
        stream.await.unwrap();
    }
    // A closed uplink still gets the rest of the answer (half close).
    let mut tunnel = session.open_tcp(&tcp).await.unwrap();
    let data = payload(100_000, 3);
    tunnel.write_all(&data).await.unwrap();
    tunnel.shutdown().await.unwrap();
    let mut back = vec![];
    tokio::time::timeout(Duration::from_secs(20), tunnel.read_to_end(&mut back))
        .await
        .expect("half-closed flow did not finish")
        .unwrap();
    assert_eq!(back, data);

    // UDP: sizes up to the VLESS limit come back intact; 8191 is dropped
    // locally and does not break the stream.
    let mut stream = session.open_udp().await.unwrap();
    for size in [1, 1400, 8190] {
        let sent = datagram("10.0.0.2:12000", &udp_target, payload(size, 4));
        send(&mut stream, &sent).await;
        let reply = receive(&mut stream, Duration::from_secs(10))
            .await
            .unwrap_or_else(|| panic!("UDP timeout for payload {size}"));
        assert_eq!(
            (reply.payload, reply.source, reply.destination),
            (sent.payload, sent.destination, sent.source),
            "UDP {size}"
        );
    }
    for size in [8191, 20_000] {
        send(
            &mut stream,
            &datagram("10.0.0.2:12000", &udp_target, vec![9; size]),
        )
        .await;
        assert!(
            receive(&mut stream, Duration::from_secs(2)).await.is_none(),
            "UDP {size} was delivered"
        );
    }
    // Two destinations and two sources in one tunnel, answered to the right pair.
    let pairs = [
        ("10.0.0.2:12000", &udp_target),
        ("10.0.0.2:12000", &udp_second),
        ("10.0.0.3:13000", &udp_target),
    ];
    for (n, (source, destination)) in pairs.iter().enumerate() {
        send(
            &mut stream,
            &datagram(source, destination, vec![n as u8; 600 + n]),
        )
        .await;
    }
    let mut replies = vec![];
    for _ in pairs {
        let r = receive(&mut stream, Duration::from_secs(10))
            .await
            .expect("UDP reply missing");
        replies.push((r.destination.to_string(), r.source.to_string(), r.payload));
    }
    replies.sort();
    let mut expected: Vec<_> = pairs
        .iter()
        .enumerate()
        .map(|(n, (s, d))| (s.to_string(), d.to_string(), vec![n as u8; 600 + n]))
        .collect();
    expected.sort();
    assert_eq!(replies, expected);
    drop(stream);

    // ICMP has no VLESS command.
    let error = session
        .open_icmp()
        .await
        .err()
        .expect("ICMP must be refused");
    assert!(matches!(error, Error::Unsupported(_)), "{error:?}");
    canary(&error, &link);
    session.health().await.unwrap();
}

/// Link and JSON exports re-import to the same profile, and the JSON one connects.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn link_and_json_round_trip_connects() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let tcp = format!("127.0.0.1:{}", env("RTRUST_VLESS_TCP"));
    let bare = Profile::import(&link).unwrap();
    let exported = bare.export(Format::Link).unwrap();
    assert!(exported.content.starts_with("vless://"));
    assert_eq!(Profile::import(&exported.content).unwrap(), bare);
    let full = profile(&link);
    let json = full.export(Format::Json).unwrap();
    let reimported = Profile::import(&json.content).unwrap();
    assert_eq!(reimported, full);
    let session = Session::connect(&reimported).await.unwrap();
    tcp_echo(&session, &tcp, &payload(64 * 1024, 5)).await;
}

/// The certificate is checked against `sni`: no CA, or another name, fails as TLS.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn certificate_is_verified() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let error = Session::connect(&Profile::import(&link).unwrap())
        .await
        .err()
        .expect("connected without trusting the fixture CA");
    assert!(matches!(error, Error::Tls), "{error:?}");
    canary(&error, &link);
    let other = replace_query(
        &replace_query(&link, "sni", "other.test"),
        "host",
        "other.test",
    );
    let error = Session::connect(&profile(&other))
        .await
        .err()
        .expect("connected with a certificate for another name");
    assert!(matches!(error, Error::Tls), "{error:?}");
    canary(&error, &link);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn wrong_path_and_wrong_uuid() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let tcp = format!("127.0.0.1:{}", env("RTRUST_VLESS_TCP"));
    // The path is checked by the WebSocket upgrade.
    let wrong_path = replace_query(&link, "path", "%2Fnot-the-fixture-path-0000");
    let started = Instant::now();
    let error = Session::connect(&profile(&wrong_path))
        .await
        .err()
        .expect("wrong path connected");
    assert!(matches!(error, Error::Rejected(404)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
    canary(&error, &link);
    canary(&error, &wrong_path);

    // The UUID is checked only by a VLESS request: the probe passes, flows carry nothing.
    let user = &link["vless://".len()..link.find('@').unwrap()];
    let wrong_uuid = link.replacen(user, "00000000-0000-4000-8000-0000000000a1", 1);
    let session = Session::connect(&profile(&wrong_uuid)).await.unwrap();
    let mut tunnel = session.open_tcp(&tcp).await.unwrap();
    tunnel.write_all(b"must not arrive").await.unwrap();
    let mut back = vec![];
    let read = tokio::time::timeout(Duration::from_secs(15), tunnel.read_to_end(&mut back))
        .await
        .expect("flow with a wrong UUID stayed open");
    if let Err(error) = &read {
        assert_no_secret(&format!("{error} {error:?}"), &link);
    }
    assert!(back.is_empty(), "{} bytes with a wrong UUID", back.len());
}

/// Cancelled opens and dropped flows give back every socket.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn cancelled_and_dropped_flows_release_sockets() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let tcp = format!("127.0.0.1:{}", env("RTRUST_VLESS_TCP"));
    let udp_target = format!("127.0.0.1:{}", env("RTRUST_VLESS_UDP"));
    let session = Session::connect(&profile(&link)).await.unwrap();
    let baseline = descriptors();
    let mut held = vec![];
    for n in 0..16u8 {
        let mut tunnel = session.open_tcp(&tcp).await.unwrap();
        tunnel.write_all(&[n; 32]).await.unwrap();
        let mut back = [0; 32];
        tunnel.read_exact(&mut back).await.unwrap();
        held.push(tunnel);
    }
    let mut udp_stream = session.open_udp().await.unwrap();
    send(
        &mut udp_stream,
        &datagram("10.0.0.2:12000", &udp_target, vec![1; 100]),
    )
    .await;
    receive(&mut udp_stream, Duration::from_secs(10))
        .await
        .expect("UDP reply missing");
    assert!(descriptors() >= baseline + 16);
    drop(held);
    drop(udp_stream);
    // Opens cancelled at every stage: TCP connect, TLS, upgrade.
    let mut cancelled = 0;
    for delay in 0..40u64 {
        if tokio::time::timeout(Duration::from_micros(delay * 500), session.open_tcp(&tcp))
            .await
            .is_err()
        {
            cancelled += 1;
        }
    }
    assert!(cancelled > 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while descriptors() > baseline && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        descriptors() <= baseline,
        "{} descriptors left over after {cancelled} cancelled opens",
        descriptors() - baseline
    );
    tcp_echo(&session, &tcp, b"still works").await;
}

/// The server blocks private targets: no data reaches the client.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn private_mode_blocks_loopback_targets() {
    if mode() != "private" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let tcp = format!("127.0.0.1:{}", env("RTRUST_VLESS_TCP"));
    let udp_target = format!("127.0.0.1:{}", env("RTRUST_VLESS_UDP"));
    let session = Session::connect(&profile(&link)).await.unwrap();
    let started = Instant::now();
    match session.open_tcp(&tcp).await {
        Err(error) => canary(&error, &link),
        Ok(mut tunnel) => {
            tunnel.write_all(b"blocked").await.unwrap();
            let mut back = vec![];
            let read = tokio::time::timeout(Duration::from_secs(20), tunnel.read_to_end(&mut back))
                .await
                .expect("blocked TCP flow did not close");
            assert!(
                back.is_empty(),
                "{} bytes from a blocked target",
                back.len()
            );
            println!(
                "private TCP: {:?} after {:?}",
                read.map(|_| "EOF"),
                started.elapsed()
            );
        }
    }
    let mut stream = session.open_udp().await.unwrap();
    send(
        &mut stream,
        &datagram("10.0.0.2:12000", &udp_target, b"blocked".to_vec()),
    )
    .await;
    assert!(receive(&mut stream, Duration::from_secs(4)).await.is_none());
}

/// Kills the restart stand's Xray when dropped, so a failed test leaves nothing running.
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Xray dies mid-flow and comes back on the same port: the flow ends, health
/// fails within the freshness window, and new flows work after the restart.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn server_crash_and_restart() {
    let Ok(link) = std::env::var("RTRUST_VLESS_RESTART_LINK") else {
        return;
    };
    let tcp = format!("127.0.0.1:{}", env("RTRUST_VLESS_TCP"));
    let session = Session::connect(&profile(&link)).await.unwrap();
    let tunnel = session.open_tcp(&tcp).await.unwrap();
    let (mut read, mut write) = tokio::io::split(tunnel);
    write.write_all(b"before").await.unwrap();
    let mut back = [0; 6];
    read.read_exact(&mut back).await.unwrap();

    let status = std::process::Command::new("kill")
        .args(["-9", &env("RTRUST_VLESS_RESTART_PID")])
        .status()
        .unwrap();
    assert!(status.success());
    let started = Instant::now();
    let mut rest = vec![];
    let ended = tokio::time::timeout(Duration::from_secs(15), read.read_to_end(&mut rest))
        .await
        .expect("flow survived the server");
    println!(
        "flow after crash: {:?} in {:?}",
        ended.map(|_| "EOF"),
        started.elapsed()
    );
    assert!(rest.is_empty());
    let error = session
        .open_tcp(&tcp)
        .await
        .err()
        .expect("opened without a server");
    canary(&error, &link);
    println!("open without server: {error:?} in {:?}", started.elapsed());
    let failed = loop {
        match session.health().await {
            Err(error) => break error,
            Ok(()) if started.elapsed() < Duration::from_secs(45) => {
                tokio::time::sleep(Duration::from_secs(1)).await
            }
            Ok(()) => panic!("health stayed Ok 45 s after the server died"),
        }
    };
    canary(&failed, &link);
    println!(
        "health failed with {failed:?} after {:?}",
        started.elapsed()
    );

    let _server = Child(
        std::process::Command::new(env("RTRUST_VLESS_XRAY"))
            .args(["run", "-c", &env("RTRUST_VLESS_RESTART_CONFIG")])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let port = link[link.find("@127.0.0.1:").unwrap() + 11..link.find('?').unwrap()].to_owned();
    let deadline = Instant::now() + Duration::from_secs(10);
    while tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .is_err()
    {
        assert!(Instant::now() < deadline, "restarted Xray did not listen");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    session.health().await.unwrap();
    tcp_echo(&session, &tcp, &payload(128 * 1024, 6)).await;
}

/// A TCP relay in front of Xray that counts the connections the client makes.
struct Counter {
    port: u16,
    accepted: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}
impl Counter {
    async fn start(link: &str) -> Self {
        let upstream = server(link);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = accepted.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let upstream = upstream.clone();
                tokio::spawn(async move {
                    if let Ok(mut outbound) = tokio::net::TcpStream::connect(upstream).await {
                        let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });
        Self {
            port,
            accepted,
            task,
        }
    }
    fn count(&self) -> usize {
        self.accepted.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// The link through this relay.
    fn link(&self, link: &str) -> String {
        link.replacen(&server(link), &format!("127.0.0.1:{}", self.port), 1)
    }
}
impl Drop for Counter {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn server(link: &str) -> String {
    link[link.find('@').unwrap() + 1..link.find('?').unwrap()].to_owned()
}

/// Resolver-like load: every query from a new source port is its own flow,
/// far more than the tunnel's flow table holds; all are answered.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn many_udp_sources_are_all_answered() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let udp_target = format!("127.0.0.1:{}", env("RTRUST_VLESS_UDP"));
    let counter = Counter::start(&link).await;
    let session = Session::connect(&profile(&counter.link(&link)))
        .await
        .unwrap();
    let baseline = descriptors();
    let mut stream = session.open_udp().await.unwrap();
    let started = Instant::now();
    for n in 0..240u16 {
        let source = format!("10.0.0.2:{}", 20_000 + n);
        let query = payload(40 + (n as usize % 60), n as u8);
        send(&mut stream, &datagram(&source, &udp_target, query.clone())).await;
        let reply = receive(&mut stream, Duration::from_secs(10))
            .await
            .unwrap_or_else(|| panic!("query {n} unanswered"));
        assert_eq!(
            (reply.payload, reply.destination.to_string()),
            (query, source)
        );
    }
    // Live flows stay bounded by the table, not by the number of sources:
    // each flow holds its socket plus both relay sockets of the counter.
    let live = descriptors().saturating_sub(baseline);
    println!(
        "240 sequential sources answered in {:?}; {} server connections; {live} extra descriptors",
        started.elapsed(),
        counter.count()
    );
    assert!(
        live <= 3 * (64 + 8),
        "{live} descriptors held for 240 sources"
    );
    // A burst within the table size is answered too.
    for n in 0..48u16 {
        let source = format!("10.0.0.3:{}", 30_000 + n);
        send(
            &mut stream,
            &datagram(&source, &udp_target, vec![n as u8; 64]),
        )
        .await;
    }
    let mut answered = std::collections::HashSet::new();
    while answered.len() < 48 {
        let reply = receive(&mut stream, Duration::from_secs(10))
            .await
            .unwrap_or_else(|| panic!("burst: {} of 48 answered", answered.len()));
        answered.insert(reply.destination.port());
    }
}

/// An unknown UUID: Xray closes every UDP flow without a byte. The client
/// backs off instead of reconnecting per packet, and the right link still works.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn wrong_uuid_udp_does_not_storm_the_server() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let udp_target = format!("127.0.0.1:{}", env("RTRUST_VLESS_UDP"));
    let counter = Counter::start(&link).await;
    let user = &link["vless://".len()..link.find('@').unwrap()];
    let wrong = counter
        .link(&link)
        .replacen(user, "00000000-0000-4000-8000-0000000000a2", 1);
    let session = Session::connect(&profile(&wrong)).await.unwrap();
    let probe = counter.count();
    let mut stream = session.open_udp().await.unwrap();
    // One source, a packet every 20 ms for 6 s.
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(6) {
        send(
            &mut stream,
            &datagram("10.0.0.2:12000", &udp_target, vec![7; 32]),
        )
        .await;
        assert!(
            receive(&mut stream, Duration::from_millis(20))
                .await
                .is_none(),
            "answer with a wrong UUID"
        );
    }
    let single = counter.count() - probe;
    println!("wrong UUID, one source, ~300 packets in 6 s: {single} server connections");
    assert!(single <= 5, "{single} connections for one refused flow");
    // Many sources: each is its own flow and costs at least one connection.
    let before = counter.count();
    for n in 0..100u16 {
        let source = format!("10.0.0.2:{}", 40_000 + n);
        send(&mut stream, &datagram(&source, &udp_target, vec![8; 32])).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    println!(
        "wrong UUID, 100 sources: {} server connections",
        counter.count() - before
    );
    drop(stream);

    let session = Session::connect(&profile(&counter.link(&link)))
        .await
        .unwrap();
    let mut stream = session.open_udp().await.unwrap();
    let sent = datagram("10.0.0.2:12000", &udp_target, payload(1000, 9));
    send(&mut stream, &sent).await;
    let reply = receive(&mut stream, Duration::from_secs(10))
        .await
        .expect("right link unanswered after the wrong one");
    assert_eq!(reply.payload, sent.payload);
}

/// XHTTP links import but never connect: no fallback to WebSocket or anything else.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "run through ci/vless_interop.py"]
async fn xhttp_is_unsupported_without_connecting() {
    if mode() != "open" {
        return;
    }
    let link = env("RTRUST_VLESS_LINK");
    let counter = Counter::start(&link).await;
    let through = counter.link(&link);
    let xhttp = replace_query(&through, "type", "xhttp")
        .replacen(&format!("&alpn={}", query(&through, "alpn")), "", 1)
        .replacen("#", "&mode=auto#", 1);
    let p = profile(&xhttp);
    assert_eq!(p.transport_name(), "VLESS XHTTP");
    let started = Instant::now();
    let error = Session::connect(&p).await.err().expect("XHTTP connected");
    assert!(matches!(error, Error::Unsupported(_)), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(1));
    canary(&error, &link);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(counter.count(), 0, "XHTTP profile reached the server");
}
