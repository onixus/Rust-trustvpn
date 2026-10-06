//! Loopback-only mixed SOCKS5/HTTP proxy port. The first byte selects the protocol:
//! 0x05 is SOCKS5 (CONNECT, UDP ASSOCIATE); an uppercase ASCII letter is an HTTP proxy
//! request (`CONNECT host:port` tunnels, or one absolute-form `http://` request per
//! connection), so system/WinINet "HTTP proxy" settings pointed at this port also work.
//! No system routes, resolver, or proxy settings are changed.
use crate::{Error, Result, Session, udp};
use rtrust_profile::Profile;
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::{JoinHandle, JoinSet},
    time::{Duration, timeout},
};

const MAX_CLIENTS: usize = 128;
const HANDSHAKE: Duration = Duration::from_secs(15);
/// Upper bound for an HTTP proxy request head (request line plus headers).
const MAX_HEAD: usize = 16 * 1024;
#[derive(Default)]
struct Counters {
    up: AtomicU64,
    down: AtomicU64,
    active: AtomicUsize,
    errors: AtomicU64,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub uploaded: u64,
    pub downloaded: u64,
    pub active: usize,
    pub errors: u64,
}
struct State {
    session: Session,
    address: SocketAddr,
    task: Mutex<Option<JoinHandle<()>>>,
    counters: Arc<Counters>,
    running: Arc<AtomicBool>,
}
impl Drop for State {
    fn drop(&mut self) {
        if let Ok(task) = self.task.get_mut()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
}
#[derive(Clone)]
pub struct Proxy(Arc<State>);
impl Proxy {
    /// Port 0 requests a free ephemeral port. Always binds IPv4 loopback, never a LAN interface.
    pub async fn start(profile: &Profile, port: u16) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|_| Error::LocalBind)?;
        let address = listener.local_addr()?;
        let session = Session::connect(profile).await?;
        session.health().await?;
        let counters = Arc::new(Counters::default());
        let running = Arc::new(AtomicBool::new(true));
        let task = tokio::spawn(serve(
            listener,
            session.clone(),
            counters.clone(),
            running.clone(),
        ));
        Ok(Self(Arc::new(State {
            session,
            address,
            task: Mutex::new(Some(task)),
            counters,
            running,
        })))
    }
    pub fn address(&self) -> SocketAddr {
        self.0.address
    }
    pub fn stats(&self) -> Stats {
        let c = &self.0.counters;
        Stats {
            uploaded: c.up.load(Ordering::Relaxed),
            downloaded: c.down.load(Ordering::Relaxed),
            active: c.active.load(Ordering::Relaxed),
            errors: c.errors.load(Ordering::Relaxed),
        }
    }
    pub fn stop(&self) {
        self.0.running.store(false, Ordering::Release);
        if let Ok(mut task) = self.0.task.lock()
            && let Some(task) = task.take()
        {
            task.abort();
        }
    }
    pub async fn health(&self) -> Result<()> {
        if !self.0.running.load(Ordering::Acquire) {
            return Err(Error::Io);
        }
        self.0.session.health().await
    }
}
struct Alive(Arc<AtomicBool>);
impl Drop for Alive {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
struct Client(Arc<Counters>);
impl Drop for Client {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}
async fn serve(
    listener: TcpListener,
    session: Session,
    counters: Arc<Counters>,
    running: Arc<AtomicBool>,
) {
    let _alive = Alive(running);
    let mut clients = JoinSet::new();
    loop {
        tokio::select! {
            _ = clients.join_next(), if !clients.is_empty() => {},
            incoming = listener.accept() => {
                let Ok((socket, peer)) = incoming else { break; };
                if !peer.ip().is_loopback() || clients.len() >= MAX_CLIENTS { continue; }
                let session = session.clone();
                let counters = counters.clone();
                counters.active.fetch_add(1, Ordering::Relaxed);
                let guard = Client(counters.clone());
                clients.spawn(async move {
                    let _guard = guard;
                    if handle(socket, peer, session, &counters).await.is_err() { counters.errors.fetch_add(1, Ordering::Relaxed); }
                });
            }
        }
    }
    // Dropping JoinSet aborts every client and drops every tunnel and UDP association.
}
#[derive(Debug)]
enum Address {
    Ip(SocketAddr),
    Name(String, u16),
}
impl Address {
    fn authority(&self) -> String {
        match self {
            Self::Ip(a) => a.to_string(),
            Self::Name(n, p) => format!("{n}:{p}"),
        }
    }
}
async fn address(input: &mut (impl AsyncRead + Unpin), kind: u8) -> Result<Address> {
    let host = match kind {
        1 => {
            let mut b = [0; 4];
            input.read_exact(&mut b).await?;
            Some(IpAddr::V4(b.into()))
        }
        4 => {
            let mut b = [0; 16];
            input.read_exact(&mut b).await?;
            Some(IpAddr::V6(b.into()))
        }
        3 => None,
        _ => return Err(Error::Destination),
    };
    if let Some(host) = host {
        return Ok(Address::Ip(SocketAddr::new(host, input.read_u16().await?)));
    }
    let len = input.read_u8().await? as usize;
    if len == 0 {
        return Err(Error::Destination);
    }
    let mut bytes = vec![0; len];
    input.read_exact(&mut bytes).await?;
    // Consume the complete bounded request before rejecting its hostname.
    // Closing with the port bytes unread can send RST on Windows and discard
    // the SOCKS error reply, so clients never receive the required status.
    let port = input.read_u16().await?;
    let name = String::from_utf8(bytes).map_err(|_| Error::Destination)?;
    if !hostname(&name) {
        return Err(Error::Destination);
    }
    Ok(Address::Name(name, port))
}
/// DNS host only; never allow URI delimiters to change the CONNECT authority.
fn hostname(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}
async fn negotiate(socket: &mut TcpStream) -> Result<(u8, Address)> {
    if socket.read_u8().await? != 5 {
        return Err(Error::Protocol);
    }
    let count = socket.read_u8().await? as usize;
    let mut methods = vec![0; count];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        socket.write_all(&[5, 255]).await?;
        return Err(Error::Protocol);
    }
    socket.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        return Err(Error::Protocol);
    }
    if header[1] != 1 && header[1] != 3 {
        reply(socket, 7, None).await?;
        return Err(Error::Unsupported("SOCKS command"));
    }
    match address(socket, header[3]).await {
        Ok(addr) => Ok((header[1], addr)),
        Err(error) => {
            reply(socket, 8, None).await?;
            Err(error)
        }
    }
}
async fn reply(socket: &mut TcpStream, code: u8, bound: Option<SocketAddr>) -> Result<()> {
    let mut bytes = vec![5, code, 0];
    encode_address(
        &mut bytes,
        bound.unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
    );
    socket.write_all(&bytes).await?;
    Ok(())
}
fn encode_address(bytes: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v) => {
            bytes.push(1);
            bytes.extend(v.octets());
        }
        IpAddr::V6(v) => {
            bytes.push(4);
            bytes.extend(v.octets());
        }
    }
    bytes.extend(addr.port().to_be_bytes());
}
enum Request {
    Socks(u8, Address),
    /// `forward` is the rewritten head and body length of an absolute-form request
    /// (None for CONNECT); `early` holds bytes the client already sent after the head.
    Http {
        target: Address,
        forward: Option<(Vec<u8>, u64)>,
        early: Vec<u8>,
    },
}
async fn handshake(socket: &mut TcpStream) -> Result<Request> {
    let mut first = [0; 1];
    match socket.peek(&mut first).await? {
        0 => return Err(Error::Io),
        _ if first[0] == 5 => {
            let (command, target) = negotiate(socket).await?;
            return Ok(Request::Socks(command, target));
        }
        _ if first[0].is_ascii_uppercase() => {}
        _ => return Err(Error::Protocol),
    }
    let parsed = match read_head(socket).await {
        Ok((mut buf, end)) => {
            parse_head(&buf[..end]).map(|(target, forward)| (target, forward, buf.split_off(end)))
        }
        Err(Error::Protocol) => Err(BAD),
        Err(e) => return Err(e),
    };
    match parsed {
        Ok((target, forward, early)) => Ok(Request::Http {
            target,
            forward,
            early,
        }),
        Err((line, error)) => {
            status(socket, line).await?;
            Err(error)
        }
    }
}
/// Reads up to and including the first CRLFCRLF; returns the buffer and the head length.
/// Anything after the head (pipelined TLS or body bytes) stays in the buffer.
async fn read_head(input: &mut (impl AsyncRead + Unpin)) -> Result<(Vec<u8>, usize)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0; 4096];
    loop {
        let n = input.read(&mut chunk).await?;
        if n == 0 {
            return Err(Error::Io);
        }
        let start = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[start..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = start + i + 4;
            return if end > MAX_HEAD {
                Err(Error::Protocol)
            } else {
                Ok((buf, end))
            };
        }
        if buf.len() > MAX_HEAD {
            return Err(Error::Protocol);
        }
    }
}
/// HTTP status line to send and the error to count. Never carries request contents.
type Refusal = (&'static str, Error);
type Parsed = (Address, Option<(Vec<u8>, u64)>);
const BAD: Refusal = ("400 Bad Request", Error::Protocol);
const METHODS: [&str; 7] = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];
/// Parses `CONNECT host:port` or an absolute-form `http://` request. For the latter the
/// head is rewritten to origin-form with hop-by-hop and proxy headers removed and
/// `Connection: close` forced, so the connection carries exactly one request.
fn parse_head(head: &[u8]) -> std::result::Result<Parsed, Refusal> {
    let text = head.strip_suffix(b"\r\n\r\n").ok_or(BAD)?;
    let mut lines = text
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let line = std::str::from_utf8(lines.next().ok_or(BAD)?).map_err(|_| BAD)?;
    let mut parts = line.split(' ');
    let (Some(method), Some(uri), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(BAD);
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0")
        || method.is_empty()
        || !method.bytes().all(|b| b.is_ascii_uppercase())
        || uri.is_empty()
        || !uri.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err(BAD);
    }
    let connect = method == "CONNECT";
    if !connect && !METHODS.contains(&method) {
        return Err((
            "501 Not Implemented",
            Error::Unsupported("HTTP proxy method"),
        ));
    }
    let (authority, path) = if connect {
        (uri, "/")
    } else {
        // Only plain http: an https:// absolute-form request must use CONNECT instead.
        let rest = uri
            .get(..7)
            .filter(|s| s.eq_ignore_ascii_case("http://"))
            .map(|_| &uri[7..])
            .ok_or(BAD)?;
        rest.split_at(rest.find(['/', '?', '#']).unwrap_or(rest.len()))
    };
    let target = target(authority, (!connect).then_some(80)).ok_or(BAD)?;
    let mut headers = Vec::new();
    let mut body = None;
    let mut chunked = false;
    for line in lines {
        let colon = line.iter().position(|&b| b == b':').ok_or(BAD)?;
        let (name, value) = (&line[..colon], line[colon + 1..].trim_ascii());
        // Rejects obs-fold continuation lines, empty names, stray CR and NUL.
        if name.is_empty()
            || !name
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || line.contains(&b'\r')
            || line.contains(&0)
        {
            return Err(BAD);
        }
        match name.to_ascii_lowercase().as_slice() {
            b"content-length" => {
                let n = std::str::from_utf8(value)
                    .ok()
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or(BAD)?;
                match body {
                    Some(m) if m != n => return Err(BAD),
                    Some(_) => continue,
                    None => body = Some(n),
                }
            }
            b"transfer-encoding" => chunked = true,
            b"host"
            | b"connection"
            | b"keep-alive"
            | b"proxy-connection"
            | b"proxy-authorization"
            | b"te"
            | b"upgrade" => continue,
            _ => {}
        }
        headers.extend_from_slice(line);
        headers.extend_from_slice(b"\r\n");
    }
    if connect {
        return Ok((target, None));
    }
    if chunked {
        return Err((
            "501 Not Implemented",
            Error::Unsupported("chunked HTTP proxy request body"),
        ));
    }
    let path = path.split('#').next().unwrap_or_default();
    let slash = if path.starts_with('/') { "" } else { "/" };
    let mut out = format!("{method} {slash}{path} {version}\r\nHost: {authority}\r\n").into_bytes();
    out.extend(headers);
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok((target, Some((out, body.unwrap_or(0)))))
}
/// `host:port`, `a.b.c.d:port` or `[v6]:port`, with the same host rules as SOCKS names.
fn target(s: &str, default: Option<u16>) -> Option<Address> {
    let (host, port) = match s.rfind(':') {
        Some(i) if !s[i..].contains(']') => (&s[..i], Some(&s[i + 1..])),
        _ => (s, None),
    };
    let port = match port {
        Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok()?,
        Some(_) => return None,
        None => default?,
    };
    if port == 0 {
        return None;
    }
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip: std::net::Ipv6Addr = v6.parse().ok()?;
        return Some(Address::Ip(SocketAddr::new(ip.into(), port)));
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Some(Address::Ip(SocketAddr::new(ip.into(), port)));
    }
    hostname(host).then(|| Address::Name(host.into(), port))
}
async fn status(socket: &mut TcpStream, line: &str) -> Result<()> {
    let response = format!("HTTP/1.1 {line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    socket.write_all(response.as_bytes()).await?;
    Ok(())
}
async fn handle(
    mut socket: TcpStream,
    peer: SocketAddr,
    session: Session,
    counters: &Counters,
) -> Result<()> {
    let request = timeout(HANDSHAKE, handshake(&mut socket))
        .await
        .map_err(|_| Error::Timeout)??;
    let (target, http) = match request {
        Request::Socks(3, target) => {
            return relay_udp(socket, peer, target, session, counters).await;
        }
        Request::Socks(_, target) => (target, None),
        Request::Http {
            target,
            forward,
            early,
        } => (target, Some((forward, early))),
    };
    let mut tunnel = match session.open_tcp(&target.authority()).await {
        Ok(t) => t,
        Err(e) => {
            match http {
                None => reply(&mut socket, 1, None).await?,
                Some(_) => status(&mut socket, "502 Bad Gateway").await?,
            }
            return Err(e);
        }
    };
    let (forward, early) = match http {
        None => {
            reply(&mut socket, 0, None).await?;
            (None, Vec::new())
        }
        Some((None, early)) => {
            socket
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await?;
            (None, early)
        }
        Some((Some(forward), early)) => (Some(forward), early),
    };
    let (mut sr, mut sw) = socket.split();
    let (mut tr, mut tw) = tokio::io::split(&mut tunnel);
    let Some((head, body)) = forward else {
        // Pipelined bytes (e.g. a TLS ClientHello sent with CONNECT) go first.
        tw.write_all(&early).await?;
        counters.up.fetch_add(early.len() as u64, Ordering::Relaxed);
        tokio::try_join!(
            copy(&mut sr, &mut tw, &counters.up),
            copy(&mut tr, &mut sw, &counters.down)
        )?;
        return Ok(());
    };
    let first = early.len().min(usize::try_from(body).unwrap_or(usize::MAX));
    tw.write_all(&head).await?;
    tw.write_all(&early[..first]).await?;
    counters
        .up
        .fetch_add((head.len() + first) as u64, Ordering::Relaxed);
    let upload = async {
        pump(
            &mut (&mut sr).take(body - first as u64),
            &mut tw,
            &counters.up,
        )
        .await?;
        // A further request on this connection (possibly for another host) must never
        // reach this origin: discard it until the client closes or the origin finishes.
        let mut sink = [0; 4096];
        while sr.read(&mut sink).await? != 0 {}
        std::future::pending::<Result<()>>().await
    };
    tokio::select! {
        r = copy(&mut tr, &mut sw, &counters.down) => r,
        r = upload => r,
    }
}
async fn copy(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
    bytes: &AtomicU64,
) -> Result<()> {
    pump(r, w, bytes).await?;
    w.shutdown().await?;
    Ok(())
}
/// Copies until EOF without half-closing the writer.
async fn pump(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
    bytes: &AtomicU64,
) -> Result<()> {
    let mut buf = [0; 16 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
        bytes.fetch_add(n as u64, Ordering::Relaxed);
    }
}
async fn relay_udp(
    mut control: TcpStream,
    peer: SocketAddr,
    expected: Address,
    session: Session,
    counters: &Counters,
) -> Result<()> {
    let expected = match expected {
        Address::Ip(a) if a.ip().is_unspecified() || a.ip() == peer.ip() => a,
        _ => {
            reply(&mut control, 2, None).await?;
            return Err(Error::Destination);
        }
    };
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let tunnel = match session.open_udp().await {
        Ok(t) => t,
        Err(e) => {
            reply(&mut control, 1, None).await?;
            return Err(e);
        }
    };
    reply(&mut control, 0, Some(socket.local_addr()?)).await?;
    let (mut read, mut write) = tokio::io::split(tunnel);
    let mut client = None;
    let mut destinations = HashSet::new();
    let mut buf = vec![0; 65535];
    let mut control_byte = [0; 1];
    // Keep a pending frame read outside select: read_exact is not cancellation safe.
    let mut incoming = Box::pin(udp::read(&mut read));
    loop {
        tokio::select! {
            _ = control.read(&mut control_byte) => return Ok(()),
            packet = socket.recv_from(&mut buf) => {
                let (n,source) = packet?;
                if source.ip() != peer.ip() || (expected.port() != 0 && source.port() != expected.port()) || client.is_some_and(|a| a != source) { continue; }
                if n < 4 || buf[..3] != [0,0,0] { continue; } // No fragmented SOCKS UDP support.
                let mut payload = &buf[4..n];
                let Ok(Address::Ip(destination)) = address(&mut payload,buf[3]).await else { continue; };
                if destination.port() == 0 || payload.len() > udp::MAX_DATAGRAM { continue; }
                if !destinations.contains(&destination) && destinations.len() >= 256 { continue; }
                client = Some(source); destinations.insert(destination);
                let frame = udp::encode(&udp::Datagram { source, destination, payload: payload.to_vec() },"rtrust-socks")?;
                write.write_all(&frame).await?;
                counters.up.fetch_add(payload.len() as u64,Ordering::Relaxed);
            },
            packet = &mut incoming => {
                let packet = packet?;
                drop(incoming);
                if let Some(client) = client && packet.destination == client && destinations.contains(&packet.source) {
                    let mut response = vec![0,0,0]; encode_address(&mut response, packet.source); response.extend(&packet.payload);
                    socket.send_to(&response,client).await?;
                    counters.down.fetch_add(packet.payload.len() as u64,Ordering::Relaxed);
                }
                incoming = Box::pin(udp::read(&mut read));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn forward(head: &str) -> (Address, String, u64) {
        let (target, forward) = parse_head(head.as_bytes()).unwrap();
        let (head, body) = forward.unwrap();
        (target, String::from_utf8(head).unwrap(), body)
    }
    fn refused(head: &[u8]) -> &'static str {
        parse_head(head).err().unwrap().0
    }
    #[test]
    fn connect_head_parses_authority() {
        let (target, forward) =
            parse_head(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Connection: keep-alive\r\n\r\n").unwrap();
        assert_eq!(target.authority(), "example.com:443");
        assert!(forward.is_none());
        let (target, _) = parse_head(b"CONNECT [2001:db8::1]:8443 HTTP/1.0\r\n\r\n").unwrap();
        assert_eq!(target.authority(), "[2001:db8::1]:8443");
        let (target, _) = parse_head(b"CONNECT 10.0.0.1:22 HTTP/1.1\r\n\r\n").unwrap();
        assert!(matches!(target, Address::Ip(a) if a == "10.0.0.1:22".parse().unwrap()));
    }
    #[test]
    fn hostname_and_port_rules_match_socks() {
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            "example.com:+443",
            "example.com:65536",
            ":443",
            "user@example.com:443",
            "exa_mple.com:443",
            "ex%41mple.com:443",
            "2001:db8::1:443",
            "[2001:db8::1]",
            "[fe80::1%25en0]:443",
            "[example.com]:443",
        ] {
            assert!(target(bad, None).is_none(), "{bad}");
        }
        assert!(target(&format!("{}:1", "a".repeat(256)), None).is_none());
        assert_eq!(
            target("a-b.example:1", None).unwrap().authority(),
            "a-b.example:1"
        );
        assert_eq!(
            target("example.com", Some(80)).unwrap().authority(),
            "example.com:80"
        );
        assert!(hostname("xn--e1afmkfd.xn--p1ai") && !hostname("") && !hostname("a/b"));
    }
    #[test]
    fn absolute_form_is_rewritten_to_origin_form() {
        let (target, head, body) = forward(
            "POST http://Example.com:8080/a/b?q=1#frag HTTP/1.1\r\n\
             Host: evil.example\r\n\
             Proxy-Connection: keep-alive\r\n\
             proxy-authorization: Basic c2VjcmV0\r\n\
             Connection: keep-alive, Upgrade\r\n\
             Keep-Alive: timeout=5\r\n\
             Upgrade: websocket\r\n\
             User-Agent: test\r\n\
             Content-Length: 5\r\n\
             Content-Length: 5\r\n\r\n",
        );
        assert_eq!(target.authority(), "Example.com:8080");
        assert_eq!(body, 5);
        assert_eq!(
            head,
            "POST /a/b?q=1 HTTP/1.1\r\nHost: Example.com:8080\r\nUser-Agent: test\r\n\
             Content-Length: 5\r\nConnection: close\r\n\r\n"
        );
        let (target, head, body) = forward("GET HTTP://example.com HTTP/1.0\r\n\r\n");
        assert_eq!(target.authority(), "example.com:80");
        assert_eq!(body, 0);
        assert_eq!(
            head,
            "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n"
        );
        let (_, head, _) = forward("HEAD http://[::1]:81?x HTTP/1.1\nAccept: */*\r\n\r\n");
        assert!(head.starts_with("HEAD /?x HTTP/1.1\r\nHost: [::1]:81\r\nAccept: */*\r\n"));
    }
    #[test]
    fn malformed_and_unsupported_heads_are_refused() {
        for head in [
            &b"GET https://example.com/ HTTP/1.1\r\n\r\n"[..],
            b"GET ftp://example.com/ HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
            b"GET http:///x HTTP/1.1\r\n\r\n",
            b"GET http://user@example.com/ HTTP/1.1\r\n\r\n",
            b"CONNECT example.com HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:443 HTTP/2.0\r\n\r\n",
            b"CONNECT  example.com:443 HTTP/1.1\r\n\r\n",
            b"CONNECT example.com:443\r\n\r\n",
            b"Connect example.com:443 HTTP/1.1\r\n\r\n",
            b"GET http://example.com/\xff HTTP/1.1\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nNoColon\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nX\rY: 1\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            b"GET http://example.com/ HTTP/1.1\r\n",
        ] {
            assert_eq!(
                refused(head),
                "400 Bad Request",
                "{}",
                String::from_utf8_lossy(head)
            );
        }
        for head in [
            &b"TRACE http://example.com/ HTTP/1.1\r\n\r\n"[..],
            b"BREW http://example.com/ HTTP/1.1\r\n\r\n",
            b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        ] {
            assert_eq!(refused(head), "501 Not Implemented");
        }
    }
    #[tokio::test]
    async fn head_reader_keeps_pipelined_bytes_and_is_bounded() {
        let (mut client, mut server) = tokio::io::duplex(64);
        let writer = tokio::spawn(async move {
            // Fragmented across the CRLFCRLF boundary, followed by a TLS ClientHello prefix.
            for part in [
                &b"CONNECT a.example:443 HTTP/1.1\r\nHost: a\r"[..],
                b"\n\r",
                b"\n\x16\x03\x01",
            ] {
                client.write_all(part).await.unwrap();
                tokio::task::yield_now().await;
            }
            client
        });
        let (buf, end) = read_head(&mut server).await.unwrap();
        assert_eq!(
            &buf[..end],
            b"CONNECT a.example:443 HTTP/1.1\r\nHost: a\r\n\r\n"
        );
        let mut rest = buf[end..].to_vec();
        let mut client = writer.await.unwrap();
        drop(client.shutdown().await);
        drop(client);
        server.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"\x16\x03\x01");

        let mut huge = b"GET http://a.example/ HTTP/1.1\r\nX: ".to_vec();
        huge.extend(vec![b'a'; MAX_HEAD]);
        huge.extend(b"\r\n\r\n");
        assert!(matches!(
            read_head(&mut huge.as_slice()).await,
            Err(Error::Protocol)
        ));
        let endless = vec![b'A'; 3 * MAX_HEAD];
        assert!(matches!(
            read_head(&mut endless.as_slice()).await,
            Err(Error::Protocol)
        ));
        assert!(matches!(
            read_head(&mut &b"GET http://a/ HTTP/1.1\r\n"[..]).await,
            Err(Error::Io)
        ));
    }
}
