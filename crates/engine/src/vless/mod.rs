//! VLESS over WebSocket and TLS, as served behind a CDN by Xray-core. Every
//! flow is its own TLS connection and WebSocket upgrade: there is no shared
//! multiplexed session, and no DNS lookup happens after `connect`.
mod header;
mod udp;
mod ws;
use super::*;
use bytes::{Buf, BytesMut};
use std::{
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Instant, SystemTime},
};
use ws::Event;

/// Concurrent TCP flows per session; each one holds a TLS connection.
const TCP_FLOWS: usize = 256;
/// Whole open of a flow: slot, TCP, TLS and the WebSocket upgrade.
const OPEN: Duration = Duration::from_secs(10);
/// One endpoint address; a dead address must not use up the whole open.
const ADDRESS: Duration = Duration::from_secs(4);
/// A recent upgrade proves the endpoint without a new connection.
const FRESH: Duration = Duration::from_secs(30);
/// Ping after this long without anything from the server. Outgoing data does
/// not count: a path that died without FIN or RST still accepts writes.
const KEEPALIVE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });
/// After a ping, anything from the server (data, Pong, Ping) must arrive in
/// this window, or the flow is closed as dead. Shorter in tests.
const PONG_WAIT: Duration = Duration::from_millis(if cfg!(test) { 500 } else { 15_000 });
/// Xray answers a ping only when it reads the frame, after everything sent
/// before it. While uplink data may still be queued for a slow target, a
/// missing answer is not judged before this long after the last write.
const DRAIN: Duration = Duration::from_secs(if cfg!(test) { 10 } else { 120 });
/// One frame write blocked this long means the path stopped taking data.
/// Behind a slow target one write can wait for megabytes of loopback socket
/// buffers to drain (up to 90 s measured on Linux at 32 KiB/s), so the
/// verdict waits as long as [`DRAIN`] does for an answer.
const STALL: Duration = Duration::from_millis(if cfg!(test) { 1500 } else { 120_000 });
/// Consecutive flows the server closed without a byte (as Xray does for an
/// unknown UUID) before the session delays new flows. Xray closes a flow to
/// an unreachable target the same way, so the run must also be varied: at
/// least [`REFUSED_TARGETS`] TCP destinations or [`REFUSED_PAIRS`] UDP
/// source/destination pairs. One refusing host never stops the session.
const REFUSED_STREAK: u32 = 8;
const REFUSED_TARGETS: usize = 4;
const REFUSED_PAIRS: usize = 8;
/// Delay of new flows after the streak, doubling per further refusal.
const BACKOFF_MIN: Duration = Duration::from_millis(if cfg!(test) { 1000 } else { 2000 });
const BACKOFF_MAX: Duration = Duration::from_millis(if cfg!(test) { 2000 } else { 30_000 });
/// Uplink bytes read at a time; the first read is sent with the request header.
const CHUNK: usize = 16 * 1024;
/// After the local side finished sending, how long to wait for the rest of
/// the answer. Xray's freedom outbound closes 1 s after the uplink ends; a
/// `Close` frame sent at once would cut the reply.
const HALF_CLOSE: Duration = Duration::from_secs(10);
/// The request header travels with the first payload sent in this window,
/// as Xray's own client does (500 ms).
const FIRST_PAYLOAD: Duration = Duration::from_millis(500);

type Tls = tokio_rustls::client::TlsStream<TcpStream>;

#[derive(Clone)]
pub struct VlessSession(Arc<Inner>);
struct Inner {
    connector: tokio_rustls::TlsConnector,
    name: rustls::pki_types::ServerName<'static>,
    host: String,
    path: Zeroizing<String>,
    uuid: Zeroizing<[u8; 16]>,
    /// Numeric, resolved once at connect.
    addresses: Vec<SocketAddr>,
    /// The address that answered last is tried first.
    preferred: AtomicUsize,
    mark: Option<u32>,
    protector: Option<SocketProtector>,
    tcp_slots: Arc<tokio::sync::Semaphore>,
    udp_flows: Arc<tokio::sync::Semaphore>,
    /// Last successful upgrade, by monotonic and wall clock: the monotonic
    /// clock may stop while the device sleeps.
    fresh: Mutex<Option<(Instant, SystemTime)>>,
    refusals: Mutex<Refusals>,
}
/// Flows the server ended without sending anything, across the session.
#[derive(Default)]
struct Refusals {
    streak: u32,
    /// Distinct TCP destinations and UDP pairs in the streak, up to the thresholds.
    targets: std::collections::HashSet<String>,
    pairs: std::collections::HashSet<(SocketAddr, SocketAddr)>,
    /// New flows are not dialed before this.
    until: Option<Instant>,
}
impl Refusals {
    fn varied(&self) -> bool {
        self.streak >= REFUSED_STREAK
            && (self.targets.len() >= REFUSED_TARGETS || self.pairs.len() >= REFUSED_PAIRS)
    }
}
/// What a reported flow went to: a TCP destination or a UDP pair.
enum Reported<'a> {
    Tcp(&'a str),
    Udp(SocketAddr, SocketAddr),
}

/// When a flow that hears nothing from the server pings, and when an
/// unanswered ping means the path is gone.
struct Keepalive {
    heard: tokio::time::Instant,
    wrote: tokio::time::Instant,
    ping: Option<tokio::time::Instant>,
}
impl Keepalive {
    fn new() -> Self {
        let now = tokio::time::Instant::now();
        Self {
            heard: now,
            wrote: now,
            ping: None,
        }
    }
    fn heard(&mut self) {
        self.heard = tokio::time::Instant::now();
        self.ping = None;
    }
    fn wrote(&mut self) {
        self.wrote = tokio::time::Instant::now();
    }
    /// The next ping (`quiet` after the last answer) or, after one, the
    /// verdict. Data written since the last answer may still be ahead of the
    /// ping in a slow target's buffers, so both wait for it to drain.
    fn deadline(&self, quiet: Duration) -> tokio::time::Instant {
        let base = match self.ping {
            None => self.heard + quiet,
            Some(ping) => ping + PONG_WAIT,
        };
        if self.wrote > self.heard {
            base.max(self.wrote + DRAIN)
        } else {
            base
        }
    }
}
/// A frame write that does not finish in [`STALL`] ends the flow.
async fn put<W: AsyncWrite + Unpin>(io: &mut W, opcode: u8, payload: &[u8]) -> Result<()> {
    tokio::time::timeout(STALL, ws::send(io, opcode, payload))
        .await
        .map_err(|_| Error::Timeout)?
}
impl VlessSession {
    pub async fn connect(
        p: &Profile,
        mark: Option<u32>,
        protector: Option<&SocketProtector>,
    ) -> Result<Self> {
        let options = p.vless.as_ref().ok_or(Error::Profile)?;
        if options.transport != "ws" {
            return Err(Error::Unsupported("VLESS XHTTP transport"));
        }
        let mut tls = tls_config(p)?;
        // WebSocket upgrades exist only in HTTP/1.1. No 0-RTT: early data is replayable.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(p.endpoint.hostname.clone())
            .map_err(|_| Error::Profile)?;
        let mut uuid = Zeroizing::new([0u8; 16]);
        let hex = Zeroizing::new(p.endpoint.password.expose().replace('-', ""));
        if hex.len() != 32 {
            return Err(Error::Profile);
        }
        for (byte, pair) in uuid.iter_mut().zip(hex.as_bytes().chunks(2)) {
            *byte = std::str::from_utf8(pair)
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok())
                .ok_or(Error::Profile)?;
        }
        let mut addresses = vec![];
        for address in &p.endpoint.addresses {
            if mark.is_some() || protector.is_some() {
                addresses.push(address.parse().map_err(|_| {
                    Error::Unsupported(
                        "resolve endpoint on the underlying network before VPN setup",
                    )
                })?);
            } else if let Ok(resolved) = tokio::net::lookup_host(address).await {
                addresses.extend(resolved.take(8));
            }
        }
        let mut seen = std::collections::HashSet::new();
        addresses.retain(|a| seen.insert(*a));
        if addresses.is_empty() {
            return Err(Error::Connect);
        }
        let session = Self(Arc::new(Inner {
            connector: tokio_rustls::TlsConnector::from(Arc::new(tls)),
            name,
            host: p.endpoint.hostname.clone(),
            path: Zeroizing::new(options.path.expose().to_owned()),
            uuid,
            addresses,
            preferred: AtomicUsize::new(0),
            mark,
            protector: protector.cloned(),
            tcp_slots: Arc::new(tokio::sync::Semaphore::new(TCP_FLOWS)),
            udp_flows: Arc::new(tokio::sync::Semaphore::new(udp::SESSION_FLOWS)),
            fresh: Mutex::new(None),
            refusals: Mutex::new(Refusals::default()),
        }));
        // Proves TCP, the certificate and the path; no VLESS request is sent.
        let (tls, _) = session.dial().await?;
        close(tls).await;
        Ok(session)
    }
    /// A new TLS connection with a completed WebSocket upgrade, and any frame
    /// bytes that arrived with the upgrade answer.
    async fn dial(&self) -> Result<(Tls, BytesMut)> {
        if self.backing_off() {
            return Err(Error::Unanswered);
        }
        let inner = &self.0;
        let count = inner.addresses.len();
        let start = inner.preferred.load(Ordering::Relaxed);
        let mut failure = Error::Connect;
        let mut connected = None;
        for offset in 0..count {
            let index = (start + offset) % count;
            let address = inner.addresses[index].to_string();
            // Marked or protected before connect, on every flow's socket.
            match tokio::time::timeout(
                ADDRESS,
                connect_tcp(&address, inner.mark, inner.protector.as_ref()),
            )
            .await
            {
                Ok(Ok(tcp)) => {
                    inner.preferred.store(index, Ordering::Relaxed);
                    connected = Some(tcp);
                    break;
                }
                Ok(Err(error)) => failure = Error::ConnectIo(error.kind()),
                Err(_) => failure = Error::Timeout,
            }
        }
        let tcp = connected.ok_or(failure)?;
        tcp.set_nodelay(true)?;
        let mut tls = inner
            .connector
            .connect(inner.name.clone(), tcp)
            .await
            .map_err(tls_failure)?;
        if !matches!(tls.get_ref().1.alpn_protocol(), None | Some(b"http/1.1")) {
            return Err(Error::Protocol);
        }
        let rest = ws::upgrade(&mut tls, &inner.host, &inner.path).await?;
        *inner.fresh.lock().unwrap_or_else(|e| e.into_inner()) =
            Some((Instant::now(), SystemTime::now()));
        Ok((tls, rest))
    }
    /// A flow's outcome: `answered` when the server sent at least one byte,
    /// otherwise the server closed it empty. Only these two are reported.
    fn outcome(&self, flow: Reported<'_>, answered: bool) {
        let mut r = self.0.refusals.lock().unwrap_or_else(|e| e.into_inner());
        if answered {
            *r = Refusals::default();
            return;
        }
        r.streak = r.streak.saturating_add(1);
        match flow {
            Reported::Tcp(target) if r.targets.len() < REFUSED_TARGETS => {
                r.targets.insert(target.to_owned());
            }
            Reported::Udp(source, destination) if r.pairs.len() < REFUSED_PAIRS => {
                r.pairs.insert((source, destination));
            }
            _ => {}
        }
        if !r.varied() {
            return;
        }
        if let Some(extra) = r.streak.checked_sub(REFUSED_STREAK) {
            let delay = BACKOFF_MIN
                .saturating_mul(1 << extra.min(16))
                .min(BACKOFF_MAX);
            r.until = Some(Instant::now() + delay);
        }
    }
    fn backing_off(&self) -> bool {
        let r = self.0.refusals.lock().unwrap_or_else(|e| e.into_inner());
        r.until.is_some_and(|until| Instant::now() < until)
    }
    fn refusing(&self) -> bool {
        self.0
            .refusals
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .varied()
    }
    fn fresh(&self) -> bool {
        let fresh = *self.0.fresh.lock().unwrap_or_else(|e| e.into_inner());
        fresh.is_some_and(|(instant, wall)| {
            instant.elapsed() < FRESH
                && SystemTime::now()
                    .duration_since(wall)
                    .is_ok_and(|age| age < FRESH)
        })
    }
    /// No connection while a recent upgrade proves the endpoint; otherwise
    /// one bounded probe upgrade.
    pub async fn health(&self) -> Result<()> {
        // Upgrades still succeed with a revoked UUID; only the empty flows show it.
        if self.refusing() {
            return Err(Error::Unanswered);
        }
        if self.fresh() {
            return Ok(());
        }
        let (tls, _) = tokio::time::timeout(OPEN, self.dial())
            .await
            .map_err(|_| Error::Timeout)??;
        close(tls).await;
        Ok(())
    }
    /// Opens the TLS connection and upgrade inside this future: dropping it
    /// before it returns closes the socket and leaves no task behind.
    pub async fn open_tcp(&self, authority: &str) -> Result<Tunnel> {
        let target = header::Target::parse(authority)?;
        let deadline = tokio::time::Instant::now() + OPEN;
        let permit = tokio::time::timeout_at(deadline, self.0.tcp_slots.clone().acquire_owned())
            .await
            .map_err(|_| Error::Credit)?
            .map_err(|_| Error::Connect)?;
        let (tls, rest) = tokio::time::timeout_at(deadline, self.dial())
            .await
            .map_err(|_| Error::Timeout)??;
        let request = header::request(&self.0.uuid, header::TCP, &target, CHUNK);
        let (io, bridge) = tokio::io::duplex(64 * 1024);
        let session = self.clone();
        let authority = authority.to_owned();
        let pump = tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp(&session, &authority, tls, rest, request, bridge).await;
        });
        Ok(Tunnel {
            io,
            pump,
            liveness: None,
            watch: Default::default(),
        })
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        udp::open(self.clone()).await
    }
}
/// Best-effort WebSocket close of a probe connection.
async fn close(mut tls: Tls) {
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        ws::send(&mut tls, ws::CLOSE, &[]).await?;
        tls.shutdown().await.map_err(Error::from)
    })
    .await;
}
async fn tcp(
    session: &VlessSession,
    target: &str,
    tls: Tls,
    rest: BytesMut,
    request: Zeroizing<Vec<u8>>,
    bridge: DuplexStream,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(tls);
    let mut frames = ws::Reader::new(read, rest);
    let (mut local_read, mut local_write) = tokio::io::split(bridge);
    let mut buf = vec![0u8; CHUNK];
    let mut uplink = true;
    let mut first = request;
    match tokio::time::timeout(FIRST_PAYLOAD, local_read.read(&mut buf)).await {
        Ok(Ok(0)) => uplink = false,
        Ok(Ok(n)) => first.extend_from_slice(&buf[..n]),
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {}
    }
    put(&mut write, ws::BINARY, &first).await?;
    drop(first);
    let mut response = header::Response::default();
    let mut answered = false;
    let mut alive = Keepalive::new();
    alive.wrote();
    // After the local side finished, the flow waits for the answer, not a ping.
    let quiet = |uplink: bool| if uplink { KEEPALIVE } else { HALF_CLOSE };
    let idle = tokio::time::sleep_until(alive.deadline(quiet(uplink)));
    tokio::pin!(idle);
    let result = loop {
        tokio::select! {
            event = frames.next() => match event {
                Err(error) => break Err(error),
                // A closed flow before any answer means the server refused or
                // could not reach the target; it is not a protocol failure.
                Ok(None) => {
                    if !answered {
                        session.outcome(Reported::Tcp(target), false);
                    }
                    break Ok(());
                }
                Ok(Some(event)) => {
                    match event {
                        Event::Ping(payload) => put(&mut write, ws::PONG, &payload).await?,
                        Event::Pong => {}
                        Event::Data(mut data) => {
                            if !answered {
                                answered = true;
                                session.outcome(Reported::Tcp(target), true);
                            }
                            if !response.done() {
                                data.advance(response.feed(&data)?);
                            }
                            if !data.is_empty() {
                                local_write.write_all(&data).await?;
                            }
                        }
                        Event::Close => {
                            if !answered {
                                session.outcome(Reported::Tcp(target), false);
                            }
                            let _ = put(&mut write, ws::CLOSE, &[]).await;
                            break Ok(());
                        }
                    }
                    alive.heard();
                    idle.as_mut().reset(alive.deadline(quiet(uplink)));
                }
            },
            read = local_read.read(&mut buf), if uplink => {
                let n = read?;
                if n == 0 {
                    uplink = false;
                } else {
                    put(&mut write, ws::BINARY, &buf[..n]).await?;
                    alive.wrote();
                }
                idle.as_mut().reset(alive.deadline(quiet(uplink)));
            }
            _ = &mut idle => {
                let deadline = alive.deadline(quiet(uplink));
                if tokio::time::Instant::now() < deadline {
                    // Moved by a write since the timer was set.
                    idle.as_mut().reset(deadline);
                } else if alive.ping.is_some() {
                    // No answer to the ping and nothing left to drain: the path is gone.
                    break Err(Error::Timeout);
                } else if !uplink {
                    let _ = put(&mut write, ws::CLOSE, &[]).await;
                    break Ok(());
                } else {
                    put(&mut write, ws::PING, &[]).await?;
                    alive.ping = Some(tokio::time::Instant::now());
                    idle.as_mut().reset(alive.deadline(quiet(uplink)));
                }
            }
        }
    };
    let _ = local_write.shutdown().await;
    result
}

#[cfg(test)]
mod tests;
