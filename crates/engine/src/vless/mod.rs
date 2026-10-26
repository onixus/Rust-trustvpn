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
/// Ping after this long without traffic, so CDNs keep the connection.
const KEEPALIVE: Duration = Duration::from_secs(30);
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
        }));
        // Proves TCP, the certificate and the path; no VLESS request is sent.
        let (tls, _) = session.dial().await?;
        close(tls).await;
        Ok(session)
    }
    /// A new TLS connection with a completed WebSocket upgrade, and any frame
    /// bytes that arrived with the upgrade answer.
    async fn dial(&self) -> Result<(Tls, BytesMut)> {
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
    pub async fn open_tcp(&self, target: &str) -> Result<Tunnel> {
        let target = header::Target::parse(target)?;
        let deadline = tokio::time::Instant::now() + OPEN;
        let permit = tokio::time::timeout_at(deadline, self.0.tcp_slots.clone().acquire_owned())
            .await
            .map_err(|_| Error::Credit)?
            .map_err(|_| Error::Connect)?;
        let (tls, rest) = tokio::time::timeout_at(deadline, self.dial())
            .await
            .map_err(|_| Error::Timeout)??;
        let request = header::request(&self.0.uuid, header::TCP, &target);
        let (io, bridge) = tokio::io::duplex(64 * 1024);
        let pump = tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp(tls, rest, request, bridge).await;
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
    tls: Tls,
    rest: BytesMut,
    request: Zeroizing<Vec<u8>>,
    bridge: DuplexStream,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(tls);
    let mut frames = ws::Reader::new(read, rest);
    let (mut local_read, mut local_write) = tokio::io::split(bridge);
    let mut buf = vec![0u8; 16 * 1024];
    let mut uplink = true;
    let mut first = request;
    match tokio::time::timeout(FIRST_PAYLOAD, local_read.read(&mut buf)).await {
        Ok(Ok(0)) => uplink = false,
        Ok(Ok(n)) => first.extend_from_slice(&buf[..n]),
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {}
    }
    ws::send(&mut write, ws::BINARY, &first).await?;
    drop(first);
    let mut response = header::Response::default();
    let idle = tokio::time::sleep(if uplink { KEEPALIVE } else { HALF_CLOSE });
    tokio::pin!(idle);
    let result = loop {
        tokio::select! {
            event = frames.next() => match event {
                Err(error) => break Err(error),
                // A closed flow before any answer means the server refused or
                // could not reach the target; it is not a protocol failure.
                Ok(None) => break Ok(()),
                Ok(Some(Event::Close)) => {
                    let _ = ws::send(&mut write, ws::CLOSE, &[]).await;
                    break Ok(());
                }
                Ok(Some(Event::Ping(payload))) => ws::send(&mut write, ws::PONG, &payload).await?,
                Ok(Some(Event::Data(mut data))) => {
                    if !response.done() {
                        data.advance(response.feed(&data)?);
                    }
                    if !data.is_empty() {
                        local_write.write_all(&data).await?;
                    }
                    let wait = if uplink { KEEPALIVE } else { HALF_CLOSE };
                    idle.as_mut().reset(tokio::time::Instant::now() + wait);
                }
            },
            read = local_read.read(&mut buf), if uplink => {
                let n = read?;
                if n == 0 {
                    uplink = false;
                    idle.as_mut().reset(tokio::time::Instant::now() + HALF_CLOSE);
                } else {
                    ws::send(&mut write, ws::BINARY, &buf[..n]).await?;
                    idle.as_mut().reset(tokio::time::Instant::now() + KEEPALIVE);
                }
            }
            _ = &mut idle => {
                if !uplink {
                    let _ = ws::send(&mut write, ws::CLOSE, &[]).await;
                    break Ok(());
                }
                ws::send(&mut write, ws::PING, &[]).await?;
                idle.as_mut().reset(tokio::time::Instant::now() + KEEPALIVE);
            }
        }
    };
    let _ = local_write.shutdown().await;
    result
}

#[cfg(test)]
mod tests;
