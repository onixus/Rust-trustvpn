//! Loopback-only SOCKS5 data plane. No system routes, resolver, or proxy settings are changed.
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
    // DNS host only; never allow URI delimiters to change the CONNECT authority.
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(Error::Destination);
    }
    Ok(Address::Name(name, port))
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
async fn handle(
    mut socket: TcpStream,
    peer: SocketAddr,
    session: Session,
    counters: &Counters,
) -> Result<()> {
    let (command, target) = timeout(HANDSHAKE, negotiate(&mut socket))
        .await
        .map_err(|_| Error::Timeout)??;
    if command == 3 {
        return relay_udp(socket, peer, target, session, counters).await;
    }
    let mut tunnel = match session.open_tcp(&target.authority()).await {
        Ok(t) => t,
        Err(e) => {
            reply(&mut socket, 1, None).await?;
            return Err(e);
        }
    };
    reply(&mut socket, 0, None).await?;
    let (mut sr, mut sw) = socket.split();
    let (mut tr, mut tw) = tokio::io::split(&mut tunnel);
    tokio::try_join!(
        copy(&mut sr, &mut tw, &counters.up),
        copy(&mut tr, &mut sw, &counters.down)
    )?;
    Ok(())
}
async fn copy(
    r: &mut (impl AsyncRead + Unpin),
    w: &mut (impl AsyncWrite + Unpin),
    bytes: &AtomicU64,
) -> Result<()> {
    let mut buf = [0; 16 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            w.shutdown().await?;
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
