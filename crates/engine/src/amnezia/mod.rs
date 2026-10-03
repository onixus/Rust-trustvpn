//! AmneziaWG 3 transport. WireGuard carries IP packets, while the engine
//! exposes TCP streams and UDP messages, so the session terminates them in a
//! userspace TCP/IP stack bound to the interface address of the profile.
mod device;
mod noise;
mod stack;
mod wire;
use super::*;
use crate::udp::{self as frames, Datagram};
use device::Device;
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};
use tokio::sync::{Notify, mpsc, oneshot};

/// Handshake retransmissions without an answer before the session reports
/// itself unhealthy; the reference keeps retrying, a caller may reconnect.
const STALLED_ATTEMPTS: u32 = 3;

pub(crate) enum Command {
    Tcp {
        remote: SocketAddr,
        up: mpsc::Receiver<Bytes>,
        down: mpsc::Sender<Bytes>,
        reply: oneshot::Sender<Result<()>>,
    },
    Udp {
        up: mpsc::Receiver<Datagram>,
        down: mpsc::Sender<Datagram>,
    },
}

#[derive(Clone)]
pub struct AmneziaSession(Arc<Inner>);
struct Inner {
    commands: mpsc::Sender<Command>,
    wake: Arc<Notify>,
    unhealthy: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
    dns: Vec<IpAddr>,
    families: (bool, bool),
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn udp_socket(
    address: SocketAddr,
    mark: Option<u32>,
    protector: Option<&SocketProtector>,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(if address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_nonblocking(true)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        #[cfg(target_os = "linux")]
        if let Some(mark) = mark {
            // Set before the first datagram: it must bypass the full-tunnel policy.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const u32).cast(),
                    std::mem::size_of_val(&mark) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        if let Some(protect) = protector {
            protect(socket.as_raw_fd())?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;
    #[cfg(not(unix))]
    let _ = protector;
    socket.connect(address)?;
    tokio::net::UdpSocket::from_std(socket)
}

impl AmneziaSession {
    pub async fn connect(
        p: &Profile,
        mark: Option<u32>,
        protector: Option<&SocketProtector>,
    ) -> Result<Self> {
        let options = p.amneziawg.as_ref().ok_or(Error::Profile)?;
        let mut addresses: Vec<SocketAddr> = vec![];
        for address in &p.endpoint.addresses {
            if mark.is_some() || protector.is_some() {
                addresses.push(
                    address.parse().map_err(|_| {
                        Error::Unsupported("pre-resolved AmneziaWG endpoint required")
                    })?,
                );
            } else {
                addresses.extend(
                    tokio::net::lookup_host(address)
                        .await
                        .map_err(|_| Error::Connect)?
                        .take(4),
                );
            }
        }
        // The caller allows 20 s in total; one retransmission fits per address.
        let patience = Duration::from_secs((15 / addresses.len().max(1) as u64).max(6));
        let interface = options.interface_addresses();
        let families = (
            interface.iter().any(|(ip, _)| ip.is_ipv4()),
            interface.iter().any(|(ip, _)| ip.is_ipv6()),
        );
        for address in addresses {
            let Ok(socket) = udp_socket(address, mark, protector) else {
                continue;
            };
            let mut device = Device::new(p, options)?;
            device.send_keepalive(Instant::now());
            let (commands, receiver) = mpsc::channel(64);
            let (ready, established) = oneshot::channel();
            let wake = Arc::new(Notify::new());
            let unhealthy = Arc::new(AtomicBool::new(false));
            let task = tokio::spawn(run(
                socket,
                device,
                stack::Stack::new(&interface, options.mtu()),
                receiver,
                wake.clone(),
                unhealthy.clone(),
                ready,
            ));
            let inner = Inner {
                commands,
                wake,
                unhealthy,
                task,
                dns: options.dns.iter().filter_map(|d| d.parse().ok()).collect(),
                families,
            };
            // Dropping `inner` stops the task of an address that did not answer.
            if let Ok(Ok(())) = tokio::time::timeout(patience, established).await {
                return Ok(Self(Arc::new(inner)));
            }
        }
        Err(Error::Connect)
    }
    pub async fn health(&self) -> Result<()> {
        if self.0.unhealthy.load(Ordering::Relaxed) || self.0.task.is_finished() {
            Err(Error::Connect)
        } else {
            Ok(())
        }
    }
    fn family(&self, address: IpAddr) -> Result<()> {
        match address {
            IpAddr::V4(_) if self.0.families.0 => Ok(()),
            IpAddr::V6(_) if self.0.families.1 => Ok(()),
            _ => Err(Error::Unsupported(
                "address family without an AmneziaWG interface address",
            )),
        }
    }
    /// Host names are resolved by the profile's DNS servers inside the tunnel.
    async fn resolve(&self, target: &str) -> Result<SocketAddr> {
        if let Ok(address) = target.parse() {
            return Ok(address);
        }
        use hickory_proto::{
            op::{Message, MessageType, OpCode, Query},
            rr::{RData, RecordType},
        };
        let authority: http::uri::Authority = target.parse().map_err(|_| Error::Destination)?;
        let port = authority.port_u16().ok_or(Error::Destination)?;
        let name: hickory_proto::rr::Name = format!("{}.", authority.host().trim_end_matches('.'))
            .parse()
            .map_err(|_| Error::Destination)?;
        let servers: Vec<IpAddr> = self
            .0
            .dns
            .iter()
            .copied()
            .filter(|server| self.family(*server).is_ok())
            .collect();
        if servers.is_empty() {
            return Err(Error::Unsupported(
                "host name destination without a DNS server in the AmneziaWG profile",
            ));
        }
        let (up, up_receiver) = mpsc::channel(4);
        let (down, mut answers) = mpsc::channel(4);
        self.command(Command::Udp {
            up: up_receiver,
            down,
        })
        .await?;
        let mut questions = vec![];
        for (enabled, kind) in [
            (self.0.families.0, RecordType::A),
            (self.0.families.1, RecordType::AAAA),
        ] {
            if enabled {
                questions.extend(servers.iter().map(|server| (kind, *server)));
            }
        }
        for (kind, server) in questions {
            let id = rand::random();
            let mut query = Message::new(id, MessageType::Query, OpCode::Query);
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(name.clone(), kind));
            let datagram = Datagram {
                source: SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0),
                destination: SocketAddr::new(server, 53),
                payload: query.to_vec().map_err(|_| Error::Destination)?,
            };
            up.send(datagram).await.map_err(|_| Error::Connect)?;
            self.0.wake.notify_one();
            let answer = tokio::time::timeout(Duration::from_secs(3), async {
                while let Some(d) = answers.recv().await {
                    if let Ok(m) = Message::from_vec(&d.payload)
                        && m.metadata.id == id
                        && d.source.ip() == server
                    {
                        return Some(m);
                    }
                }
                None
            })
            .await;
            let Ok(Some(answer)) = answer else { continue };
            for record in &answer.answers {
                match &record.data {
                    RData::A(a) => return Ok(SocketAddr::new(a.0.into(), port)),
                    RData::AAAA(a) => return Ok(SocketAddr::new(a.0.into(), port)),
                    _ => {}
                }
            }
        }
        Err(Error::Destination)
    }
    async fn command(&self, command: Command) -> Result<()> {
        self.0
            .commands
            .send(command)
            .await
            .map_err(|_| Error::Connect)
    }
    pub async fn open_tcp(&self, target: &str) -> Result<Tunnel> {
        let remote = self.resolve(target).await?;
        self.family(remote.ip())?;
        let (up, up_receiver) = mpsc::channel::<Bytes>(8);
        let (down, mut down_receiver) = mpsc::channel::<Bytes>(8);
        let (reply, connected) = oneshot::channel();
        self.command(Command::Tcp {
            remote,
            up: up_receiver,
            down,
            reply,
        })
        .await?;
        tokio::time::timeout(Duration::from_secs(10), connected)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Connect)??;
        let (io, bridge) = tokio::io::duplex(64 * 1024);
        let keep = self.clone();
        let pump = tokio::spawn(async move {
            let wake = keep.0.wake.clone();
            let (mut read, mut write) = tokio::io::split(bridge);
            let upload = async {
                let mut buffer = vec![0u8; 16 * 1024];
                loop {
                    match read.read(&mut buffer).await {
                        Ok(n) if n > 0 => {
                            if up.send(Bytes::copy_from_slice(&buffer[..n])).await.is_err() {
                                break;
                            }
                            wake.notify_one();
                        }
                        _ => break,
                    }
                }
                // End of stream: the stack sends FIN once queued data is out.
                drop(up);
                wake.notify_one();
            };
            let download = async {
                while let Some(data) = down_receiver.recv().await {
                    // Capacity was freed: the stack may read from the socket again.
                    wake.notify_one();
                    if write.write_all(&data).await.is_err() {
                        break;
                    }
                }
                down_receiver.close();
                wake.notify_one();
                let _ = write.shutdown().await;
            };
            tokio::join!(upload, download);
        });
        Ok(Tunnel { io, pump })
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        let (up, up_receiver) = mpsc::channel(64);
        let (down, mut down_receiver) = mpsc::channel::<Datagram>(64);
        self.command(Command::Udp {
            up: up_receiver,
            down,
        })
        .await?;
        let (io, bridge) = tokio::io::duplex(128 * 1024);
        let keep = self.clone();
        let pump = tokio::spawn(async move {
            let wake = keep.0.wake.clone();
            let (mut read, mut write) = tokio::io::split(bridge);
            let upload = async {
                while let Ok(datagram) = crate::hysteria::datagrams::outgoing(&mut read).await {
                    if up.send(datagram).await.is_err() {
                        break;
                    }
                    wake.notify_one();
                }
            };
            let download = async {
                while let Some(datagram) = down_receiver.recv().await {
                    // The reply frame has no application name field.
                    let Ok(mut frame) = frames::encode(&datagram, "") else {
                        continue;
                    };
                    frame.remove(40);
                    let len = (frame.len() - 4) as u32;
                    frame[..4].copy_from_slice(&len.to_be_bytes());
                    if write.write_all(&frame).await.is_err() {
                        break;
                    }
                }
            };
            // Either direction ending closes the UDP stream, as for other transports.
            tokio::select! {
                _ = upload => {}
                _ = download => {}
            }
        });
        Ok(Tunnel { io, pump })
    }
}

async fn run(
    socket: tokio::net::UdpSocket,
    mut device: Device,
    mut stack: stack::Stack,
    mut commands: mpsc::Receiver<Command>,
    wake: Arc<Notify>,
    unhealthy: Arc<AtomicBool>,
    ready: oneshot::Sender<()>,
) {
    let mut ready = Some(ready);
    let mut buffer = vec![0u8; 65_536];
    loop {
        let now = Instant::now();
        device.timers(now);
        for packet in stack.poll() {
            device.send_ip(packet, now);
        }
        for datagram in device.take_output() {
            // UDP: a full socket buffer drops the datagram, the flows recover.
            let _ = socket.try_send(&datagram);
        }
        unhealthy.store(
            device.failed() || device.attempts() >= STALLED_ATTEMPTS,
            Ordering::Relaxed,
        );
        if device.established()
            && let Some(ready) = ready.take()
        {
            let _ = ready.send(());
        }
        let deadline = [device.deadline(), stack.deadline()]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(now + Duration::from_secs(3600));
        tokio::select! {
            received = socket.recv(&mut buffer) => {
                let Ok(mut size) = received else {
                    // ICMP errors surface here; the handshake timers decide.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                // Drain a burst before running the stack once.
                for burst in 0..64 {
                    if burst > 0 {
                        match socket.try_recv(&mut buffer) {
                            Ok(n) => size = n,
                            Err(_) => break,
                        }
                    }
                    if let Some(packet) = device.receive(&mut buffer[..size], Instant::now()) {
                        stack.input(packet);
                    }
                }
            }
            command = commands.recv() => match command {
                Some(command) => stack.command(command),
                // Every session handle is gone.
                None => return,
            },
            _ = wake.notified() => {}
            _ = tokio::time::sleep_until(deadline.into()) => {}
        }
    }
}

#[cfg(test)]
mod tests;
