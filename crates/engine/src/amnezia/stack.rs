//! Userspace TCP/IP endpoint inside the tunnel: outgoing TCP connections and
//! UDP sockets from the interface address, bridged to bounded channels.
use super::Command;
use crate::{Error, Result, udp::Datagram};
use bytes::Bytes;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

const MAX_TCP: usize = 256;
const MAX_UDP_TUNNELS: usize = 64;
/// Local UDP sockets of one stream: one per application source address.
const MAX_UDP_SOCKETS: usize = 256;
const UDP_IDLE: Duration = Duration::from_secs(60);
const TCP_BUFFER: usize = 64 * 1024;
const UDP_BUFFER: usize = 32 * 1024;
const QUEUE: usize = 512;

struct Packets {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
    mtu: usize,
}
struct Rx(Vec<u8>);
struct Tx<'a>(&'a mut VecDeque<Vec<u8>>);
impl RxToken for Rx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Tx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        self.0.push_back(bytes);
        result
    }
}
impl Device for Packets {
    type RxToken<'a> = Rx;
    type TxToken<'a> = Tx<'a>;
    fn receive(&mut self, _: SmolInstant) -> Option<(Rx, Tx<'_>)> {
        if self.output.len() >= QUEUE {
            return None;
        }
        Some((Rx(self.input.pop_front()?), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        (self.output.len() < QUEUE).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

struct TcpFlow {
    socket: SocketHandle,
    port: u16,
    up: mpsc::Receiver<Bytes>,
    /// Dropped after the peer's FIN so the reader sees end of stream.
    down: Option<mpsc::Sender<Bytes>>,
    reply: Option<oneshot::Sender<Result<()>>>,
    /// Upload bytes the send buffer did not take yet.
    chunk: Option<Bytes>,
    up_closed: bool,
}
struct UdpTunnel {
    up: mpsc::Receiver<Datagram>,
    down: mpsc::Sender<Datagram>,
    /// Application source address to its local socket.
    sockets: HashMap<SocketAddr, (SocketHandle, u16, Instant)>,
}

pub struct Stack {
    device: Packets,
    interface: Interface,
    sockets: SocketSet<'static>,
    tcp: Vec<TcpFlow>,
    udp: Vec<UdpTunnel>,
    ports: HashSet<u16>,
    families: (bool, bool),
    epoch: Instant,
}

impl Stack {
    /// Uses the first IPv4 and the first IPv6 interface address.
    pub fn new(addresses: &[(IpAddr, u8)], mtu: usize) -> Self {
        let mut device = Packets {
            input: VecDeque::new(),
            output: VecDeque::new(),
            mtu,
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        let v4 = addresses.iter().find(|(ip, _)| ip.is_ipv4());
        let v6 = addresses.iter().find(|(ip, _)| ip.is_ipv6());
        interface.update_ip_addrs(|a| {
            for (ip, prefix) in v4.into_iter().chain(v6) {
                let _ = a.push(IpCidr::new(IpAddress::from(*ip), *prefix));
            }
        });
        // Point-to-point: the gateway address is never put on the wire.
        let _ = interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Addr::new(0, 0, 0, 1));
        let _ = interface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Addr::LOCALHOST);
        Self {
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            tcp: vec![],
            udp: vec![],
            ports: HashSet::new(),
            families: (v4.is_some(), v6.is_some()),
            epoch: Instant::now(),
        }
    }
    fn now(&self) -> SmolInstant {
        SmolInstant::from_millis(self.epoch.elapsed().as_millis() as i64)
    }
    fn port(&mut self) -> Option<u16> {
        (0..64)
            .map(|_| rand::random_range(49_152..=65_535))
            .find(|port| self.ports.insert(*port))
    }
    /// A decrypted IP packet from the peer. A full queue drops it; TCP retransmits.
    pub fn input(&mut self, packet: Vec<u8>) {
        if self.device.input.len() < QUEUE {
            self.device.input.push_back(packet);
        }
    }
    /// When the stack needs to run again without new input.
    pub fn deadline(&mut self) -> Option<Instant> {
        let now = self.now();
        self.interface
            .poll_delay(now, &self.sockets)
            .map(|delay| Instant::now() + Duration::from_micros(delay.total_micros()))
    }
    pub fn command(&mut self, command: Command) {
        match command {
            Command::Tcp {
                remote,
                up,
                down,
                reply,
            } => {
                let opened = (|| {
                    if self.tcp.len() >= MAX_TCP {
                        return Err(Error::Unsupported("AmneziaWG TCP stream capacity"));
                    }
                    let port = self.port().ok_or(Error::Connect)?;
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                    );
                    // Unanswered segments end the connection instead of pinning a slot.
                    socket.set_timeout(Some(SmolDuration::from_secs(60)));
                    socket.set_nagle_enabled(false);
                    if socket
                        .connect(self.interface.context(), IpEndpoint::from(remote), port)
                        .is_err()
                    {
                        self.ports.remove(&port);
                        return Err(Error::Destination);
                    }
                    Ok((self.sockets.add(socket), port))
                })();
                match opened {
                    Ok((socket, port)) => self.tcp.push(TcpFlow {
                        socket,
                        port,
                        up,
                        down: Some(down),
                        reply: Some(reply),
                        chunk: None,
                        up_closed: false,
                    }),
                    Err(error) => {
                        let _ = reply.send(Err(error));
                    }
                }
            }
            Command::Udp { up, down } => {
                // Over capacity the stream is dropped: its reader sees it closed.
                if self.udp.len() < MAX_UDP_TUNNELS {
                    self.udp.push(UdpTunnel {
                        up,
                        down,
                        sockets: HashMap::new(),
                    });
                }
            }
        }
    }
    fn pump_tcp(&mut self) {
        let mut index = 0;
        while index < self.tcp.len() {
            let flow = &mut self.tcp[index];
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.socket);
            if let Some(reply) = flow.reply.take() {
                if socket.may_send() {
                    let _ = reply.send(Ok(()));
                } else if socket.state() == tcp::State::Closed {
                    // Reset or handshake timeout.
                    let _ = reply.send(Err(Error::Connect));
                } else if reply.is_closed() {
                    socket.abort();
                } else {
                    flow.reply = Some(reply);
                }
            }
            if flow.reply.is_none() {
                while socket.can_send() {
                    let chunk = match flow.chunk.take() {
                        Some(chunk) => chunk,
                        None => match flow.up.try_recv() {
                            Ok(chunk) => chunk,
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => {
                                if !flow.up_closed {
                                    flow.up_closed = true;
                                    socket.close();
                                }
                                break;
                            }
                        },
                    };
                    let sent = socket.send_slice(&chunk).unwrap_or(0);
                    if sent < chunk.len() {
                        flow.chunk = Some(chunk.slice(sent..));
                        break;
                    }
                }
                while socket.can_recv() {
                    let Some(down) = &flow.down else { break };
                    match down.try_reserve() {
                        Ok(permit) => {
                            let data = socket
                                .recv(|b| {
                                    let n = b.len().min(16 * 1024);
                                    (n, Bytes::copy_from_slice(&b[..n]))
                                })
                                .unwrap_or_default();
                            permit.send(data);
                        }
                        Err(mpsc::error::TrySendError::Full(())) => break,
                        // The stream was dropped by its owner.
                        Err(mpsc::error::TrySendError::Closed(())) => {
                            socket.abort();
                            break;
                        }
                    }
                }
                if !socket.may_recv() && !socket.can_recv() {
                    flow.down = None;
                }
                // Both halves gone without a clean close: the owner dropped the stream.
                if flow.up_closed && flow.down.as_ref().is_some_and(|d| d.is_closed()) {
                    socket.abort();
                }
            }
            index += 1;
        }
    }
    fn pump_udp(&mut self) {
        let limit = self.device.mtu;
        let mut index = 0;
        while index < self.udp.len() {
            let mut closed = self.udp[index].down.is_closed();
            loop {
                let datagram = match self.udp[index].up.try_recv() {
                    Ok(datagram) => datagram,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        closed = true;
                        break;
                    }
                };
                let v6 = datagram.destination.is_ipv6();
                // No fragmentation inside the tunnel: larger datagrams are dropped.
                let fits = datagram.payload.len() + if v6 { 48 } else { 28 } <= limit;
                if !fits || !(if v6 { self.families.1 } else { self.families.0 }) {
                    continue;
                }
                let known = self.udp[index].sockets.get_mut(&datagram.source);
                let handle = match known {
                    Some((handle, _, seen)) => {
                        *seen = Instant::now();
                        *handle
                    }
                    None => {
                        if self.udp[index].sockets.len() >= MAX_UDP_SOCKETS {
                            continue;
                        }
                        let Some(port) = self.port() else { continue };
                        let buffer = || {
                            udp::PacketBuffer::new(
                                vec![udp::PacketMetadata::EMPTY; 32],
                                vec![0; UDP_BUFFER],
                            )
                        };
                        let mut socket = udp::Socket::new(buffer(), buffer());
                        if socket.bind(port).is_err() {
                            self.ports.remove(&port);
                            continue;
                        }
                        let handle = self.sockets.add(socket);
                        self.udp[index]
                            .sockets
                            .insert(datagram.source, (handle, port, Instant::now()));
                        handle
                    }
                };
                // A full send buffer drops the datagram, as a real socket would.
                let _ = self
                    .sockets
                    .get_mut::<udp::Socket>(handle)
                    .send_slice(&datagram.payload, IpEndpoint::from(datagram.destination));
            }
            let tunnel = &mut self.udp[index];
            for (source, (handle, _, seen)) in tunnel.sockets.iter_mut() {
                let socket = self.sockets.get_mut::<udp::Socket>(*handle);
                while socket.can_recv() {
                    let Ok(permit) = tunnel.down.try_reserve() else {
                        break;
                    };
                    let Ok((payload, meta)) = socket.recv() else {
                        break;
                    };
                    *seen = Instant::now();
                    permit.send(Datagram {
                        source: SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port),
                        destination: *source,
                        payload: payload.to_vec(),
                    });
                }
            }
            let (sockets, ports) = (&mut self.sockets, &mut self.ports);
            tunnel.sockets.retain(|_, (handle, port, seen)| {
                let keep = !closed && seen.elapsed() < UDP_IDLE;
                if !keep {
                    sockets.remove(*handle);
                    ports.remove(port);
                }
                keep
            });
            if closed {
                self.udp.swap_remove(index);
            } else {
                index += 1;
            }
        }
    }
    /// Runs the stack and returns the IP packets to encrypt.
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let now = self.now();
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        self.pump_tcp();
        self.pump_udp();
        // Dispatch what the pumps queued, including FIN/RST, before removal.
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        let (sockets, ports) = (&mut self.sockets, &mut self.ports);
        self.tcp.retain(|flow| {
            let closed = sockets.get::<tcp::Socket>(flow.socket).state() == tcp::State::Closed;
            if closed {
                sockets.remove(flow.socket);
                ports.remove(&flow.port);
            }
            !closed
        });
        self.device.output.drain(..).collect()
    }
}
