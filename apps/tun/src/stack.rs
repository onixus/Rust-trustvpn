use crate::packet::{Key, MTU};
use futures_util::FutureExt;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::tcp::{Socket, SocketBuffer, State},
    time::{Duration as SmolDuration, Instant as SmolInstant},
    wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address},
};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    task::JoinHandle,
};

pub const MAX_FLOWS: usize = 128;
const QUEUE: usize = 256;
const BUFFER: usize = 32 * 1024;

#[derive(Default)]
struct Packets {
    input: Option<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
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
        Some((Rx(self.input.take()?), Tx(&mut self.output)))
    }
    fn transmit(&mut self, _: SmolInstant) -> Option<Tx<'_>> {
        (self.output.len() < QUEUE).then_some(Tx(&mut self.output))
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = MTU;
        c
    }
}

struct Flow {
    socket: SocketHandle,
    bridge: DuplexStream,
    task: Option<JoinHandle<Result<(), rtrust_engine::Error>>>,
    last_activity: Instant,
    input_closed: bool,
    output_closed: bool,
}
impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub struct Stack {
    device: Packets,
    interface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<Key, Flow>,
    epoch: Instant,
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}
impl Stack {
    pub fn new() -> Self {
        let mut device = Packets::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
        interface.update_ip_addrs(|a| {
            a.push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0)).unwrap();
            a.push(IpCidr::new(IpAddress::Ipv6(Ipv6Address::LOCALHOST), 0))
                .unwrap();
        });
        interface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .unwrap();
        interface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::LOCALHOST)
            .unwrap();
        interface.set_any_ip(true);
        Self {
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            flows: HashMap::new(),
            epoch: Instant::now(),
        }
    }

    /// Validates before allocating; retransmitted SYNs reuse the same flow.
    pub fn ingest(
        &mut self,
        bytes: Vec<u8>,
        connect: impl FnOnce(Key, DuplexStream) -> JoinHandle<Result<(), rtrust_engine::Error>>,
    ) {
        let Some(crate::packet::Packet::Tcp { key, syn }) = crate::packet::parse(&bytes) else {
            return;
        };
        if !self.flows.contains_key(&key) {
            if !syn || self.flows.len() >= MAX_FLOWS {
                return;
            }
            let mut socket = Socket::new(
                SocketBuffer::new(vec![0; BUFFER]),
                SocketBuffer::new(vec![0; BUFFER]),
            );
            socket.set_timeout(Some(SmolDuration::from_secs(300)));
            socket.set_ack_delay(None);
            if socket.listen(key.1).is_err() {
                return;
            }
            let (bridge, remote) = tokio::io::duplex(BUFFER);
            let task = Some(connect(key, remote));
            self.flows.insert(
                key,
                Flow {
                    socket: self.sockets.add(socket),
                    bridge,
                    task,
                    last_activity: Instant::now(),
                    input_closed: false,
                    output_closed: false,
                },
            );
        }
        // One ingress slot; backpressure drops packets, and TCP retransmits.
        if self.device.input.is_none() {
            self.device.input = Some(bytes);
        }
        self.poll();
    }

    pub fn poll(&mut self) {
        let now = SmolInstant::from_millis(self.epoch.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        let mut buffer = [0; 16384];
        for flow in self.flows.values_mut() {
            let socket = self.sockets.get_mut::<Socket>(flow.socket);
            if flow.last_activity.elapsed() > Duration::from_secs(300) {
                socket.abort();
            }
            if flow.task.as_ref().is_some_and(|task| task.is_finished())
                && !matches!(flow.task.take().unwrap().now_or_never(), Some(Ok(Ok(()))))
            {
                socket.abort();
            }
            if matches!(
                socket.state(),
                State::Listen | State::SynReceived | State::Closed | State::TimeWait
            ) {
                continue;
            }
            if socket.can_recv() && !flow.input_closed {
                let data = socket.peek(16384).unwrap();
                match flow.bridge.write(data).now_or_never() {
                    Some(Ok(n)) if n > 0 => {
                        socket.recv(|_| (n, ())).unwrap();
                        flow.last_activity = Instant::now();
                    }
                    Some(_) => socket.abort(),
                    None => {}
                }
            }
            if !socket.may_recv()
                && !flow.input_closed
                && let Some(result) = flow.bridge.shutdown().now_or_never()
            {
                flow.input_closed = true;
                if result.is_err() {
                    socket.abort();
                }
            }
            if socket.can_send() && !flow.output_closed {
                let capacity = (socket.send_capacity() - socket.send_queue()).min(buffer.len());
                match flow.bridge.read(&mut buffer[..capacity]).now_or_never() {
                    Some(Ok(0)) => {
                        flow.output_closed = true;
                        socket.close();
                    }
                    Some(Ok(n)) => {
                        socket.send_slice(&buffer[..n]).unwrap();
                        flow.last_activity = Instant::now();
                    }
                    Some(Err(_)) => socket.abort(),
                    None => {}
                }
            }
        }
        // Dispatch FIN/RST before removing closed sockets.
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        self.flows.retain(|_, f| {
            if self.sockets.get::<Socket>(f.socket).state() == State::Closed {
                self.sockets.remove(f.socket);
                false
            } else {
                true
            }
        });
    }

    pub fn output(&mut self) -> Option<Vec<u8>> {
        self.device.output.pop_front()
    }
    pub fn connections(&self) -> usize {
        self.flows.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn parallel_tcp_downloads_preserve_every_byte() {
        parallel_downloads(false).await;
        parallel_downloads(true).await;
    }
    async fn parallel_downloads(v6: bool) {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stack = Stack::new();
            let mut packets = Packets::default();
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 10;
            let mut client = Interface::new(config, &mut packets, SmolInstant::from_millis(0));
            client.update_ip_addrs(|a| {
                let local = if v6 {
                    IpAddress::Ipv6(crate::ipv6::ADDRESS)
                } else {
                    IpAddress::v4(10, 77, 0, 2)
                };
                a.push(IpCidr::new(local, 0)).unwrap();
            });
            let mut sockets = SocketSet::new(vec![]);
            let mut clients = vec![];
            for port in 4000..4004 {
                let mut socket = Socket::new(
                    SocketBuffer::new(vec![0; BUFFER]),
                    SocketBuffer::new(vec![0; BUFFER]),
                );
                socket
                    .connect(
                        client.context(),
                        (
                            if v6 {
                                IpAddress::Ipv6("2001:db8::1".parse().unwrap())
                            } else {
                                IpAddress::v4(198, 18, 0, 1)
                            },
                            80,
                        ),
                        port,
                    )
                    .unwrap();
                clients.push((sockets.add(socket), false, Vec::new()));
            }
            let epoch = Instant::now();
            loop {
                let now = SmolInstant::from_millis(epoch.elapsed().as_millis() as i64);
                client.poll(now, &mut packets, &mut sockets);
                while let Some(bytes) = packets.output.pop_front() {
                    stack.ingest(bytes, |_, mut bridge| {
                        tokio::spawn(async move {
                            let mut request = [0; 3];
                            bridge.read_exact(&mut request).await?;
                            assert_eq!(&request, b"GET");
                            bridge.write_all(&vec![0x5a; 512 * 1024]).await?;
                            bridge.shutdown().await?;
                            Ok(())
                        })
                    });
                }
                stack.poll();
                while let Some(bytes) = stack.output() {
                    packets.input = Some(bytes);
                    client.poll(now, &mut packets, &mut sockets);
                }
                for (handle, sent, data) in &mut clients {
                    let socket = sockets.get_mut::<Socket>(*handle);
                    if !*sent && socket.can_send() {
                        socket.send_slice(b"GET").unwrap();
                        *sent = true;
                    }
                    if socket.can_recv() {
                        socket
                            .recv(|b| {
                                data.extend_from_slice(b);
                                (b.len(), ())
                            })
                            .unwrap();
                    }
                }
                if clients.iter().all(|(_, _, data)| data.len() == 512 * 1024) {
                    for (_, _, data) in clients {
                        assert!(data.iter().all(|b| *b == 0x5a));
                    }
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn syn_retransmission_limit_checksums_and_expiry() {
        let mut stack = Stack::new();
        let mut created = 0;
        let mut add = |key: Key, bridge: DuplexStream| {
            created += 1;
            tokio::spawn(async move {
                let _keep = (key, bridge);
                std::future::pending().await
            })
        };
        let syn = crate::packet::test_syn(4000);
        assert!(crate::packet::parse(&syn).is_some());
        for _ in 0..1000 {
            stack.ingest(syn.clone(), &mut add);
        }
        assert_eq!(stack.connections(), 1);
        let mut corrupt = syn.clone();
        corrupt[20] ^= 1;
        stack.ingest(corrupt, &mut add);
        assert_eq!(stack.connections(), 1);
        for port in 4001..4300 {
            stack.ingest(crate::packet::test_syn(port), &mut add);
        }
        assert_eq!(stack.connections(), MAX_FLOWS);
        assert!(stack.device.output.len() <= QUEUE);
        assert_eq!(created, MAX_FLOWS);
        while stack.output().is_some() {}
        for flow in stack.flows.values_mut() {
            flow.last_activity = Instant::now() - Duration::from_secs(301);
        }
        stack.poll();
        assert_eq!(stack.connections(), 0);
    }
}
