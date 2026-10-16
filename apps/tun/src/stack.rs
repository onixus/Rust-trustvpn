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
/// A SYN that is never acknowledged, or whose SYN-ACK the host resets, must
/// not hold a flow slot for the full idle timeout: a stale backlog after sleep
/// would otherwise fill the table and silently refuse every new connection.
pub const HANDSHAKE: Duration = Duration::from_secs(10);
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
    /// The socket left LISTEN at least once, so LISTEN again means the host
    /// reset the handshake (smoltcp returns to LISTEN on RST in SYN-RECEIVED).
    engaged: bool,
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
    retired: Vec<JoinHandle<Result<(), rtrust_engine::Error>>>,
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
            retired: Vec::new(),
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
            if !syn {
                return;
            }
            if self.flows.len() + self.retired.len() >= MAX_FLOWS {
                crate::stats::COUNTERS
                    .syn_refused
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return;
            }
            crate::stats::COUNTERS
                .syn_accepted
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                    engaged: false,
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
            match socket.state() {
                State::Listen if flow.engaged => {
                    // RST answered our SYN-ACK: the peer socket is gone.
                    crate::stats::COUNTERS
                        .handshake_reset
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    socket.abort();
                }
                State::Listen | State::SynReceived if flow.last_activity.elapsed() > HANDSHAKE => {
                    crate::stats::COUNTERS
                        .handshake_timeout
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    socket.abort();
                }
                State::Listen => {}
                _ => flow.engaged = true,
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
        // Finished tasks own no sockets. Retain aborted but still running owners
        // until the next policy drain can join them; bound them with live flows.
        self.retired.retain(|task| !task.is_finished());
        self.flows.retain(|_, f| {
            if self.sockets.get::<Socket>(f.socket).state() == State::Closed {
                if let Some(task) = f.task.take() {
                    task.abort();
                    self.retired.push(task);
                }
                self.sockets.remove(f.socket);
                false
            } else {
                true
            }
        });
    }

    /// Revoke pending connects as well as established TCP sockets, then wait
    /// until their socket owners have exited before acknowledging a policy swap.
    pub async fn drain(&mut self) {
        let mut tasks = std::mem::take(&mut self.retired);
        for (_, mut flow) in self.flows.drain() {
            if let Some(task) = flow.task.take() {
                task.abort();
                tasks.push(task);
            }
            self.sockets.remove(flow.socket);
        }
        for task in tasks {
            let _ = task.await;
        }
        self.device.input = None;
        self.device.output.clear();
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
    async fn policy_drain_joins_a_pending_connect_and_removes_old_output() {
        struct Owned(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for Owned {
            fn drop(&mut self) {
                self.0.store(false, std::sync::atomic::Ordering::SeqCst);
            }
        }
        use std::sync::Arc;
        let owns_socket = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let entered = Arc::new(tokio::sync::Notify::new());
        let signalled = entered.clone();
        let owned = owns_socket.clone();
        let mut stack = Stack::new();
        stack.ingest(crate::packet::test_syn(4000), move |_, _| {
            tokio::spawn(async move {
                let _socket = Owned(owned);
                signalled.notify_one();
                std::future::pending::<Result<(), rtrust_engine::Error>>().await
            })
        });
        entered.notified().await;
        assert_eq!(stack.connections(), 1);
        stack.drain().await;
        assert!(!owns_socket.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(stack.connections(), 0);
        assert!(stack.output().is_none());
    }
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

    fn pending_connect(
        key: Key,
        bridge: DuplexStream,
    ) -> JoinHandle<Result<(), rtrust_engine::Error>> {
        tokio::spawn(async move {
            let _keep = (key, bridge);
            std::future::pending().await
        })
    }
    /// Acknowledgement number of the stack's SYN-ACK: the sequence number a
    /// host RST must carry to be accepted in SYN-RECEIVED.
    fn syn_ack_ack(packet: &[u8]) -> u32 {
        assert_eq!(packet[33] & 0x12, 0x12, "expected SYN-ACK");
        u32::from_be_bytes(packet[28..32].try_into().unwrap())
    }

    #[tokio::test]
    async fn host_reset_after_syn_ack_frees_the_flow_slot() {
        let mut stack = Stack::new();
        stack.ingest(crate::packet::test_syn(5000), pending_connect);
        assert_eq!(stack.connections(), 1);
        let syn_ack = stack.output().expect("SYN-ACK queued");
        let seq = syn_ack_ack(&syn_ack);
        stack.ingest(crate::packet::test_rst(5000, seq), pending_connect);
        assert_eq!(
            stack.connections(),
            0,
            "RST must close the handshake, not park it in LISTEN"
        );
        // A later SYN for the same tuple opens a fresh flow and is answered.
        stack.ingest(crate::packet::test_syn(5000), pending_connect);
        assert_eq!(stack.connections(), 1);
        assert!(stack.output().is_some_and(|p| p[33] & 0x12 == 0x12));
    }

    #[tokio::test]
    async fn stale_backlog_resets_do_not_exhaust_the_flow_table() {
        let mut stack = Stack::new();
        // Every slot is taken by a handshake the host immediately resets.
        for port in 0..MAX_FLOWS as u16 {
            stack.ingest(crate::packet::test_syn(6000 + port), pending_connect);
            let syn_ack = stack.output().expect("SYN-ACK queued");
            let seq = syn_ack_ack(&syn_ack);
            stack.ingest(crate::packet::test_rst(6000 + port, seq), pending_connect);
        }
        assert_eq!(stack.connections(), 0);
        // Aborted connect owners retire as soon as the runtime polls them.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        stack.poll();
        assert!(stack.retired.is_empty());
        // A live connection attempt still gets its SYN-ACK.
        stack.ingest(crate::packet::test_syn(7000), pending_connect);
        assert_eq!(stack.connections(), 1);
        assert!(stack.output().is_some_and(|p| p[33] & 0x12 == 0x12));
    }

    #[tokio::test]
    async fn unanswered_handshakes_expire_before_the_idle_timeout() {
        let mut stack = Stack::new();
        stack.ingest(crate::packet::test_syn(8000), pending_connect);
        assert_eq!(stack.connections(), 1);
        while stack.output().is_some() {}
        for flow in stack.flows.values_mut() {
            flow.last_activity = Instant::now() - HANDSHAKE - Duration::from_millis(1);
        }
        stack.poll();
        assert_eq!(stack.connections(), 0);
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

/// Independent tester coverage for issue #99 (reset handshakes, handshake
/// limit, engaged-flow regression). Synthetic addresses only.
#[cfg(test)]
mod tester_tests {
    use super::*;

    fn pending_connect(
        key: Key,
        bridge: DuplexStream,
    ) -> JoinHandle<Result<(), rtrust_engine::Error>> {
        tokio::spawn(async move {
            let _keep = (key, bridge);
            std::future::pending().await
        })
    }
    fn syn_ack_ack(packet: &[u8]) -> u32 {
        assert_eq!(packet[33] & 0x12, 0x12, "expected SYN-ACK");
        u32::from_be_bytes(packet[28..32].try_into().unwrap())
    }
    fn state_of(stack: &Stack, port: u16) -> Option<(State, bool)> {
        stack
            .flows
            .iter()
            .find(|(key, _)| key.0.port() == port)
            .map(|(_, flow)| {
                (
                    stack.sockets.get::<Socket>(flow.socket).state(),
                    flow.engaged,
                )
            })
    }
    /// `stats::COUNTERS` is process-wide and shared with every test in this
    /// binary, so deltas are lower bounds under parallel execution; a
    /// `--test-threads=1` run checks them exactly.
    fn counters() -> crate::stats::Snapshot {
        crate::stats::snapshot()
    }

    /// Criterion 1: the reset is counted, the socket is removed from the
    /// socket set (no leak behind the flow map) and the same tuple reconnects.
    #[tokio::test]
    async fn host_reset_is_counted_and_leaves_no_socket_behind() {
        let before = counters();
        let mut stack = Stack::new();
        stack.ingest(crate::packet::test_syn(9100), pending_connect);
        assert_eq!(state_of(&stack, 9100), Some((State::SynReceived, true)));
        let seq = syn_ack_ack(&stack.output().unwrap());
        stack.ingest(crate::packet::test_rst(9100, seq), pending_connect);
        assert_eq!(stack.connections(), 0);
        assert_eq!(
            stack.sockets.iter().count(),
            0,
            "reset socket must be removed"
        );
        assert!(counters().since(&before).handshake_reset >= 1);
        stack.ingest(crate::packet::test_syn(9100), pending_connect);
        assert_eq!(state_of(&stack, 9100), Some((State::SynReceived, true)));
        assert!(stack.output().is_some_and(|p| p[33] & 0x12 == 0x12));
        assert!(counters().since(&before).syn_accepted >= 2);
    }

    /// Criterion 2, stronger than the developer test: after a full table of
    /// reset handshakes, a full table of live handshakes is admitted.
    #[tokio::test]
    async fn a_full_table_of_resets_then_a_full_table_of_live_syns_is_admitted() {
        let before = counters();
        let mut stack = Stack::new();
        for port in 0..MAX_FLOWS as u16 {
            stack.ingest(crate::packet::test_syn(10000 + port), pending_connect);
            let seq = syn_ack_ack(&stack.output().unwrap());
            stack.ingest(crate::packet::test_rst(10000 + port, seq), pending_connect);
        }
        assert_eq!(stack.connections(), 0);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        stack.poll();
        assert!(stack.retired.is_empty());
        for port in 0..MAX_FLOWS as u16 {
            stack.ingest(crate::packet::test_syn(11000 + port), pending_connect);
            assert!(stack.output().is_some_and(|p| p[33] & 0x12 == 0x12));
        }
        assert_eq!(stack.connections(), MAX_FLOWS);
        let delta = counters().since(&before);
        assert!(delta.handshake_reset >= MAX_FLOWS as u64);
        assert!(delta.syn_accepted >= 2 * MAX_FLOWS as u64);
    }

    /// Criterion 4: SYN retransmissions before the SYN-ACK is answered are a
    /// normal handshake, not a reset; a flow still in LISTEN (its SYN dropped
    /// by ingress backpressure) is kept until the handshake limit, and
    /// recovers once the SYN gets through.
    #[tokio::test]
    async fn syn_retransmissions_and_an_unengaged_listen_are_not_resets() {
        let mut stack = Stack::new();
        let syn = crate::packet::test_syn(9200);
        for _ in 0..50 {
            stack.ingest(syn.clone(), pending_connect);
            stack.poll();
        }
        assert_eq!(stack.connections(), 1);
        assert_eq!(state_of(&stack, 9200), Some((State::SynReceived, true)));
        // Ingress backpressure: a full output queue makes the device refuse
        // the SYN, so the flow exists but its socket never left LISTEN.
        while stack.output().is_some() {}
        stack
            .device
            .output
            .extend(std::iter::repeat_n(vec![0u8; 1], QUEUE));
        stack.ingest(crate::packet::test_syn(9201), pending_connect);
        assert_eq!(state_of(&stack, 9201), Some((State::Listen, false)));
        for _ in 0..5 {
            stack.poll();
        }
        assert_eq!(
            state_of(&stack, 9201),
            Some((State::Listen, false)),
            "LISTEN before engagement must survive until HANDSHAKE"
        );
        // Still below the handshake limit: nothing is aborted.
        for flow in stack.flows.values_mut() {
            flow.last_activity = Instant::now() - HANDSHAKE + Duration::from_secs(1);
        }
        stack.poll();
        assert_eq!(stack.connections(), 2);
        assert_eq!(state_of(&stack, 9200), Some((State::SynReceived, true)));
        // Backpressure clears: the queued SYN is served and the flow engages.
        stack.device.output.clear();
        stack.poll();
        assert_eq!(state_of(&stack, 9201), Some((State::SynReceived, true)));
        assert!(stack.output().is_some_and(|p| p[33] & 0x12 == 0x12));
    }

    /// Criterion 3: a LISTEN socket that never saw its SYN expires at the
    /// handshake limit and is counted as a timeout.
    #[tokio::test]
    async fn unengaged_listen_expires_at_the_handshake_limit() {
        let before = counters();
        let mut stack = Stack::new();
        stack
            .device
            .output
            .extend(std::iter::repeat_n(vec![0u8; 1], QUEUE));
        stack.ingest(crate::packet::test_syn(9300), pending_connect);
        assert_eq!(state_of(&stack, 9300), Some((State::Listen, false)));
        for flow in stack.flows.values_mut() {
            flow.last_activity = Instant::now() - HANDSHAKE - Duration::from_millis(1);
        }
        stack.poll();
        assert_eq!(stack.connections(), 0);
        assert_eq!(stack.sockets.iter().count(), 0);
        assert!(counters().since(&before).handshake_timeout >= 1);
    }

    /// Criterion 3 regression: an established, engaged flow is not touched by
    /// the handshake limit; only the 300 s idle timeout removes it.
    #[tokio::test]
    async fn established_flow_survives_the_handshake_limit_until_idle_timeout() {
        let mut stack = Stack::new();
        let mut packets = Packets::default();
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 11;
        let mut client = Interface::new(config, &mut packets, SmolInstant::from_millis(0));
        client.update_ip_addrs(|a| a.push(IpCidr::new(IpAddress::v4(10, 77, 0, 2), 0)).unwrap());
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; BUFFER]),
            SocketBuffer::new(vec![0; BUFFER]),
        );
        socket
            .connect(client.context(), (IpAddress::v4(198, 18, 0, 1), 80), 9400)
            .unwrap();
        let handle = sockets.add(socket);
        let epoch = Instant::now();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let now = SmolInstant::from_millis(epoch.elapsed().as_millis() as i64);
                client.poll(now, &mut packets, &mut sockets);
                while let Some(bytes) = packets.output.pop_front() {
                    stack.ingest(bytes, pending_connect);
                }
                stack.poll();
                while let Some(bytes) = stack.output() {
                    packets.input = Some(bytes);
                    client.poll(now, &mut packets, &mut sockets);
                }
                if state_of(&stack, 9400) == Some((State::Established, true))
                    && sockets.get::<Socket>(handle).state() == State::Established
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("three-way handshake completes");
        assert_eq!(stack.connections(), 1);
        for flow in stack.flows.values_mut() {
            flow.last_activity = Instant::now() - HANDSHAKE - Duration::from_secs(5);
        }
        for _ in 0..3 {
            stack.poll();
        }
        assert_eq!(
            state_of(&stack, 9400),
            Some((State::Established, true)),
            "handshake limit must not abort an established flow"
        );
        // The idle timeout still applies to established flows.
        for flow in stack.flows.values_mut() {
            flow.last_activity = Instant::now() - Duration::from_secs(301);
        }
        stack.poll();
        assert_eq!(stack.connections(), 0);
        assert_eq!(stack.sockets.iter().count(), 0);
    }
}
