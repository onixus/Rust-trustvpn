use crate::{
    packet::{self, Packet},
    stack::Stack,
};
use rtrust_engine::{
    Session,
    udp::{self, Datagram},
};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    time::{Duration, Instant},
};
use tokio::{io::AsyncWriteExt, sync::mpsc, task::JoinSet};

/// Packet-oriented interface; recv must be cancellation safe. Implementations
/// preserve packet boundaries and bound queued memory.
pub trait PacketDevice: Send + Sync {
    fn recv(
        &self,
        buffer: &mut [u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
    fn send(
        &self,
        packet: &[u8],
    ) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
    /// Non-blocking read; `WouldBlock` when nothing is queued. Devices that
    /// cannot peek report `WouldBlock`, which disables backlog discard.
    fn try_recv(&self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}
#[cfg(not(target_os = "ios"))]
impl PacketDevice for tun_rs::AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::recv(self, buffer).await
    }
    #[cfg(unix)]
    fn try_recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::try_recv(self, buffer)
    }
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::send(self, packet).await
    }
}

/// True when the data plane ended degraded (`Session::health`) in a session
/// that never delivered an inbound byte: however long it lasted, it is no
/// evidence of a stable connection. A degraded exit after proven traffic is.
pub fn unproven<T>(result: &Result<T, Box<dyn std::error::Error + Send + Sync>>) -> bool {
    degraded(result) == Some(false)
}
/// `Some(proven)` when the data plane ended degraded.
pub fn degraded<T>(result: &Result<T, Box<dyn std::error::Error + Send + Sync>>) -> Option<bool> {
    match result
        .as_ref()
        .err()?
        .downcast_ref::<rtrust_engine::Error>()?
    {
        rtrust_engine::Error::Degraded { proven } => Some(*proven),
        _ => None,
    }
}

/// Packets queued on the device before this session existed belong to an
/// earlier one: after sleep they are mostly SYNs of host sockets that have
/// already given up. Opening upstream streams for them wastes the fresh
/// session's capacity, and their resets would then occupy flow slots. TCP and
/// DNS retransmit what still matters. Bounded so a busy device cannot starve
/// the session start.
pub const BACKLOG_LIMIT: usize = 4096;
/// Longest wait for the first queued packet before the session starts.
pub const PRIME_WAIT: Duration = Duration::from_millis(5);
fn discard_backlog<D: PacketDevice>(device: &D) -> usize {
    let mut buffer = [0; 65536];
    let mut discarded = 0;
    while discarded < BACKLOG_LIMIT {
        match device.try_recv(&mut buffer) {
            Ok(_) => discarded += 1,
            Err(_) => break,
        }
    }
    if discarded > 0 {
        crate::stats::COUNTERS
            .backlog_discarded
            .fetch_add(discarded as u64, std::sync::atomic::Ordering::Relaxed);
    }
    discarded
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn run(
    session: Session,
    tunnel: rtrust_engine::Tunnel,
    device: std::sync::Arc<tun_rs::AsyncDevice>,
    address: Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_dns(session, tunnel, device, address, Vec::new(), None).await
}

pub async fn run_with_dns<D: PacketDevice>(
    session: Session,
    tunnel: rtrust_engine::Tunnel,
    device: std::sync::Arc<D>,
    address: Ipv4Addr,
    dns: Vec<rtrust_engine::dns::Resolver>,
    routing: Option<(
        std::sync::Arc<rtrust_engine::routing::Router>,
        rtrust_engine::SocketProtector,
    )>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_policy(session, tunnel, device, address, dns, routing, None).await
}

pub async fn run_with_policy<D: PacketDevice>(
    session: Session,
    tunnel: rtrust_engine::Tunnel,
    device: std::sync::Arc<D>,
    address: Ipv4Addr,
    dns: Vec<rtrust_engine::dns::Resolver>,
    routing: Option<(
        std::sync::Arc<rtrust_engine::routing::Router>,
        rtrust_engine::SocketProtector,
    )>,
    mut updates: Option<&mut crate::policy::Receiver>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let dns = std::sync::Arc::new(dns);
    // One awaited read first: it registers interest with the reactor, so the
    // non-blocking sweep below sees readiness the kernel recorded while no
    // session was reading. Bounded, so an empty device costs milliseconds.
    {
        let mut primer = [0; 65536];
        if let Ok(Ok(_)) = tokio::time::timeout(PRIME_WAIT, device.recv(&mut primer)).await {
            crate::stats::COUNTERS
                .backlog_discarded
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            discard_backlog(device.as_ref());
        }
    }
    let mut dns_jobs = JoinSet::new();
    let mut direct_jobs = JoinSet::new();
    let mut direct_flows: HashMap<packet::Key, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (mut udp_tx, udp_rx) = mpsc::channel(64);
    let (reply_tx, mut reply_rx) = mpsc::channel(64);
    let mut workers = JoinSet::new();
    let mut direct_reply = reply_tx.clone();
    workers.spawn(relay_udp(session.clone(), tunnel, udp_rx, reply_tx));
    let (mut icmp_tx, icmp_rx) = mpsc::channel(64);
    let (icmp_reply_tx, mut icmp_reply_rx) = mpsc::channel(64);
    workers.spawn(relay_icmp(session.clone(), icmp_rx, icmp_reply_tx));
    let mut assembler = crate::fragments::Reassembler::default();
    let mut stack = Stack::new();
    let mut incoming = [0; 65536];
    let mut tick = tokio::time::interval(Duration::from_millis(5));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let monitor = session.clone();
    workers.spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tokio::time::timeout(Duration::from_secs(10), monitor.health())
                .await
                .map_err(|_| rtrust_engine::Error::Timeout)??;
        }
    });
    loop {
        tokio::select! {
            update = async { updates.as_mut().unwrap().input.recv().await }, if updates.is_some() => {
                let Some(update) = update else { updates = None; continue; };
                let Some((router, _)) = &routing else {
                    let _ = update.reply.send(Err("Flow policy unavailable for this mode".into())); continue;
                };
                let prepared = match update.prepare(router) {
                    Ok(policy) => policy,
                    Err(error) => { let _ = update.reply.send(Err(error)); continue; }
                };
                // Prepare the replacement upstream stream while the prior policy
                // remains authoritative. Failure leaves its flows undisturbed.
                let tunnel = match tokio::time::timeout(Duration::from_secs(5), session.open_udp()).await {
                    Ok(Ok(tunnel)) => tunnel,
                    _ => { let _ = update.reply.send(Err("Cannot prepare policy cutover".into())); continue; }
                };
                if update.reply.is_closed() { continue; }
                // Pause packet intake. Abort AND join every old socket owner,
                // including TCP setup/protection, DNS and both UDP relay paths.
                stack.drain().await;
                dns_jobs.shutdown().await;
                direct_jobs.shutdown().await;
                workers.shutdown().await;
                direct_flows.clear();
                assembler = crate::fragments::Reassembler::default();
                let result = if update.reply.is_closed() { Err("Policy request cancelled".into()) }
                    else { router.commit_local(&update.expected, prepared).map_err(|e| e.to_string()) };
                let (sender, receiver) = mpsc::channel(64); udp_tx = sender;
                let (reply, incoming_reply) = mpsc::channel(64); reply_rx = incoming_reply;
                direct_reply = reply.clone();
                workers.spawn(relay_udp(session.clone(), tunnel, receiver, reply));
                let (sender, receiver) = mpsc::channel(64); icmp_tx = sender;
                let (reply, incoming_reply) = mpsc::channel(64); icmp_reply_rx = incoming_reply;
                workers.spawn(relay_icmp(session.clone(), receiver, reply));
                let monitor = session.clone();
                workers.spawn(async move { loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    tokio::time::timeout(Duration::from_secs(10), monitor.health()).await
                        .map_err(|_| rtrust_engine::Error::Timeout)??;
                }});
                // Even a stale/cancelled commit resumes under its intact old
                // policy. Only a completed drain + publication receives success.
                let _ = update.reply.send(result);
            }
            received = device.recv(&mut incoming) => {
                let len = received?;
                if !((len>=20 && incoming[0]>>4==4 && incoming[12..16]==address.octets()) || (len>=40 && incoming[0]>>4==6 && incoming[8..24]==crate::ipv6::ADDRESS.octets())) {continue;}
                let Some(incoming) = assembler.push(&incoming[..len]) else { continue; };
                // The endpoint cannot relay IPv6: refuse locally, never via the
                // underlying network, so the application falls back to IPv4.
                if !session.ipv6() && incoming[0] >> 4 == 6 {
                    if packet::parse(&incoming).is_some()
                        && let Some(reply) = crate::ipv6::refuse(&incoming) {
                            tokio::time::timeout(Duration::from_secs(2), device.send(&reply)).await??;
                    }
                    continue;
                }
                match packet::parse(&incoming) {
                    Some(Packet::Tcp { key, .. }) if (key.0.ip() == address || key.0.ip() == crate::ipv6::ADDRESS) => stack.ingest(incoming, |key, mut remote| {
                        let session = session.clone();
                        let dns = dns.clone();
                        let routing = routing.clone();
                        tokio::spawn(async move {
                            let action = routing.as_ref().map(|r| r.0.route_flow(key.1));
                            if action.is_some_and(|action| !matches!(action, rtrust_engine::routing::Action::Tunnel | rtrust_engine::routing::Action::Direct)) {
                                return Err(rtrust_engine::Error::Unsupported("blocked flow policy decision"));
                            }
                            if key.1.port() == 53 && !dns.is_empty() {
                                return rtrust_engine::dns::serve_tcp(&dns, &session, &mut remote, routing.as_ref().map(|r| r.0.as_ref())).await;
                            }
                            if let Some((router, protect)) = &routing {
                                if key.1.port() == 53 { return rtrust_engine::dns::forward_tcp(&session, key.1, &mut remote, router).await; }
                                if action == Some(rtrust_engine::routing::Action::Direct) {
                                    let mut direct = rtrust_engine::direct_tcp(key.1, protect).await?;
                                    tokio::io::copy_bidirectional(&mut remote, &mut direct).await?;
                                    return Ok(());
                                }
                            }
                            if key.1.port() == 53 && !session.ipv6() {
                                return rtrust_engine::dns::forward_tcp_without_aaaa(&session, key.1, &mut remote).await;
                            }
                            let mut tunnel = session.open_tcp(&key.1.to_string()).await?;
                            tokio::io::copy_bidirectional(&mut remote, &mut tunnel).await?;
                            Ok(())
                        })
                    }),
                    Some(Packet::Udp(d)) if (d.source.ip() == address || d.source.ip() == crate::ipv6::ADDRESS) => {
                        let action = routing.as_ref().map(|r| r.0.route_flow(d.destination));
                        if d.destination.port() == 53 && !session.ipv6()
                            && let Some(payload) = rtrust_engine::dns::aaaa_nodata(&d.payload) {
                            if let Some(bytes) = packet::udp_packet(&Datagram { source: d.destination, destination: d.source, payload }) {
                                tokio::time::timeout(Duration::from_secs(2), device.send(&bytes)).await??;
                            }
                        } else if d.destination.port() == 53 && !dns.is_empty() {
                            if dns_jobs.len() < 32 {
                                let dns = dns.clone(); let session = session.clone();
                                let router = routing.as_ref().map(|r| r.0.clone());
                                dns_jobs.spawn(async move {
                                    let version = router.as_ref().map(|router| router.version());
                                    let payload = rtrust_engine::dns::exchange(&dns, &session, &d.payload).await?;
                                    if let (Some(router), Some(version)) = (router, version) { router.learn_for(&version, &d.payload, &payload); }
                                    Ok::<_,rtrust_engine::Error>(Datagram { source: d.destination, destination: d.source, payload })
                                });
                            }
                        } else if d.destination.port() == 53 && routing.is_some() {
                            if dns_jobs.len() < 32 {
                                let session = session.clone();
                                let router = routing.as_ref().unwrap().0.clone();
                                dns_jobs.spawn(async move {
                                    rtrust_engine::dns::forward_udp(&session, d, &router).await
                                });
                            }
                        } else if let Some((_, protect)) = &routing {
                            if action == Some(rtrust_engine::routing::Action::Tunnel) { let _ = udp_tx.try_send(d); }
                            else if action == Some(rtrust_engine::routing::Action::Direct) {
                                direct_flows.retain(|_, sender| !sender.is_closed());
                                let key = (d.source, d.destination);
                                if !direct_flows.contains_key(&key) && direct_flows.len() < 128 {
                                    let (sender, receiver) = mpsc::channel(16);
                                    direct_flows.insert(key, sender);
                                    let protect = protect.clone(); let reply = direct_reply.clone();
                                    direct_jobs.spawn(direct_udp_flow(key, protect, receiver, reply));
                                }
                                if let Some(sender) = direct_flows.get(&key) { let _ = sender.try_send(d.payload); }
                            }
                        } else { let _ = udp_tx.try_send(d); }
                    },
                    // Android unprivileged direct ICMP is not a supported bypass path.
                    Some(Packet::Icmp(echo)) if routing.as_ref().is_none_or(|r| r.0.route_flow(std::net::SocketAddr::new(echo.destination,0)) == rtrust_engine::routing::Action::Tunnel) => { let _ = icmp_tx.try_send(echo); },
                    _ => {},
                }
            }
            reply = reply_rx.recv() => {
                let reply = reply.ok_or("UDP relay stopped")?;
                if let Some(bytes) = packet::udp_packet(&reply) {
                    for fragment in crate::fragments::split(bytes) {
                        tokio::time::timeout(Duration::from_secs(2), device.send(&fragment)).await??;
                    }
                }
            }
            _ = direct_jobs.join_next(), if !direct_jobs.is_empty() => {}
            result = dns_jobs.join_next(), if !dns_jobs.is_empty() => {
                // A resolver failure drops only this query; never forward it as plaintext.
                if let Some(Ok(Ok(reply))) = result
                    && let Some(bytes) = packet::udp_packet(&reply) {
                        for fragment in crate::fragments::split(bytes) {
                            tokio::time::timeout(Duration::from_secs(2), device.send(&fragment)).await??;
                        }
                }
            }
            reply = icmp_reply_rx.recv() => {
                let reply = reply.ok_or("ICMP relay stopped")?;
                for fragment in crate::fragments::split(reply) {
                    tokio::time::timeout(Duration::from_secs(2), device.send(&fragment)).await??;
                }
            }
            _ = tick.tick() => stack.poll(),

            result = workers.join_next() => {
                if let Some(Ok(Err(error))) = result { return Err(error.into()); }
                return Err("Transport worker stopped".into());
            },
        }
        while let Some(bytes) = stack.output() {
            tokio::time::timeout(Duration::from_secs(2), device.send(&bytes)).await??;
        }
    }
}

async fn relay_udp(
    session: Session,
    mut tunnel: rtrust_engine::Tunnel,
    mut input: mpsc::Receiver<Datagram>,
    output: mpsc::Sender<Datagram>,
) -> Result<(), rtrust_engine::Error> {
    let mut delay = Duration::from_millis(250);
    loop {
        let started = Instant::now();
        if udp_stream(tunnel, &mut input, &output).await.is_ok() {
            return Ok(());
        }
        // Endpoint 1.1.0 can close _udp2 on an ICMP port-unreachable from
        // any destination. Replace only this stream: TCP/ICMP flows and the
        // device must survive. The independent health worker detects loss of
        // the whole transport. Stop cancels this bounded retry task as usual.
        if started.elapsed() >= Duration::from_secs(10) {
            delay = Duration::from_millis(250);
        }
        loop {
            tokio::time::sleep(delay).await;
            delay = (delay * 2).min(Duration::from_secs(5));
            if let Ok(Ok(reopened)) =
                tokio::time::timeout(Duration::from_secs(10), session.open_udp()).await
            {
                tunnel = reopened;
                break;
            }
        }
    }
}

async fn udp_stream(
    tunnel: rtrust_engine::Tunnel,
    input: &mut mpsc::Receiver<Datagram>,
    output: &mpsc::Sender<Datagram>,
) -> Result<(), rtrust_engine::Error> {
    let (mut reader, mut writer) = tokio::io::split(tunnel);
    let mut mappings = HashMap::new();
    // Preserve the partially read frame when an outgoing datagram wins select.
    let mut read = Box::pin(udp::read(&mut reader));
    loop {
        tokio::select! {
            outgoing = input.recv() => {
                let Some(d) = outgoing else { return Ok(()); };
                mappings.retain(|_, seen: &mut Instant| seen.elapsed() < Duration::from_secs(60));
                let key = (d.source, d.destination);
                if !mappings.contains_key(&key) && mappings.len() >= 256 {
                    // A full table must not refuse new flows until old ones
                    // age out: evict the least recently used mapping instead.
                    let Some(oldest) = mappings.iter().min_by_key(|(_, seen)| **seen).map(|(k, _)| *k) else { continue; };
                    mappings.remove(&oldest);
                    crate::stats::COUNTERS.udp_evicted.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                mappings.insert(key, Instant::now());
                let frame = udp::encode(&d, "rtrust-tun")?;
                tokio::time::timeout(Duration::from_secs(10), writer.write_all(&frame)).await.map_err(|_| rtrust_engine::Error::Protocol)??;
            }
            result = &mut read => {
                let d = result?;
                if mappings.get(&(d.destination, d.source)).is_some_and(|seen| seen.elapsed() < Duration::from_secs(60)) {
                    let _ = output.try_send(d);
                }
                drop(read);
                read = Box::pin(udp::read(&mut reader));
            }
        }
    }
}

// ICMP is optional at the endpoint. Rejection never fabricates a reply or tears down TCP/UDP.
async fn relay_icmp(
    session: Session,
    mut input: mpsc::Receiver<crate::echo::Echo>,
    output: mpsc::Sender<Vec<u8>>,
) -> Result<(), rtrust_engine::Error> {
    while let Some(first) = input.recv().await {
        if let Ok(tunnel) = session.open_icmp().await {
            let _ = icmp_stream(tunnel, first, &mut input, &output).await;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}
async fn icmp_stream(
    tunnel: rtrust_engine::Tunnel,
    first: crate::echo::Echo,
    input: &mut mpsc::Receiver<crate::echo::Echo>,
    output: &mpsc::Sender<Vec<u8>>,
) -> Result<(), rtrust_engine::Error> {
    let (mut reader, mut writer) = tokio::io::split(tunnel);
    let mut pending = crate::echo::Pending::default();
    writer.write_all(&pending.insert(first).unwrap()).await?;
    let mut read = Box::pin(rtrust_engine::icmp::read(&mut reader));
    loop {
        tokio::select! {
            incoming=input.recv()=>{
                let Some(echo)=incoming else{return Ok(());};
                if let Some(frame)=pending.insert(echo) {
                    tokio::time::timeout(Duration::from_secs(10),writer.write_all(&frame)).await.map_err(|_|rtrust_engine::Error::Timeout)??;
                }
            }
            reply=&mut read=>{
                if let Some(packet)=pending.reply(reply?) {let _=output.try_send(packet);}
                drop(read);read=Box::pin(rtrust_engine::icmp::read(&mut reader));
            }
        }
    }
}

async fn direct_udp_flow(
    key: packet::Key,
    protect: rtrust_engine::SocketProtector,
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Datagram>,
) -> Result<(), rtrust_engine::Error> {
    let socket = rtrust_engine::direct_udp(key.1, &protect).await?;
    let mut buffer = vec![0; 65535];
    loop {
        tokio::select! {
            data = input.recv() => {
                let Some(data) = data else { return Ok(()); };
                tokio::time::timeout(Duration::from_secs(5),socket.send(&data)).await.map_err(|_| rtrust_engine::Error::Timeout)??;
            }
            received = socket.recv(&mut buffer) => {
                let length = received?;
                let _ = output.try_send(Datagram { source:key.1, destination:key.0, payload:buffer[..length].to_vec() });
            }
            _ = tokio::time::sleep(Duration::from_secs(60)) => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_degraded_exit_without_any_delivery_is_unproven() {
        let exit = |proven| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Err(rtrust_engine::Error::Degraded { proven }.into())
        };
        assert!(super::unproven(&exit(false)));
        assert_eq!(super::degraded(&exit(true)), Some(true));
        assert!(!super::unproven(&exit(true)));
        for other in [
            Err(rtrust_engine::Error::Timeout.into()),
            Err("Transport worker stopped".into()),
            Ok(()),
        ] {
            assert_eq!(super::degraded(&other), None);
            assert!(!super::unproven(&other));
        }
    }
}

#[cfg(test)]
mod backlog_tests {
    use super::*;
    struct Queued(std::sync::Mutex<usize>);
    impl PacketDevice for Queued {
        async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }
        async fn send(&self, p: &[u8]) -> std::io::Result<usize> {
            Ok(p.len())
        }
        fn try_recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
            let mut left = self.0.lock().unwrap();
            if *left == 0 {
                return Err(std::io::ErrorKind::WouldBlock.into());
            }
            *left -= 1;
            Ok(40)
        }
    }
    #[test]
    fn backlog_discard_is_bounded_and_counted() {
        let before = crate::stats::snapshot();
        assert_eq!(discard_backlog(&Queued(std::sync::Mutex::new(7))), 7);
        let flooded = Queued(std::sync::Mutex::new(BACKLOG_LIMIT * 2));
        assert_eq!(discard_backlog(&flooded), BACKLOG_LIMIT);
        assert_eq!(*flooded.0.lock().unwrap(), BACKLOG_LIMIT);
        assert!(
            crate::stats::snapshot().since(&before).backlog_discarded >= 7 + BACKLOG_LIMIT as u64
        );
        struct Blind;
        impl PacketDevice for Blind {
            async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
                std::future::pending().await
            }
            async fn send(&self, p: &[u8]) -> std::io::Result<usize> {
                Ok(p.len())
            }
        }
        assert_eq!(discard_backlog(&Blind), 0);
    }
}

/// Independent tester coverage for issue #99 (backlog discard, criterion 6).
#[cfg(test)]
mod tester_backlog_tests {
    use super::*;
    use std::sync::Mutex;

    /// try_recv and recv share one queue, like a real device: discard must
    /// stop at the first non-Ok result and leave later packets for recv.
    struct Shared {
        queue: Mutex<std::collections::VecDeque<std::io::Result<usize>>>,
        try_calls: std::sync::atomic::AtomicUsize,
    }
    impl Shared {
        fn with(items: Vec<std::io::Result<usize>>) -> Self {
            Self {
                queue: Mutex::new(items.into()),
                try_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
    }
    impl PacketDevice for Shared {
        async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
            loop {
                if let Some(item) = self.queue.lock().unwrap().pop_front() {
                    return item;
                }
                tokio::task::yield_now().await;
            }
        }
        async fn send(&self, p: &[u8]) -> std::io::Result<usize> {
            Ok(p.len())
        }
        fn try_recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
            self.try_calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.queue
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Err(std::io::ErrorKind::WouldBlock.into()))
        }
    }

    #[tokio::test]
    async fn discard_stops_at_would_block_and_recv_still_serves_later_packets() {
        let device = Shared::with(vec![Ok(60), Ok(60), Ok(1500)]);
        assert_eq!(discard_backlog(&device), 3);
        // Exactly one extra probe that returned WouldBlock; no spinning.
        assert_eq!(
            device.try_calls.load(std::sync::atomic::Ordering::Relaxed),
            4
        );
        device.queue.lock().unwrap().push_back(Ok(80));
        let mut buffer = [0; 65536];
        let served = tokio::time::timeout(Duration::from_secs(1), device.recv(&mut buffer))
            .await
            .expect("recv must not hang after discard")
            .unwrap();
        assert_eq!(served, 80);
    }

    #[tokio::test]
    async fn discard_stops_at_any_error_and_never_blocks_on_an_empty_device() {
        // A hard error (not WouldBlock) also ends the discard without panic
        // and the packets behind it stay for recv.
        let device = Shared::with(vec![
            Ok(40),
            Err(std::io::ErrorKind::Interrupted.into()),
            Ok(40),
        ]);
        assert_eq!(discard_backlog(&device), 1);
        let mut buffer = [0; 65536];
        assert_eq!(device.recv(&mut buffer).await.unwrap(), 40);
        // Empty device: one probe, zero discarded.
        let empty = Shared::with(vec![]);
        let started = Instant::now();
        assert_eq!(discard_backlog(&empty), 0);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            empty.try_calls.load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    /// The default `try_recv` (devices without a non-blocking read) reports
    /// WouldBlock, so discard is a no-op there rather than an error.
    #[test]
    fn default_try_recv_reports_would_block() {
        struct Blind;
        impl PacketDevice for Blind {
            async fn recv(&self, _: &mut [u8]) -> std::io::Result<usize> {
                std::future::pending().await
            }
            async fn send(&self, p: &[u8]) -> std::io::Result<usize> {
                Ok(p.len())
            }
        }
        let mut buffer = [0; 16];
        assert_eq!(
            Blind.try_recv(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(discard_backlog(&Blind), 0);
    }
}
