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
}
#[cfg(not(target_os = "ios"))]
impl PacketDevice for tun_rs::AsyncDevice {
    async fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::recv(self, buffer).await
    }
    async fn send(&self, packet: &[u8]) -> std::io::Result<usize> {
        tun_rs::AsyncDevice::send(self, packet).await
    }
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
    let dns = std::sync::Arc::new(dns);
    let mut dns_jobs = JoinSet::new();
    let mut direct_jobs = JoinSet::new();
    let mut direct_flows: HashMap<packet::Key, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let (udp_tx, udp_rx) = mpsc::channel(64);
    let (reply_tx, mut reply_rx) = mpsc::channel(64);
    let mut workers = JoinSet::new();
    let direct_reply = reply_tx.clone();
    workers.spawn(relay_udp(
        session.clone(),
        tunnel,
        udp_rx,
        reply_tx,
        routing.as_ref().map(|r| r.0.clone()),
    ));
    let (icmp_tx, icmp_rx) = mpsc::channel(64);
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
                            if key.1.port() == 53 && !dns.is_empty() {
                                return rtrust_engine::dns::serve_tcp(&dns, &session, &mut remote, routing.as_ref().map(|r| r.0.as_ref())).await;
                            }
                            if let Some((router, protect)) = &routing {
                                if key.1.port() == 53 { return rtrust_engine::dns::forward_tcp(&session, key.1, &mut remote, router).await; }
                                if !router.tunneled(key.1) {
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
                                    let payload = rtrust_engine::dns::exchange(&dns, &session, &d.payload).await?;
                                    if let Some(router) = router { router.learn(&d.payload, &payload); }
                                    Ok::<_,rtrust_engine::Error>(Datagram { source: d.destination, destination: d.source, payload })
                                });
                            }
                        } else if let Some((router, protect)) = &routing {
                            if router.tunneled(d.destination) { let _ = udp_tx.try_send(d); }
                            else {
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
                    Some(Packet::Icmp(echo)) if routing.as_ref().is_none_or(|r| r.0.tunneled(std::net::SocketAddr::new(echo.destination,0))) => { let _ = icmp_tx.try_send(echo); },
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
    router: Option<std::sync::Arc<rtrust_engine::routing::Router>>,
) -> Result<(), rtrust_engine::Error> {
    let mut delay = Duration::from_millis(250);
    loop {
        let started = Instant::now();
        if udp_stream(tunnel, &mut input, &output, router.as_ref())
            .await
            .is_ok()
        {
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
    router: Option<&std::sync::Arc<rtrust_engine::routing::Router>>,
) -> Result<(), rtrust_engine::Error> {
    let (mut reader, mut writer) = tokio::io::split(tunnel);
    let mut mappings = HashMap::new();
    let mut queries: HashMap<(packet::Key, u16), Vec<u8>> = HashMap::new();
    // Preserve the partially read frame when an outgoing datagram wins select.
    let mut read = Box::pin(udp::read(&mut reader));
    loop {
        tokio::select! {
            outgoing = input.recv() => {
                let Some(d) = outgoing else { return Ok(()); };
                mappings.retain(|_, seen: &mut Instant| seen.elapsed() < Duration::from_secs(60));
                let key = (d.source, d.destination);
                if !mappings.contains_key(&key) && mappings.len() >= 256 { continue; }
                mappings.insert(key, Instant::now());
                queries.retain(|(key, _), _| mappings.contains_key(key));
                if d.destination.port()==53 && (2..=4096).contains(&d.payload.len()) && queries.len()<512 {
                    let id=u16::from_be_bytes([d.payload[0],d.payload[1]]);
                    queries.insert((key,id),d.payload.clone());
                }
                let frame = udp::encode(&d, "rtrust-tun")?;
                tokio::time::timeout(Duration::from_secs(10), writer.write_all(&frame)).await.map_err(|_| rtrust_engine::Error::Protocol)??;
            }
            result = &mut read => {
                let d = result?;
                if mappings.get(&(d.destination, d.source)).is_some_and(|seen| seen.elapsed() < Duration::from_secs(60)) {
                    if d.payload.len()>=2 {
                        let id=u16::from_be_bytes([d.payload[0],d.payload[1]]);
                        if let (Some(router), Some(query)) = (router, queries.remove(&((d.destination, d.source),id))) { router.learn(&query, &d.payload); }
                    }
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
