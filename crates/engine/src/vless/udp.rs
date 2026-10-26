//! UDP over VLESS: one WebSocket flow (command 2) per source and destination
//! pair, packets framed as `[u16 length][payload]`. The tunnel side speaks the
//! same `_udp2` framing as the other transports.
use super::*;
use crate::hysteria::datagrams::outgoing;
use crate::udp::Datagram;
use std::{collections::HashMap, sync::atomic::AtomicU64};

/// Largest payload Xray relays intact: it drops larger downlink packets
/// (8190 bytes plus the 2-byte length fill its 8 KiB buffer) and splits
/// larger uplink ones, so they are dropped here before sending.
pub(crate) const VLESS_UDP_MAX: usize = 8190;
/// Flows per tunnel and per session.
pub(super) const TUNNEL_FLOWS: usize = 64;
pub(super) const SESSION_FLOWS: usize = 1024;
/// A flow without traffic either way is closed; Xray answers a blocked
/// target with silence, not a close. Shorter in tests.
const IDLE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 60 });
const SWEEP: Duration = Duration::from_millis(if cfg!(test) { 200 } else { 5000 });
/// Packets waiting for one flow; more are dropped, as on a full link.
pub(super) const QUEUE: usize = 32;
/// After a failed handshake a flow drops its packets this long before the
/// next datagram may open it again, so a dead endpoint is not redialed per packet.
const RETRY: Duration = Duration::from_secs(2);

/// Datagrams dropped for exceeding [`VLESS_UDP_MAX`], since start.
pub(crate) static OVERSIZE: AtomicU64 = AtomicU64::new(0);

struct Flow {
    packets: tokio::sync::mpsc::Sender<Vec<u8>>,
    seen: Instant,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) async fn open(session: VlessSession) -> Result<Tunnel> {
    let (io, bridge) = tokio::io::duplex(128 * 1024);
    let pump = tokio::spawn(async move {
        let _ = relay(session, bridge).await;
    });
    Ok(Tunnel {
        io,
        pump,
        liveness: None,
        watch: Default::default(),
    })
}

async fn relay(session: VlessSession, bridge: DuplexStream) -> Result<()> {
    let (mut read, mut write) = tokio::io::split(bridge);
    let (back, mut answers) = tokio::sync::mpsc::channel::<Datagram>(128);
    let mut flows: HashMap<(SocketAddr, SocketAddr), Flow> = HashMap::new();
    let mut request = Box::pin(outgoing(&mut read));
    let mut sweep = tokio::time::interval(SWEEP);
    loop {
        tokio::select! {
            _ = sweep.tick() => flows.retain(|_, flow| flow.seen.elapsed() < IDLE),
            datagram = &mut request => {
                let d = datagram?;
                drop(request);
                request = Box::pin(outgoing(&mut read));
                if d.payload.len() > VLESS_UDP_MAX {
                    OVERSIZE.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let key = (d.source, d.destination);
                if flows.get(&key).is_some_and(|flow| flow.packets.is_closed()) {
                    flows.remove(&key);
                }
                if !flows.contains_key(&key) {
                    if flows.len() >= TUNNEL_FLOWS {
                        continue;
                    }
                    let Ok(permit) = session.0.udp_flows.clone().try_acquire_owned() else {
                        continue;
                    };
                    let (packets, queue) = tokio::sync::mpsc::channel(QUEUE);
                    let task = tokio::spawn(flow(session.clone(), key, queue, back.clone(), permit));
                    flows.insert(key, Flow { packets, seen: Instant::now(), task });
                }
                let flow = flows.get_mut(&key).expect("inserted above");
                flow.seen = Instant::now();
                let _ = flow.packets.try_send(d.payload);
            }
            answer = answers.recv() => {
                let Some(d) = answer else { return Ok(()) };
                if let Some(flow) = flows.get_mut(&(d.destination, d.source)) {
                    flow.seen = Instant::now();
                }
                // The tunnel side of `_udp2` carries no application name.
                let mut frame = crate::udp::encode(&d, "")?;
                frame.remove(40);
                let len = (frame.len() - 4) as u32;
                frame[..4].copy_from_slice(&len.to_be_bytes());
                tokio::time::timeout(Duration::from_secs(10), write.write_all(&frame))
                    .await
                    .map_err(|_| Error::Timeout)??;
            }
        }
    }
}

fn packet(payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
}

async fn flow(
    session: VlessSession,
    (source, destination): (SocketAddr, SocketAddr),
    mut queue: tokio::sync::mpsc::Receiver<Vec<u8>>,
    back: tokio::sync::mpsc::Sender<Datagram>,
    _permit: tokio::sync::OwnedSemaphorePermit,
) {
    let dialed = tokio::time::timeout(OPEN, session.dial()).await;
    let Ok(Ok((tls, rest))) = dialed else {
        tokio::time::sleep(RETRY).await;
        return;
    };
    let _ = carry(&session, tls, rest, destination, source, &mut queue, &back).await;
}

async fn carry(
    session: &VlessSession,
    tls: Tls,
    rest: BytesMut,
    destination: SocketAddr,
    source: SocketAddr,
    queue: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    back: &tokio::sync::mpsc::Sender<Datagram>,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(tls);
    let mut frames = ws::Reader::new(read, rest);
    let target = header::Target::Ip(destination.ip(), destination.port());
    // The packet that opened the flow is already queued and goes with the header.
    let mut first = header::request(&session.0.uuid, header::UDP, &target);
    while let Ok(payload) = queue.try_recv() {
        packet(&payload, &mut first);
    }
    ws::send(&mut write, ws::BINARY, &first).await?;
    drop(first);
    let mut response = header::Response::default();
    let mut pending = BytesMut::new();
    let idle = tokio::time::sleep(KEEPALIVE);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            payload = queue.recv() => {
                let Some(payload) = payload else { break };
                let mut out = Vec::with_capacity(payload.len() + 2);
                packet(&payload, &mut out);
                ws::send(&mut write, ws::BINARY, &out).await?;
                idle.as_mut().reset(tokio::time::Instant::now() + KEEPALIVE);
            }
            event = frames.next() => match event? {
                None | Some(Event::Close) => break,
                Some(Event::Ping(payload)) => ws::send(&mut write, ws::PONG, &payload).await?,
                Some(Event::Data(mut data)) => {
                    if !response.done() {
                        data.advance(response.feed(&data)?);
                    }
                    pending.extend_from_slice(&data);
                    // Several packets may share a frame, and one may span frames.
                    while pending.len() >= 2 {
                        let len = u16::from_be_bytes([pending[0], pending[1]]) as usize;
                        if pending.len() < 2 + len {
                            break;
                        }
                        pending.advance(2);
                        let payload = pending.split_to(len).to_vec();
                        let _ = back.try_send(Datagram { source: destination, destination: source, payload });
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + KEEPALIVE);
                }
            },
            _ = &mut idle => {
                ws::send(&mut write, ws::PING, &[]).await?;
                idle.as_mut().reset(tokio::time::Instant::now() + KEEPALIVE);
            }
        }
    }
    let _ = ws::send(&mut write, ws::CLOSE, &[]).await;
    Ok(())
}
