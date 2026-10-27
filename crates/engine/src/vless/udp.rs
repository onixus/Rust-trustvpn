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
/// Flows per tunnel and per session. A full tunnel table evicts its least
/// recently active flow, so resolvers that pick a new source port for every
/// query never lock UDP out.
pub(super) const TUNNEL_FLOWS: usize = 64;
pub(super) const SESSION_FLOWS: usize = 1024;
/// A flow the server has not answered for this long is closed; the next
/// datagram opens a new one. Xray answers a blocked target with silence.
const IDLE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 60 });
/// DNS flows are one query and its answer: closed soon after the last packet.
const DNS_IDLE: Duration = Duration::from_millis(if cfg!(test) { 500 } else { 5000 });
/// Xray occasionally never relays any answer of a fresh UDP connection (seen
/// with a plain client too). A flow that heard nothing this long after it
/// opened is reopened by its next datagram, once per pair until it is answered,
/// so a target that is silent by design costs one extra connection, not a storm.
const FIRST_ANSWER: Duration = Duration::from_millis(if cfg!(test) { 300 } else { 2000 });
/// Pairs reopened for a missing first answer; more are left as they are.
const REOPENED: usize = 256;
const SWEEP: Duration = Duration::from_millis(if cfg!(test) { 100 } else { 1000 });
/// Packets waiting for one flow; more are dropped, as on a full link.
pub(super) const QUEUE: usize = 32;
/// After a failed handshake, or a flow the server closed without sending a
/// byte (as Xray does for an unknown UUID), the flow drops its packets this
/// long before the next datagram may open it again, so a refusing endpoint
/// is not redialed per packet.
pub(super) const RETRY: Duration = Duration::from_secs(2);

/// Datagrams dropped for exceeding [`VLESS_UDP_MAX`] either way, since start.
pub(crate) static OVERSIZE: AtomicU64 = AtomicU64::new(0);

type Key = (SocketAddr, SocketAddr);
struct Flow {
    packets: tokio::sync::mpsc::Sender<Vec<u8>>,
    /// Last datagram either way: the least recently active flow is evicted first.
    active: Instant,
    /// Last answer from the server, or the start: only answers prove the path.
    answered: Instant,
    /// A DNS flow that already got its answer goes first when the table is full.
    resolved: bool,
    /// When the flow opened, and whether the server answered it at all.
    opened: Instant,
    heard: bool,
    task: tokio::task::JoinHandle<()>,
    /// Held here, not by the task, so eviction frees the slot at once.
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl Drop for Flow {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn dns(key: &Key) -> bool {
    key.1.port() == 53
}
fn expired(key: &Key, flow: &Flow) -> bool {
    flow.answered.elapsed() >= IDLE || (dns(key) && flow.active.elapsed() >= DNS_IDLE)
}
/// Removes the flow to give up first: answered DNS, then the least recently active.
fn evict(flows: &mut HashMap<Key, Flow>) -> bool {
    let victim = flows
        .iter()
        .min_by_key(|(_, f)| (!f.resolved, f.active))
        .map(|(key, _)| *key);
    victim.is_some_and(|key| flows.remove(&key).is_some())
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
    let mut flows: HashMap<Key, Flow> = HashMap::new();
    let mut reopened: std::collections::HashSet<Key> = Default::default();
    let mut request = Box::pin(outgoing(&mut read));
    let mut sweep = tokio::time::interval(SWEEP);
    loop {
        tokio::select! {
            _ = sweep.tick() => flows.retain(|key, flow| !expired(key, flow)),
            datagram = &mut request => {
                let d = datagram?;
                drop(request);
                request = Box::pin(outgoing(&mut read));
                if d.payload.len() > VLESS_UDP_MAX {
                    OVERSIZE.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let key = (d.source, d.destination);
                let unheard = flows.get(&key).is_some_and(|flow| !flow.heard && flow.opened.elapsed() >= FIRST_ANSWER);
                if flows.get(&key).is_some_and(|flow| flow.packets.is_closed() || expired(&key, flow))
                    || (unheard && reopened.len() < REOPENED && reopened.insert(key))
                {
                    flows.remove(&key);
                }
                if !flows.contains_key(&key) {
                    if flows.len() >= TUNNEL_FLOWS {
                        evict(&mut flows);
                    }
                    let permit = match session.0.udp_flows.clone().try_acquire_owned() {
                        Ok(permit) => permit,
                        // Other tunnels hold the session's flows: reuse one of ours.
                        Err(_) if evict(&mut flows) => {
                            let Ok(permit) = session.0.udp_flows.clone().try_acquire_owned() else {
                                continue;
                            };
                            permit
                        }
                        Err(_) => continue,
                    };
                    let (packets, queue) = tokio::sync::mpsc::channel(QUEUE);
                    let task = tokio::spawn(flow(session.clone(), key, queue, back.clone()));
                    let now = Instant::now();
                    flows.insert(key, Flow { packets, active: now, answered: now, resolved: false, opened: now, heard: false, task, _permit: permit });
                }
                let flow = flows.get_mut(&key).expect("inserted above");
                flow.active = Instant::now();
                let _ = flow.packets.try_send(d.payload);
            }
            answer = answers.recv() => {
                let Some(d) = answer else { return Ok(()) };
                let key = (d.destination, d.source);
                if let Some(flow) = flows.get_mut(&key) {
                    flow.active = Instant::now();
                    flow.answered = flow.active;
                    flow.resolved = dns(&key);
                    flow.heard = true;
                }
                reopened.remove(&key);
                // The tunnel side of `_udp2` carries no application name. Flows
                // drop oversized answers; one that still fails costs only itself.
                let Ok(mut frame) = crate::udp::encode(&d, "") else { continue };
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
    (source, destination): Key,
    mut queue: tokio::sync::mpsc::Receiver<Vec<u8>>,
    back: tokio::sync::mpsc::Sender<Datagram>,
) {
    let mut heard = false;
    if let Ok(Ok((tls, rest))) = tokio::time::timeout(OPEN, session.dial()).await {
        let _ = carry(
            &session,
            tls,
            rest,
            (source, destination),
            &mut queue,
            &back,
            &mut heard,
        )
        .await;
    }
    if !heard {
        tokio::time::sleep(RETRY).await;
    }
}

async fn carry(
    session: &VlessSession,
    tls: Tls,
    rest: BytesMut,
    (source, destination): Key,
    queue: &mut tokio::sync::mpsc::Receiver<Vec<u8>>,
    back: &tokio::sync::mpsc::Sender<Datagram>,
    heard: &mut bool,
) -> Result<()> {
    let (read, mut write) = tokio::io::split(tls);
    let mut frames = ws::Reader::new(read, rest);
    let target = header::Target::Ip(destination.ip(), destination.port());
    // The packet that opened the flow is already queued and goes with the header.
    let mut queued = vec![];
    while let Ok(payload) = queue.try_recv() {
        queued.push(payload);
    }
    let size = queued.iter().map(|p| p.len() + 2).sum();
    let mut first = header::request(&session.0.uuid, header::UDP, &target, size);
    for payload in &queued {
        packet(payload, &mut first);
    }
    drop(queued);
    put(&mut write, ws::BINARY, &first).await?;
    drop(first);
    let mut response = header::Response::default();
    let mut pending = BytesMut::new();
    // As on TCP flows; a dead path that keeps being written to is closed by
    // the relay's rule for flows without answers instead.
    let mut alive = Keepalive::new();
    alive.wrote();
    let idle = tokio::time::sleep_until(alive.deadline(KEEPALIVE));
    tokio::pin!(idle);
    loop {
        tokio::select! {
            payload = queue.recv() => {
                let Some(payload) = payload else { break };
                let mut out = Vec::with_capacity(payload.len() + 2);
                packet(&payload, &mut out);
                put(&mut write, ws::BINARY, &out).await?;
                alive.wrote();
                idle.as_mut().reset(alive.deadline(KEEPALIVE));
            }
            event = frames.next() => {
                match event? {
                    None | Some(Event::Close) => {
                        if !*heard {
                            session.outcome(Reported::Udp(source, destination), false);
                        }
                        break;
                    }
                    Some(Event::Ping(payload)) => put(&mut write, ws::PONG, &payload).await?,
                    Some(Event::Pong) => {}
                    Some(Event::Data(mut data)) => {
                        if !*heard {
                            *heard = true;
                            session.outcome(Reported::Udp(source, destination), true);
                        }
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
                            let payload = pending.split_to(len);
                            if len > VLESS_UDP_MAX {
                                OVERSIZE.fetch_add(1, Ordering::Relaxed);
                                continue;
                            }
                            let _ = back.try_send(Datagram { source: destination, destination: source, payload: payload.to_vec() });
                        }
                    }
                }
                alive.heard();
                idle.as_mut().reset(alive.deadline(KEEPALIVE));
            }
            _ = &mut idle => {
                let deadline = alive.deadline(KEEPALIVE);
                if tokio::time::Instant::now() < deadline {
                    idle.as_mut().reset(deadline);
                } else if alive.ping.is_some() {
                    // No answer to the ping: close; the next datagram opens a new flow.
                    return Err(Error::Timeout);
                } else {
                    put(&mut write, ws::PING, &[]).await?;
                    alive.ping = Some(tokio::time::Instant::now());
                    idle.as_mut().reset(alive.deadline(KEEPALIVE));
                }
            }
        }
    }
    let _ = put(&mut write, ws::CLOSE, &[]).await;
    Ok(())
}
