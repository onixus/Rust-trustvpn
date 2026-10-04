//! Gecko obfuscation (Hysteria 2.9.2+): QUIC long-header packets are split
//! into 2-8 randomly padded fragments on top of Salamander; short-header
//! packets pass through. Wire format follows upstream `extras/obfs/gecko*.go`.
use super::super::*;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::{HashMap, VecDeque},
    io::{self, IoSliceMut},
    net::SocketAddr,
    sync::Mutex,
    time::Instant,
};
const FRAGMENT: u8 = 0x80;
const HEADER: usize = 5;
const SALT: usize = 8;
const MIN_CHUNKS: usize = 2;
const MAX_CHUNKS: usize = 8;
const TTL: Duration = Duration::from_secs(8);
const MAX_PENDING: usize = 4096;
const MAX_PER_SOURCE: usize = 8;
/// Largest datagram upstream reads; also bounds a reassembled packet.
const BUFFER: usize = 2048;
pub struct Gecko {
    /// The Salamander layer keyed with the same password.
    pub inner: Arc<dyn AsyncUdpSocket>,
    pub min: usize,
    pub max: usize,
    pub state: Mutex<State>,
}
#[derive(Default)]
pub struct State {
    message: u8,
    partial: HashMap<(SocketAddr, u8), Partial>,
    ready: VecDeque<(RecvMeta, Vec<u8>)>,
    scratch: Vec<Vec<u8>>,
}
struct Partial {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    deadline: Instant,
}
impl std::fmt::Debug for Gecko {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Gecko([REDACTED])")
    }
}
impl Gecko {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Padding that puts the whole UDP datagram in `[min, max]` when possible.
    fn padding(&self, chunk: usize) -> usize {
        let base = SALT + HEADER + chunk;
        let low = self.min.max(base);
        if low > self.max {
            0
        } else {
            low - base + rand::random_range(0..=self.max - low)
        }
    }
    fn frames(&self, packet: &[u8]) -> Vec<Vec<u8>> {
        let count = rand::random_range(MIN_CHUNKS..=MAX_CHUNKS);
        let size = packet.len() / count;
        let message = {
            let mut state = self.state();
            state.message = state.message.wrapping_add(1);
            state.message
        };
        (0..count)
            .map(|index| {
                let start = index * size;
                let end = if index + 1 == count {
                    packet.len()
                } else {
                    start + size
                };
                let chunk = &packet[start..end];
                let pad = self.padding(chunk.len());
                let mut frame = Vec::with_capacity(HEADER + pad + chunk.len());
                frame.extend_from_slice(&[FRAGMENT, message, (index as u8) << 4 | count as u8]);
                frame.extend_from_slice(&(pad as u16).to_be_bytes());
                frame.extend((0..pad).map(|_| rand::random::<u8>()));
                frame.extend_from_slice(chunk);
                frame
            })
            .collect()
    }
}
impl State {
    /// Adds one fragment; returns the packet once all fragments arrived.
    fn accept(&mut self, from: SocketAddr, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        if frame.len() < HEADER || frame[0] & FRAGMENT == 0 {
            return None;
        }
        let (message, index, total) =
            (frame[1], (frame[2] >> 4) as usize, (frame[2] & 15) as usize);
        let pad = u16::from_be_bytes([frame[3], frame[4]]) as usize;
        if !(MIN_CHUNKS..=MAX_CHUNKS).contains(&total)
            || index >= total
            || HEADER + pad > frame.len()
        {
            return None;
        }
        self.partial.retain(|_, p| p.deadline > now);
        let key = (from, message);
        if !self.partial.contains_key(&key) {
            if self.partial.keys().filter(|(a, _)| *a == from).count() >= MAX_PER_SOURCE {
                return None;
            }
            if self.partial.len() >= MAX_PENDING {
                let oldest = self
                    .partial
                    .iter()
                    .min_by_key(|(_, p)| p.deadline)
                    .map(|(k, _)| *k)?;
                self.partial.remove(&oldest);
            }
            self.partial.insert(
                key,
                Partial {
                    chunks: vec![None; total],
                    received: 0,
                    deadline: now + TTL,
                },
            );
        }
        let partial = self.partial.get_mut(&key)?;
        if partial.chunks.len() != total || partial.chunks[index].is_some() {
            return None;
        }
        partial.chunks[index] = Some(frame[HEADER + pad..].to_vec());
        partial.received += 1;
        if partial.received < total {
            return None;
        }
        let partial = self.partial.remove(&key)?;
        let packet: Vec<u8> = partial.chunks.into_iter().flatten().flatten().collect();
        (packet.len() <= BUFFER).then_some(packet)
    }
}
impl AsyncUdpSocket for Gecko {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        if t.segment_size.is_some() {
            return Err(io::Error::other("Obfuscated GSO not supported"));
        }
        if t.contents.first().is_none_or(|b| b & 0x80 == 0) {
            return self.inner.try_send(t);
        }
        // A partly sent message is abandoned: the retransmission gets a new ID
        // and the peer expires the incomplete one.
        for frame in self.frames(t.contents) {
            self.inner.try_send(&Transmit {
                destination: t.destination,
                ecn: t.ecn,
                contents: &frame,
                segment_size: None,
                src_ip: t.src_ip,
            })?;
        }
        Ok(())
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut state = self.state();
        loop {
            // Deliver one datagram per caller buffer; no GRO on the output.
            if !state.ready.is_empty() {
                let mut count = 0;
                while count < bufs.len().min(meta.len()) {
                    let Some((m, packet)) = state.ready.pop_front() else {
                        break;
                    };
                    if packet.len() > bufs[count].len() {
                        continue;
                    }
                    bufs[count][..packet.len()].copy_from_slice(&packet);
                    meta[count] = RecvMeta {
                        len: packet.len(),
                        stride: packet.len(),
                        ..m
                    };
                    count += 1;
                }
                if count > 0 {
                    return Poll::Ready(Ok(count));
                }
            }
            // Quinn sizes its buffers for GRO batches already.
            let size = bufs.first().map_or(BUFFER, |b| b.len()).max(BUFFER);
            let slots = bufs.len().max(1);
            let mut scratch = std::mem::take(&mut state.scratch);
            scratch.resize_with(slots, Vec::new);
            for buffer in &mut scratch {
                buffer.resize(size, 0);
            }
            let mut received = vec![RecvMeta::default(); slots];
            let result = {
                let mut slices: Vec<_> = scratch.iter_mut().map(|b| IoSliceMut::new(b)).collect();
                self.inner.poll_recv(cx, &mut slices, &mut received)
            };
            let count = match result {
                Poll::Ready(Ok(count)) => count,
                other => {
                    state.scratch = scratch;
                    return other;
                }
            };
            let now = Instant::now();
            for (buffer, m) in scratch.iter().zip(&received).take(count) {
                let stride = m.stride.max(1);
                for offset in (0..m.len).step_by(stride) {
                    let datagram = &buffer[offset..(offset + stride).min(m.len)];
                    let packet = match datagram.first() {
                        None => continue,
                        Some(b) if b & FRAGMENT == 0 => Some(datagram.to_vec()),
                        Some(_) => state.accept(m.addr, datagram, now),
                    };
                    if let Some(packet) = packet {
                        state.ready.push_back((*m, packet));
                    }
                }
            }
            state.scratch = scratch;
        }
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn gecko() -> Gecko {
        Gecko {
            inner: Arc::new(Unused),
            min: 512,
            max: 1200,
            state: Default::default(),
        }
    }
    #[derive(Debug)]
    struct Unused;
    impl AsyncUdpSocket for Unused {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unimplemented!()
        }
        fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
            unimplemented!()
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            unimplemented!()
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            unimplemented!()
        }
    }
    #[test]
    fn fragments_are_padded_and_reassemble_in_any_order() {
        let g = gecko();
        let packet: Vec<u8> = (0..1200).map(|n| (n % 251) as u8 | 0x80).collect();
        let from: SocketAddr = "192.0.2.1:443".parse().unwrap();
        for _ in 0..50 {
            let mut frames = g.frames(&packet);
            assert!((MIN_CHUNKS..=MAX_CHUNKS).contains(&frames.len()));
            for frame in &frames {
                assert_eq!(frame[0], FRAGMENT);
                assert_eq!((frame[2] & 15) as usize, frames.len());
                let wire = SALT + frame.len();
                assert!((512..=1200).contains(&wire) || wire > 1200 && frame[3..5] == [0, 0]);
            }
            frames.reverse();
            let mut state = State::default();
            let now = Instant::now();
            let last = frames.pop().unwrap();
            for frame in &frames {
                assert!(state.accept(from, frame, now).is_none());
            }
            // Duplicates and foreign sources do not complete the message.
            assert!(state.accept(from, &frames[0], now).is_none());
            assert!(
                state
                    .accept("192.0.2.2:443".parse().unwrap(), &last, now)
                    .is_none()
            );
            assert_eq!(state.accept(from, &last, now).unwrap(), packet);
            assert!(state.partial.keys().all(|(a, _)| *a != from));
        }
    }
    #[test]
    fn malformed_expired_and_excess_fragments_are_dropped() {
        let g = gecko();
        let from: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let now = Instant::now();
        let mut state = State::default();
        for bad in [
            &[0x80, 1, 0x01, 0, 0][..],
            &[0x80, 1, 0x22, 0, 0],
            &[0x80, 1, 0x02, 0, 9, 1],
        ] {
            assert!(state.accept(from, bad, now).is_none());
        }
        assert!(state.partial.is_empty());
        let frames = g.frames(&[0xc0; 600]);
        state.accept(from, &frames[0], now);
        assert!(
            state
                .accept(from, &frames[1..].concat(), now + TTL)
                .is_none()
        );
        assert!(state.partial.is_empty() || state.partial.values().all(|p| p.received == 1));
        for message in 0..20u8 {
            state.accept(from, &[0x80, message, 0x02, 0, 0, 1], now);
        }
        assert_eq!(
            state.partial.keys().filter(|(a, _)| *a == from).count(),
            MAX_PER_SOURCE
        );
    }
}
