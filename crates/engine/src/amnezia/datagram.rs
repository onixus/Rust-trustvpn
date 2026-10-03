//! UDP over the tunnel's IP layer, with IPv4/IPv6 fragmentation: the outer TUN
//! hands over datagrams of any size, the tunnel carries packets up to its MTU.
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

const UDP: u8 = 17;
const FRAGMENT: u8 = 44;
/// Bounds for peer-controlled reassembly state.
const MAX_DATAGRAMS: usize = 64;
const MAX_BYTES: usize = 2 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 128;
const LIFETIME: Duration = Duration::from_secs(10);

fn sum(mut total: u32, bytes: &[u8]) -> u32 {
    let (pairs, rest) = bytes.as_chunks::<2>();
    for pair in pairs {
        total += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        total += u32::from(*last) << 8;
    }
    total
}
fn finish(mut total: u32) -> u16 {
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}
fn pseudo(source: IpAddr, destination: IpAddr, length: usize) -> u32 {
    let total = match (source, destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => sum(sum(0, &s.octets()), &d.octets()),
        (IpAddr::V6(s), IpAddr::V6(d)) => sum(sum(0, &s.octets()), &d.octets()),
        _ => 0,
    };
    // The length fits 16 bits for every datagram accepted here.
    total + length as u32 + u32::from(UDP)
}

/// IP packets of at most `mtu` bytes carrying one UDP datagram. `id` must
/// differ between datagrams of the same address pair. Empty when the address
/// families differ or the payload exceeds what the IP length field allows.
pub fn packets(
    source: SocketAddr,
    destination: SocketAddr,
    payload: &[u8],
    mtu: usize,
    id: u32,
) -> Vec<Vec<u8>> {
    let length = 8 + payload.len();
    if length > 65_535 - 20 {
        return vec![];
    }
    let mut segment = Vec::with_capacity(length);
    segment.extend(source.port().to_be_bytes());
    segment.extend(destination.port().to_be_bytes());
    segment.extend((length as u16).to_be_bytes());
    segment.extend([0, 0]);
    segment.extend(payload);
    let checksum = match finish(sum(pseudo(source.ip(), destination.ip(), length), &segment)) {
        // Zero means "no checksum" in IPv4 and is forbidden in IPv6.
        0 => 0xffff,
        value => value,
    };
    segment[6..8].copy_from_slice(&checksum.to_be_bytes());
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            let header = |data: &[u8], offset: usize, more: bool| {
                let mut p = Vec::with_capacity(20 + data.len());
                p.extend([0x45, 0]);
                p.extend(((20 + data.len()) as u16).to_be_bytes());
                p.extend((id as u16).to_be_bytes());
                p.extend((((more as u16) << 13) | (offset / 8) as u16).to_be_bytes());
                p.extend([64, UDP, 0, 0]);
                p.extend(from.octets());
                p.extend(to.octets());
                let checksum = finish(sum(0, &p));
                p[10..12].copy_from_slice(&checksum.to_be_bytes());
                p.extend(data);
                p
            };
            let step = (mtu.saturating_sub(20) / 8 * 8).max(8);
            if 20 + length <= mtu {
                vec![header(&segment, 0, false)]
            } else {
                segment
                    .chunks(step)
                    .enumerate()
                    .map(|(i, data)| header(data, i * step, (i + 1) * step < length))
                    .collect()
            }
        }
        (IpAddr::V6(from), IpAddr::V6(to)) => {
            let header = |data: &[u8], fragment: Option<(usize, bool)>| {
                let extension = if fragment.is_some() { 8 } else { 0 };
                let mut p = Vec::with_capacity(40 + extension + data.len());
                p.extend([0x60, 0, 0, 0]);
                p.extend(((extension + data.len()) as u16).to_be_bytes());
                p.extend([if fragment.is_some() { FRAGMENT } else { UDP }, 64]);
                p.extend(from.octets());
                p.extend(to.octets());
                if let Some((offset, more)) = fragment {
                    p.extend([UDP, 0]);
                    p.extend((offset as u16 | more as u16).to_be_bytes());
                    p.extend(id.to_be_bytes());
                }
                p.extend(data);
                p
            };
            let step = (mtu.saturating_sub(48) / 8 * 8).max(8);
            if 40 + length <= mtu {
                vec![header(&segment, None)]
            } else {
                segment
                    .chunks(step)
                    .enumerate()
                    .map(|(i, data)| header(data, Some((i * step, (i + 1) * step < length))))
                    .collect()
            }
        }
        _ => vec![],
    }
}

/// What an incoming IP packet is to the UDP path.
pub enum Incoming {
    /// Not UDP: the TCP/IP stack handles it.
    Other(Vec<u8>),
    /// A complete datagram: source, destination and payload.
    Datagram(SocketAddr, SocketAddr, Vec<u8>),
    /// A fragment was stored, or the packet was invalid.
    Consumed,
}

struct Partial {
    created: Instant,
    parts: BTreeMap<usize, Vec<u8>>,
    /// Known once the last fragment has arrived.
    total: Option<usize>,
    bytes: usize,
}
#[derive(Default)]
pub struct Reassembly {
    partial: HashMap<(IpAddr, IpAddr, u32), Partial>,
    bytes: usize,
}

impl Reassembly {
    pub fn input(&mut self, packet: Vec<u8>, now: Instant) -> Incoming {
        let (source, destination, protocol, start, fragment): (IpAddr, IpAddr, _, _, _) =
            match packet.first().map(|b| b >> 4) {
                Some(4) if packet.len() >= 20 => {
                    let start = usize::from(packet[0] & 15) * 4;
                    let flags = u16::from_be_bytes([packet[6], packet[7]]);
                    let (more, offset) = (flags & 0x2000 != 0, usize::from(flags & 0x1fff) * 8);
                    if start < 20 || start > packet.len() {
                        return Incoming::Consumed;
                    }
                    (
                        Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).into(),
                        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]).into(),
                        packet[9],
                        start,
                        (more || offset != 0).then(|| {
                            let id = u16::from_be_bytes([packet[4], packet[5]]);
                            (u32::from(id), offset, more)
                        }),
                    )
                }
                Some(6) if packet.len() >= 40 => {
                    let address = |at: usize| -> IpAddr {
                        Ipv6Addr::from(<[u8; 16]>::try_from(&packet[at..at + 16]).unwrap()).into()
                    };
                    let (source, destination) = (address(8), address(24));
                    if packet[6] == FRAGMENT {
                        if packet.len() < 48 {
                            return Incoming::Consumed;
                        }
                        let field = u16::from_be_bytes([packet[42], packet[43]]);
                        let id = u32::from_be_bytes(packet[44..48].try_into().unwrap());
                        (
                            source,
                            destination,
                            packet[40],
                            48,
                            Some((id, usize::from(field & !7), field & 1 != 0)),
                        )
                    } else {
                        (source, destination, packet[6], 40, None)
                    }
                }
                _ => return Incoming::Consumed,
            };
        if protocol != UDP {
            // TCP segments fit the MSS; other fragmented protocols are not relayed.
            return if fragment.is_some() {
                Incoming::Consumed
            } else {
                Incoming::Other(packet)
            };
        }
        let segment = match fragment {
            None => packet[start..].to_vec(),
            Some((id, offset, more)) => {
                match self.fragment(
                    (source, destination, id),
                    offset,
                    more,
                    &packet[start..],
                    now,
                ) {
                    Some(segment) => segment,
                    None => return Incoming::Consumed,
                }
            }
        };
        if segment.len() < 8 {
            return Incoming::Consumed;
        }
        let length = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
        if length < 8 || length > segment.len() {
            return Incoming::Consumed;
        }
        let segment = &segment[..length];
        let unchecked = source.is_ipv4() && segment[6..8] == [0, 0];
        if !unchecked && finish(sum(pseudo(source, destination, length), segment)) != 0 {
            return Incoming::Consumed;
        }
        let port = |at: usize| u16::from_be_bytes([segment[at], segment[at + 1]]);
        Incoming::Datagram(
            SocketAddr::new(source, port(0)),
            SocketAddr::new(destination, port(2)),
            segment[8..].to_vec(),
        )
    }
    fn remove(&mut self, key: &(IpAddr, IpAddr, u32)) {
        if let Some(partial) = self.partial.remove(key) {
            self.bytes -= partial.bytes;
        }
    }
    fn fragment(
        &mut self,
        key: (IpAddr, IpAddr, u32),
        offset: usize,
        more: bool,
        data: &[u8],
        now: Instant,
    ) -> Option<Vec<u8>> {
        let expired: Vec<_> = self
            .partial
            .iter()
            .filter(|(_, p)| now.duration_since(p.created) > LIFETIME)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            self.remove(&key);
        }
        // Every fragment but the last carries a multiple of eight bytes.
        if data.is_empty()
            || (more && !data.len().is_multiple_of(8))
            || offset + data.len() > 65_535
        {
            self.remove(&key);
            return None;
        }
        if !self.partial.contains_key(&key) {
            if self.partial.len() >= MAX_DATAGRAMS {
                return None;
            }
            self.partial.insert(
                key,
                Partial {
                    created: now,
                    parts: BTreeMap::new(),
                    total: None,
                    bytes: 0,
                },
            );
        }
        let room = MAX_BYTES - self.bytes;
        let partial = self.partial.get_mut(&key)?;
        let end = offset + data.len();
        // Overlaps and inconsistent lengths discard the datagram (RFC 5722).
        let overlaps = partial
            .parts
            .iter()
            .any(|(at, part)| *at < end && offset < at + part.len());
        let inconsistent = match partial.total {
            Some(total) => end > total || !more,
            None => !more && partial.parts.iter().any(|(at, part)| at + part.len() > end),
        };
        if overlaps || inconsistent || data.len() > room || partial.parts.len() >= MAX_FRAGMENTS {
            self.remove(&key);
            return None;
        }
        if !more {
            partial.total = Some(end);
        }
        partial.parts.insert(offset, data.to_vec());
        partial.bytes += data.len();
        self.bytes += data.len();
        if partial.total != Some(partial.bytes) {
            return None;
        }
        // No overlaps and the sizes add up: the parts are contiguous from zero.
        let partial = self.partial.remove(&key)?;
        self.bytes -= partial.bytes;
        Some(partial.parts.into_values().flatten().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn roundtrip(source: &str, destination: &str, size: usize, mtu: usize) {
        let (source, destination): (SocketAddr, SocketAddr) =
            (source.parse().unwrap(), destination.parse().unwrap());
        let payload: Vec<u8> = (0..size).map(|n| (n * 7) as u8).collect();
        let mut sent = packets(source, destination, &payload, mtu, 0xabcd_1234);
        assert!(sent.iter().all(|p| p.len() <= mtu), "{size}");
        let header = if source.is_ipv4() { 20 } else { 40 };
        assert_eq!(sent.len() > 1, header + 8 + size > mtu);
        // Fragments may arrive in any order.
        sent.reverse();
        let mut reassembly = Reassembly::default();
        let now = Instant::now();
        let count = sent.len();
        for (i, packet) in sent.into_iter().enumerate() {
            match reassembly.input(packet, now) {
                Incoming::Datagram(from, to, data) => {
                    assert_eq!(
                        (i, from, to, data),
                        (count - 1, source, destination, payload)
                    );
                    assert!(reassembly.partial.is_empty() && reassembly.bytes == 0);
                    return;
                }
                Incoming::Consumed => assert!(i < count - 1, "{size}"),
                Incoming::Other(_) => panic!("UDP was not recognised"),
            }
        }
        panic!("datagram of {size} bytes was not delivered");
    }
    #[test]
    fn datagrams_of_every_size_survive_fragmentation() {
        for size in [0, 1, 1232, 1252, 1253, 1400, 1472, 4000, 65_507] {
            roundtrip("10.8.1.2:5000", "192.0.2.1:53", size, 1280);
        }
        for size in [0, 1, 1232, 1233, 1400, 9000, 65_507] {
            roundtrip("[fd00:8::2]:5000", "[2001:db8::1]:53", size, 1280);
        }
        roundtrip("10.8.1.2:5000", "192.0.2.1:53", 3000, 576);
        assert!(
            packets(
                "10.8.1.2:1".parse().unwrap(),
                "[::1]:1".parse().unwrap(),
                b"x",
                1280,
                1
            )
            .is_empty()
        );
    }
    #[test]
    fn ipv4_header_and_udp_checksums_verify() {
        let p = &packets(
            "10.8.1.2:5000".parse().unwrap(),
            "192.0.2.1:53".parse().unwrap(),
            b"query",
            1280,
            7,
        )[0];
        assert_eq!(finish(sum(0, &p[..20])), 0);
        assert_eq!((p[0], p[9], p.len()), (0x45, UDP, 33));
        let mut corrupt = p.clone();
        corrupt[30] ^= 1;
        assert!(matches!(
            Reassembly::default().input(corrupt, Instant::now()),
            Incoming::Consumed
        ));
    }
    #[test]
    fn hostile_fragments_are_bounded_and_discarded() {
        let source: SocketAddr = "192.0.2.1:53".parse().unwrap();
        let destination: SocketAddr = "10.8.1.2:5000".parse().unwrap();
        let now = Instant::now();
        let mut reassembly = Reassembly::default();
        // First fragments only: state stays bounded and expires.
        for id in 0..1000 {
            let first = packets(source, destination, &[1; 3000], 1280, id).remove(0);
            assert!(matches!(reassembly.input(first, now), Incoming::Consumed));
        }
        assert_eq!(reassembly.partial.len(), MAX_DATAGRAMS);
        assert!(reassembly.bytes <= MAX_BYTES);
        let late = now + LIFETIME + Duration::from_secs(1);
        let first = packets(source, destination, &[1; 3000], 1280, 5000).remove(0);
        assert!(matches!(reassembly.input(first, late), Incoming::Consumed));
        assert_eq!((reassembly.partial.len(), reassembly.bytes), (1, 1256));
        // A duplicate (overlapping) fragment discards the datagram.
        let mut reassembly = Reassembly::default();
        let parts = packets(source, destination, &[2; 3000], 1280, 9);
        for packet in [&parts[0], &parts[0], &parts[1], &parts[2]] {
            assert!(matches!(
                reassembly.input(packet.clone(), now),
                Incoming::Consumed
            ));
        }
        // TCP passes through untouched; fragmented non-UDP is dropped.
        let mut tcp = parts[0].clone();
        tcp[9] = 6;
        assert!(matches!(
            reassembly.input(tcp.clone(), now),
            Incoming::Consumed
        ));
        tcp[6..8].copy_from_slice(&[0, 0]);
        assert!(matches!(reassembly.input(tcp, now), Incoming::Other(_)));
        assert!(matches!(
            reassembly.input(vec![0x45; 10], now),
            Incoming::Consumed
        ));
    }
}
