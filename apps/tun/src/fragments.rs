//! Bounded IPv4/IPv6 reassembly. Overlapping fragments poison that tuple for its lifetime.
use crate::packet::{MAX_PACKET, MTU, finish, sum, word};
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
const LIMIT: usize = 64;
const LIFETIME: Duration = Duration::from_secs(10);
type Key = (Vec<u8>, u32, u8);
struct Entry {
    created: Instant,
    header: Vec<u8>,
    chunks: Vec<(usize, Vec<u8>)>,
    end: Option<usize>,
    poisoned: bool,
}
#[derive(Default)]
pub struct Reassembler {
    entries: HashMap<Key, Entry>,
}
impl Reassembler {
    pub fn push(&mut self, b: &[u8]) -> Option<Vec<u8>> {
        self.at(b, Instant::now())
    }
    fn at(&mut self, b: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.entries
            .retain(|_, e| now.duration_since(e.created) < LIFETIME);
        if b.first().is_some_and(|v| v >> 4 == 6) {
            return self.v6(b, now);
        }
        if b.len() < 20
            || b.len() > MAX_PACKET
            || b[0] != 0x45
            || usize::from(word(b, 2)) != b.len()
            || b[8] == 0
            || finish(sum(&b[..20])) != 0
        {
            return None;
        }
        let flags = word(b, 6);
        if flags & 0xbfff == 0 {
            return Some(b.to_vec());
        }
        if flags & 0xc000 != 0 {
            return None;
        }
        let more = flags & 0x2000 != 0;
        let start = usize::from(flags & 0x1fff) * 8;
        self.collect(
            (b[12..20].to_vec(), u32::from(word(b, 4)), b[9]),
            b[..20].to_vec(),
            start,
            &b[20..],
            more,
            now,
        )
    }
    fn v6(&mut self, b: &[u8], now: Instant) -> Option<Vec<u8>> {
        if b.len() < 48
            || b.len() > MAX_PACKET
            || usize::from(word(b, 4)) + 40 != b.len()
            || b[7] == 0
        {
            return None;
        }
        if b[6] != 44 {
            return Some(b.to_vec());
        }
        if b[41] != 0 || word(b, 42) & 6 != 0 || !matches!(b[40], 6 | 17 | 58) {
            return None;
        }
        let flags = word(b, 42);
        let start = usize::from(flags & 0xfff8);
        let more = flags & 1 != 0;
        let mut header = b[..40].to_vec();
        header[6] = b[40];
        self.collect(
            (
                b[8..40].to_vec(),
                u32::from_be_bytes(b[44..48].try_into().unwrap()),
                b[40],
            ),
            header,
            start,
            &b[48..],
            more,
            now,
        )
    }
    fn collect(
        &mut self,
        key: Key,
        header: Vec<u8>,
        start: usize,
        data: &[u8],
        more: bool,
        now: Instant,
    ) -> Option<Vec<u8>> {
        let end = start + data.len();
        let hlen = header.len();
        if data.is_empty() || end > MAX_PACKET - hlen || (more && !data.len().is_multiple_of(8)) {
            return None;
        }
        if !self.entries.contains_key(&key) && self.entries.len() >= LIMIT {
            return None;
        }
        let e = self.entries.entry(key.clone()).or_insert_with(|| Entry {
            created: now,
            header: header.clone(),
            chunks: vec![],
            end: None,
            poisoned: false,
        });
        if e.poisoned {
            return None;
        }
        if e.chunks
            .iter()
            .any(|(offset, bytes)| start < offset + bytes.len() && end > *offset)
            || e.end
                .is_some_and(|last| end > last || (!more && end != last) || (more && end >= last))
            || (!more
                && e.chunks
                    .iter()
                    .any(|(offset, bytes)| offset + bytes.len() > end))
        {
            e.poisoned = true;
            e.chunks.clear();
            return None;
        }
        // At most 8192 disjoint 8-byte pieces fit one datagram; bound metadata too.
        if e.chunks.len() >= 128 {
            e.poisoned = true;
            e.chunks.clear();
            return None;
        }
        if start == 0 {
            e.header = header;
        }
        if !more {
            e.end = Some(end);
        }
        e.chunks.push((start, data.to_vec()));
        let total = e.end?;
        if e.chunks.iter().map(|(_, v)| v.len()).sum::<usize>() != total {
            return None;
        }
        let e = self.entries.remove(&key).unwrap();
        let mut out = vec![0; hlen + total];
        out[..hlen].copy_from_slice(&e.header);
        if hlen == 20 {
            out[2..4].copy_from_slice(&((20 + total) as u16).to_be_bytes());
            out[6..8].fill(0);
            out[10..12].fill(0);
            let c = finish(sum(&out[..20]));
            out[10..12].copy_from_slice(&c.to_be_bytes());
        } else {
            out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
        }
        for (offset, bytes) in e.chunks {
            out[hlen + offset..hlen + offset + bytes.len()].copy_from_slice(&bytes);
        }
        Some(out)
    }
}
/// Fragment an already validated/generated IPv4 response for the configured TUN MTU.
pub fn split(mut b: Vec<u8>) -> Vec<Vec<u8>> {
    if b.len() <= MTU {
        return vec![b];
    }
    if b.first().is_some_and(|v| v >> 4 == 6) {
        return split6(b);
    }
    if b.len() > MAX_PACKET || b.len() < 20 || b[0] != 0x45 {
        return vec![];
    }
    b[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
    let stride = (MTU - 20) / 8 * 8;
    let total = b.len() - 20;
    b[20..]
        .chunks(stride)
        .enumerate()
        .map(|(index, data)| {
            let mut out = b[..20].to_vec();
            out.extend_from_slice(data);
            let len = out.len() as u16;
            out[2..4].copy_from_slice(&len.to_be_bytes());
            let offset = index * stride;
            let flags = (offset / 8) as u16
                | if offset + data.len() < total {
                    0x2000
                } else {
                    0
                };
            out[6..8].copy_from_slice(&flags.to_be_bytes());
            out[10..12].fill(0);
            let checksum = finish(sum(&out[..20]));
            out[10..12].copy_from_slice(&checksum.to_be_bytes());
            out
        })
        .collect()
}
fn split6(b: Vec<u8>) -> Vec<Vec<u8>> {
    if b.len() < 48 || b.len() > MAX_PACKET {
        return vec![];
    }
    let stride = (MTU - 48) / 8 * 8;
    let id = rand::random::<u32>();
    let total = b.len() - 40;
    b[40..]
        .chunks(stride)
        .enumerate()
        .map(|(i, data)| {
            let mut out = b[..40].to_vec();
            out[6] = 44;
            out[4..6].copy_from_slice(&((8 + data.len()) as u16).to_be_bytes());
            out.extend_from_slice(&[b[6], 0]);
            let flags = (i * stride) as u16 | u16::from(i * stride + data.len() < total);
            out.extend_from_slice(&flags.to_be_bytes());
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(data);
            out
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        crate::packet::udp_packet(&rtrust_engine::udp::Datagram {
            source: "10.0.0.1:1".parse().unwrap(),
            destination: "10.0.0.2:2".parse().unwrap(),
            payload: vec![0x5a; 5000],
        })
        .unwrap()
    }
    #[test]
    fn reorder_loss_overlap_and_expiration() {
        let original = packet();
        let parts = split(original.clone());
        assert!(parts.len() > 1);
        let now = Instant::now();
        let mut r = Reassembler::default();
        for p in parts.iter().rev().take(parts.len() - 1) {
            assert!(r.at(p, now).is_none());
        }
        let result = r.at(&parts[0], now).unwrap();
        let crate::packet::Packet::Udp(d) = crate::packet::parse(&result).unwrap() else {
            panic!()
        };
        assert_eq!(d.payload, vec![0x5a; 5000]);
        assert!(r.at(&parts[0], now).is_none());
        assert!(r.at(&parts[0], now).is_none());
        for p in &parts[1..] {
            assert!(r.at(p, now).is_none());
        }
        let later = now + LIFETIME;
        for p in &parts[..parts.len() - 1] {
            assert!(r.at(p, later).is_none());
        }
        assert!(r.at(parts.last().unwrap(), later).is_some());
    }
    #[test]
    fn ipv6_fragments_reorder_and_overlap_rejection() {
        let d = rtrust_engine::udp::Datagram {
            source: "[fd00:5254::2]:1234".parse().unwrap(),
            destination: "[2001:db8::1]:53".parse().unwrap(),
            payload: vec![0x5a; 60000],
        };
        let original = crate::ipv6::udp_packet(&d).unwrap();
        let parts = split(original.clone());
        assert!(parts.iter().all(|b| b.len() <= MTU));
        let mut r = Reassembler::default();
        let now = Instant::now();
        for part in parts.iter().rev().take(parts.len() - 1) {
            assert!(r.at(part, now).is_none());
        }
        assert_eq!(r.at(&parts[0], now).unwrap(), original);
        assert!(r.at(&parts[0], now).is_none());
        assert!(r.at(&parts[0], now).is_none());
        for part in &parts[1..] {
            assert!(r.at(part, now).is_none());
        }
    }
    #[test]
    fn incomplete_datagrams_and_metadata_are_bounded() {
        let base = split(packet())[0].clone();
        let mut r = Reassembler::default();
        let now = Instant::now();
        for id in 0..1000u16 {
            let mut b = base.clone();
            b[4..6].copy_from_slice(&id.to_be_bytes());
            b[10..12].fill(0);
            let c = finish(sum(&b[..20]));
            b[10..12].copy_from_slice(&c.to_be_bytes());
            assert!(r.at(&b, now).is_none());
        }
        assert_eq!(r.entries.len(), LIMIT);
        r.at(&[], now + LIFETIME);
        assert!(r.entries.is_empty());
    }
}
