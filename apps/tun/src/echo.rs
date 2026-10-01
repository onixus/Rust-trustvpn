//! Echo correlation and packet construction; only authenticated remote replies produce packets.
use crate::packet::{finish, sum, word};
use rtrust_engine::icmp;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::{Duration, Instant},
};
#[derive(Debug)]
pub struct Echo {
    pub source: IpAddr,
    pub destination: IpAddr,
    pub id: u16,
    pub sequence: u16,
    pub ttl: u8,
    pub original: Vec<u8>,
}
impl Echo {
    pub fn parse(b: &[u8]) -> Option<Self> {
        let (source, destination, offset, ttl) = match b.first().map(|v| v >> 4) {
            Some(4)
                if b.len() >= 28
                    && b[9] == 1
                    && b[20] == 8
                    && b[21] == 0
                    && finish(sum(&b[20..])) == 0 =>
            {
                (
                    IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])),
                    IpAddr::V4(Ipv4Addr::new(b[16], b[17], b[18], b[19])),
                    20,
                    b[8],
                )
            }
            Some(6)
                if b.len() >= 48
                    && b[6] == 58
                    && b[40] == 128
                    && b[41] == 0
                    && crate::ipv6::checksum(b) == 0 =>
            {
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).ok()?)),
                    40,
                    b[7],
                )
            }
            _ => return None,
        };
        Some(Self {
            source,
            destination,
            id: word(b, offset + 4),
            sequence: word(b, offset + 6),
            ttl,
            original: b.to_vec(),
        })
    }
    pub fn reply(&self, r: &icmp::Reply) -> Option<Vec<u8>> {
        let source = r.source;
        let v6 = self.source.is_ipv6();
        let offset = if v6 { 40 } else { 20 };
        if source.is_ipv6() != v6
            || source.is_unspecified()
            || source.is_multicast()
            || matches!(source,IpAddr::V4(ip) if ip.is_broadcast())
        {
            return None;
        }
        let payload = match (v6, r.kind, r.code) {
            (false, 0, 0) | (true, 129, 0) if source == self.destination => {
                let mut p = self.original[offset..].to_vec();
                p[0] = r.kind;
                p
            }
            (false, 3, 0..=3 | 5..=15)
            | (false, 11, 0..=1)
            | (true, 1, 0..=7)
            | (true, 3, 0..=1) => {
                let mut p = vec![r.kind, r.code, 0, 0, 0, 0, 0, 0];
                let len = if v6 {
                    self.original.len().min(1232)
                } else {
                    28
                };
                p.extend_from_slice(&self.original[..len]);
                p
            }
            _ => return None,
        };
        let mut b = vec![0; offset];
        b.extend_from_slice(&payload);
        b[offset + 2..offset + 4].fill(0);
        match (source, self.source) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                b[0] = 0x45;
                let len = b.len() as u16;
                b[2..4].copy_from_slice(&len.to_be_bytes());
                b[8] = 64;
                b[9] = 1;
                b[12..16].copy_from_slice(&src.octets());
                b[16..20].copy_from_slice(&dst.octets());
                let c = finish(sum(&b[20..]));
                b[22..24].copy_from_slice(&c.to_be_bytes());
                let c = finish(sum(&b[..20]));
                b[10..12].copy_from_slice(&c.to_be_bytes());
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                b[0] = 0x60;
                let len = (b.len() - 40) as u16;
                b[4..6].copy_from_slice(&len.to_be_bytes());
                b[6] = 58;
                b[7] = 64;
                b[8..24].copy_from_slice(&src.octets());
                b[24..40].copy_from_slice(&dst.octets());
                let c = crate::ipv6::checksum(&b);
                b[42..44].copy_from_slice(&c.to_be_bytes());
            }
            _ => return None,
        }
        Some(b)
    }
}
#[derive(Default)]
pub struct Pending {
    entries: HashMap<(u16, u16), (Instant, Echo)>,
    next: u16,
}
impl Pending {
    pub fn insert(&mut self, echo: Echo) -> Option<[u8; 23]> {
        self.entries
            .retain(|_, (time, _)| time.elapsed() < Duration::from_secs(10));
        if self.entries.len() >= 256 {
            return None;
        }
        while self.entries.keys().any(|(id, _)| *id == self.next) {
            self.next = self.next.wrapping_add(1);
        }
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let frame = icmp::request(
            id,
            echo.destination,
            echo.sequence,
            echo.ttl,
            (echo.original.len() - if echo.source.is_ipv6() { 48 } else { 28 }) as u16,
        );
        self.entries
            .insert((id, echo.sequence), (Instant::now(), echo));
        Some(frame)
    }
    pub fn reply(&mut self, r: icmp::Reply) -> Option<Vec<u8>> {
        let (time, echo) = self.entries.get(&(r.id, r.sequence))?;
        if time.elapsed() >= Duration::from_secs(10) {
            self.entries.remove(&(r.id, r.sequence));
            return None;
        }
        let packet = echo.reply(&r)?;
        self.entries.remove(&(r.id, r.sequence));
        Some(packet)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_echo_reply_checksum_and_payload() {
        let d = rtrust_engine::udp::Datagram {
            source: "[fd00:5254::2]:1".parse().unwrap(),
            destination: "[2001:db8::1]:2".parse().unwrap(),
            payload: vec![0x37; 5000],
        };
        let mut b = crate::ipv6::udp_packet(&d).unwrap();
        b[6] = 58;
        b[40..48].copy_from_slice(&[128, 0, 0, 0, 0x12, 0x34, 0, 7]);
        let c = crate::ipv6::checksum(&b);
        b[42..44].copy_from_slice(&c.to_be_bytes());
        let echo = Echo::parse(&b).unwrap();
        let mut pending = Pending::default();
        let req = pending.insert(echo).unwrap();
        let reply = pending
            .reply(icmp::Reply {
                id: word(&req, 0),
                source: d.destination.ip(),
                kind: 129,
                code: 0,
                sequence: 7,
            })
            .unwrap();
        assert_eq!(crate::ipv6::checksum(&reply), 0);
        assert_eq!(reply[40], 129);
        assert_eq!(&reply[44..], &b[44..]);
    }
    #[test]
    fn only_matching_remote_echo_restores_original_payload_and_id() {
        let mut b = vec![0; 36];
        b[0] = 0x45;
        b[2..4].copy_from_slice(&36u16.to_be_bytes());
        b[8] = 37;
        b[9] = 1;
        b[12..16].copy_from_slice(&[10, 77, 0, 2]);
        b[16..20].copy_from_slice(&[192, 0, 2, 1]);
        b[20] = 8;
        b[24..28].copy_from_slice(&[1, 2, 0, 9]);
        b[28..].fill(0xaa);
        let c = finish(sum(&b[20..]));
        b[22..24].copy_from_slice(&c.to_be_bytes());
        let c = finish(sum(&b[..20]));
        b[10..12].copy_from_slice(&c.to_be_bytes());
        let echo = Echo::parse(&b).unwrap();
        let mut pending = Pending::default();
        let frame = pending.insert(echo).unwrap();
        let id = word(&frame, 0);
        assert!(
            pending
                .reply(icmp::Reply {
                    id,
                    source: "192.0.2.2".parse().unwrap(),
                    kind: 0,
                    code: 0,
                    sequence: 9
                })
                .is_none()
        );
        let out = pending
            .reply(icmp::Reply {
                id,
                source: "192.0.2.1".parse().unwrap(),
                kind: 0,
                code: 0,
                sequence: 9,
            })
            .unwrap();
        assert_eq!(&out[24..], &b[24..]);
        assert_eq!(out[20], 0);
        assert_eq!(finish(sum(&out[20..])), 0);
        assert!(
            pending
                .reply(icmp::Reply {
                    id,
                    source: "192.0.2.1".parse().unwrap(),
                    kind: 0,
                    code: 0,
                    sequence: 9
                })
                .is_none()
        );
    }
}
