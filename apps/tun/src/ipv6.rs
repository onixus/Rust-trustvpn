//! Bounded IPv6 TCP/UDP path. Extension headers are rejected until normalized.
use crate::packet::{MAX_PACKET, Packet, finish, sum, word};
use rtrust_engine::udp::Datagram;
use std::net::{Ipv6Addr, SocketAddr};
pub const ADDRESS: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x5254, 0, 0, 0, 0, 0, 2);
pub(crate) fn checksum(b: &[u8]) -> u16 {
    finish(sum(&b[8..40]) + (b.len() - 40) as u32 + u32::from(b[6]) + sum(&b[40..]))
}
pub fn parse(b: &[u8]) -> Option<Packet> {
    if b.len() < 48
        || b.len() > MAX_PACKET
        || b[0] >> 4 != 6
        || usize::from(word(b, 4)) + 40 != b.len()
        || b[7] == 0
    {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&b[24..40]).ok()?);
    if source.is_unspecified()
        || source.is_multicast()
        || destination.is_unspecified()
        || destination.is_multicast()
    {
        return None;
    }
    if b[6] == 58 {
        return crate::echo::Echo::parse(b).map(Packet::Icmp);
    }
    let p = &b[40..];
    let key = (
        SocketAddr::new(source.into(), word(p, 0)),
        SocketAddr::new(destination.into(), word(p, 2)),
    );
    if key.0.port() == 0 || key.1.port() == 0 || checksum(b) != 0 {
        return None;
    }
    match b[6] {
        6 if p.len() >= 20
            && usize::from(p[12] >> 4) * 4 >= 20
            && usize::from(p[12] >> 4) * 4 <= p.len() =>
        {
            Some(Packet::Tcp {
                key,
                syn: p[13] & 0x17 == 2,
            })
        }
        17 if usize::from(word(p, 4)) == p.len() && word(p, 6) != 0 => {
            Some(Packet::Udp(Datagram {
                source: key.0,
                destination: key.1,
                payload: p[8..].to_vec(),
            }))
        }
        _ => None,
    }
}
pub fn udp_packet(d: &Datagram) -> Option<Vec<u8>> {
    let (SocketAddr::V6(src), SocketAddr::V6(dst)) = (d.source, d.destination) else {
        return None;
    };
    let len = 48 + d.payload.len();
    if len > MAX_PACKET {
        return None;
    }
    let mut b = vec![0; len];
    b[0] = 0x60;
    b[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    b[6] = 17;
    b[7] = 64;
    b[8..24].copy_from_slice(&src.ip().octets());
    b[24..40].copy_from_slice(&dst.ip().octets());
    b[40..42].copy_from_slice(&src.port().to_be_bytes());
    b[42..44].copy_from_slice(&dst.port().to_be_bytes());
    b[44..46].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    b[48..].copy_from_slice(&d.payload);
    let c = checksum(&b);
    b[46..48].copy_from_slice(&(if c == 0 { u16::MAX } else { c }).to_be_bytes());
    Some(b)
}
/// Local refusal for an IPv6 packet when the endpoint has no IPv6 egress.
/// TCP gets a RST, so the application sees "connection refused" and falls back
/// to IPv4 instead of a reset after a locally completed handshake. UDP and echo
/// requests get ICMPv6 "administratively prohibited". ICMPv6 errors and RSTs are
/// never answered. The input must already have passed `parse`.
pub fn refuse(b: &[u8]) -> Option<Vec<u8>> {
    let (source, destination) = (&b[8..24], &b[24..40]);
    let p = &b[40..];
    let mut r = match b[6] {
        6 => {
            let flags = p[13];
            if flags & 0x04 != 0 {
                return None;
            }
            let mut t = vec![0; 60];
            t[40..42].copy_from_slice(&p[2..4]);
            t[42..44].copy_from_slice(&p[0..2]);
            if flags & 0x10 != 0 {
                // RFC 9293 3.10.7.1: <SEQ=SEG.ACK><CTL=RST>
                t[44..48].copy_from_slice(&p[8..12]);
                t[53] = 0x04;
            } else {
                let data = p.len() - usize::from(p[12] >> 4) * 4;
                let length =
                    data as u32 + u32::from(flags & 0x02 != 0) + u32::from(flags & 0x01 != 0);
                let ack = u32::from_be_bytes(p[4..8].try_into().unwrap()).wrapping_add(length);
                t[48..52].copy_from_slice(&ack.to_be_bytes());
                t[53] = 0x14;
            }
            t[52] = 5 << 4;
            t[6] = 6;
            t
        }
        17 | 58 => {
            if b[6] == 58 && p[0] != 128 {
                return None;
            }
            // RFC 4443: the error carries as much of the packet as fits in 1280 bytes.
            let quoted = b.len().min(1280 - 48);
            let mut t = vec![0; 48 + quoted];
            t[40] = 1;
            t[41] = 1;
            t[48..].copy_from_slice(&b[..quoted]);
            t[6] = 58;
            t
        }
        _ => return None,
    };
    r[0] = 0x60;
    let length = (r.len() - 40) as u16;
    r[4..6].copy_from_slice(&length.to_be_bytes());
    r[7] = 64;
    r[8..24].copy_from_slice(destination);
    r[24..40].copy_from_slice(source);
    let offset = if r[6] == 6 { 56 } else { 42 };
    let c = checksum(&r);
    r[offset..offset + 2].copy_from_slice(&c.to_be_bytes());
    Some(r)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn tcp(flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 60 + payload.len()];
        b[0] = 0x60;
        b[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        b[6] = 6;
        b[7] = 64;
        b[8..24].copy_from_slice(&ADDRESS.octets());
        b[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        b[40..42].copy_from_slice(&50000u16.to_be_bytes());
        b[42..44].copy_from_slice(&443u16.to_be_bytes());
        b[44..48].copy_from_slice(&1000u32.to_be_bytes());
        b[48..52].copy_from_slice(&7000u32.to_be_bytes());
        b[52] = 5 << 4;
        b[53] = flags;
        b[60..].copy_from_slice(payload);
        let c = checksum(&b);
        b[56..58].copy_from_slice(&c.to_be_bytes());
        assert!(parse(&b).is_some());
        b
    }
    fn reset(b: &[u8]) -> (Key, u32, u32, u8) {
        let r = refuse(b).unwrap();
        let Some(Packet::Tcp { key, syn: false }) = parse(&r) else {
            panic!()
        };
        let word32 = |o: usize| u32::from_be_bytes(r[o..o + 4].try_into().unwrap());
        (key, word32(44), word32(48), r[53])
    }
    use crate::packet::Key;
    #[test]
    fn syn_is_refused_with_valid_rst_ack() {
        let (key, seq, ack, flags) = reset(&tcp(0x02, &[]));
        assert_eq!(
            key,
            (
                "[2001:db8::1]:443".parse().unwrap(),
                SocketAddr::new(ADDRESS.into(), 50000)
            )
        );
        assert_eq!((seq, ack, flags), (0, 1001, 0x14));
    }
    #[test]
    fn acked_segment_gets_plain_rst_and_rst_is_never_answered() {
        let (_, seq, ack, flags) = reset(&tcp(0x18, b"hello"));
        assert_eq!((seq, ack, flags), (7000, 0, 0x04));
        assert!(refuse(&tcp(0x04, &[])).is_none());
        assert!(refuse(&tcp(0x14, &[])).is_none());
    }
    #[test]
    fn udp_gets_bounded_icmpv6_prohibited() {
        let d = Datagram {
            source: SocketAddr::new(ADDRESS.into(), 5353),
            destination: "[2001:db8::1]:443".parse().unwrap(),
            payload: vec![7; 3000],
        };
        let b = udp_packet(&d).unwrap();
        let r = refuse(&b).unwrap();
        assert_eq!(r.len(), 1280);
        assert_eq!((r[6], r[40], r[41]), (58, 1, 1));
        assert_eq!(checksum(&r), 0);
        assert_eq!(&r[8..24], &b[24..40]);
        assert_eq!(&r[24..40], &b[8..24]);
        assert_eq!(&r[48..], &b[..1232]);
        // ICMPv6 errors are not answered.
        assert!(refuse(&r).is_none());
    }
    #[test]
    fn udp_ipv6_checksum_lengths_and_addresses() {
        let d = Datagram {
            source: "[fd00:5254::2]:1234".parse().unwrap(),
            destination: "[2001:db8::1]:53".parse().unwrap(),
            payload: vec![0xac; 1500],
        };
        let b = udp_packet(&d).unwrap();
        let Packet::Udp(actual) = parse(&b).unwrap() else {
            panic!()
        };
        assert_eq!(actual, d);
        for n in 0..b.len() {
            assert!(parse(&b[..n]).is_none());
        }
        let mut bad = b.clone();
        bad[46..48].fill(0);
        assert!(parse(&bad).is_none());
        let mut bad = b.clone();
        bad[55] ^= 1;
        assert!(parse(&bad).is_none());
        let mut bad = b;
        bad[6] = 0;
        assert!(parse(&bad).is_none());
    }
}
