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
#[cfg(test)]
mod tests {
    use super::*;
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
