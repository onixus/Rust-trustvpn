use rtrust_engine::udp::Datagram;
use std::net::{Ipv4Addr, SocketAddr};

pub const MTU: usize = 1500;
pub const MAX_PACKET: usize = 65535;
pub type Key = (SocketAddr, SocketAddr);

#[derive(Debug)]
pub enum Packet {
    Tcp { key: Key, syn: bool },
    Udp(Datagram),
    Icmp(crate::echo::Echo),
}

pub(crate) fn word(b: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([b[offset], b[offset + 1]])
}

pub(crate) fn sum(bytes: &[u8]) -> u32 {
    bytes
        .chunks(2)
        .map(|b| u32::from(b[0]) * 256 + u32::from(*b.get(1).unwrap_or(&0)))
        .sum()
}

pub(crate) fn finish(mut n: u32) -> u16 {
    while n >> 16 != 0 {
        n = (n & 65535) + (n >> 16);
    }
    !(n as u16)
}

fn transport_sum(ip: &[u8], payload: &[u8]) -> u32 {
    sum(&ip[12..20]) + u32::from(ip[9]) + payload.len() as u32 + sum(payload)
}

/// Reject unsupported IP options, unassembled fragments and IPv6 before allocating flows.
/// This deliberately does not manufacture successful ICMP echo replies.
pub fn parse(bytes: &[u8]) -> Option<Packet> {
    if bytes.first().is_some_and(|b| b >> 4 == 6) {
        return crate::ipv6::parse(bytes);
    }
    if bytes.len() < 28
        || bytes.len() > MAX_PACKET
        || bytes[0] != 0x45
        || usize::from(word(bytes, 2)) != bytes.len()
        || word(bytes, 6) & 0xbfff != 0
        || bytes[8] == 0
        || finish(sum(&bytes[..20])) != 0
    {
        return None;
    }
    let source = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
    let destination = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
    if source.is_unspecified()
        || source.is_multicast()
        || source.is_broadcast()
        || destination.is_unspecified()
        || destination.is_multicast()
        || destination.is_broadcast()
    {
        return None;
    }
    if bytes[9] == 1 {
        return crate::echo::Echo::parse(bytes).map(Packet::Icmp);
    }
    let payload = &bytes[20..];
    let key = (
        SocketAddr::new(source.into(), word(payload, 0)),
        SocketAddr::new(destination.into(), word(payload, 2)),
    );
    if key.0.port() == 0 || key.1.port() == 0 {
        return None;
    }
    match bytes[9] {
        6 if payload.len() >= 20
            && usize::from(payload[12] >> 4) * 4 >= 20
            && usize::from(payload[12] >> 4) * 4 <= payload.len()
            && finish(transport_sum(bytes, payload)) == 0 =>
        {
            Some(Packet::Tcp {
                key,
                syn: payload[13] & 0x17 == 2,
            })
        }
        17 if usize::from(word(payload, 4)) == payload.len()
            && (word(payload, 6) == 0 || finish(transport_sum(bytes, payload)) == 0) =>
        {
            Some(Packet::Udp(Datagram {
                source: key.0,
                destination: key.1,
                payload: payload[8..].to_vec(),
            }))
        }
        _ => None,
    }
}

pub fn udp_packet(d: &Datagram) -> Option<Vec<u8>> {
    if d.source.is_ipv6() {
        return crate::ipv6::udp_packet(d);
    }
    let (SocketAddr::V4(source), SocketAddr::V4(destination)) = (d.source, d.destination) else {
        return None;
    };
    let len = 28 + d.payload.len();
    if len > MAX_PACKET {
        return None;
    }
    let mut b = vec![0; len];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    b[6] = 0x40;
    b[8] = 64;
    b[9] = 17;
    b[12..16].copy_from_slice(&source.ip().octets());
    b[16..20].copy_from_slice(&destination.ip().octets());
    let checksum = finish(sum(&b[..20]));
    b[10..12].copy_from_slice(&checksum.to_be_bytes());
    b[20..22].copy_from_slice(&source.port().to_be_bytes());
    b[22..24].copy_from_slice(&destination.port().to_be_bytes());
    b[24..26].copy_from_slice(&((len - 20) as u16).to_be_bytes());
    b[28..].copy_from_slice(&d.payload);
    let checksum = finish(transport_sum(&b, &b[20..]));
    b[26..28].copy_from_slice(&(if checksum == 0 { 65535 } else { checksum }).to_be_bytes());
    Some(b)
}

#[cfg(test)]
pub(crate) fn test_syn(port: u16) -> Vec<u8> {
    let d = Datagram {
        source: format!("10.77.0.2:{port}").parse().unwrap(),
        destination: "198.18.0.1:80".parse().unwrap(),
        payload: vec![0; 12],
    };
    let mut b = udp_packet(&d).unwrap();
    b[9] = 6;
    b[24..40].fill(0);
    b[32] = 0x50;
    b[33] = 2;
    b[34..36].fill(0xff);
    let checksum = finish(transport_sum(&b, &b[20..]));
    b[36..38].copy_from_slice(&checksum.to_be_bytes());
    b[10..12].fill(0);
    let checksum = finish(sum(&b[..20]));
    b[10..12].copy_from_slice(&checksum.to_be_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn udp_roundtrip_and_malformed_rejection() {
        for size in [0, 1, 1472] {
            let d = Datagram {
                source: "10.77.0.2:4000".parse().unwrap(),
                destination: "198.18.0.1:53".parse().unwrap(),
                payload: vec![0xab; size],
            };
            let packet = udp_packet(&d).unwrap();
            let Packet::Udp(actual) = parse(&packet).unwrap() else {
                panic!()
            };
            assert_eq!(actual.payload, d.payload);
            assert_eq!(actual.source, d.source);
            assert_eq!(actual.destination, d.destination);
            for i in 0..packet.len() {
                assert!(parse(&packet[..i]).is_none());
            }
            let mut corrupt = packet.clone();
            corrupt[22] ^= 1;
            assert!(parse(&corrupt).is_none());
            for flags in [0x20, 0x80, 0x01] {
                let mut fragment = packet.clone();
                fragment[6] = flags;
                fragment[10..12].fill(0);
                let checksum = finish(sum(&fragment[..20]));
                fragment[10..12].copy_from_slice(&checksum.to_be_bytes());
                assert!(parse(&fragment).is_none());
            }
        }
    }
}
