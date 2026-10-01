//! Official TrustTunnel fixed-size _icmp frames. Echo data is kept by the client.
use crate::Result;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};
#[derive(Debug, PartialEq)]
pub struct Reply {
    pub id: u16,
    pub source: IpAddr,
    pub kind: u8,
    pub code: u8,
    pub sequence: u16,
}
pub fn request(id: u16, destination: IpAddr, sequence: u16, ttl: u8, size: u16) -> [u8; 23] {
    let mut b = [0; 23];
    b[..2].copy_from_slice(&id.to_be_bytes());
    match destination {
        IpAddr::V4(ip) => b[14..18].copy_from_slice(&ip.octets()),
        IpAddr::V6(ip) => b[2..18].copy_from_slice(&ip.octets()),
    }
    b[18..20].copy_from_slice(&sequence.to_be_bytes());
    b[20] = ttl;
    b[21..].copy_from_slice(&size.to_be_bytes());
    b
}
pub async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Reply> {
    let mut b = [0; 22];
    reader.read_exact(&mut b).await?;
    let raw: [u8; 16] = b[2..18].try_into().unwrap();
    let source = if raw[..12] == [0; 12] && raw != Ipv6Addr::LOCALHOST.octets() {
        IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]))
    } else {
        IpAddr::V6(Ipv6Addr::from(raw))
    };
    Ok(Reply {
        id: u16::from_be_bytes([b[0], b[1]]),
        source,
        kind: b[18],
        code: b[19],
        sequence: u16::from_be_bytes([b[20], b[21]]),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn official_fixed_wire_layout_and_truncation() {
        let req = request(0x1234, "192.0.2.1".parse().unwrap(), 0x5678, 31, 1400);
        assert_eq!(&req[..2], &[0x12, 0x34]);
        assert_eq!(&req[2..14], &[0; 12]);
        assert_eq!(&req[14..], &[192, 0, 2, 1, 0x56, 0x78, 31, 5, 120]);
        let mut reply = req[..22].to_vec();
        reply[18] = 0;
        reply[19] = 0;
        reply[20] = 0x56;
        reply[21] = 0x78;
        assert_eq!(
            read(&mut reply.as_slice()).await.unwrap(),
            Reply {
                id: 0x1234,
                source: "192.0.2.1".parse().unwrap(),
                kind: 0,
                code: 0,
                sequence: 0x5678
            }
        );
        for len in 0..22 {
            assert!(read(&mut &reply[..len]).await.is_err());
        }
    }
}
