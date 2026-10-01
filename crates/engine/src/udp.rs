//! TrustTunnel _udp2 framing, not QUIC datagrams. No allocation before length validation.
use crate::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};
pub const MAX_DATAGRAM: usize = 65_507;
#[derive(Debug, PartialEq)]
pub struct Datagram {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
}
fn ip_bytes(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v) => v.octets(),
        IpAddr::V4(v) => {
            let mut b = [0; 16];
            b[12..].copy_from_slice(&v.octets());
            b
        }
    }
}
fn ip(b: [u8; 16]) -> IpAddr {
    if b[..12] == [0; 12] && b != Ipv6Addr::LOCALHOST.octets() {
        Ipv4Addr::new(b[12], b[13], b[14], b[15]).into()
    } else {
        Ipv6Addr::from(b).into()
    }
}
pub fn encode(d: &Datagram, app: &str) -> Result<Vec<u8>> {
    if d.payload.len() > MAX_DATAGRAM || app.len() > 255 {
        return Err(Error::Protocol);
    }
    let mut b = Vec::with_capacity(41 + app.len() + d.payload.len());
    b.extend_from_slice(&((37 + app.len() + d.payload.len()) as u32).to_be_bytes());
    b.extend_from_slice(&ip_bytes(d.source.ip()));
    b.extend_from_slice(&d.source.port().to_be_bytes());
    b.extend_from_slice(&ip_bytes(d.destination.ip()));
    b.extend_from_slice(&d.destination.port().to_be_bytes());
    b.push(app.len() as u8);
    b.extend_from_slice(app.as_bytes());
    b.extend_from_slice(&d.payload);
    Ok(b)
}
pub async fn read<R: AsyncRead + Unpin>(stream: &mut R) -> Result<Datagram> {
    let len = stream.read_u32().await? as usize;
    if !(36..=36 + MAX_DATAGRAM).contains(&len) {
        return Err(Error::Protocol);
    }
    let mut src = [0; 16];
    stream.read_exact(&mut src).await?;
    let src_port = stream.read_u16().await?;
    let mut dst = [0; 16];
    stream.read_exact(&mut dst).await?;
    let dst_port = stream.read_u16().await?;
    let mut payload = vec![0; len - 36];
    stream.read_exact(&mut payload).await?;
    Ok(Datagram {
        source: SocketAddr::new(ip(src), src_port),
        destination: SocketAddr::new(ip(dst), dst_port),
        payload,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn packet_matches_wire_layout_and_handles_fragmented_input() {
        let d = Datagram {
            source: "10.0.0.2:1024".parse().unwrap(),
            destination: "[::1]:53".parse().unwrap(),
            payload: b"DNS".to_vec(),
        };
        let encoded = encode(&d, "").unwrap();
        assert_eq!(encoded[40], 0);
        let mut incoming = encoded;
        incoming.remove(40);
        incoming[..4].copy_from_slice(&39u32.to_be_bytes());
        assert_eq!(read(&mut incoming.as_slice()).await.unwrap(), d);
    }
    #[tokio::test]
    async fn oversized_frame_rejected_before_allocation() {
        assert!(read(&mut u32::MAX.to_be_bytes().as_slice()).await.is_err());
    }
}
