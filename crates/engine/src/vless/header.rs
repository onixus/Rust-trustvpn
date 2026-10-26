//! VLESS request and response headers (protocol version 0, no addons, no flow).
use crate::{Error, Result};
use std::net::IpAddr;
use zeroize::Zeroizing;

pub(super) const TCP: u8 = 1;
pub(super) const UDP: u8 = 2;

/// A destination as VLESS encodes it: port first, then the typed address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Target {
    Ip(IpAddr, u16),
    Domain(String, u16),
}
impl Target {
    /// `host:port`, with IPv6 in brackets, as `Session::open_tcp` receives it.
    pub(super) fn parse(authority: &str) -> Result<Self> {
        let authority: http::uri::Authority = authority.parse().map_err(|_| Error::Destination)?;
        let port = authority
            .port_u16()
            .filter(|p| *p != 0)
            .ok_or(Error::Destination)?;
        let host = authority.host();
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bare.parse::<IpAddr>() {
            return Ok(Self::Ip(ip, port));
        }
        if host.starts_with('[') || host.is_empty() || host.len() > 255 {
            return Err(Error::Destination);
        }
        Ok(Self::Domain(host.to_owned(), port))
    }
}

/// `0 | uuid | 0 (no addons) | command | port | type | address`.
pub(super) fn request(uuid: &[u8; 16], command: u8, target: &Target) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(22 + 256));
    out.push(0);
    out.extend_from_slice(uuid);
    out.push(0);
    out.push(command);
    match target {
        Target::Ip(IpAddr::V4(ip), port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Target::Domain(name, port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(2);
            // `Target::parse` bounds the name to 255 bytes.
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Target::Ip(IpAddr::V6(ip), port) => {
            out.extend_from_slice(&port.to_be_bytes());
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
    out
}

/// Incremental parser of `0 | addons length | addons`. The server sends it
/// only together with its first downlink bytes, possibly split across frames.
#[derive(Default)]
pub(super) struct Response {
    /// Position in the header; `Addons` counts the addon bytes left to skip.
    state: State,
}
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    #[default]
    Version,
    Length,
    Addons(u8),
    Done,
}
impl Response {
    pub(super) fn done(&self) -> bool {
        self.state == State::Done
    }
    /// Consumes header bytes from the front of `data`; returns the offset of
    /// the first payload byte.
    pub(super) fn feed(&mut self, data: &[u8]) -> Result<usize> {
        let mut at = 0;
        while at < data.len() {
            self.state = match self.state {
                State::Version if data[at] != 0 => return Err(Error::Protocol),
                State::Version => State::Length,
                State::Length if data[at] == 0 => State::Done,
                State::Length => State::Addons(data[at]),
                State::Addons(left) => {
                    let take = (left as usize).min(data.len() - at);
                    at += take;
                    let left = left - take as u8;
                    self.state = if left == 0 {
                        State::Done
                    } else {
                        State::Addons(left)
                    };
                    continue;
                }
                State::Done => return Ok(at),
            };
            at += 1;
        }
        Ok(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: [u8; 16] = [0x11; 16];
    #[test]
    fn request_layout_matches_xray() {
        let v4 = request(&UUID, TCP, &Target::parse("192.0.2.1:443").unwrap());
        let mut expected = vec![0];
        expected.extend(UUID);
        expected.extend([0, 1, 0x01, 0xbb, 1, 192, 0, 2, 1]);
        assert_eq!(*v4, expected);
        let v6 = request(&UUID, UDP, &Target::parse("[2001:db8::1]:53").unwrap());
        assert_eq!(v6[17..22], [0, 2, 0, 53, 3]);
        assert_eq!(
            v6[22..],
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
        let domain = request(&UUID, TCP, &Target::parse("example.com:80").unwrap());
        assert_eq!(domain[17..23], [0, 1, 0, 80, 2, 11]);
        assert_eq!(&domain[23..], b"example.com");
        let long = format!("{}.com:80", "a".repeat(251));
        assert!(Target::parse(&long).is_ok());
        let too_long = format!("{}.com:80", "a".repeat(252));
        assert!(Target::parse(&too_long).is_err());
        for bad in ["example.com", "example.com:0", "[example.com]:80", ":80"] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn response_is_parsed_incrementally() {
        let mut r = Response::default();
        assert_eq!(r.feed(&[]).unwrap(), 0);
        assert_eq!(r.feed(&[0]).unwrap(), 1);
        assert_eq!(r.feed(&[3, 9]).unwrap(), 2);
        assert!(!r.done());
        assert_eq!(r.feed(&[9, 9, b'x']).unwrap(), 2);
        assert!(r.done());
        assert_eq!(r.feed(b"payload").unwrap(), 0);
        let mut r = Response::default();
        assert_eq!(r.feed(&[0, 0, b'h', b'i']).unwrap(), 2);
        assert!(Response::default().feed(&[1, 0]).is_err());
    }
}
