//! AmneziaWG 3 datagram layout: random prefixes (S1–S4), message type ranges
//! (H1–H4), header protection, trailers, junk and signature packets.
use super::noise::{COOKIE, INITIATION, RESPONSE, TAG, TRANSPORT_HEADER};
use crate::{Error, Result};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use rtrust_profile::amnezia::{self, AmneziaWg, Range, Tag};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Initiation,
    Response,
    Cookie,
    Transport,
}
/// The reference's initial estimate of the largest datagram seen on the path.
pub const DEFAULT_WINDOW: usize = 500;
/// A keepalive: transport header and an empty authenticated payload.
const MIN_MESSAGE: usize = TRANSPORT_HEADER + TAG;
const NONCE: usize = 12;

pub fn pick((low, high): Range) -> u32 {
    rand::random_range(low..=high)
}
/// Uniform in `[0, n)`, and 0 for an empty range like Go's `fastrandn`.
fn below(n: usize) -> usize {
    if n == 0 { 0 } else { rand::random_range(0..n) }
}
fn random(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    rand::fill(&mut bytes[..]);
    bytes
}

pub struct Wire {
    paddings: [usize; 4],
    headers: [Range; 4],
    key: Option<zeroize::Zeroizing<[u8; 32]>>,
    trailers: bool,
    addition: Range,
    junk: (u32, usize, usize),
    signatures: Vec<Vec<Tag>>,
    mtu: usize,
}
impl Wire {
    pub fn new(o: &AmneziaWg) -> Result<Self> {
        let key = if o.header_protection_key.is_empty() {
            None
        } else {
            Some(zeroize::Zeroizing::new(
                amnezia::key(o.header_protection_key.expose(), "").map_err(|_| Error::Profile)?,
            ))
        };
        Ok(Self {
            paddings: o.paddings.map(|n| n as usize),
            headers: o.header_ranges().map_err(|_| Error::Profile)?,
            key,
            trailers: o.random_trailers,
            addition: amnezia::range(&o.content_padding_addition, "")
                .map_err(|_| Error::Profile)?,
            junk: (o.jc, o.jmin as usize, o.jmax as usize),
            signatures: o
                .signatures
                .iter()
                .map(|s| amnezia::signature(s))
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| Error::Profile)?
                .into_iter()
                .filter(|tags| !tags.is_empty())
                .collect(),
            mtu: o.mtu(),
        })
    }
    pub fn header(&self, kind: Kind) -> u32 {
        pick(self.headers[kind as usize])
    }
    pub fn padding(&self, kind: Kind) -> usize {
        self.paddings[kind as usize]
    }
    /// Keystream for one datagram; the nonce is the start of its random prefix.
    fn keystream(&self, nonce: &[u8], out: &mut [u8]) {
        if let Some(key) = &self.key {
            ChaCha20::new(key[..].into(), nonce[..NONCE].into()).apply_keystream(out);
        }
    }
    /// Prefix, the message with its protected header, and for handshake
    /// messages an optional random trailer within the observed window.
    pub fn frame(&self, kind: Kind, message: &[u8], window: usize) -> Vec<u8> {
        let padding = self.padding(kind);
        let protected = match kind {
            Kind::Transport => TRANSPORT_HEADER,
            _ => message.len(),
        };
        let trailer = if self.trailers && kind != Kind::Transport {
            below(window.saturating_sub(padding + message.len()))
        } else {
            0
        };
        let mut datagram = random(padding + message.len() + trailer);
        datagram[padding..padding + message.len()].copy_from_slice(message);
        if self.key.is_some() {
            let mut stream = [0u8; INITIATION];
            self.keystream(&datagram[..NONCE], &mut stream[..protected]);
            for (byte, mask) in datagram[padding..].iter_mut().zip(&stream[..protected]) {
                *byte ^= mask;
            }
        }
        datagram
    }
    /// Classifies by size and type range, as the reference does, and returns
    /// the message with its header in the clear.
    pub fn parse<'a>(&self, datagram: &'a mut [u8]) -> Option<(Kind, &'a mut [u8])> {
        if datagram.len() < MIN_MESSAGE {
            return None;
        }
        let mut stream = [0u8; INITIATION];
        self.keystream(&datagram[..NONCE], &mut stream);
        let size = datagram.len();
        let matches = |kind: Kind, exact: Option<usize>| {
            let padding = self.padding(kind);
            let fits = match exact {
                Some(n) => size == padding + n || (self.trailers && size > padding + n),
                None => size >= padding + MIN_MESSAGE,
            };
            fits && {
                let mut header: [u8; 4] = datagram[padding..padding + 4].try_into().unwrap();
                for (byte, mask) in header.iter_mut().zip(&stream) {
                    *byte ^= mask;
                }
                let (low, high) = self.headers[kind as usize];
                (low..=high).contains(&u32::from_le_bytes(header))
            }
        };
        let (kind, length) = if matches(Kind::Initiation, Some(INITIATION)) {
            (Kind::Initiation, Some(INITIATION))
        } else if matches(Kind::Response, Some(RESPONSE)) {
            (Kind::Response, Some(RESPONSE))
        } else if matches(Kind::Cookie, Some(COOKIE)) {
            (Kind::Cookie, Some(COOKIE))
        } else if matches(Kind::Transport, None) {
            (Kind::Transport, None)
        } else {
            return None;
        };
        let padding = self.padding(kind);
        let message = match length {
            Some(n) => &mut datagram[padding..padding + n],
            None => &mut datagram[padding..],
        };
        let protected = length.unwrap_or(TRANSPORT_HEADER);
        for (byte, mask) in message.iter_mut().zip(&stream[..protected]) {
            *byte ^= mask;
        }
        Some((kind, message))
    }
    /// Zero bytes appended to a packet before encryption. `window` already
    /// covers this packet, so padding never exceeds the largest size seen.
    pub fn content_padding(&self, packet: usize, window: usize) -> usize {
        let space = window.saturating_sub(self.padding(Kind::Transport) + MIN_MESSAGE + packet);
        if self.addition != (0, 0) {
            (pick(self.addition) as usize).min(space)
        } else if self.trailers {
            below(space)
        } else {
            // WireGuard: a multiple of 16, never beyond the tunnel MTU.
            let unit = if packet > self.mtu {
                packet % self.mtu
            } else {
                packet
            };
            unit.next_multiple_of(16).min(self.mtu) - unit
        }
    }
    /// Signature packets I1–I5, then the junk packets, sent before an initiation.
    pub fn preamble(&self) -> Vec<Vec<u8>> {
        let mut packets: Vec<Vec<u8>> = self
            .signatures
            .iter()
            .map(|tags| {
                let mut packet = vec![];
                for tag in tags {
                    match tag {
                        Tag::Bytes(bytes) => packet.extend(bytes),
                        Tag::Random(n) => packet.extend(random(*n)),
                        Tag::Chars(n) => packet.extend(random(*n).iter().map(|b| {
                            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                [(b % 52) as usize]
                        })),
                        Tag::Digits(n) => packet.extend(random(*n).iter().map(|b| b'0' + b % 10)),
                        Tag::Timestamp => packet.extend(
                            (std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs() as u32)
                                .to_be_bytes(),
                        ),
                        Tag::DataSize(n) => packet.extend(std::iter::repeat_n(0, *n)),
                    }
                }
                packet
            })
            .collect();
        let (count, min, max) = self.junk;
        packets.extend((0..count).map(|_| random(min + below(max - min))));
        packets
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_profile::Secret;
    fn options(protect: bool, trailers: bool) -> AmneziaWg {
        AmneziaWg {
            paddings: [15, 20, 12, 16],
            headers: ["100-200", "300", "400-500", "600-700"].map(String::from),
            header_protection_key: Secret::new(if protect {
                "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
            } else {
                ""
            }),
            random_trailers: trailers,
            jc: 3,
            jmin: 10,
            jmax: 50,
            signatures: [
                "<b 0xc0ff><r 6><rc 4><rd 4><t><dz 2>".into(),
                String::new(),
                "<r 9>".into(),
                String::new(),
                String::new(),
            ],
            ..Default::default()
        }
    }
    fn message(wire: &Wire, kind: Kind, len: usize) -> Vec<u8> {
        let mut m: Vec<u8> = (0..len).map(|n| n as u8).collect();
        m[..4].copy_from_slice(&wire.header(kind).to_le_bytes());
        m
    }
    #[test]
    fn every_message_kind_roundtrips_in_every_mode() {
        for (protect, trailers) in [(false, false), (true, false), (false, true), (true, true)] {
            let wire = Wire::new(&options(protect, trailers)).unwrap();
            for (kind, len) in [
                (Kind::Initiation, INITIATION),
                (Kind::Response, RESPONSE),
                (Kind::Cookie, COOKIE),
                (Kind::Transport, MIN_MESSAGE),
                (Kind::Transport, 1312),
            ] {
                for _ in 0..50 {
                    let m = message(&wire, kind, len);
                    let mut datagram = wire.frame(kind, &m, DEFAULT_WINDOW);
                    let padding = wire.padding(kind);
                    if kind == Kind::Transport || !trailers {
                        assert_eq!(datagram.len(), padding + len);
                    } else {
                        assert!(
                            (padding + len..DEFAULT_WINDOW.max(padding + len + 1))
                                .contains(&datagram.len())
                        );
                    }
                    if protect {
                        // No stable bytes: the type and indices are masked.
                        assert_ne!(datagram[padding..padding + 16], m[..16]);
                        assert_eq!(
                            kind == Kind::Transport,
                            datagram[padding + 16..][..16] == m[16..32]
                        );
                    }
                    let (parsed, body) = wire.parse(&mut datagram).unwrap();
                    assert_eq!((parsed, &*body), (kind, &m[..]));
                }
            }
        }
    }
    #[test]
    fn foreign_datagrams_are_dropped() {
        let wire = Wire::new(&options(true, false)).unwrap();
        for len in [0, 31, 32, 148, 163, 1400] {
            for _ in 0..200 {
                // A random type lands in a 101-value range with probability 2^-25.
                assert!(wire.parse(&mut random(len)).is_none());
            }
        }
        let plain = Wire::new(&options(false, false)).unwrap();
        let standard = [&[1u8, 0, 0, 0][..], &[0; 144]].concat();
        assert!(
            plain
                .parse(&mut [&[0; 15][..], &standard].concat())
                .is_none()
        );
    }
    #[test]
    fn preamble_and_padding_follow_the_configuration() {
        let wire = Wire::new(&options(false, false)).unwrap();
        let packets = wire.preamble();
        assert_eq!(packets.len(), 5);
        assert_eq!((packets[0].len(), packets[1].len()), (22, 9));
        assert_eq!(packets[0][..2], [0xc0, 0xff]);
        assert!(packets[0][8..12].iter().all(u8::is_ascii_alphabetic));
        assert!(packets[0][12..16].iter().all(u8::is_ascii_digit));
        assert_eq!(packets[0][20..], [0, 0]);
        assert!(packets[2..].iter().all(|p| (10..50).contains(&p.len())));
        assert_eq!(wire.content_padding(0, 500), 0);
        assert_eq!(wire.content_padding(1, 500), 15);
        assert_eq!(wire.content_padding(1279, 1500), 1);
        let mut o = options(false, false);
        o.content_padding_addition = "40-60".into();
        let wire = Wire::new(&o).unwrap();
        assert!((40..=60).contains(&wire.content_padding(100, 500)));
        // S4 + header + tag + packet already fills the window.
        assert_eq!(wire.content_padding(452, 500), 0);
        let wire = Wire::new(&options(false, true)).unwrap();
        assert!((0..352).contains(&wire.content_padding(100, 500)));
    }
}
