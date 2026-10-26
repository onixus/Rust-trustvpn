//! Minimal RFC 6455 client: one HTTP/1.1 upgrade, masked binary frames out,
//! unmasked binary frames in. No extensions, subprotocols or redirects.
use crate::{Error, Result};
use base64::Engine;
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Upper bound of the response head; the server sends a few short headers.
const MAX_HEAD: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;
/// Largest accepted data frame. Checked from the header, before any buffering.
pub(super) const MAX_FRAME: u64 = 1024 * 1024;
/// A generic browser identity; the request carries no client identifiers.
const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const CONTINUATION: u8 = 0;
const TEXT: u8 = 1;
pub(super) const BINARY: u8 = 2;
pub(super) const CLOSE: u8 = 8;
pub(super) const PING: u8 = 9;
pub(super) const PONG: u8 = 10;

pub(super) fn accept(key: &str) -> String {
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}{GUID}").as_bytes(),
    );
    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
}

/// Sends the upgrade request and validates a `101` answer. Returns bytes the
/// server sent after the head (the start of the frame stream). Errors never
/// carry the status text, headers or the request path.
pub(super) async fn upgrade<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    host: &str,
    path: &str,
) -> Result<BytesMut> {
    let key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    let request = zeroize::Zeroizing::new(format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ));
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;
    let mut head = BytesMut::with_capacity(1024);
    let end = loop {
        if let Some(n) = head.windows(4).position(|w| w == b"\r\n\r\n") {
            break n;
        }
        if head.len() >= MAX_HEAD {
            return Err(Error::Protocol);
        }
        let mut chunk = [0u8; 1024];
        let want = chunk.len().min(MAX_HEAD + 3 - head.len());
        let n = io.read(&mut chunk[..want]).await?;
        if n == 0 {
            return Err(Error::Protocol);
        }
        head.extend_from_slice(&chunk[..n]);
    };
    let rest = head.split_off(end + 4);
    let text = std::str::from_utf8(&head[..end]).map_err(|_| Error::Protocol)?;
    let mut lines = text.split("\r\n");
    let status = lines.next().ok_or(Error::Protocol)?;
    let mut fields = status.splitn(3, ' ');
    if !matches!(fields.next(), Some("HTTP/1.1" | "HTTP/1.0")) {
        return Err(Error::Protocol);
    }
    let code = fields
        .next()
        .filter(|c| c.len() == 3)
        .and_then(|c| c.parse::<u16>().ok())
        .filter(|c| (100..600).contains(c))
        .ok_or(Error::Protocol)?;
    if code != 101 {
        // Redirects are not followed: the path is a secret of this endpoint.
        return Err(Error::Rejected(code));
    }
    let (mut upgrade, mut connection, mut accepted) = (false, false, false);
    let expected = accept(&key);
    for (count, line) in lines.enumerate() {
        if count >= MAX_HEADERS {
            return Err(Error::Protocol);
        }
        let (name, value) = line.split_once(':').ok_or(Error::Protocol)?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "upgrade" => upgrade = value.eq_ignore_ascii_case("websocket"),
            "connection" => {
                connection = value
                    .split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            }
            "sec-websocket-accept" => accepted = value == expected,
            // Nothing was offered, so nothing may be negotiated.
            "sec-websocket-extensions" | "sec-websocket-protocol" => {
                return Err(Error::Protocol);
            }
            _ => {}
        }
    }
    if !(upgrade && connection && accepted) {
        return Err(Error::Protocol);
    }
    Ok(rest)
}

/// One client frame: FIN set, masked with a fresh random key.
pub(super) fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(0x80 | opcode);
    match payload.len() {
        n @ 0..=125 => out.push(0x80 | n as u8),
        n @ 126..=0xffff => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mask: [u8; 4] = rand::random();
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}
pub(super) async fn send<W: AsyncWrite + Unpin>(
    io: &mut W,
    opcode: u8,
    payload: &[u8],
) -> Result<()> {
    io.write_all(&frame(opcode, payload)).await?;
    io.flush().await?;
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Event {
    /// Payload bytes of binary frames, in order, in arbitrary chunks.
    Data(Bytes),
    Ping(Bytes),
    Close,
}
/// Cancel-safe frame decoder: state lives here and reads only fill `buf`, so
/// `next` may be dropped in a `select!` without losing bytes.
pub(super) struct Reader<R> {
    io: R,
    buf: BytesMut,
    /// Payload bytes left in the current data frame.
    remaining: u64,
    /// Inside a fragmented binary message (last data frame had no FIN).
    message: bool,
}
impl<R: AsyncRead + Unpin> Reader<R> {
    pub(super) fn new(io: R, buffered: BytesMut) -> Self {
        Self {
            io,
            buf: buffered,
            remaining: 0,
            message: false,
        }
    }
    /// `None` at end of stream.
    pub(super) async fn next(&mut self) -> Result<Option<Event>> {
        loop {
            if let Some(event) = self.parse()? {
                return Ok(Some(event));
            }
            if self.buf.capacity() - self.buf.len() < 4096 {
                self.buf.reserve(16 * 1024);
            }
            if self.io.read_buf(&mut self.buf).await? == 0 {
                return Ok(None);
            }
        }
    }
    fn parse(&mut self) -> Result<Option<Event>> {
        loop {
            if self.remaining > 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                let take = self.remaining.min(self.buf.len() as u64) as usize;
                self.remaining -= take as u64;
                return Ok(Some(Event::Data(self.buf.split_to(take).freeze())));
            }
            if self.buf.len() < 2 {
                return Ok(None);
            }
            let (first, second) = (self.buf[0], self.buf[1]);
            let (fin, opcode) = (first & 0x80 != 0, first & 0x0f);
            // RSV bits mean an extension; a masked server frame breaks RFC 6455.
            if first & 0x70 != 0 || second & 0x80 != 0 {
                return Err(Error::Protocol);
            }
            let (len, header) = match second & 0x7f {
                126 if self.buf.len() < 4 => return Ok(None),
                126 => (u16::from_be_bytes([self.buf[2], self.buf[3]]) as u64, 4),
                127 if self.buf.len() < 10 => return Ok(None),
                127 => (
                    u64::from_be_bytes(self.buf[2..10].try_into().expect("8 bytes")),
                    10,
                ),
                n => (n as u64, 2),
            };
            match opcode {
                CONTINUATION | BINARY => {
                    if len > MAX_FRAME || (opcode == BINARY) == self.message {
                        return Err(Error::Protocol);
                    }
                    self.message = !fin;
                    self.buf.advance(header);
                    self.remaining = len;
                }
                CLOSE | PING | PONG => {
                    if !fin || len > 125 {
                        return Err(Error::Protocol);
                    }
                    if self.buf.len() < header + len as usize {
                        return Ok(None);
                    }
                    self.buf.advance(header);
                    let payload = self.buf.split_to(len as usize).freeze();
                    match opcode {
                        CLOSE => return Ok(Some(Event::Close)),
                        PING => return Ok(Some(Event::Ping(payload))),
                        _ => {}
                    }
                }
                // The tunnel is binary only.
                TEXT => return Err(Error::Protocol),
                // Reserved opcodes.
                _ => return Err(Error::Protocol),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    async fn events(bytes: &[u8]) -> Result<Vec<Event>> {
        let mut reader = Reader::new(bytes, BytesMut::new());
        let mut out = vec![];
        while let Some(event) = reader.next().await? {
            out.push(event);
        }
        Ok(out)
    }
    fn server(opcode: u8, fin: bool, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![(if fin { 0x80 } else { 0 }) | opcode];
        if payload.len() < 126 {
            out.push(payload.len() as u8);
        } else {
            out.push(126);
            out.extend((payload.len() as u16).to_be_bytes());
        }
        out.extend(payload);
        out
    }
    #[test]
    fn accept_matches_rfc_6455_example() {
        assert_eq!(
            accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
    #[test]
    fn client_frames_are_masked() {
        for len in [0, 5, 125, 126, 65535, 65536] {
            let payload = vec![0x5a; len];
            let f = frame(BINARY, &payload);
            assert_eq!(f[0], 0x82);
            assert_ne!(f[1] & 0x80, 0);
            let (header, ext) = match len {
                0..=125 => (2, 0),
                126..=65535 => (4, 2),
                _ => (10, 8),
            };
            assert_eq!(f.len(), header + 4 + len, "{len}");
            let _ = ext;
            let mask = &f[header..header + 4];
            let unmasked: Vec<u8> = f[header + 4..]
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ mask[i % 4])
                .collect();
            assert_eq!(unmasked, payload);
        }
    }
    #[tokio::test]
    async fn frames_decode_across_fragments() {
        let mut wire = server(BINARY, false, b"he");
        wire.extend(server(PING, true, b"p"));
        wire.extend(server(CONTINUATION, true, &[b'y'; 300]));
        wire.extend(server(PONG, true, b""));
        wire.extend(server(CLOSE, true, &[3, 232]));
        let all = events(&wire).await.unwrap();
        assert_eq!(all[0], Event::Data(Bytes::from_static(b"he")));
        assert_eq!(all[1], Event::Ping(Bytes::from_static(b"p")));
        assert_eq!(all[2], Event::Data(Bytes::from(vec![b'y'; 300])));
        assert_eq!(all[3], Event::Close);
        // One byte at a time gives the same stream.
        let (mut tx, rx) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move { tx.write_all(&wire).await });
        let mut reader = Reader::new(rx, BytesMut::new());
        let mut data = vec![];
        while let Some(event) = reader.next().await.unwrap() {
            match event {
                Event::Data(d) => data.extend(d),
                Event::Close => break,
                Event::Ping(_) => {}
            }
        }
        writer.await.unwrap().unwrap();
        assert_eq!(data.len(), 302);
    }
    #[tokio::test]
    async fn invalid_frames_are_rejected() {
        let mut too_big = vec![0x82, 127];
        too_big.extend((MAX_FRAME + 1).to_be_bytes());
        let mut masked = server(BINARY, true, b"x");
        masked[1] |= 0x80;
        let mut rsv = server(BINARY, true, b"x");
        rsv[0] |= 0x40;
        let mut long_ping = vec![0x89, 126];
        long_ping.extend(126u16.to_be_bytes());
        for bad in [
            too_big,
            server(TEXT, true, b"x"),
            masked,
            rsv,
            server(CONTINUATION, true, b"x"),
            [server(BINARY, false, b"x"), server(BINARY, true, b"y")].concat(),
            server(PING, false, b""),
            long_ping,
            server(3, true, b""),
        ] {
            assert!(events(&bad).await.is_err(), "{bad:?}");
        }
        // The oversize frame fails from its header alone, before any payload.
        let mut header = vec![0x82, 127];
        header.extend(u64::MAX.to_be_bytes());
        assert!(events(&header).await.is_err());
    }
}
