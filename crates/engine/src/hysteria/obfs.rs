use super::super::*;
use blake2::{Blake2b, Digest, digest::consts::U32};
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
};
pub struct Salamander {
    pub inner: Arc<dyn AsyncUdpSocket>,
    pub key: Zeroizing<Vec<u8>>,
    pub buffers: std::sync::Mutex<Vec<Vec<u8>>>,
}
impl std::fmt::Debug for Salamander {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salamander([REDACTED])")
    }
}
fn mask(key: &[u8], salt: &[u8], data: &mut [u8]) {
    let mut digest = Blake2b::<U32>::new();
    digest.update(key);
    digest.update(salt);
    let hash = digest.finalize();
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= hash[i % 32]
    }
}
impl AsyncUdpSocket for Salamander {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        if t.segment_size.is_some() {
            return Err(io::Error::other("Obfuscated GSO not supported"));
        }
        let salt = rand::random::<[u8; 8]>();
        let mut data = Vec::with_capacity(t.contents.len() + 8);
        data.extend_from_slice(&salt);
        data.extend_from_slice(t.contents);
        mask(&self.key, &salt, &mut data[8..]);
        self.inner.try_send(&Transmit {
            destination: t.destination,
            ecn: t.ecn,
            contents: &data,
            segment_size: None,
            src_ip: t.src_ip,
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Quinn allocates buffers for plaintext QUIC packets. Salamander adds
        // eight wire bytes per GRO segment; receive those before removing salt.
        let mut storage = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        storage.resize_with(bufs.len(), Vec::new);
        for (scratch, target) in storage.iter_mut().zip(bufs.iter()) {
            scratch.resize(target.len() + 8 * self.inner.max_receive_segments(), 0);
        }
        let mut receive: Vec<_> = storage.iter_mut().map(|b| IoSliceMut::new(b)).collect();
        let count = std::task::ready!(self.inner.poll_recv(cx, &mut receive, meta))?;
        for ((scratch, buffer), m) in receive
            .iter_mut()
            .zip(bufs.iter_mut())
            .zip(meta.iter_mut())
            .take(count)
        {
            let stride = m.stride.max(1);
            let mut written = 0;
            for offset in (0..m.len).step_by(stride) {
                let end = (offset + stride).min(m.len);
                if end - offset <= 8 || end - offset - 8 > buffer.len() - written {
                    continue;
                }
                let salt: [u8; 8] = scratch[offset..offset + 8].try_into().unwrap();
                mask(&self.key, &salt, &mut scratch[offset + 8..end]);
                buffer[written..written + end - offset - 8]
                    .copy_from_slice(&scratch[offset + 8..end]);
                written += end - offset - 8;
            }
            m.len = written;
            m.stride = stride.saturating_sub(8).max(1);
        }
        Poll::Ready(Ok(count))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Debug)]
    struct Mock(Vec<u8>);
    impl AsyncUdpSocket for Mock {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            unimplemented!("read-only fixture")
        }
        fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
            unimplemented!("read-only fixture")
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:443".parse().unwrap())
        }
        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            bufs: &mut [IoSliceMut<'_>],
            meta: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            let n = bufs[0].len().min(self.0.len());
            bufs[0][..n].copy_from_slice(&self.0[..n]);
            meta[0].len = n;
            meta[0].stride = n;
            Poll::Ready(Ok(1))
        }
    }
    #[test]
    fn receive_preserves_a_full_mtu_packet_plus_salamander_salt() {
        let plain = vec![0x42; 1472];
        let salt = *b"12345678";
        let mut wire = salt.to_vec();
        wire.extend(&plain);
        mask(b"password", &salt, &mut wire[8..]);
        let socket = Salamander {
            inner: Arc::new(Mock(wire)),
            key: Zeroizing::new(b"password".to_vec()),
            buffers: Default::default(),
        };
        let mut output = vec![0; 1472];
        let mut metadata = [RecvMeta::default()];
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            socket.poll_recv(&mut cx, &mut [IoSliceMut::new(&mut output)], &mut metadata),
            Poll::Ready(Ok(1))
        ));
        assert_eq!(metadata[0].len, 1472);
        assert_eq!(output, plain);
    }
    #[test]
    fn salamander_is_salt_dependent_and_reversible() {
        let original = b"QUIC test packet";
        let mut data = original.to_vec();
        mask(b"password", b"12345678", &mut data);
        assert_ne!(data, original);
        let mut other = original.to_vec();
        mask(b"password", b"87654321", &mut other);
        assert_ne!(data, other);
        mask(b"password", b"12345678", &mut data);
        assert_eq!(data, original)
    }
}
