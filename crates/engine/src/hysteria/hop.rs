//! UDP port hopping: QUIC sees one fixed peer address while packets rotate
//! across the server's port set, each hop on a fresh local socket.
use super::super::*;
use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    io::{self, IoSliceMut},
    net::SocketAddr,
    sync::Mutex,
    time::Instant,
};
pub type SocketFactory = Box<dyn Fn() -> io::Result<Arc<dyn AsyncUdpSocket>> + Send + Sync>;
pub struct Hopping {
    /// Address given to quinn; replies from any hop port are reported as this.
    peer: SocketAddr,
    ports: Vec<(u16, u16)>,
    interval: (u64, u64),
    factory: SocketFactory,
    state: Mutex<State>,
}
struct State {
    current: Arc<dyn AsyncUdpSocket>,
    /// The socket before the last hop keeps receiving in-flight replies.
    previous: Option<Arc<dyn AsyncUdpSocket>>,
    port: u16,
    next: Instant,
    /// Wakes the receive task at `next`, so hops happen on time while idle.
    timer: Pin<Box<tokio::time::Sleep>>,
    generation: u64,
    /// The receive task waits on the old sockets; wake it to poll a new one.
    receiver: Option<std::task::Waker>,
}
impl std::fmt::Debug for Hopping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hopping")
            .field("ports", &self.ports)
            .finish()
    }
}
impl Hopping {
    pub fn new(
        peer: SocketAddr,
        ports: Vec<(u16, u16)>,
        interval: (u64, u64),
        factory: SocketFactory,
    ) -> io::Result<Self> {
        if ports.is_empty() || interval.0 == 0 || interval.1 < interval.0 {
            return Err(io::Error::other("Invalid port hopping"));
        }
        let current = factory()?;
        let port = pick(&ports);
        let next = Instant::now() + delay(interval);
        Ok(Self {
            peer,
            interval,
            state: Mutex::new(State {
                current,
                previous: None,
                port,
                next,
                timer: Box::pin(tokio::time::sleep_until(next.into())),
                generation: 0,
                receiver: None,
            }),
            ports,
            factory,
        })
    }
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    /// Hops when due: the previous socket is closed and the current one kept
    /// receiving for one more interval. A failed socket creation skips the hop.
    fn hop_if_due(&self, state: &mut State) {
        let now = Instant::now();
        if now < state.next {
            return;
        }
        if let Ok(socket) = (self.factory)() {
            state.previous = Some(std::mem::replace(&mut state.current, socket));
            state.port = pick(&self.ports);
            state.generation += 1;
            if let Some(waker) = state.receiver.take() {
                waker.wake();
            }
        }
        state.next = now + delay(self.interval);
        let next = state.next;
        state.timer.as_mut().reset(next.into());
    }
    fn current(&self) -> (Arc<dyn AsyncUdpSocket>, u16) {
        let mut state = self.state();
        self.hop_if_due(&mut state);
        (state.current.clone(), state.port)
    }
}
fn pick(ports: &[(u16, u16)]) -> u16 {
    let total: u32 = ports.iter().map(|(a, b)| (*b - *a) as u32 + 1).sum();
    let mut index = rand::random_range(0..total);
    for (a, b) in ports {
        let size = (*b - *a) as u32 + 1;
        if index < size {
            return a + index as u16;
        }
        index -= size;
    }
    ports[0].0
}
fn delay((min, max): (u64, u64)) -> Duration {
    Duration::from_secs(if min == max {
        min
    } else {
        rand::random_range(min..=max)
    })
}
impl AsyncUdpSocket for Hopping {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(Poller {
            socket: self,
            inner: Mutex::new(None),
        })
    }
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        let (socket, port) = self.current();
        socket.try_send(&Transmit {
            destination: SocketAddr::new(self.peer.ip(), port),
            ecn: t.ecn,
            contents: t.contents,
            segment_size: t.segment_size,
            src_ip: None,
        })
    }
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (current, previous) = {
            let mut state = self.state();
            self.hop_if_due(&mut state);
            let _ = state.timer.as_mut().poll(cx);
            state.receiver = Some(cx.waker().clone());
            (state.current.clone(), state.previous.clone())
        };
        for socket in std::iter::once(current).chain(previous) {
            if let Poll::Ready(result) = socket.poll_recv(cx, bufs, meta) {
                let count = result?;
                for m in meta.iter_mut().take(count) {
                    if m.addr.ip() == self.peer.ip() {
                        m.addr = self.peer;
                    }
                    m.dst_ip = None;
                }
                return Poll::Ready(Ok(count));
            }
        }
        Poll::Pending
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state().current.local_addr()
    }
    fn max_receive_segments(&self) -> usize {
        self.state().current.max_receive_segments()
    }
    fn max_transmit_segments(&self) -> usize {
        self.state().current.max_transmit_segments()
    }
    fn may_fragment(&self) -> bool {
        self.state().current.may_fragment()
    }
}
/// The poller of one socket generation.
type Generation = (u64, Pin<Box<dyn UdpPoller>>);
/// Writability of whichever socket is current, re-created after each hop.
struct Poller {
    socket: Arc<Hopping>,
    inner: Mutex<Option<Generation>>,
}
impl std::fmt::Debug for Poller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HoppingPoller")
    }
}
impl UdpPoller for Poller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let (generation, current) = {
            let state = self.socket.state();
            (state.generation, state.current.clone())
        };
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.as_ref().is_none_or(|(g, _)| *g != generation) {
            *inner = Some((generation, current.create_io_poller()));
        }
        inner.as_mut().unwrap().1.as_mut().poll_writable(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use quinn::Runtime;
    #[test]
    fn picks_only_configured_ports() {
        let ports = vec![(443, 443), (20000, 20002)];
        for _ in 0..200 {
            let port = pick(&ports);
            assert!(port == 443 || (20000..=20002).contains(&port), "{port}");
        }
        assert!((5..=9).contains(&delay((5, 9)).as_secs()));
        assert_eq!(delay((30, 30)).as_secs(), 30);
    }
    #[tokio::test]
    async fn hops_to_new_socket_and_reports_one_peer() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ports = [
            server.local_addr().unwrap().port(),
            second.local_addr().unwrap().port(),
        ];
        let factory: SocketFactory = Box::new(|| {
            let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
            socket.set_nonblocking(true)?;
            quinn::TokioRuntime.wrap_udp_socket(socket)
        });
        let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let hop = Arc::new(
            Hopping::new(
                peer,
                ports.iter().map(|p| (*p, *p)).collect(),
                (1, 1),
                factory,
            )
            .unwrap(),
        );
        let mut sources = std::collections::HashSet::new();
        let mut buffer = [0; 16];
        for round in 0..4u8 {
            hop.state().next = Instant::now();
            let transmit = Transmit {
                destination: peer,
                ecn: None,
                contents: &[round],
                segment_size: None,
                src_ip: None,
            };
            let mut poller = hop.clone().create_io_poller();
            loop {
                std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                    .await
                    .unwrap();
                match hop.try_send(&transmit) {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    result => break result.unwrap(),
                }
            }
            let port = hop.state().port;
            let receiver = if port == ports[0] { &server } else { &second };
            let (n, from) = receiver.recv_from(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], &[round]);
            sources.insert(from.port());
            receiver.send_to(b"reply", from).await.unwrap();
            let mut reply = [0; 16];
            let mut meta = [RecvMeta::default()];
            let count = std::future::poll_fn(|cx| {
                hop.poll_recv(cx, &mut [IoSliceMut::new(&mut reply)], &mut meta)
            })
            .await
            .unwrap();
            assert_eq!(count, 1);
            assert_eq!(meta[0].addr, peer);
        }
        // Every hop uses a fresh local socket.
        assert_eq!(sources.len(), 4);
    }
}
