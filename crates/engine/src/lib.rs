//! TrustTunnel HTTP/2 and HTTP/3 transport. This is not a system VPN: it never modifies routes or DNS.
mod amnezia;
pub mod dns;
mod h3transport;
mod hysteria;
pub mod icmp;
mod liveness;
pub mod proxy;
pub mod routing;
pub mod udp;
use base64::Engine;
use bytes::Bytes;
use http::{Request, StatusCode};
use rtrust_profile::Profile;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    net::TcpStream,
};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, Error>;

/// Process-wide TCP flow counts since start, across sessions: numbers only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FlowCounters {
    /// TCP CONNECTs the endpoint accepted.
    pub tcp_opened: u64,
    /// Watched flows (ports that answer the first write) answered after it.
    pub tcp_answered: u64,
    /// Watched flows closed after writing without any answer.
    pub tcp_quiet: u64,
    /// TCP CONNECTs that failed in transport (no endpoint answer).
    pub tcp_open_failed: u64,
    /// Opens of any kind that found no stream credit in time.
    pub credit_timeout: u64,
}
pub fn flow_counters() -> FlowCounters {
    use std::sync::atomic::Ordering::Relaxed;
    let flows = &liveness::FLOWS;
    FlowCounters {
        tcp_opened: flows.opened.load(Relaxed),
        tcp_answered: flows.answered.load(Relaxed),
        tcp_quiet: flows.quiet.load(Relaxed),
        tcp_open_failed: flows.failed.load(Relaxed),
        credit_timeout: flows.credit.load(Relaxed),
    }
}
/// Protect/bind a transport socket before its first packet (Android VpnService).
/// Failure is terminal for that attempt: no unprotected fallback is allowed.
pub type SocketProtector = Arc<dyn Fn(i32) -> std::io::Result<()> + Send + Sync>;
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("Local SOCKS port is unavailable; choose another port")]
    LocalBind,
    #[error("Profile is invalid")]
    Profile,
    #[error("Not supported by this transport: {0}")]
    Unsupported(&'static str),
    #[error("No trusted CA certificates available")]
    Trust,
    #[error("Endpoint connection failed")]
    Connect,
    #[error("Endpoint connection failed ({0:?})")]
    ConnectIo(std::io::ErrorKind),
    #[error("TLS certificate or handshake validation failed")]
    Tls,
    #[error("Tunnel protocol negotiation failed")]
    Protocol,
    #[error("Endpoint rejected authentication")]
    Authentication,
    #[error("Endpoint rejected CONNECT (status {0})")]
    Rejected(u16),
    #[error("Operation timed out")]
    Timeout,
    /// No stream credit within the open deadline: the session already has
    /// as many streams open as the endpoint allows, and none was freed.
    #[error("Tunnel stream limit reached")]
    Credit,
    #[error("Tunnel I/O failed")]
    Io,
    #[error("Invalid destination authority")]
    Destination,
    /// Outbound traffic stayed unanswered while opens to several destinations
    /// failed or stayed silent, or most TCP flows that wrote first across
    /// several hosts never got an answer. `proven`: the session delivered
    /// inbound data earlier in its life, so it was not dead from the start.
    /// In the second case only an answer from before the judged window
    /// counts: the few answered flows right after a reconnect are exactly
    /// what hid the dead session (issue #99).
    /// `kind`: which evidence judged it.
    #[error("Tunnel carries no traffic")]
    Degraded { proven: bool, kind: Stall },
    /// The connection under the session closed; returned by `Session::health`.
    #[error("Tunnel connection closed")]
    Closed(Close),
}
/// Which liveness evidence ended a session as degraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stall {
    /// Outbound demand unanswered while opens failed or stayed silent.
    Silent,
    /// Most first-write TCP flows across several hosts got no answer.
    Quiet,
}
impl Stall {
    /// Stable token for event logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Silent => "silent",
            Self::Quiet => "quiet",
        }
    }
}
/// Why the connection under a session closed: a class and numeric protocol
/// codes only. Endpoint-supplied text (GOAWAY debug data, QUIC reason
/// phrases) is never kept, so the value is safe for event logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Close {
    /// The endpoint closed the TCP/TLS stream (EOF) without GOAWAY.
    PeerClosed,
    /// HTTP/2 GOAWAY. `remote`: sent by the endpoint, else raised by h2 here.
    GoAway { code: u32, remote: bool },
    /// QUIC CONNECTION_CLOSE with an HTTP/3 application code from the endpoint.
    QuicApplication(u64),
    /// QUIC CONNECTION_CLOSE with a transport code. `remote` as for GOAWAY.
    QuicTransport { code: u64, remote: bool },
    /// QUIC idle timeout: nothing from the endpoint despite keepalives.
    IdleTimeout,
    /// QUIC stateless reset: the endpoint no longer knows the connection.
    StatelessReset,
    /// TLS record or alert failure on an established connection.
    Tls,
    /// Socket error on the connection.
    Io(std::io::ErrorKind),
    /// Closed by this client.
    Local,
}
impl Close {
    /// Stable `reason=<class>[ key=value]...` tokens for event logs.
    pub fn fields(self) -> String {
        let by = |remote: bool| if remote { "peer" } else { "local" };
        match self {
            Self::PeerClosed => "reason=peer_closed".into(),
            Self::GoAway { code, remote } => format!("reason=goaway code={code} by={}", by(remote)),
            Self::QuicApplication(code) => {
                format!("reason=quic_close layer=app code={code} by=peer")
            }
            // 0x100..=0x1ff carry a TLS alert (RFC 9001 section 4.8).
            Self::QuicTransport { code, remote } if (0x100..0x200).contains(&code) => {
                format!("reason=tls_error alert={} by={}", code - 0x100, by(remote))
            }
            Self::QuicTransport { code, remote } => {
                format!(
                    "reason=quic_close layer=transport code={code} by={}",
                    by(remote)
                )
            }
            Self::IdleTimeout => "reason=idle_timeout".into(),
            Self::StatelessReset => "reason=stateless_reset".into(),
            Self::Tls => "reason=tls_error".into(),
            Self::Io(kind) => format!("reason=io_error kind={}", io_kind(kind)),
            Self::Local => "reason=local_stop".into(),
        }
    }
}
/// `ErrorKind` as a snake_case token (`ConnectionReset` -> `connection_reset`).
pub fn io_kind(kind: std::io::ErrorKind) -> String {
    let mut token = String::new();
    for c in format!("{kind:?}")
        .chars()
        .filter(char::is_ascii_alphanumeric)
    {
        if c.is_ascii_uppercase() && !token.is_empty() {
            token.push('_');
        }
        token.push(c.to_ascii_lowercase());
    }
    token
}
/// Connection-level h2 failures only; stream resets say nothing about the
/// connection. Synthetic `BrokenPipe` is h2's marker for a peer EOF, and
/// tokio-rustls reports TLS record failures as `InvalidData`.
fn h2_close(error: &h2::Error) -> Option<Close> {
    if error.is_go_away() {
        return Some(Close::GoAway {
            code: error.reason().map_or(0, u32::from),
            remote: error.is_remote(),
        });
    }
    Some(match error.get_io()?.kind() {
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::UnexpectedEof => Close::PeerClosed,
        std::io::ErrorKind::InvalidData => Close::Tls,
        kind => Close::Io(kind),
    })
}
/// A failed check on a connection that has closed reports the close, but only
/// for failures the close explains. An answer the endpoint gave (407, another
/// status) or a local TLS/profile failure keeps its error: callers treat
/// those as permanent.
fn on_closed(error: Error, closed: Option<Close>) -> Error {
    let transport = matches!(
        error,
        Error::Protocol
            | Error::Connect
            | Error::ConnectIo(_)
            | Error::Io
            | Error::Credit
            | Error::Timeout
    );
    match closed {
        Some(close) if transport => Error::Closed(close),
        _ => error,
    }
}
#[cfg(test)]
mod on_closed_tests {
    use super::*;
    #[test]
    fn only_transport_failures_become_the_close() {
        let closes = [
            Close::PeerClosed,
            Close::GoAway {
                code: 0xb,
                remote: true,
            },
            Close::QuicApplication(0x100),
            Close::StatelessReset,
        ];
        for close in closes {
            // H2/H3 checks fail with these on a closed connection; Hysteria
            // with `Connect`.
            for error in [
                Error::Protocol,
                Error::Connect,
                Error::ConnectIo(std::io::ErrorKind::BrokenPipe),
                Error::Io,
                Error::Credit,
                Error::Timeout,
            ] {
                assert!(matches!(on_closed(error, Some(close)), Error::Closed(c) if c == close));
            }
            for error in [
                Error::Authentication,
                Error::Rejected(407),
                Error::Rejected(503),
                Error::Tls,
                Error::Trust,
                Error::Profile,
                Error::Unsupported("x"),
                Error::Destination,
            ] {
                let kept = format!("{error:?}");
                assert_eq!(format!("{:?}", on_closed(error, Some(close))), kept);
            }
        }
        assert!(matches!(on_closed(Error::Protocol, None), Error::Protocol));
    }
}
/// The first connection-level error h2 recorded, if any. h2 keeps it for
/// every handle and never overwrites it, so a GOAWAY stays visible after the
/// EOF behind it. One poll with a no-op waker: it only reads that state.
fn connection_close(sender: &h2::client::SendRequest<Bytes>) -> Option<Close> {
    let mut probe = sender.clone();
    match probe.poll_ready(&mut Context::from_waker(std::task::Waker::noop())) {
        Poll::Ready(Err(error)) => h2_close(&error),
        _ => None,
    }
}
fn quic_close(error: &quinn::ConnectionError) -> Close {
    use quinn::ConnectionError as E;
    match error {
        E::ApplicationClosed(close) => Close::QuicApplication(close.error_code.into_inner()),
        E::ConnectionClosed(close) => Close::QuicTransport {
            code: u64::from(close.error_code),
            remote: true,
        },
        E::TransportError(error) => Close::QuicTransport {
            code: u64::from(error.code),
            remote: false,
        },
        E::TimedOut => Close::IdleTimeout,
        E::Reset => Close::StatelessReset,
        E::LocallyClosed => Close::Local,
        E::VersionMismatch | E::CidsExhausted => Close::QuicTransport {
            code: 0,
            remote: false,
        },
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

/// All unsupported security-sensitive fields fail closed. Routes are not applied by diagnostic mode.
pub fn check_capabilities(p: &Profile) -> Result<()> {
    p.validate().map_err(|_| Error::Profile)?;
    let e = &p.endpoint;
    if e.skip_verification {
        return Err(Error::Unsupported("disabled certificate verification"));
    }
    if !e.custom_sni.is_empty() && e.custom_sni != e.hostname {
        return Err(Error::Unsupported("separate SNI and verification identity"));
    }
    if e.anti_dpi {
        return Err(Error::Unsupported("anti-DPI"));
    }
    if !e.client_random_prefix.is_empty() {
        return Err(Error::Unsupported("TLS client_random prefix"));
    }
    for (k, v) in &e.extra {
        if k != "tls_profile" || v.as_str() != Some("default") {
            return Err(Error::Unsupported(
                "additional endpoint options / TLS fingerprint",
            ));
        }
    }
    Ok(())
}

/// The flag records whether the endpoint relays IPv6 (`has_ipv6` in the profile).
#[derive(Clone)]
pub struct Session(Transport, bool, Arc<liveness::Liveness>);
#[derive(Clone)]
enum Transport {
    H2(H2Session),
    H3(h3transport::H3Session),
    Hysteria(hysteria::HysteriaSession),
    Amnezia(amnezia::AmneziaSession),
}
/// Closed diagnostic vocabulary; never includes the profile's raw transport string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlannedTransport {
    H2,
    H3,
    Hysteria,
    AmneziaWg,
    Unknown,
}
/// Mirrors connect/connect_marked selection without opening a socket.
pub fn planned_transport(p: &Profile) -> PlannedTransport {
    match p.protocol {
        rtrust_profile::Protocol::AmneziaWg => PlannedTransport::AmneziaWg,
        rtrust_profile::Protocol::Hysteria2 => PlannedTransport::Hysteria,
        rtrust_profile::Protocol::TrustTunnel if p.endpoint.upstream_protocol == "http3" => {
            PlannedTransport::H3
        }
        rtrust_profile::Protocol::TrustTunnel => PlannedTransport::H2,
    }
}
impl Session {
    fn new(transport: Transport, ipv6: bool) -> Self {
        Self(
            transport,
            ipv6,
            Arc::new(liveness::Liveness::new(liveness::SILENCE)),
        )
    }
    /// Test hook: a shorter silence window, set before any flow is opened.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn with_silence(mut self, silence: Duration) -> Self {
        self.2 = Arc::new(liveness::Liveness::new(silence));
        self
    }
    pub async fn connect(p: &Profile) -> Result<Self> {
        check_capabilities(p)?;
        tokio::time::timeout(Duration::from_secs(20), async {
            if p.protocol == rtrust_profile::Protocol::AmneziaWg {
                return Ok(Self::new(
                    Transport::Amnezia(amnezia::AmneziaSession::connect(p, None, None).await?),
                    p.endpoint.has_ipv6,
                ));
            }
            if p.protocol == rtrust_profile::Protocol::Hysteria2 {
                return Ok(Self::new(
                    Transport::Hysteria(hysteria::HysteriaSession::connect(p, None, None).await?),
                    p.endpoint.has_ipv6,
                ));
            }
            if p.endpoint.upstream_protocol == "http3" {
                Ok(Self::new(
                    Transport::H3(h3transport::H3Session::connect(p, None, None).await?),
                    p.endpoint.has_ipv6,
                ))
            } else {
                Ok(Self::new(
                    Transport::H2(H2Session::connect(p).await?),
                    p.endpoint.has_ipv6,
                ))
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    /// Linux service transport bypass. Only numeric, pre-resolved addresses are accepted.
    #[cfg(target_os = "linux")]
    pub async fn connect_marked(p: &Profile, mark: u32) -> Result<Self> {
        check_capabilities(p)?;
        if p.protocol == rtrust_profile::Protocol::AmneziaWg && mark != 0 {
            return tokio::time::timeout(
                Duration::from_secs(20),
                amnezia::AmneziaSession::connect(p, Some(mark), None),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map(|s| Self::new(Transport::Amnezia(s), p.endpoint.has_ipv6));
        }
        if p.protocol == rtrust_profile::Protocol::Hysteria2 && mark != 0 {
            return tokio::time::timeout(
                Duration::from_secs(20),
                hysteria::HysteriaSession::connect(p, Some(mark), None),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map(|s| Self::new(Transport::Hysteria(s), p.endpoint.has_ipv6));
        }
        if mark == 0 {
            return Err(Error::Unsupported("marked transport requires a mark"));
        }
        if p.endpoint.upstream_protocol == "http3" {
            return tokio::time::timeout(
                Duration::from_secs(20),
                h3transport::H3Session::connect(p, Some(mark), None),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map(|s| Self::new(Transport::H3(s), p.endpoint.has_ipv6));
        }
        let session = tokio::time::timeout(
            Duration::from_secs(20),
            H2Session::connect_inner(p, Some(mark), None),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(Self::new(Transport::H2(session), p.endpoint.has_ipv6))
    }
    #[cfg(unix)]
    pub async fn connect_protected(p: &Profile, protector: &SocketProtector) -> Result<Self> {
        check_capabilities(p)?;
        if p.protocol == rtrust_profile::Protocol::AmneziaWg {
            return tokio::time::timeout(
                Duration::from_secs(20),
                amnezia::AmneziaSession::connect(p, None, Some(protector)),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map(|s| Self::new(Transport::Amnezia(s), p.endpoint.has_ipv6));
        }
        if p.protocol == rtrust_profile::Protocol::Hysteria2 {
            return tokio::time::timeout(
                Duration::from_secs(20),
                hysteria::HysteriaSession::connect(p, None, Some(protector)),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map(|s| Self::new(Transport::Hysteria(s), p.endpoint.has_ipv6));
        }
        if p.endpoint.upstream_protocol == "http3" {
            return tokio::time::timeout(
                Duration::from_secs(20),
                h3transport::H3Session::connect(p, None, Some(protector)),
            )
            .await
            .map_err(|_| Error::Timeout)?
            .map(|s| Self::new(Transport::H3(s), p.endpoint.has_ipv6));
        }
        if p.endpoint
            .addresses
            .iter()
            .any(|address| address.parse::<std::net::SocketAddr>().is_err())
        {
            return Err(Error::Unsupported(
                "resolve endpoint on the underlying network before VPN setup",
            ));
        }
        let session = tokio::time::timeout(
            Duration::from_secs(20),
            H2Session::connect_inner(p, None, Some(protector)),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(Self::new(Transport::H2(session), p.endpoint.has_ipv6))
    }
    /// Why the underlying connection closed, once it has.
    pub fn closed(&self) -> Option<Close> {
        match &self.0 {
            Transport::H2(s) => s.0.closed.get().copied(),
            Transport::H3(s) => s.closed(),
            Transport::Hysteria(s) => s.closed(),
            Transport::Amnezia(_) => None,
        }
    }
    /// Stable transport token for event logs.
    pub fn transport_name(&self) -> &'static str {
        match &self.0 {
            Transport::H2(_) => "h2",
            Transport::H3(_) => "h3",
            Transport::Hysteria(_) => "hysteria2",
            Transport::Amnezia(_) => "amneziawg",
        }
    }
    /// False when the endpoint has no IPv6 egress; IPv6 flows must fail locally.
    pub fn ipv6(&self) -> bool {
        self.1
    }
    /// Fails when the endpoint stopped answering, and also when outbound
    /// traffic has stayed unanswered while opens to several destinations failed
    /// or stayed silent.
    /// A transport failure on a closed connection is `Error::Closed` with
    /// its reason.
    pub async fn health(&self) -> Result<()> {
        let checked = match &self.0 {
            Transport::H2(s) => s.health().await,
            Transport::H3(s) => s.health().await,
            Transport::Hysteria(s) => s.health().await,
            Transport::Amnezia(s) => s.health().await,
        };
        if let Err(error) = checked {
            return Err(on_closed(error, self.closed()));
        }
        match self.2.degraded() {
            None => Ok(()),
            Some((proven, kind)) => Err(Error::Degraded { proven, kind }),
        }
    }
    pub async fn open_tcp(&self, target: &str) -> Result<Tunnel> {
        rtrust_profile::validate_address(target).map_err(|_| Error::Destination)?;
        // A CONNECT is demand of its own (a flow that never opens never
        // writes), dated from its start once its outcome counts as evidence.
        let started = self.2.now();
        let opened = match &self.0 {
            Transport::H2(s) => s.open_tcp(target).await,
            Transport::H3(s) => s.open(target).await,
            Transport::Hysteria(s) => s.open_tcp(target).await,
            Transport::Amnezia(s) => s.open_tcp(target).await,
        };
        self.track(opened, Some((target, started)))
    }
    pub async fn open_icmp(&self) -> Result<Tunnel> {
        let opened = match &self.0 {
            Transport::H2(s) => s.open("_icmp").await,
            Transport::H3(s) => s.open("_icmp").await,
            Transport::Hysteria(_) => {
                return Err(Error::Unsupported("Hysteria does not relay ICMP"));
            }
            Transport::Amnezia(_) => return Err(Error::Unsupported("ICMP relay over AmneziaWG")),
        };
        self.track(opened, None)
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        let opened = match &self.0 {
            Transport::H2(s) => s.open_udp().await,
            Transport::H3(s) => s.open("_udp2").await,
            Transport::Hysteria(s) => s.open_udp().await,
            Transport::Amnezia(s) => s.open_udp().await,
        };
        self.track(opened, None)
    }
    /// `flow`: target and start of a per-destination TCP CONNECT, the only open
    /// that counts as evidence (see `Liveness::opened`). Every tunnel still
    /// records its traffic.
    fn track(&self, opened: Result<Tunnel>, flow: Option<(&str, Duration)>) -> Result<Tunnel> {
        if let Err(Error::Credit) = opened {
            liveness::FLOWS
                .credit
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        if let Some((target, started)) = flow {
            self.2.opened(
                &opened.as_ref().map(|_| ()).map_err(Clone::clone),
                target,
                started,
            );
        }
        opened.map(|mut tunnel| {
            if let Some((target, _)) = flow {
                liveness::FLOWS
                    .opened
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tunnel.watch = self.2.watch(target);
            }
            tunnel.liveness = Some(self.2.clone());
            tunnel
        })
    }
}
struct Inner {
    sender: h2::client::SendRequest<Bytes>,
    auth: http::HeaderValue,
    driver: tokio::task::JoinHandle<()>,
    /// First connection-level failure, from the driver or a request.
    closed: Arc<std::sync::OnceLock<Close>>,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
#[derive(Clone)]
pub struct H2Session(Arc<Inner>);
impl H2Session {
    pub async fn connect(p: &Profile) -> Result<Self> {
        check_capabilities(p)?;
        tokio::time::timeout(Duration::from_secs(20), Self::connect_inner(p, None, None))
            .await
            .map_err(|_| Error::Timeout)?
    }
    async fn connect_inner(
        p: &Profile,
        mark: Option<u32>,
        protector: Option<&SocketProtector>,
    ) -> Result<Self> {
        let mut config = tls_config(p)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(p.endpoint.hostname.clone())
            .map_err(|_| Error::Profile)?;
        let mut connected = None;
        let mut failure = Error::Connect;
        for address in &p.endpoint.addresses {
            // A failed address must not consume the entire global timeout.
            match tokio::time::timeout(
                Duration::from_secs(4),
                connect_tcp(address, mark, protector),
            )
            .await
            {
                Ok(Ok(tcp)) => {
                    connected = Some(tcp);
                    break;
                }
                Ok(Err(error)) => failure = Error::ConnectIo(error.kind()),
                Err(_) => failure = Error::Timeout,
            }
        }
        let tcp = connected.ok_or(failure)?;
        tcp.set_nodelay(true)?;
        let tls = connector.connect(name, tcp).await.map_err(|error| {
            // EOF/reset while an endpoint restarts is a transport failure, not
            // evidence of an invalid certificate. Never log the error payload.
            if error
                .get_ref()
                .is_some_and(|cause| cause.is::<rustls::Error>())
            {
                Error::Tls
            } else {
                Error::ConnectIo(error.kind())
            }
        })?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(Error::Protocol);
        }
        let (sender, connection) = h2::client::Builder::new()
            .initial_window_size(131_072)
            .initial_connection_window_size(1_048_576)
            .handshake(tls)
            .await
            .map_err(|_| Error::Protocol)?;
        let credentials = Zeroizing::new(format!(
            "{}:{}",
            p.endpoint.username.expose(),
            p.endpoint.password.expose()
        ));
        let auth_text = Zeroizing::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
        ));
        let mut auth = http::HeaderValue::from_str(&auth_text).map_err(|_| Error::Profile)?;
        auth.set_sensitive(true);
        let closed = Arc::new(std::sync::OnceLock::new());
        let record = closed.clone();
        // Aborted with `Inner`, which aborts the driver before its own sender
        // drops, so this handle changes nothing about how the connection ends.
        let streams = sender.clone();
        let driver = tokio::spawn(async move {
            let ended = connection.await;
            let close = connection_close(&streams)
                .or_else(|| ended.as_ref().err().and_then(h2_close))
                .unwrap_or(Close::PeerClosed);
            let _ = record.set(close);
        });
        Ok(Self(Arc::new(Inner {
            sender,
            auth,
            driver,
            closed,
        })))
    }
    /// Records a connection-level failure; the caller's error stays `Protocol`.
    /// The connection's own first error wins over the stream's: an open
    /// stream ends with `BrokenPipe` on the EOF that follows a GOAWAY.
    fn lost(&self, error: h2::Error) -> Error {
        if let Some(close) = connection_close(&self.0.sender).or_else(|| h2_close(&error)) {
            let _ = self.0.closed.set(close);
        }
        Error::Protocol
    }
    async fn stream(&self, authority: &str) -> Result<(h2::RecvStream, h2::SendStream<Bytes>)> {
        let uri = http::Uri::builder()
            .authority(authority)
            .build()
            .map_err(|_| Error::Destination)?;
        let request = Request::builder()
            .method("CONNECT")
            .uri(uri)
            .header("user-agent", "rtrust/0.1")
            .header("proxy-authorization", self.0.auth.clone())
            .body(())
            .map_err(|_| Error::Destination)?;
        // One deadline for readiness and the response, as on HTTP/3. Each
        // request uses a fresh clone, which h2 lets queue one stream past the
        // endpoint's concurrency limit, so credit starvation mostly ends below
        // as `Timeout`; a handle that does wait here ends as `Credit`. Both
        // are failed opens.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut sender = tokio::time::timeout_at(deadline, self.0.sender.clone().ready())
            .await
            .map_err(|_| Error::Credit)?
            .map_err(|e| self.lost(e))?;
        let (response, send) = sender
            .send_request(request, authority == "_check")
            .map_err(|e| self.lost(e))?;
        let response = tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|e| self.lost(e))?;
        match response.status() {
            StatusCode::OK => Ok((response.into_body(), send)),
            StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err(Error::Authentication),
            code => Err(Error::Rejected(code.as_u16())),
        }
    }
    pub async fn health(&self) -> Result<()> {
        let _ = self.stream("_check").await?;
        Ok(())
    }
    pub async fn open_tcp(&self, authority: &str) -> Result<Tunnel> {
        rtrust_profile::validate_address(authority).map_err(|_| Error::Destination)?;
        self.open(authority).await
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        self.open("_udp2").await
    }
    async fn open(&self, authority: &str) -> Result<Tunnel> {
        let (mut recv, mut send) = self.stream(authority).await?;
        let (client, bridge) = tokio::io::duplex(64 * 1024);
        let (mut reader, mut writer) = tokio::io::split(bridge);
        let session = self.clone();
        let pump = tokio::spawn(async move {
            let _session = session;
            let upload = async {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    let count = reader.read(&mut buf).await?;
                    if count == 0 {
                        send.send_data(Bytes::new(), true).map_err(|_| Error::Io)?;
                        return Ok::<_, Error>(());
                    }
                    let mut data = Bytes::copy_from_slice(&buf[..count]);
                    while !data.is_empty() {
                        send.reserve_capacity(data.len());
                        let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
                            .await
                            .ok_or(Error::Io)?
                            .map_err(|_| Error::Io)?;
                        if cap == 0 {
                            continue;
                        }
                        let n = cap.min(data.len());
                        send.send_data(data.split_to(n), false)
                            .map_err(|_| Error::Io)?;
                    }
                }
            };
            let download = async {
                while let Some(data) = recv.data().await {
                    let data = data.map_err(|_| Error::Io)?;
                    writer.write_all(&data).await?;
                    recv.flow_control()
                        .release_capacity(data.len())
                        .map_err(|_| Error::Io)?;
                }
                writer.shutdown().await?;
                Ok::<_, Error>(())
            };
            let _ = tokio::try_join!(upload, download);
        });
        Ok(Tunnel {
            io: client,
            pump,
            liveness: None,
            watch: Default::default(),
        })
    }
}

pub struct Tunnel {
    io: DuplexStream,
    pump: tokio::task::JoinHandle<()>,
    /// The owning session's evidence; set by `Session`, never shared across sessions.
    liveness: Option<Arc<liveness::Liveness>>,
    /// Whether this TCP flow's first write was answered (verdict B).
    watch: liveness::Watch,
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.pump.abort();
        liveness::closed(self.watch);
    }
}
impl AsyncRead for Tunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let polled = Pin::new(&mut this.io).poll_read(cx, buf);
        if let (Some(liveness), Poll::Ready(Ok(()))) = (&this.liveness, &polled)
            && buf.filled().len() > before
        {
            liveness.inbound();
            liveness.read(&mut this.watch);
        }
        polled
    }
}
impl AsyncWrite for Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.io).poll_write(cx, buf);
        if let (Some(liveness), Poll::Ready(Ok(1..))) = (&this.liveness, &polled) {
            liveness.outbound();
            liveness.wrote(&mut this.watch);
        }
        polled
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// Explicit, bounded HTTP request through the tunnel. A success is data-plane evidence, not a system VPN.
pub async fn probe_http(p: &Profile, destination: &str) -> Result<String> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let session = Session::connect(p).await?;
        session.health().await?;
        let mut stream = session.open_tcp(destination).await?;
        stream
            .write_all(
                format!("GET / HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        use tokio::io::AsyncBufReadExt;
        let mut response = Vec::new();
        let mut reader = tokio::io::BufReader::new(stream.take(512));
        reader.read_until(b'\n', &mut response).await?;
        if !response.ends_with(b"\r\n") {
            return Err(Error::Protocol);
        }
        let first = std::str::from_utf8(&response).map_err(|_| Error::Protocol)?;
        let mut fields = first.split_whitespace();
        if !fields.next().is_some_and(|s| s.starts_with("HTTP/1.")) {
            return Err(Error::Protocol);
        }
        let status = fields
            .next()
            .and_then(|s| s.parse::<u16>().ok())
            .filter(|n| (100..600).contains(n))
            .ok_or(Error::Protocol)?;
        Ok(format!(
            "HTTP {status}: response received through authenticated {} tunnel",
            p.transport_name()
        ))
    })
    .await
    .map_err(|_| Error::Timeout)?
}

fn tls_config(p: &Profile) -> Result<rustls::ClientConfig> {
    tls_config_with_ca(&p.endpoint.certificate)
}
fn tls_config_with_ca(certificate: &str) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls)?
        .with_root_certificates(trust_roots(certificate)?)
        .with_no_client_auth();

    Ok(config)
}
/// The profile's custom CA, or the platform roots when none is embedded.
fn trust_roots(certificate: &str) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    if certificate.is_empty() {
        #[cfg(any(target_os = "android", target_os = "ios"))]
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let native = rustls_native_certs::load_native_certs();
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        for cert in native.certs {
            let _ = roots.add(cert);
        }
    } else {
        for cert in rustls_pemfile::certs(&mut certificate.as_bytes()) {
            roots
                .add(cert.map_err(|_| Error::Trust)?)
                .map_err(|_| Error::Trust)?;
        }
    }
    if roots.is_empty() {
        return Err(Error::Trust);
    }
    Ok(roots)
}

async fn connect_tcp(
    address: &str,
    mark: Option<u32>,
    protector: Option<&SocketProtector>,
) -> std::io::Result<TcpStream> {
    #[cfg(unix)]
    if mark.is_some() || protector.is_some() {
        use std::os::fd::AsRawFd;
        let address: std::net::SocketAddr = address
            .parse()
            .map_err(|_| std::io::Error::other("Numeric endpoint required"))?;
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        #[cfg(target_os = "linux")]
        if let Some(mark) = mark {
            // Set before connect: even SYN packets must bypass the full-tunnel policy.
            let result = unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    (&mark as *const u32).cast(),
                    std::mem::size_of_val(&mark) as libc::socklen_t,
                )
            };
            if result != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        if let Some(protect) = protector {
            protect(socket.as_raw_fd())?;
        }
        return socket.connect(address).await;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (mark, protector);
    TcpStream::connect(address).await
}

/// Explicit mobile split-routing path. The caller must protect and bind every socket.
#[cfg(unix)]
pub async fn direct_tcp(
    destination: std::net::SocketAddr,
    protect: &SocketProtector,
) -> Result<TcpStream> {
    tokio::time::timeout(
        Duration::from_secs(15),
        connect_tcp(&destination.to_string(), None, Some(protect)),
    )
    .await
    .map_err(|_| Error::Timeout)?
    .map_err(Into::into)
}
#[cfg(not(unix))]
pub async fn direct_tcp(
    _destination: std::net::SocketAddr,
    _protect: &SocketProtector,
) -> Result<TcpStream> {
    Err(Error::Unsupported("direct mobile route on this platform"))
}
pub async fn direct_udp(
    destination: std::net::SocketAddr,
    protect: &SocketProtector,
) -> Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let bind = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        socket.set_nonblocking(true)?;
        protect(socket.as_raw_fd())?;
        socket.connect(destination)?;
        Ok(tokio::net::UdpSocket::from_std(socket)?)
    }
    #[cfg(not(unix))]
    {
        let _ = (destination, protect);
        Err(Error::Unsupported("direct mobile route on this platform"))
    }
}
