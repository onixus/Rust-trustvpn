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
mod vless;
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
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

/// All unsupported security-sensitive fields fail closed. Routes are not applied by diagnostic mode.
pub fn check_capabilities(p: &Profile) -> Result<()> {
    p.validate().map_err(|_| Error::Profile)?;
    // XHTTP links import for export, but only the WebSocket transport connects.
    if p.vless.as_ref().is_some_and(|v| v.transport != "ws") {
        return Err(Error::Unsupported("VLESS XHTTP transport"));
    }
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
    Vless(vless::VlessSession),
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
            use rtrust_profile::Protocol;
            let transport = match p.protocol {
                Protocol::AmneziaWg => {
                    Transport::Amnezia(amnezia::AmneziaSession::connect(p, None, None).await?)
                }
                Protocol::Hysteria2 => {
                    Transport::Hysteria(hysteria::HysteriaSession::connect(p, None, None).await?)
                }
                Protocol::Vless => {
                    Transport::Vless(vless::VlessSession::connect(p, None, None).await?)
                }
                Protocol::TrustTunnel if p.endpoint.upstream_protocol == "http3" => {
                    Transport::H3(h3transport::H3Session::connect(p, None, None).await?)
                }
                Protocol::TrustTunnel => Transport::H2(H2Session::connect(p).await?),
            };
            Ok(Self::new(transport, p.endpoint.has_ipv6))
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    /// Linux service transport bypass. Only numeric, pre-resolved addresses are accepted.
    #[cfg(target_os = "linux")]
    pub async fn connect_marked(p: &Profile, mark: u32) -> Result<Self> {
        check_capabilities(p)?;
        if mark == 0 {
            return Err(Error::Unsupported("marked transport requires a mark"));
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            use rtrust_profile::Protocol;
            let mark = Some(mark);
            let transport = match p.protocol {
                Protocol::AmneziaWg => {
                    Transport::Amnezia(amnezia::AmneziaSession::connect(p, mark, None).await?)
                }
                Protocol::Hysteria2 => {
                    Transport::Hysteria(hysteria::HysteriaSession::connect(p, mark, None).await?)
                }
                Protocol::Vless => {
                    Transport::Vless(vless::VlessSession::connect(p, mark, None).await?)
                }
                Protocol::TrustTunnel if p.endpoint.upstream_protocol == "http3" => {
                    Transport::H3(h3transport::H3Session::connect(p, mark, None).await?)
                }
                Protocol::TrustTunnel => {
                    Transport::H2(H2Session::connect_inner(p, mark, None).await?)
                }
            };
            Ok(Self::new(transport, p.endpoint.has_ipv6))
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    #[cfg(unix)]
    pub async fn connect_protected(p: &Profile, protector: &SocketProtector) -> Result<Self> {
        check_capabilities(p)?;
        use rtrust_profile::Protocol;
        if p.protocol == Protocol::TrustTunnel
            && p.endpoint.upstream_protocol != "http3"
            && p.endpoint
                .addresses
                .iter()
                .any(|address| address.parse::<std::net::SocketAddr>().is_err())
        {
            return Err(Error::Unsupported(
                "resolve endpoint on the underlying network before VPN setup",
            ));
        }
        tokio::time::timeout(Duration::from_secs(20), async {
            let protector = Some(protector);
            let transport = match p.protocol {
                Protocol::AmneziaWg => {
                    Transport::Amnezia(amnezia::AmneziaSession::connect(p, None, protector).await?)
                }
                Protocol::Hysteria2 => Transport::Hysteria(
                    hysteria::HysteriaSession::connect(p, None, protector).await?,
                ),
                Protocol::Vless => {
                    Transport::Vless(vless::VlessSession::connect(p, None, protector).await?)
                }
                Protocol::TrustTunnel if p.endpoint.upstream_protocol == "http3" => {
                    Transport::H3(h3transport::H3Session::connect(p, None, protector).await?)
                }
                Protocol::TrustTunnel => {
                    Transport::H2(H2Session::connect_inner(p, None, protector).await?)
                }
            };
            Ok(Self::new(transport, p.endpoint.has_ipv6))
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    /// False when the endpoint has no IPv6 egress; IPv6 flows must fail locally.
    pub fn ipv6(&self) -> bool {
        self.1
    }
    /// Fails when the endpoint stopped answering, and also when outbound
    /// traffic has stayed unanswered while opens to several destinations failed
    /// or stayed silent.
    pub async fn health(&self) -> Result<()> {
        match &self.0 {
            Transport::H2(s) => s.health().await?,
            Transport::H3(s) => s.health().await?,
            Transport::Hysteria(s) => s.health().await?,
            Transport::Amnezia(s) => s.health().await?,
            Transport::Vless(s) => s.health().await?,
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
            Transport::Vless(s) => s.open_tcp(target).await,
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
            Transport::Vless(_) => return Err(Error::Unsupported("ICMP relay over VLESS")),
        };
        self.track(opened, None)
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        let opened = match &self.0 {
            Transport::H2(s) => s.open_udp().await,
            Transport::H3(s) => s.open("_udp2").await,
            Transport::Hysteria(s) => s.open_udp().await,
            Transport::Amnezia(s) => s.open_udp().await,
            Transport::Vless(s) => s.open_udp().await,
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
        // Credentials of another protocol are never sent as TrustTunnel CONNECT auth.
        if p.protocol != rtrust_profile::Protocol::TrustTunnel {
            return Err(Error::Unsupported(
                "TrustTunnel transport for another protocol",
            ));
        }
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
        let tls = connector.connect(name, tcp).await.map_err(tls_failure)?;
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
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self(Arc::new(Inner {
            sender,
            auth,
            driver,
        })))
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
            .map_err(|_| Error::Protocol)?;
        let (response, send) = sender
            .send_request(request, authority == "_check")
            .map_err(|_| Error::Protocol)?;
        let response = tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| Error::Timeout)?
            .map_err(|_| Error::Protocol)?;
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

/// EOF/reset while an endpoint restarts is a transport failure, not evidence
/// of an invalid certificate. Never log the error payload.
fn tls_failure(error: std::io::Error) -> Error {
    if error
        .get_ref()
        .is_some_and(|cause| cause.is::<rustls::Error>())
    {
        Error::Tls
    } else {
        Error::ConnectIo(error.kind())
    }
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
