//! TrustTunnel HTTP/2 and HTTP/3 transport. This is not a system VPN: it never modifies routes or DNS.
mod h3transport;
pub mod icmp;
pub mod proxy;
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
    #[error("Tunnel I/O failed")]
    Io,
    #[error("Invalid destination authority")]
    Destination,
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

#[derive(Clone)]
pub struct Session(Transport);
#[derive(Clone)]
enum Transport {
    H2(H2Session),
    H3(h3transport::H3Session),
}
impl Session {
    pub async fn connect(p: &Profile) -> Result<Self> {
        check_capabilities(p)?;
        tokio::time::timeout(Duration::from_secs(20), async {
            if p.endpoint.upstream_protocol == "http3" {
                Ok(Self(Transport::H3(
                    h3transport::H3Session::connect(p).await?,
                )))
            } else {
                Ok(Self(Transport::H2(H2Session::connect(p).await?)))
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    /// Linux service transport bypass. Only numeric, pre-resolved addresses are accepted.
    #[cfg(target_os = "linux")]
    pub async fn connect_marked(p: &Profile, mark: u32) -> Result<Self> {
        check_capabilities(p)?;
        if p.endpoint.upstream_protocol != "http2" || mark == 0 {
            return Err(Error::Unsupported("marked transport requires HTTP/2"));
        }
        let session = tokio::time::timeout(
            Duration::from_secs(20),
            H2Session::connect_inner(p, Some(mark)),
        )
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(Self(Transport::H2(session)))
    }
    pub async fn health(&self) -> Result<()> {
        match &self.0 {
            Transport::H2(s) => s.health().await,
            Transport::H3(s) => s.health().await,
        }
    }
    pub async fn open_tcp(&self, target: &str) -> Result<Tunnel> {
        rtrust_profile::validate_address(target).map_err(|_| Error::Destination)?;
        match &self.0 {
            Transport::H2(s) => s.open_tcp(target).await,
            Transport::H3(s) => s.open(target).await,
        }
    }
    pub async fn open_icmp(&self) -> Result<Tunnel> {
        match &self.0 {
            Transport::H2(s) => s.open("_icmp").await,
            Transport::H3(s) => s.open("_icmp").await,
        }
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        match &self.0 {
            Transport::H2(s) => s.open_udp().await,
            Transport::H3(s) => s.open("_udp2").await,
        }
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
        tokio::time::timeout(Duration::from_secs(20), Self::connect_inner(p, None))
            .await
            .map_err(|_| Error::Timeout)?
    }
    async fn connect_inner(p: &Profile, mark: Option<u32>) -> Result<Self> {
        let mut config = tls_config(p)?;
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let name = rustls::pki_types::ServerName::try_from(p.endpoint.hostname.clone())
            .map_err(|_| Error::Profile)?;
        let mut connected = None;
        for address in &p.endpoint.addresses {
            // A failed address must not consume the entire global timeout.
            if let Ok(Ok(tcp)) =
                tokio::time::timeout(Duration::from_secs(4), connect_tcp(address, mark)).await
            {
                connected = Some(tcp);
                break;
            }
        }
        let tcp = connected.ok_or(Error::Connect)?;
        tcp.set_nodelay(true)?;
        let tls = connector.connect(name, tcp).await.map_err(|_| Error::Tls)?;
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
        let mut sender = self
            .0
            .sender
            .clone()
            .ready()
            .await
            .map_err(|_| Error::Protocol)?;
        let (response, send) = sender
            .send_request(request, authority == "_check")
            .map_err(|_| Error::Protocol)?;
        let response = tokio::time::timeout(Duration::from_secs(10), response)
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
        Ok(Tunnel { io: client, pump })
    }
}

pub struct Tunnel {
    io: DuplexStream,
    pump: tokio::task::JoinHandle<()>,
}
impl Drop for Tunnel {
    fn drop(&mut self) {
        self.pump.abort();
    }
}
impl AsyncRead for Tunnel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for Tunnel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
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
            p.endpoint.upstream_protocol
        ))
    })
    .await
    .map_err(|_| Error::Timeout)?
}

fn tls_config(p: &Profile) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    if p.endpoint.certificate.is_empty() {
        let native = rustls_native_certs::load_native_certs();
        for cert in native.certs {
            let _ = roots.add(cert);
        }
    } else {
        for cert in rustls_pemfile::certs(&mut p.endpoint.certificate.as_bytes()) {
            roots
                .add(cert.map_err(|_| Error::Trust)?)
                .map_err(|_| Error::Trust)?;
        }
    }
    if roots.is_empty() {
        return Err(Error::Trust);
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Tls)?
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(config)
}

async fn connect_tcp(address: &str, mark: Option<u32>) -> std::io::Result<TcpStream> {
    #[cfg(target_os = "linux")]
    if let Some(mark) = mark {
        use std::os::fd::AsRawFd;
        let address: std::net::SocketAddr = address
            .parse()
            .map_err(|_| std::io::Error::other("Numeric endpoint required"))?;
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
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
        return socket.connect(address).await;
    }
    #[cfg(not(target_os = "linux"))]
    let _ = mark;
    TcpStream::connect(address).await
}
