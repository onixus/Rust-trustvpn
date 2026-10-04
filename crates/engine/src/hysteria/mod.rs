//! Hysteria 2 QUIC transport, independent of TrustTunnel HTTP/3 CONNECT.
mod brutal;
pub(crate) mod datagrams;
mod gecko;
mod hop;
mod obfs;
use super::*;
use quinn::Runtime;
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicU32, Ordering},
    },
};
type DatagramRoutes = Arc<Mutex<HashMap<u32, tokio::sync::mpsc::Sender<Bytes>>>>;
#[derive(Clone)]
pub struct HysteriaSession(Arc<Inner>);
struct Inner {
    endpoint: quinn::Endpoint,
    _sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    connection: quinn::Connection,
    h3: tokio::task::JoinHandle<()>,
    datagrams: tokio::task::JoinHandle<()>,
    routes: DatagramRoutes,
    fragment_slots: Arc<tokio::sync::Semaphore>,
    fragment_bytes: Arc<tokio::sync::Semaphore>,
    udp_slots: Arc<tokio::sync::Semaphore>,
    next_id: AtomicU32,
    udp: bool,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.h3.abort();
        self.datagrams.abort();
        self.endpoint.close(0u32.into(), b"")
    }
}
impl HysteriaSession {
    pub async fn connect(
        p: &Profile,
        mark: Option<u32>,
        protector: Option<&SocketProtector>,
    ) -> Result<Self> {
        let options = p.hysteria2.as_ref().ok_or(Error::Profile)?;
        if p.endpoint.skip_verification {
            return Err(Error::Unsupported(
                "Hysteria certificate verification override",
            ));
        }
        let mut tls = tls_config(p)?;
        if !options.pin_sha256.is_empty() {
            tls.dangerous()
                .set_certificate_verifier(Arc::new(PinnedCertificate::new(p, options)?));
        }
        tls.alpn_protocols = vec![b"h3".to_vec()];
        if !options.client_certificate.is_empty() {
            tls.client_auth_cert_resolver = Arc::new(ClientCertificate::load(options)?);
        }
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Error::Tls)?;
        let mut config = quinn::ClientConfig::new(Arc::new(quic));
        let mut transport = quinn::TransportConfig::default();
        let quic = &options.quic;
        transport.keep_alive_interval(Some(Duration::from_millis(quic.keep_alive_period_ms())));
        transport.max_idle_timeout(Some(
            Duration::from_millis(quic.idle_timeout_ms())
                .try_into()
                .map_err(|_| Error::Protocol)?,
        ));
        if quic.stream_receive_window != 0 {
            transport.stream_receive_window(
                quic.stream_receive_window
                    .try_into()
                    .map_err(|_| Error::Profile)?,
            );
        }
        if quic.connection_receive_window != 0 {
            transport.receive_window(
                quic.connection_receive_window
                    .try_into()
                    .map_err(|_| Error::Profile)?,
            );
        }
        let fallback: Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> =
            match options.congestion.as_str() {
                "bbr" => Arc::new(quinn::congestion::BbrConfig::default()),
                "reno" => Arc::new(quinn::congestion::NewRenoConfig::default()),
                _ => Arc::new(quinn::congestion::CubicConfig::default()),
            };
        // Brutal is enabled after authentication only if the server agrees on a rate.
        let rate = brutal::Rate::default();
        if options.up_bps == 0 {
            transport.congestion_controller_factory(fallback);
        } else {
            transport.congestion_controller_factory(Arc::new(brutal::Factory {
                rate: rate.clone(),
                fallback,
            }));
        }
        transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
        // Apply backpressure between fragments instead of queuing megabytes of
        // unreliable datagrams that can overwhelm the peer's receive queue.
        transport.datagram_send_buffer_size(16 * 1200);
        transport
            .mtu_discovery_config(None)
            .initial_mtu(1200)
            .min_mtu(1200);
        config.transport_config(Arc::new(transport));
        let mut connected = None;
        'addresses: for address in &p.endpoint.addresses {
            let addresses: Vec<std::net::SocketAddr> =
                if mark.is_some() || protector.is_some() {
                    vec![address.parse().map_err(|_| {
                        Error::Unsupported("pre-resolved Hysteria endpoint required")
                    })?]
                } else {
                    tokio::net::lookup_host(address)
                        .await
                        .map_err(|_| Error::Connect)?
                        .take(8)
                        .collect()
                };
            for address in addresses {
                let factory = socket_factory(address, mark, protector.cloned());
                let socket: Arc<dyn quinn::AsyncUdpSocket> = if options.hop_ports.is_empty() {
                    factory().map_err(|_| Error::Connect)?
                } else {
                    Arc::new(
                        hop::Hopping::new(
                            address,
                            rtrust_profile::hysteria::port_ranges(&options.hop_ports)
                                .map_err(|_| Error::Profile)?,
                            options.hop_interval_ms(),
                            factory,
                        )
                        .map_err(|_| Error::Connect)?,
                    )
                };
                let socket: Arc<dyn quinn::AsyncUdpSocket> =
                    if options.salamander.expose().is_empty() {
                        socket
                    } else {
                        Arc::new(obfs::Salamander {
                            buffers: Default::default(),
                            inner: socket,
                            key: Zeroizing::new(options.salamander.expose().as_bytes().to_vec()),
                        })
                    };
                let socket: Arc<dyn quinn::AsyncUdpSocket> = match &options.gecko {
                    None => socket,
                    Some(g) => Arc::new(gecko::Gecko {
                        inner: socket,
                        min: g.min_packet_size.into(),
                        max: g.max_packet_size.into(),
                        state: Default::default(),
                    }),
                };
                let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
                    quinn::EndpointConfig::default(),
                    None,
                    socket,
                    Arc::new(quinn::TokioRuntime),
                )
                .map_err(|_| Error::Connect)?;
                endpoint.set_default_client_config(config.clone());
                let connecting = endpoint
                    .connect(address, &p.endpoint.hostname)
                    .map_err(|_| Error::Connect)?;
                match tokio::time::timeout(Duration::from_secs(5), connecting).await {
                    Ok(Ok(connection)) => {
                        connected = Some((endpoint, connection));
                        break 'addresses;
                    }
                    Ok(Err(quinn::ConnectionError::TransportError(_))) => return Err(Error::Tls),
                    _ => continue,
                }
            }
        }
        let (endpoint, connection) = connected.ok_or(Error::Connect)?;
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|_| Error::Protocol)?;
        let task = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        // The driver guard is canceled on every unsuccessful handshake.
        let guard = Abort(task);
        let mut auth = http::HeaderValue::from_str(p.endpoint.password.expose())
            .map_err(|_| Error::Profile)?;
        auth.set_sensitive(true);
        let request = http::Request::builder()
            .method("POST")
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", auth)
            .header("Hysteria-CC-RX", (options.down_bps / 8).to_string())
            .header("Hysteria-Padding", padding(rand::random_range(256..2048)))
            .body(())
            .map_err(|_| Error::Profile)?;
        let mut stream = sender
            .send_request(request)
            .await
            .map_err(|_| Error::Protocol)?;
        stream.finish().await.map_err(|_| Error::Protocol)?;
        let response = stream.recv_response().await.map_err(|_| Error::Protocol)?;
        if response.status().as_u16() != 233 {
            return Err(Error::Authentication);
        }
        rate.set(brutal::negotiate(
            response
                .headers()
                .get("Hysteria-CC-RX")
                .and_then(|v| v.to_str().ok()),
            options.up_bps / 8,
        ));
        let udp = response
            .headers()
            .get("Hysteria-UDP")
            .is_some_and(|v| v == "true");
        let routes: DatagramRoutes = Arc::new(Mutex::new(HashMap::new()));
        let receiver_routes = routes.clone();
        let receive = connection.clone();
        let datagrams = tokio::spawn(async move {
            while let Ok(data) = receive.read_datagram().await {
                if data.len() < 8 {
                    continue;
                }
                let id = u32::from_be_bytes(data[..4].try_into().unwrap());
                let mut routes = receiver_routes.lock().unwrap_or_else(|e| e.into_inner());
                routes.retain(|_, sender| !sender.is_closed());
                if let Some(sender) = routes.get(&id) {
                    let _ = sender.try_send(data);
                }
            }
        });
        Ok(Self(Arc::new(Inner {
            endpoint,
            _sender: sender,
            connection,
            h3: guard.take(),
            datagrams,
            routes,
            fragment_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            fragment_bytes: Arc::new(tokio::sync::Semaphore::new(4 * 1024 * 1024)),
            udp_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            next_id: AtomicU32::new(1),
            udp,
        })))
    }
    pub async fn health(&self) -> Result<()> {
        if self.0.connection.close_reason().is_some() {
            Err(Error::Connect)
        } else {
            Ok(())
        }
    }
    pub async fn open_tcp(&self, target: &str) -> Result<Tunnel> {
        let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), async {
            let (mut send, mut recv) = self
                .0
                .connection
                .open_bi()
                .await
                .map_err(|_| Error::Connect)?;
            let mut header = Vec::new();
            varint(0x401, &mut header)?;
            varint(target.len() as u64, &mut header)?;
            header.extend_from_slice(target.as_bytes());
            let pad = padding(rand::random_range(64..512));
            varint(pad.len() as u64, &mut header)?;
            header.extend_from_slice(pad.as_bytes());
            send.write_all(&header).await.map_err(|_| Error::Io)?;
            let status = recv.read_u8().await?;
            let message = read_varint(&mut recv).await?;
            skip(&mut recv, message, 2048).await?;
            let padding = read_varint(&mut recv).await?;
            skip(&mut recv, padding, 4096).await?;
            if status != 0 {
                return Err(Error::Rejected(status as u16));
            }
            Ok((send, recv))
        })
        .await
        .map_err(|_| Error::Timeout)??;
        let (io, mut bridge) = tokio::io::duplex(64 * 1024);
        let keep = self.clone();
        let pump = tokio::spawn(async move {
            let _keep = keep;
            let (mut read, mut write) = tokio::io::split(&mut bridge);
            let upload = async {
                tokio::io::copy(&mut read, &mut send).await?;
                send.shutdown().await
            };
            let download = async {
                tokio::io::copy(&mut recv, &mut write).await?;
                write.shutdown().await
            };
            let _ = tokio::try_join!(upload, download);
        });
        Ok(Tunnel { io, pump })
    }
    pub async fn open_udp(&self) -> Result<Tunnel> {
        datagrams::open(self.clone()).await
    }
}
/// `pinSHA256` as in the official client (leaf certificate only), but strictly
/// in addition to normal chain and hostname validation, never instead of it.
#[derive(Debug)]
struct PinnedCertificate {
    verified: Arc<rustls::client::WebPkiServerVerifier>,
    pin: [u8; 32],
}
impl PinnedCertificate {
    fn new(p: &Profile, options: &rtrust_profile::Hysteria2) -> Result<Self> {
        let mut pin = [0; 32];
        for (byte, pair) in pin.iter_mut().zip(options.pin_sha256.as_bytes().chunks(2)) {
            *byte = std::str::from_utf8(pair)
                .ok()
                .and_then(|hex| u8::from_str_radix(hex, 16).ok())
                .ok_or(Error::Profile)?;
        }
        let verified = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(trust_roots(&p.endpoint.certificate)?),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map_err(|_| Error::Trust)?;
        Ok(Self { verified, pin })
    }
}
impl rustls::client::danger::ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let verified = self.verified.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        use sha2::Digest;
        if sha2::Sha256::digest(end_entity.as_ref()).as_slice() != self.pin {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(verified)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verified.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.verified.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verified.supported_verify_schemes()
    }
}
/// Mutual TLS identity; offered whenever the server requests a certificate,
/// as the official client does.
#[derive(Debug)]
struct ClientCertificate(Arc<rustls::sign::CertifiedKey>);
impl ClientCertificate {
    fn load(options: &rtrust_profile::Hysteria2) -> Result<Self> {
        let chain = rustls_pemfile::certs(&mut options.client_certificate.as_bytes())
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Profile)?;
        let key = rustls_pemfile::private_key(&mut options.client_key.expose().as_bytes())
            .map_err(|_| Error::Profile)?
            .ok_or(Error::Profile)?;
        let provider = rustls::crypto::ring::default_provider();
        let key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|_| Error::Profile)?;
        Ok(Self(Arc::new(rustls::sign::CertifiedKey::new(chain, key))))
    }
}
impl rustls::client::ResolvesClientCert for ClientCertificate {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
    fn has_certs(&self) -> bool {
        true
    }
}
/// Every transport socket, including each port-hopping replacement, is marked
/// or protected before its first packet; failure never falls back to a plain socket.
pub(crate) fn socket_factory(
    address: std::net::SocketAddr,
    mark: Option<u32>,
    protector: Option<SocketProtector>,
) -> hop::SocketFactory {
    Box::new(move || {
        let socket = std::net::UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })?;
        socket.set_nonblocking(true)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            #[cfg(target_os = "linux")]
            if let Some(mark) = mark {
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
            if let Some(protect) = &protector {
                protect(socket.as_raw_fd())?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = mark;
        #[cfg(not(unix))]
        let _ = &protector;
        quinn::TokioRuntime.wrap_udp_socket(socket)
    })
}
/// Random alphanumeric padding with the official client's length ranges.
fn padding(len: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..len)
        .map(|_| CHARS[rand::random_range(0..CHARS.len())] as char)
        .collect()
}
struct Abort(tokio::task::JoinHandle<()>);
impl Abort {
    fn take(mut self) -> tokio::task::JoinHandle<()> {
        std::mem::replace(&mut self.0, tokio::spawn(async {}))
    }
}
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort()
    }
}
fn varint(value: u64, out: &mut Vec<u8>) -> Result<()> {
    if value < 64 {
        out.push(value as u8)
    } else if value < 16384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes())
    } else if value < (1 << 30) {
        out.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes())
    } else {
        return Err(Error::Protocol);
    }
    Ok(())
}
async fn read_varint(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64> {
    let first = reader.read_u8().await?;
    let len = 1usize << ((first >> 6) as usize);
    let mut result = (first & 63) as u64;
    for _ in 1..len {
        result = (result << 8) | reader.read_u8().await? as u64;
    }
    Ok(result)
}
async fn skip(reader: &mut (impl AsyncRead + Unpin), len: u64, limit: usize) -> Result<()> {
    if len > limit as u64 {
        return Err(Error::Protocol);
    }
    let mut data = vec![0; len as usize];
    reader.read_exact(&mut data).await?;
    Ok(())
}
