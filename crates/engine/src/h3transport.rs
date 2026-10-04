use super::*;
use bytes::Buf;
type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type Stream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
struct State {
    sender: Sender,
    auth: http::HeaderValue,
    driver: tokio::task::JoinHandle<()>,
    connection: quinn::Connection,
    _endpoint: quinn::Endpoint,
    /// Set by the first `_check` answered with 200 (credentials accepted).
    verified: std::sync::atomic::AtomicBool,
}
/// Endpoint 1.1.0 can finish a CONNECT stream without the response it queued
/// (vendor/h3/RTRUST-PATCH.md). The patched h3 reports that for this stream
/// only instead of closing the connection.
enum Answer {
    Response(Box<Stream>),
    Lost,
}
impl Drop for State {
    fn drop(&mut self) {
        self.connection.close(0u32.into(), b"closed");
        self.driver.abort();
    }
}
#[derive(Clone)]
pub(super) struct H3Session(Arc<State>);
impl H3Session {
    /// `mark`/`protector` route the QUIC socket around the system tunnel; they
    /// require numeric endpoint addresses so no DNS query enters the tunnel.
    pub async fn connect(
        p: &Profile,
        mark: Option<u32>,
        protector: Option<&SocketProtector>,
    ) -> Result<Self> {
        let mut tls = tls_config(p)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Error::Tls)?;
        let mut config = quinn::ClientConfig::new(Arc::new(quic));
        // A system tunnel may sit idle; keepalives stop the 30 s idle timeout
        // from tearing down the session, while a dead path still surfaces.
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .map_err(|_| Error::Profile)?,
        ));
        config.transport_config(Arc::new(transport));
        let bypass = mark.is_some() || protector.is_some();
        let mut connected = None;
        let mut failure = Error::Connect;
        'addresses: for address in &p.endpoint.addresses {
            let resolved: Vec<std::net::SocketAddr> = if bypass {
                vec![address.parse().map_err(|_| {
                    Error::Unsupported(
                        "resolve endpoint on the underlying network before VPN setup",
                    )
                })?]
            } else {
                tokio::net::lookup_host(address)
                    .await
                    .map_err(|_| Error::Connect)?
                    .take(8)
                    .collect()
            };
            for addr in resolved {
                // Marked/protected before the first packet; never a plain fallback.
                let socket = match hysteria::socket_factory(addr, mark, protector.cloned())() {
                    Ok(socket) => socket,
                    Err(error) => {
                        failure = Error::ConnectIo(error.kind());
                        continue;
                    }
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
                    .connect(addr, &p.endpoint.hostname)
                    .map_err(|_| Error::Connect)?;
                match tokio::time::timeout(Duration::from_secs(4), connecting).await {
                    Ok(Ok(connection)) => {
                        connected = Some((endpoint, connection));
                        break 'addresses;
                    }
                    Ok(Err(quinn::ConnectionError::TransportError(_))) => return Err(Error::Tls),
                    Ok(Err(_)) => failure = Error::Connect,
                    Err(_) => failure = Error::Timeout,
                }
            }
        }
        let (endpoint, connection) = connected.ok_or(failure)?;
        // Grease is off: endpoint 1.1.0 would see a GREASE frame + FIN as an
        // unknown frame and miss the end of the request body (see `finish`).
        let (mut driver, sender) = h3::client::builder()
            .send_grease(false)
            .build(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(|_| Error::Protocol)?;
        let credentials = Zeroizing::new(format!(
            "{}:{}",
            p.endpoint.username.expose(),
            p.endpoint.password.expose()
        ));
        let text = Zeroizing::new(format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes())
        ));
        let mut auth = http::HeaderValue::from_str(&text).map_err(|_| Error::Profile)?;
        auth.set_sensitive(true);
        let driver = tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });
        Ok(Self(Arc::new(State {
            sender,
            auth,
            driver,
            connection,
            _endpoint: endpoint,
            verified: false.into(),
        })))
    }
    async fn stream(&self, target: &str) -> Result<Stream> {
        match self.request(target).await? {
            Answer::Response(stream) => Ok(*stream),
            Answer::Lost => Err(Error::Protocol),
        }
    }
    async fn request(&self, target: &str) -> Result<Answer> {
        let request = Request::builder()
            .method("CONNECT")
            .uri(
                http::Uri::builder()
                    .authority(target)
                    .build()
                    .map_err(|_| Error::Destination)?,
            )
            .header("user-agent", "rtrust/0.1")
            .header("proxy-authorization", self.0.auth.clone())
            .body(())
            .map_err(|_| Error::Destination)?;
        let mut sender = self.0.sender.clone();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut stream = sender
                .send_request(request)
                .await
                .map_err(|_| Error::Protocol)?;
            if target == "_check" {
                stream.finish().await.map_err(|_| Error::Io)?;
            }
            let response = match stream.recv_response().await {
                Ok(response) => response,
                Err(h3::error::StreamError::StreamError { code, .. })
                    if code == h3::error::Code::H3_FRAME_UNEXPECTED =>
                {
                    return Ok(Answer::Lost);
                }
                Err(_) => return Err(Error::Protocol),
            };
            match response.status() {
                StatusCode::OK => Ok(Answer::Response(Box::new(stream))),
                StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err(Error::Authentication),
                code => Err(Error::Rejected(code.as_u16())),
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    /// A `_check` finished without its response still proves a live,
    /// authenticated session once a first check returned 200; the endpoint
    /// received and answered it on this connection.
    pub async fn health(&self) -> Result<()> {
        use std::sync::atomic::Ordering;
        match self.request("_check").await? {
            Answer::Response(_) => {
                self.0.verified.store(true, Ordering::Relaxed);
                Ok(())
            }
            Answer::Lost if self.0.verified.load(Ordering::Relaxed) => Ok(()),
            Answer::Lost => Err(Error::Protocol),
        }
    }
    pub async fn open(&self, target: &str) -> Result<Tunnel> {
        let stream = self.stream(target).await?;
        let (mut send, mut recv) = stream.split();
        let (client, bridge) = tokio::io::duplex(64 * 1024);
        let (mut reader, mut writer) = tokio::io::split(bridge);
        let session = self.clone();
        let pump = tokio::spawn(async move {
            let _session = session;
            let upload = async {
                let mut bytes = [0u8; 16 * 1024];
                loop {
                    let n = reader.read(&mut bytes).await?;
                    if n == 0 {
                        return finish(&mut send).await;
                    }
                    send.send_data(Bytes::copy_from_slice(&bytes[..n]))
                        .await
                        .map_err(|_| Error::Io)?;
                }
            };
            let download = async {
                while let Some(mut data) = recv.recv_data().await.map_err(|_| Error::Io)? {
                    while data.has_remaining() {
                        let bytes = data.chunk();
                        writer.write_all(bytes).await?;
                        let n = bytes.len();
                        data.advance(n);
                    }
                }
                writer.shutdown().await?;
                Ok::<_, Error>(())
            };
            let _ = tokio::try_join!(upload, download);
        });
        Ok(Tunnel { io: client, pump })
    }
}

/// Half-close a CONNECT stream. Endpoint 1.1.0 (quiche) wakes its stream
/// reader only on h3 DATA events; a FIN that arrives without new DATA raises
/// only `Finished`, so the target never sees EOF. An empty DATA frame written
/// immediately before FIN lets quinn carry both in one STREAM frame, which
/// raises a DATA event whose read observes the finished stream.
async fn finish<S: h3::quic::SendStream<Bytes>>(
    stream: &mut h3::client::RequestStream<S, Bytes>,
) -> Result<()> {
    stream
        .send_data(Bytes::new())
        .await
        .map_err(|_| Error::Io)?;
    stream.finish().await.map_err(|_| Error::Io)
}
