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
    pub async fn connect(p: &Profile) -> Result<Self> {
        let mut tls = tls_config(p)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| Error::Tls)?;
        let config = quinn::ClientConfig::new(Arc::new(quic));
        let mut connected = None;
        for address in &p.endpoint.addresses {
            let resolved = tokio::net::lookup_host(address)
                .await
                .map_err(|_| Error::Connect)?;
            for addr in resolved.take(8) {
                let bind = if addr.is_ipv4() {
                    "0.0.0.0:0"
                } else {
                    "[::]:0"
                };
                let mut endpoint =
                    quinn::Endpoint::client(bind.parse().map_err(|_| Error::Connect)?)
                        .map_err(|_| Error::Connect)?;
                endpoint.set_default_client_config(config.clone());
                let connecting = endpoint
                    .connect(addr, &p.endpoint.hostname)
                    .map_err(|_| Error::Connect)?;
                match tokio::time::timeout(Duration::from_secs(4), connecting).await {
                    Ok(Ok(connection)) => {
                        connected = Some((endpoint, connection));
                        break;
                    }
                    Ok(Err(quinn::ConnectionError::TransportError(_))) => return Err(Error::Tls),
                    _ => continue,
                }
            }
            if connected.is_some() {
                break;
            }
        }
        let (endpoint, connection) = connected.ok_or(Error::Connect)?;
        let (mut driver, sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
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
        })))
    }
    async fn stream(&self, target: &str) -> Result<Stream> {
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
            let response = stream.recv_response().await.map_err(|_| Error::Protocol)?;
            match response.status() {
                StatusCode::OK => Ok(stream),
                StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err(Error::Authentication),
                code => Err(Error::Rejected(code.as_u16())),
            }
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
    pub async fn health(&self) -> Result<()> {
        let _ = self.stream("_check").await?;
        Ok(())
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
                        send.finish().await.map_err(|_| Error::Io)?;
                        return Ok::<_, Error>(());
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
