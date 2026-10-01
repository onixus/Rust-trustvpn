//! Encrypted DNS inside the authenticated VPN. No local bootstrap lookup or plaintext fallback.
use crate::{Error, Result, Session};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const LIMIT: usize = 65_507;
#[derive(Clone, Debug)]
pub struct Resolver {
    host: String,
    target: String,
    https: Option<url::Url>,
}
impl Resolver {
    pub fn parse(value: &str) -> Result<Self> {
        let url = url::Url::parse(value).map_err(|_| Error::Unsupported("DNS URL"))?;
        let host = url
            .host_str()
            .ok_or(Error::Unsupported("DNS hostname"))?
            .trim_matches(['[', ']'])
            .to_owned();
        if !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !matches!(url.scheme(), "tls" | "https")
            || url.port() == Some(0)
            || (url.scheme() == "tls" && (!matches!(url.path(), "" | "/") || url.query().is_some()))
        {
            return Err(Error::Unsupported("DNS URL options"));
        }
        let port = url
            .port()
            .unwrap_or(if url.scheme() == "tls" { 853 } else { 443 });
        let target = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let https = (url.scheme() == "https").then_some(url);
        Ok(Self {
            host,
            target,
            https,
        })
    }
    pub async fn exchange(&self, session: &Session, query: &[u8]) -> Result<Vec<u8>> {
        if !(12..=LIMIT).contains(&query.len()) || query[2] & 0x80 != 0 {
            return Err(Error::Protocol);
        }
        tokio::time::timeout(Duration::from_secs(15), async {
            let tunnel = session.open_tcp(&self.target).await?;
            // A custom VPN endpoint CA must never replace DNS server trust.
            let mut config = crate::tls_config_with_ca("")?;
            if self.https.is_some() {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }
            let name = rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| Error::Tls)?;
            let mut stream = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, tunnel)
                .await
                .map_err(|_| Error::Tls)?;
            let answer = if let Some(url) = &self.https {
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                        .await
                        .map_err(|_| Error::Protocol)?;
                let driver = tokio::spawn(connection);
                // Abort the HTTP driver on cancellation as well as normal completion.
                struct Driver(tokio::task::JoinHandle<std::result::Result<(), hyper::Error>>);
                impl Drop for Driver {
                    fn drop(&mut self) {
                        self.0.abort();
                    }
                }
                let _driver = Driver(driver);
                let authority = &url[url::Position::BeforeHost..url::Position::AfterPort];
                let request =
                    http::Request::post(&url[url::Position::BeforePath..url::Position::AfterQuery])
                        .header("Host", authority)
                        .header("Content-Type", "application/dns-message")
                        .header("Accept", "application/dns-message")
                        .body(Full::new(Bytes::copy_from_slice(query)))
                        .map_err(|_| Error::Protocol)?;
                let response = sender
                    .send_request(request)
                    .await
                    .map_err(|_| Error::Protocol)?;
                if response.status() != http::StatusCode::OK
                    || response
                        .headers()
                        .get("content-type")
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.split(';').next())
                        .map(str::trim)
                        != Some("application/dns-message")
                {
                    return Err(Error::Protocol);
                }
                Limited::new(response.into_body(), LIMIT)
                    .collect()
                    .await
                    .map_err(|_| Error::Protocol)?
                    .to_bytes()
                    .to_vec()
            } else {
                stream.write_u16(query.len() as u16).await?;
                stream.write_all(query).await?;
                read_message(&mut stream).await?
            };
            validate_answer(query, &answer)?;
            Ok(answer)
        })
        .await
        .map_err(|_| Error::Timeout)?
    }
}
pub async fn exchange(resolvers: &[Resolver], session: &Session, query: &[u8]) -> Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(20), async {
        for resolver in resolvers {
            if let Ok(answer) = resolver.exchange(session, query).await {
                return Ok(answer);
            }
        }
        Err(Error::Protocol)
    })
    .await
    .map_err(|_| Error::Timeout)?
}
pub async fn serve_tcp<T: AsyncRead + AsyncWrite + Unpin>(
    resolvers: &[Resolver],
    session: &Session,
    stream: &mut T,
    router: Option<&crate::routing::Router>,
) -> Result<()> {
    loop {
        let query = tokio::time::timeout(Duration::from_secs(30), read_message(stream))
            .await
            .map_err(|_| Error::Timeout)??;
        let answer = exchange(resolvers, session, &query).await?;
        if let Some(router) = router {
            router.learn(&query, &answer);
        }
        stream.write_u16(answer.len() as u16).await?;
        stream.write_all(&answer).await?;
    }
}
pub fn encrypted(upstreams: &[String]) -> Result<Option<Vec<Resolver>>> {
    if upstreams
        .iter()
        .all(|s| s.parse::<std::net::IpAddr>().is_ok())
    {
        return Ok(None);
    }
    // An encrypted policy may not silently fall back to a plaintext resolver.
    upstreams
        .iter()
        .map(|s| Resolver::parse(s))
        .collect::<Result<Vec<_>>>()
        .map(Some)
}
async fn read_message<T: AsyncRead + Unpin>(stream: &mut T) -> Result<Vec<u8>> {
    let length = stream.read_u16().await? as usize;
    if !(12..=LIMIT).contains(&length) {
        return Err(Error::Protocol);
    }
    let mut answer = vec![0; length];
    stream.read_exact(&mut answer).await?;
    Ok(answer)
}
fn validate_answer(query: &[u8], answer: &[u8]) -> Result<()> {
    if answer.len() < 12
        || answer.len() > LIMIT
        || answer[..2] != query[..2]
        || answer[2] & 0x80 == 0
        || answer[2] & 0x78 != query[2] & 0x78
    {
        return Err(Error::Protocol);
    }
    let question = hickory_proto::op::Message::from_vec(query).map_err(|_| Error::Protocol)?;
    let response = hickory_proto::op::Message::from_vec(answer).map_err(|_| Error::Protocol)?;
    if question.queries.len() != 1 || question.queries != response.queries {
        return Err(Error::Protocol);
    }
    Ok(())
}
pub async fn forward_tcp<T: AsyncRead + AsyncWrite + Unpin>(
    session: &Session,
    destination: std::net::SocketAddr,
    stream: &mut T,
    router: &crate::routing::Router,
) -> Result<()> {
    let mut tunnel = session.open_tcp(&destination.to_string()).await?;
    loop {
        tokio::time::timeout(Duration::from_secs(30), async {
            let query = read_message(stream).await?;
            tunnel.write_u16(query.len() as u16).await?;
            tunnel.write_all(&query).await?;
            let answer = read_message(&mut tunnel).await?;
            validate_answer(&query, &answer)?;
            router.learn(&query, &answer);
            stream.write_u16(answer.len() as u16).await?;
            stream.write_all(&answer).await?;
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Timeout)??;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn encrypted_dns_never_accepts_cleartext_or_ambiguous_credentials() {
        for uri in [
            "tls://1.1.1.1",
            "tls://dns.example:8853",
            "https://dns.example/dns-query",
            "https://[2606:4700:4700::1111]/dns-query",
        ] {
            assert!(Resolver::parse(uri).is_ok(), "{uri}");
        }
        for uri in [
            "http://dns.example/query",
            "tls://user:secret@dns.example",
            "https://dns.example/#secret",
            "tls://dns.example/path",
            "tls://dns.example:0",
            "udp://1.1.1.1",
        ] {
            assert!(Resolver::parse(uri).is_err(), "{uri}");
        }
        assert!(encrypted(&["tls://1.1.1.1".into(), "8.8.8.8".into()]).is_err());
        assert!(encrypted(&["1.1.1.1".into()]).unwrap().is_none());
    }
    #[test]
    fn unrelated_or_truncated_dns_answers_fail() {
        let query = [
            0x52, 0x54, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1,
        ];
        let mut answer = query;
        answer[2] |= 0x80;
        assert!(validate_answer(&query, &answer).is_ok());
        answer[0] ^= 1;
        assert!(validate_answer(&query, &answer).is_err());
        assert!(validate_answer(&query, &[0; 3]).is_err());
    }
}
