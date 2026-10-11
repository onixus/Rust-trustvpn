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
        let version = router.map(crate::routing::Router::version);
        let answer = exchange(resolvers, session, &query).await?;
        if let (Some(router), Some(version)) = (router, version) {
            router.learn_for(&version, &query, &answer);
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
/// One forwarded UDP DNS query owns one upstream stream. Keeping the query's
/// epoch outside a shared tuple/ID table prevents late replies from acquiring a
/// newer policy epoch and avoids a lifetime limit on DNS routing evidence.
pub async fn forward_udp(
    session: &Session,
    query: crate::udp::Datagram,
    router: &crate::routing::Router,
) -> Result<crate::udp::Datagram> {
    let version = router.version();
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut tunnel = session.open_udp().await?;
        forward_udp_query(&mut tunnel, &query, router, &version).await
    })
    .await
    .map_err(|_| Error::Timeout)?
}
async fn forward_udp_query<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    query: &crate::udp::Datagram,
    router: &crate::routing::Router,
    version: &crate::routing::PolicyVersion,
) -> Result<crate::udp::Datagram> {
    if !(12..=LIMIT).contains(&query.payload.len()) || query.destination.port() != 53 {
        return Err(Error::Protocol);
    }
    stream
        .write_all(&crate::udp::encode(query, "rtrust-tun")?)
        .await?;
    let reply = crate::udp::read(stream).await?;
    if reply.source != query.destination || reply.destination != query.source {
        return Err(Error::Protocol);
    }
    validate_answer(&query.payload, &reply.payload)?;
    router.learn_for(version, &query.payload, &reply.payload);
    Ok(reply)
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
            let version = router.version();
            tunnel.write_u16(query.len() as u16).await?;
            tunnel.write_all(&query).await?;
            let answer = read_message(&mut tunnel).await?;
            validate_answer(&query, &answer)?;
            router.learn_for(&version, &query, &answer);
            stream.write_u16(answer.len() as u16).await?;
            stream.write_all(&answer).await?;
            Ok::<_, Error>(())
        })
        .await
        .map_err(|_| Error::Timeout)??;
    }
}

/// Empty NOERROR answer (NODATA) for a single AAAA question. Used when the
/// endpoint has no IPv6 egress, so applications pick IPv4 instead of opening
/// IPv6 flows that the endpoint would reject.
pub fn aaaa_nodata(query: &[u8]) -> Option<Vec<u8>> {
    use hickory_proto::op::{Message, MessageType, OpCode};
    let question = Message::from_vec(query).ok()?;
    if question.metadata.message_type != MessageType::Query
        || question.metadata.op_code != OpCode::Query
        || question.queries.len() != 1
        || question.queries[0].query_type() != hickory_proto::rr::RecordType::AAAA
    {
        return None;
    }
    let mut answer = Message::new(question.metadata.id, MessageType::Response, OpCode::Query);
    answer.metadata.recursion_desired = question.metadata.recursion_desired;
    answer.metadata.recursion_available = true;
    answer.metadata.checking_disabled = question.metadata.checking_disabled;
    answer.add_query(question.queries[0].clone());
    answer.to_vec().ok()
}
/// DNS over TCP through the tunnel with AAAA questions answered locally.
/// The tunnel stream opens only for the first question that needs it.
pub async fn forward_tcp_without_aaaa<T: AsyncRead + AsyncWrite + Unpin>(
    session: &Session,
    destination: std::net::SocketAddr,
    stream: &mut T,
) -> Result<()> {
    let mut tunnel = None;
    loop {
        tokio::time::timeout(Duration::from_secs(30), async {
            let query = read_message(stream).await?;
            let answer = match aaaa_nodata(&query) {
                Some(answer) => answer,
                None => {
                    if tunnel.is_none() {
                        tunnel = Some(session.open_tcp(&destination.to_string()).await?);
                    }
                    let tunnel = tunnel.as_mut().unwrap();
                    tunnel.write_u16(query.len() as u16).await?;
                    tunnel.write_all(&query).await?;
                    let answer = read_message(tunnel).await?;
                    validate_answer(&query, &answer)?;
                    answer
                }
            };
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
    fn query(kind: hickory_proto::rr::RecordType) -> Vec<u8> {
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        let mut m = Message::new(0x1234, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query("example.com.".parse().unwrap(), kind));
        m.to_vec().unwrap()
    }
    // A real framed reply over an independent duplex stream, using the same
    // helper as the production per-query stream. The server validates the wire
    // request rather than mirroring implementation data structures.
    async fn udp_reply(
        router: &crate::routing::Router,
        version: &crate::routing::PolicyVersion,
        wrong_tuple: bool,
        wrong_question: bool,
    ) -> Result<crate::udp::Datagram> {
        use hickory_proto::{
            op::{Message, MessageType},
            rr::{Name, RData, Record, RecordType, rdata::A},
        };
        let q = query(RecordType::A);
        let request = crate::udp::Datagram {
            source: "169.254.254.2:12345".parse().unwrap(),
            destination: "1.1.1.1:53".parse().unwrap(),
            payload: q.clone(),
        };
        let mut answer = Message::from_vec(&q).unwrap();
        answer.metadata.message_type = MessageType::Response;
        if wrong_question {
            answer.queries[0].set_name(Name::from_ascii("other.example.").unwrap());
        }
        answer.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
        let reply = crate::udp::Datagram {
            source: if wrong_tuple {
                "8.8.8.8:53".parse().unwrap()
            } else {
                request.destination
            },
            destination: request.source,
            payload: answer.to_vec().unwrap(),
        };
        let (mut client, mut server) = tokio::io::duplex(4096);
        let wire = crate::udp::encode(&request, "rtrust-tun").unwrap();
        let task = tokio::spawn(async move {
            let mut actual = vec![0; wire.len()];
            server.read_exact(&mut actual).await.unwrap();
            assert_eq!(actual, wire);
            let mut encoded = crate::udp::encode(&reply, "").unwrap();
            // Incoming _udp2 frames do not carry the outbound application byte.
            encoded.remove(40);
            let len = (encoded.len() - 4) as u32;
            encoded[..4].copy_from_slice(&len.to_be_bytes());
            server.write_all(&encoded).await.unwrap();
        });
        let result = forward_udp_query(&mut client, &request, router, version).await;
        task.await.unwrap();
        result
    }
    fn udp_router() -> crate::routing::Router {
        crate::routing::Policy {
            mode: "general".into(),
            exclusions: vec!["example.com".into()],
        }
        .compile_with_context(crate::routing::Context {
            revision: Some("r1".into()),
            ..Default::default()
        })
        .unwrap()
    }
    #[tokio::test]
    async fn forwarded_udp_keeps_learning_after_512_completed_and_reused_id_queries() {
        let router = udp_router();
        for n in 0..514 {
            // Clear cached evidence between queries, so every success proves a
            // fresh answer learned under the new epoch, even with reused tuple/ID.
            if n > 0 {
                router
                    .apply_local(
                        &router.version(),
                        &crate::routing::Policy {
                            mode: "general".into(),
                            exclusions: vec!["example.com".into()],
                        },
                        crate::routing::Context {
                            revision: Some(format!("r{}", n + 1)),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
            assert_eq!(
                router.decide("192.0.2.1:443".parse().unwrap()).action,
                crate::routing::Action::Tunnel
            );
            udp_reply(&router, &router.version(), false, false)
                .await
                .unwrap();
            assert_eq!(
                router.decide("192.0.2.1:443".parse().unwrap()).action,
                crate::routing::Action::Direct
            );
        }
    }
    #[tokio::test]
    async fn forwarded_udp_rejects_mismatched_replies_and_obsolete_query_epoch() {
        let router = udp_router();
        let old = router.version();
        assert!(udp_reply(&router, &old, true, false).await.is_err());
        assert!(udp_reply(&router, &old, false, true).await.is_err());
        router
            .apply_local(
                &old,
                &crate::routing::Policy {
                    mode: "general".into(),
                    exclusions: vec!["example.com".into()],
                },
                crate::routing::Context {
                    revision: Some("r2".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        udp_reply(&router, &old, false, false).await.unwrap();
        assert_eq!(
            router.decide("192.0.2.1:443".parse().unwrap()).action,
            crate::routing::Action::Tunnel
        );
        udp_reply(&router, &router.version(), false, false)
            .await
            .unwrap();
        assert_eq!(
            router.decide("192.0.2.1:443".parse().unwrap()).action,
            crate::routing::Action::Direct
        );
    }
    #[test]
    fn aaaa_gets_valid_empty_answer() {
        let q = query(hickory_proto::rr::RecordType::AAAA);
        let answer = aaaa_nodata(&q).unwrap();
        validate_answer(&q, &answer).unwrap();
        let m = hickory_proto::op::Message::from_vec(&answer).unwrap();
        assert!(m.answers.is_empty());
        assert_eq!(
            m.metadata.response_code,
            hickory_proto::op::ResponseCode::NoError
        );
        assert!(m.metadata.recursion_desired);
    }
    #[test]
    fn other_questions_pass_through() {
        assert!(aaaa_nodata(&query(hickory_proto::rr::RecordType::A)).is_none());
        assert!(aaaa_nodata(&query(hickory_proto::rr::RecordType::HTTPS)).is_none());
        assert!(aaaa_nodata(b"garbage").is_none());
        let mut response = query(hickory_proto::rr::RecordType::AAAA);
        response[2] |= 0x80;
        assert!(aaaa_nodata(&response).is_none());
    }
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
