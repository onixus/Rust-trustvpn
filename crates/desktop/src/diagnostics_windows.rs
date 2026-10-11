//! Windows system-path evidence. Socket interface selection is mandatory, never
//! approximated by binding only a source address. No proxy or alternate endpoint.
use super::Fact;

fn interface_value(index: u32, ipv6: bool) -> Result<u32, Fact> {
    if index == 0 || (!ipv6 && index > 0x00ff_ffff) {
        return Err(Fact::Unsupported);
    }
    // Winsock IP_UNICAST_IF takes network order; IPV6_UNICAST_IF host order.
    // https://learn.microsoft.com/windows/win32/winsock/ipproto-ip-socket-options
    // https://learn.microsoft.com/windows/win32/winsock/ipproto-ipv6-socket-options
    Ok(if ipv6 { index } else { index.to_be() })
}
fn same_interface(expected: (u64, u32), observed: (u64, u32)) -> bool {
    expected.0 != 0 && expected.1 != 0 && expected == observed
}
fn response_status(bytes: &[u8]) -> Result<Option<u16>, Fact> {
    if bytes.len() > 8192 {
        return Err(Fact::Failed);
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(bytes).map_err(|_| Fact::Failed)? {
        httparse::Status::Partial => Ok(None),
        httparse::Status::Complete(_) => {
            let code = response.code.ok_or(Fact::Failed)?;
            if !(200..=599).contains(&code) {
                return Err(Fact::Failed);
            }
            Ok(Some(code))
        }
    }
}

fn resolver_answers(bytes: &[u8]) -> Result<Vec<std::net::IpAddr>, Fact> {
    if bytes.len() > 8192 {
        return Err(Fact::Failed);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Fact::Failed)?;
    let mut answers = Vec::new();
    for line in text.lines() {
        let ip = line.parse::<std::net::IpAddr>().map_err(|_| Fact::Failed)?;
        if !answers.contains(&ip) {
            answers.push(ip);
        }
        if answers.len() > super::ADDRESS_LIMIT {
            return Err(Fact::Failed);
        }
    }
    if answers.is_empty() {
        Err(Fact::Failed)
    } else {
        Ok(answers)
    }
}
async fn read_response(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> Result<u16, Fact> {
    use tokio::io::AsyncReadExt;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|_| Fact::ConnectionFailed)?;
        if count == 0 {
            return Err(Fact::Failed);
        }
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(status) = response_status(&bytes)? {
            return Ok(status);
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        os::windows::io::AsRawSocket,
        sync::Arc,
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use windows_sys::Win32::{
        NetworkManagement::{IpHelper::*, Ndis::*},
        Networking::WinSock::*,
    };
    const DEVICE: &str = "RTrustTunnel";

    pub async fn resolve(host: &str) -> Result<Vec<IpAddr>, Fact> {
        // A child isolates the synchronous OS resolver: timeout/cancellation kills
        // it rather than leaving an unbounded detached blocking resolver thread.
        let root = std::env::var_os("SystemRoot").ok_or(Fact::Unsupported)?;
        let exe =
            std::path::PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let script = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); try { [Net.Dns]::GetHostAddresses($env:RTRUST_DIAGNOSTIC_HOST) | ForEach-Object { [Console]::WriteLine($_.ToString()) }; exit 0 } catch { exit 1 }";
        let mut child = tokio::process::Command::new(exe)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                script,
            ])
            .creation_flags(0x0800_0000) // CREATE_NO_WINDOW: diagnostics stays in the UI.
            .env("RTRUST_DIAGNOSTIC_HOST", host)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| Fact::Unsupported)?;
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut bytes = Vec::new();
            child
                .stdout
                .take()
                .ok_or(Fact::Failed)?
                .take(8193)
                .read_to_end(&mut bytes)
                .await
                .map_err(|_| Fact::Failed)?;
            if bytes.len() > 8192 || !child.wait().await.map_err(|_| Fact::Failed)?.success() {
                return Err(Fact::Failed);
            }
            resolver_answers(&bytes)
        })
        .await
        .map_err(|_| Fact::Timeout)?
    }

    fn identity() -> Result<(u64, u32), Fact> {
        let alias: Vec<u16> = DEVICE.encode_utf16().chain(Some(0)).collect();
        let mut luid = NET_LUID_LH::default();
        if unsafe { ConvertInterfaceAliasToLuid(alias.as_ptr(), &mut luid) } != 0 {
            return Err(Fact::Unsupported);
        }
        let mut row = MIB_IF_ROW2 {
            InterfaceLuid: luid,
            ..Default::default()
        };
        if unsafe { GetIfEntry2(&mut row) } != 0 || row.OperStatus != IfOperStatusUp {
            return Err(Fact::SessionChanged);
        }
        let end = row.Alias.iter().position(|v| *v == 0).ok_or(Fact::Failed)?;
        if !row.Alias[..end].iter().copied().eq(DEVICE.encode_utf16()) {
            return Err(Fact::SessionChanged);
        }
        let observed = (unsafe { row.InterfaceLuid.Value }, row.InterfaceIndex);
        if !same_interface((unsafe { luid.Value }, row.InterfaceIndex), observed) {
            return Err(Fact::SessionChanged);
        }
        Ok(observed)
    }
    fn address(ip: IpAddr) -> SOCKADDR_INET {
        match ip {
            IpAddr::V4(ip) => SOCKADDR_INET {
                Ipv4: SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_addr: u32::from_ne_bytes(ip.octets()),
                        },
                    },
                    ..Default::default()
                },
            },
            IpAddr::V6(ip) => SOCKADDR_INET {
                Ipv6: SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: ip.octets() },
                    },
                    ..Default::default()
                },
            },
        }
    }
    fn source(address: SOCKADDR_INET) -> Result<SocketAddr, Fact> {
        // Read only the arm selected by the OS's family discriminant.
        unsafe {
            match address.si_family {
                AF_INET => Ok(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::from(
                        address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                    )),
                    0,
                )),
                AF_INET6 => Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                    Ipv6Addr::from(address.Ipv6.sin6_addr.u.Byte),
                    0,
                    0,
                    address.Ipv6.Anonymous.sin6_scope_id,
                ))),
                _ => Err(Fact::Unsupported),
            }
        }
    }
    fn best(ip: IpAddr) -> Result<((u64, u32), SocketAddr), Fact> {
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut src = SOCKADDR_INET::default();
        if unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &address(ip),
                0,
                &mut route,
                &mut src,
            )
        } != 0
        {
            return Err(Fact::Failed);
        }
        Ok((
            (unsafe { route.InterfaceLuid.Value }, route.InterfaceIndex),
            source(src)?,
        ))
    }
    pub fn route(ip: IpAddr) -> Result<bool, Fact> {
        let expected = identity()?;
        let (actual, _) = best(ip)?;
        Ok(same_interface(expected, actual))
    }
    pub async fn https(host: &str, ip: IpAddr) -> Result<u16, Fact> {
        tokio::time::timeout(Duration::from_secs(5), async {
            let expected = identity()?;
            let (actual, source) = best(ip)?;
            if !same_interface(expected, actual) {
                return Err(Fact::RouteMismatch);
            }
            if source.ip().is_unspecified() || source.ip().is_ipv6() != ip.is_ipv6() {
                return Err(Fact::Failed);
            }
            let socket = if ip.is_ipv6() {
                tokio::net::TcpSocket::new_v6()
            } else {
                tokio::net::TcpSocket::new_v4()
            }
            .map_err(|_| Fact::Unsupported)?;
            let value = interface_value(expected.1, ip.is_ipv6())?;
            let (level, option) = if ip.is_ipv6() {
                (IPPROTO_IPV6, IPV6_UNICAST_IF)
            } else {
                (IPPROTO_IP, IP_UNICAST_IF)
            };
            if unsafe {
                setsockopt(
                    socket.as_raw_socket() as SOCKET,
                    level,
                    option,
                    (&value as *const u32).cast(),
                    4,
                )
            } != 0
            {
                return Err(Fact::Unsupported);
            }
            socket.bind(source).map_err(|_| Fact::ConnectionFailed)?;
            if !same_interface(expected, identity()?) || !same_interface(expected, best(ip)?.0) {
                return Err(Fact::SessionChanged);
            }
            // This socket alone performs TCP/TLS; there is no unbound fallback.
            let stream = socket
                .connect(SocketAddr::new(ip, 443))
                .await
                .map_err(|_| Fact::ConnectionFailed)?;
            if !same_interface(expected, identity()?) {
                return Err(Fact::SessionChanged);
            }
            let roots =
                rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|_| Fact::Unsupported)?
            .with_root_certificates(roots)
            .with_no_client_auth();
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            let name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| Fact::Unsupported)?;
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(name, stream)
                .await
                .map_err(|e| {
                    if e.get_ref()
                        .is_some_and(|e| e.downcast_ref::<rustls::Error>().is_some())
                    {
                        Fact::TlsFailed
                    } else {
                        Fact::ConnectionFailed
                    }
                })?;
            if !same_interface(expected, identity()?) {
                return Err(Fact::SessionChanged);
            }
            let authority = if ip.is_ipv6() && host.parse::<Ipv6Addr>().is_ok() {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            tls.write_all(
                format!("HEAD / HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .map_err(|_| Fact::ConnectionFailed)?;
            let status = read_response(&mut tls).await?;
            if !same_interface(expected, identity()?) {
                return Err(Fact::SessionChanged);
            }
            Ok(status)
        })
        .await
        .map_err(|_| Fact::Timeout)?
    }
}
#[cfg(target_os = "windows")]
pub use platform::{https, resolve, route};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn winsock_interface_options_require_nonzero_exact_identity_and_family_byte_order() {
        assert_eq!(interface_value(0, false), Err(Fact::Unsupported));
        assert_eq!(interface_value(0x0100_0000, false), Err(Fact::Unsupported));
        assert_eq!(
            interface_value(42, false).unwrap().to_ne_bytes(),
            42u32.to_be_bytes()
        );
        assert_eq!(interface_value(42, true), Ok(42));
        assert!(same_interface((7, 42), (7, 42)));
        assert!(!same_interface((7, 42), (8, 42)));
        assert!(!same_interface((7, 42), (7, 43)));
        assert!(!same_interface((0, 0), (0, 0)));
    }
    #[test]
    fn only_complete_bounded_final_http_headers_are_response_evidence() {
        assert_eq!(response_status(b"HTTP/1.1 200 OK\r\n"), Ok(None));
        assert_eq!(
            response_status(b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere/\r\n\r\n"),
            Ok(Some(302))
        );
        assert_eq!(
            response_status(b"HTTP/1.1 503 Service Unavailable\r\n\r\n"),
            Ok(Some(503))
        );
        assert_eq!(
            response_status(b"HTTP/1.1 100 Continue\r\n\r\n"),
            Err(Fact::Failed)
        );
        assert_eq!(
            response_status(b"HTTP/1.1 999 Wrong\r\n\r\n"),
            Err(Fact::Failed)
        );
        assert_eq!(response_status(&vec![b'a'; 8193]), Err(Fact::Failed));
        assert_eq!(response_status(b"not HTTP\r\n\r\n"), Err(Fact::Failed));
    }
    #[test]
    fn resolver_rejects_overflow_and_malformed_output_without_guessing() {
        assert_eq!(
            resolver_answers(b"192.0.2.1\r\n192.0.2.1\r\n2001:db8::1\r\n")
                .unwrap()
                .len(),
            2
        );
        assert_eq!(resolver_answers(b"192.0.2.1\nerror\n"), Err(Fact::Failed));
        assert_eq!(resolver_answers(b""), Err(Fact::Failed));
        let many = (1..=9)
            .map(|i| format!("192.0.2.{i}\n"))
            .collect::<String>();
        assert_eq!(resolver_answers(many.as_bytes()), Err(Fact::Failed));
    }
    #[tokio::test]
    async fn head_response_finishes_at_headers_without_waiting_for_body_or_eof() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(512);
        server.write_all(b"HTTP/1.1 302 Found\r\nContent-Length: 999999\r\nLocation: https://elsewhere/\r\n\r\n").await.unwrap();
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                read_response(&mut client)
            )
            .await
            .unwrap(),
            Ok(302)
        );
        // Server remains open and never sends the declared body.
        drop(server);
    }
    #[tokio::test]
    async fn incomplete_headers_cannot_be_success_and_cancellation_leaves_no_reader() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(512);
        server.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                read_response(&mut client)
            )
            .await
            .is_err()
        );
        // No spawned reader survives dropping the diagnostic transport.
        drop(client);
        assert!(server.write_all(b"X-Test: yes\r\n\r\n").await.is_err());
        let (mut client, server) = tokio::io::duplex(32);
        drop(server);
        assert_eq!(read_response(&mut client).await, Err(Fact::Failed));
    }
}
