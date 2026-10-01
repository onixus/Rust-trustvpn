use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;
#[cfg(not(target_os = "macos"))]
pub const SOCKET: &str = "/run/rtrust/control.sock";
#[cfg(target_os = "macos")]
pub const SOCKET: &str = "/private/var/run/rtrust/control.sock";
pub const LIMIT: usize = 2 * rtrust_profile::MAX_INPUT;
pub const VERSION: u32 = 1;
pub use ipnet::Ipv4Net;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub command: Command,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", deny_unknown_fields)]
pub enum Command {
    Start {
        profile: Box<rtrust_profile::Profile>,
        networks: Vec<Ipv4Net>,
    },
    StartFull {
        profile: Box<rtrust_profile::Profile>,
        dns: std::net::Ipv4Addr,
    },
    Status,
    PrepareUpdate,
    EnableAlwaysOn {
        profile: Box<rtrust_profile::Profile>,
        dns: std::net::Ipv4Addr,
    },
    DisableAlwaysOn,
    AlwaysOnStatus,
    Stop,
    Recover,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum State {
    Connected,
    Blocked,
    Idle,
    Error,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub state: State,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub always_on: Option<bool>,
}
impl Response {
    pub fn new(state: State, message: &str) -> Self {
        Self {
            version: VERSION,
            state,
            message: message.into(),
            always_on: None,
        }
    }
}
pub fn networks(text: &str) -> Result<Vec<Ipv4Net>, String> {
    let nets: Vec<_> = text
        .split([',', ' ', '\n'])
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<Ipv4Net>()
                .map_err(|_| "Ожидаются IPv4 CIDR, например 198.18.0.0/24".to_owned())
        })
        .collect::<Result<_, _>>()?;
    validate_networks(&nets)?;
    Ok(nets)
}
pub fn validate_networks(nets: &[Ipv4Net]) -> Result<(), String> {
    let forbidden: Vec<Ipv4Net> = ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/3"]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();
    if nets.is_empty() || nets.len() > 16 {
        return Err("Укажите от 1 до 16 IPv4-сетей".into());
    }
    for (i, net) in nets.iter().enumerate() {
        if net.prefix_len() < 8
            || net.addr() != net.network()
            || forbidden
                .iter()
                .any(|n| n.contains(&net.network()) || net.contains(&n.network()))
            || nets[..i]
                .iter()
                .any(|n| n.contains(&net.network()) || net.contains(&n.network()))
        {
            return Err("Недопустимая, перекрывающаяся или слишком широкая IPv4-сеть".into());
        }
    }
    Ok(())
}
pub async fn read<T: serde::de::DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<T, String> {
    let len = stream.read_u32().await.map_err(|_| "IPC closed")? as usize;
    if len == 0 || len > LIMIT {
        return Err("IPC frame limit exceeded".into());
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "IPC closed")?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid IPC message (redacted)".into())
}
pub async fn write<T: Serialize>(
    stream: &mut (impl AsyncWrite + Unpin),
    value: &T,
) -> Result<(), String> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| "IPC serialization failed")?);
    if bytes.len() > LIMIT {
        return Err("IPC frame limit exceeded".into());
    }
    stream
        .write_u32(bytes.len() as u32)
        .await
        .map_err(|_| "IPC closed")?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| "IPC closed".into())
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod client;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub use client::Client;

/// DNS must be a routable IPv4 host, including private VPN resolvers.
pub fn validate_dns(ip: std::net::Ipv4Addr) -> Result<(), String> {
    let first = ip.octets()[0];
    if first == 0 || ip.is_loopback() || ip.is_link_local() || first >= 224 {
        return Err("DNS должен быть IPv4-адресом сервера, доступного через VPN".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn full_dns_rejects_local_and_non_unicast_destinations() {
        for address in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.53",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                super::validate_dns(address.parse().unwrap()).is_err(),
                "{address}"
            );
        }
        for address in ["1.1.1.1", "10.0.0.53", "198.18.0.1"] {
            assert!(super::validate_dns(address.parse().unwrap()).is_ok());
        }
    }

    use super::*;
    #[test]
    fn bounded_network_selection() {
        assert!(networks("198.18.0.0/24,10.20.0.0/16").is_ok());
        for value in [
            "",
            "0.0.0.0/0",
            "127.0.0.0/8",
            "198.18.0.1/24",
            "198.18.0.0/24,198.18.0.1/32",
            "::/0",
            "224.0.0.1/32",
        ] {
            assert!(networks(value).is_err(), "{value}");
        }
    }
    #[tokio::test]
    async fn oversized_frame_rejected_before_body_and_secrets_redacted() {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_u32(u32::MAX).await.unwrap();
        assert!(read::<Request>(&mut reader).await.is_err());
        let malformed = b"secret-password";
        writer.write_u32(malformed.len() as u32).await.unwrap();
        writer.write_all(malformed).await.unwrap();
        assert!(
            !read::<Request>(&mut reader)
                .await
                .err()
                .unwrap()
                .contains("secret-password")
        );
    }
}

#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
mod broker;
