//! Bounded, secret-redacting TrustTunnel profile codec. No network or filesystem I/O.
pub mod amnezia;
pub mod hysteria;
mod link;
pub mod routing;
pub use amnezia::AmneziaWg;
pub use hysteria::{Hysteria2, Protocol};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};
use zeroize::Zeroize;

pub const MAX_INPUT: usize = 1024 * 1024;
pub const MAX_LINK: usize = 64 * 1024;
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Input exceeds the size limit")]
    TooLarge,
    #[error("Invalid configuration syntax (input redacted)")]
    Syntax,
    #[error("Unsupported profile version")]
    Version,
    #[error("Missing or invalid field: {0}")]
    Field(&'static str),
    #[error("Malformed TrustTunnel link (payload redacted)")]
    Link,
    #[error("Ambiguous configuration: both root and nested endpoint")]
    Ambiguous,
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);
impl Secret {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub hostname: String,
    pub addresses: Vec<String>,
    pub username: Secret,
    pub password: Secret,
    #[serde(default)]
    pub custom_sni: String,
    #[serde(default = "yes")]
    pub has_ipv6: bool,
    #[serde(default)]
    pub skip_verification: bool,
    #[serde(default)]
    pub certificate: String,
    #[serde(default = "http2")]
    pub upstream_protocol: String,
    #[serde(default, alias = "client_random")]
    pub client_random_prefix: String,
    #[serde(default)]
    pub anti_dpi: bool,
    #[serde(default)]
    pub dns_upstreams: Vec<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Endpoint([REDACTED])")
    }
}
fn yes() -> bool {
    true
}
fn http2() -> String {
    "http2".into()
}

// Debug deliberately omits raw CLI/extension contents: these may contain credentials.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Protocol::is_trust_tunnel")]
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hysteria2: Option<Hysteria2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amneziawg: Option<AmneziaWg>,
    pub name: String,
    pub endpoint: Endpoint,
    #[serde(default)]
    pub policy: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_cli: Option<toml::Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extensions: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown_tlv: Vec<(u64, Vec<u8>)>,
}
impl fmt::Debug for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Profile")
            .field("schema_version", &self.schema_version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    EndpointToml,
    CliToml,
    Link,
    Json,
    /// `awg-quick` configuration of an AmneziaWG profile.
    Conf,
}
impl Format {
    pub const ALL: [Self; 4] = [Self::EndpointToml, Self::CliToml, Self::Link, Self::Json];
    pub fn extension(self) -> &'static str {
        match self {
            Self::Link => "txt",
            Self::Json => "json",
            Self::Conf => "conf",
            _ => "toml",
        }
    }
}
impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EndpointToml => "Endpoint TOML",
            Self::CliToml => "CLI TOML",
            Self::Link => "VPN link",
            Self::Json => "R-TrustTunnel JSON",
            Self::Conf => "AmneziaWG config",
        })
    }
}
pub struct Export {
    pub content: String,
    pub losses: Vec<&'static str>,
}
impl Drop for Export {
    fn drop(&mut self) {
        self.content.zeroize();
    }
}

impl Profile {
    pub fn transport_name(&self) -> &str {
        match self.protocol {
            Protocol::Hysteria2 => "Hysteria 2",
            Protocol::AmneziaWg => "AmneziaWG",
            Protocol::TrustTunnel => &self.endpoint.upstream_protocol,
        }
    }
    /// True when the transport to the server is UDP (QUIC or WireGuard), so a
    /// kill switch must admit UDP rather than TCP to the endpoint.
    pub fn udp_transport(&self) -> bool {
        match self.protocol {
            Protocol::Hysteria2 | Protocol::AmneziaWg => true,
            Protocol::TrustTunnel => self.endpoint.upstream_protocol == "http3",
        }
    }
    /// Server UDP port ranges a firewall must allow for Hysteria port hopping;
    /// empty when only the endpoint address ports are used.
    pub fn hop_port_ranges(&self) -> Vec<(u16, u16)> {
        self.hysteria2
            .as_ref()
            .filter(|h| !h.hop_ports.is_empty())
            .and_then(|h| hysteria::port_ranges(&h.hop_ports).ok())
            .unwrap_or_default()
    }
    pub fn formats(&self) -> &'static [Format] {
        match self.protocol {
            Protocol::Hysteria2 => &[Format::Json, Format::Link],
            Protocol::AmneziaWg => &[Format::Json, Format::Conf],
            Protocol::TrustTunnel => &Format::ALL,
        }
    }
    pub fn from_endpoint(endpoint: Endpoint, name: String) -> Self {
        Self {
            schema_version: 1,
            protocol: Protocol::TrustTunnel,
            hysteria2: None,
            amneziawg: None,
            name,
            endpoint,
            policy: Value::Null,
            original_cli: None,
            extensions: BTreeMap::new(),
            unknown_tlv: vec![],
        }
    }
    pub fn import(input: &str) -> Result<Self> {
        if input.len() > MAX_INPUT {
            return Err(Error::TooLarge);
        }
        let input = input.trim().trim_start_matches('\u{feff}');
        if input.starts_with("hy2://") || input.starts_with("hysteria2://") {
            return hysteria::link(input);
        }
        if input.starts_with("tt://") {
            return link::decode(input);
        }
        if !input.starts_with('{') && amnezia::detect(input) {
            return amnezia::conf(input);
        }
        let mut p = if input.starts_with('{') {
            let mut value: Value = serde_json::from_str(input).map_err(|_| Error::Syntax)?;
            if value.get("schema_version").is_some() {
                serde_json::from_value(value).map_err(|_| Error::Syntax)?
            } else if value.get("server").is_some() {
                hysteria::config(value)?
            } else if value.get("address").is_some() {
                Self::legacy_json(&value)?
            } else {
                let name = value
                    .as_object_mut()
                    .and_then(|m| m.remove("name"))
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default();
                Self::from_endpoint(
                    serde_json::from_value(value).map_err(|_| Error::Syntax)?,
                    name,
                )
            }
        } else {
            let value: toml::Value = match toml::from_str(input) {
                Ok(v) => v,
                Err(_) => return hysteria::yaml(input),
            };
            if value.get("endpoint").is_some()
                && (value.get("hostname").is_some() || value.get("addresses").is_some())
            {
                return Err(Error::Ambiguous);
            }
            let mut endpoint_value = value.get("endpoint").unwrap_or(&value).clone();
            let name = endpoint_value
                .as_table_mut()
                .and_then(|m| m.remove("name"))
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default();
            let endpoint: Endpoint = endpoint_value.try_into().map_err(|_| Error::Syntax)?;
            let mut p = Self::from_endpoint(endpoint, name);
            if value.get("endpoint").is_some() {
                p.original_cli = Some(value);
            }
            p
        };
        if p.name.is_empty() {
            p.name = p.endpoint.hostname.clone();
        }
        p.validate()?;
        Ok(p)
    }
    fn legacy_json(v: &Value) -> Result<Self> {
        let field = |k: &str| v.get(k).and_then(Value::as_str).ok_or(Error::Syntax);
        let address = field("address")?;
        let port = v
            .get("port")
            .and_then(|x| {
                x.as_str()
                    .and_then(|s| s.parse::<u16>().ok())
                    .or_else(|| x.as_u64().and_then(|n| u16::try_from(n).ok()))
            })
            .ok_or(Error::Field("port"))?;
        let address = if address.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{address}]:{port}")
        } else {
            format!("{address}:{port}")
        };
        let hostname = v
            .get("domain")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .unwrap_or(field("address")?)
            .to_owned();
        let protocol = field("protocol")?.to_ascii_lowercase();
        let protocol = match protocol.as_str() {
            "quic" | "http3" | "h3" => "http3",
            "http2" | "h2" => "http2",
            _ => return Err(Error::Field("protocol")),
        };
        let e = Endpoint {
            hostname,
            addresses: vec![address],
            username: Secret::new(field("username")?),
            password: Secret::new(field("password")?),
            custom_sni: v
                .get("sni")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
            has_ipv6: true,
            skip_verification: false,
            certificate: String::new(),
            upstream_protocol: protocol.into(),
            client_random_prefix: String::new(),
            anti_dpi: false,
            dns_upstreams: vec![],
            extra: BTreeMap::new(),
        };
        // The legacy JSON has no CA field. Its embedded official link is authoritative for TLS trust.
        if let Some(uri) = v
            .get("deeplink")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            let mut p = link::decode(uri)?;
            if p.endpoint.username != e.username
                || p.endpoint.password != e.password
                || p.endpoint.addresses != e.addresses
                || p.endpoint.hostname != e.hostname
                || p.endpoint.upstream_protocol != e.upstream_protocol
                || (if p.endpoint.custom_sni.is_empty() {
                    &p.endpoint.hostname
                } else {
                    &p.endpoint.custom_sni
                }) != (if e.custom_sni.is_empty() {
                    &e.hostname
                } else {
                    &e.custom_sni
                })
            {
                return Err(Error::Ambiguous);
            }
            p.name = v
                .get("label")
                .and_then(Value::as_str)
                .unwrap_or(&p.name)
                .to_owned();
            return Ok(p);
        }
        Ok(Self::from_endpoint(
            e,
            v.get("label")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .into(),
        ))
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(Error::Version);
        }
        match (&self.protocol, &self.hysteria2, &self.amneziawg) {
            (Protocol::TrustTunnel, None, None) => {}
            (Protocol::Hysteria2, Some(options), None) => {
                options.validate()?;
                if self.endpoint.upstream_protocol != "http3" || self.original_cli.is_some() {
                    return Err(Error::Field("protocol"));
                }
            }
            (Protocol::AmneziaWg, None, Some(options)) => {
                options.validate()?;
                amnezia::key(self.endpoint.password.expose(), "private key")?;
                // Several addresses are the resolved addresses of the one peer.
                if self.endpoint.upstream_protocol != "http3" || self.original_cli.is_some() {
                    return Err(Error::Field("protocol"));
                }
            }
            _ => return Err(Error::Field("protocol")),
        }
        let e = &self.endpoint;
        if self.name.len() > 1024 {
            return Err(Error::Field("name"));
        }
        if e.hostname.is_empty()
            || e.hostname.len() > 253
            || e.hostname
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@'))
        {
            return Err(Error::Field("hostname"));
        }
        if e.addresses.is_empty() || e.addresses.len() > 64 {
            return Err(Error::Field("addresses"));
        }
        for address in &e.addresses {
            validate_address(address)?;
        }
        for (name, s) in [
            ("username", e.username.expose()),
            ("password", e.password.expose()),
        ] {
            if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
                return Err(Error::Field(name));
            }
        }
        if e.username.expose().contains(':') {
            return Err(Error::Field("username"));
        }
        if !matches!(e.upstream_protocol.as_str(), "http2" | "http3") {
            return Err(Error::Field("upstream_protocol"));
        }
        if e.custom_sni.len() > 253
            || e.custom_sni
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(Error::Field("custom_sni"));
        }
        if e.dns_upstreams.len() > 32
            || e.dns_upstreams
                .iter()
                .any(|s| s.is_empty() || s.len() > 2048 || s.chars().any(char::is_control))
        {
            return Err(Error::Field("dns_upstreams"));
        }
        if !e.client_random_prefix.is_empty() {
            let parts: Vec<_> = e.client_random_prefix.split('/').collect();
            if parts.len() > 2
                || parts.iter().any(|s| {
                    s.is_empty()
                        || s.len() > 64
                        || s.len() % 2 != 0
                        || !s.bytes().all(|c| c.is_ascii_hexdigit())
                })
                || (parts.len() == 2 && parts[0].len() != parts[1].len())
            {
                return Err(Error::Field("client_random_prefix"));
            }
        }
        if !e.certificate.is_empty() {
            pem_der(&e.certificate)?;
        }
        Ok(())
    }
    pub fn export(&self, format: Format) -> Result<Export> {
        self.validate()?;
        if format == Format::Conf && self.protocol != Protocol::AmneziaWg {
            return Err(Error::Field("only AmneziaWG profiles export a config"));
        }
        if self.protocol == Protocol::AmneziaWg {
            return match format {
                Format::Json => Ok(Export {
                    content: serde_json::to_string_pretty(self).map_err(|_| Error::Syntax)?,
                    losses: vec![],
                }),
                Format::Conf => {
                    let mut losses = vec![];
                    if !self.policy.is_null() {
                        losses.push("Routing policy is only preserved in JSON");
                    }
                    if !self.extensions.is_empty()
                        || !self.endpoint.extra.is_empty()
                        || !self.endpoint.dns_upstreams.is_empty()
                    {
                        losses.push("Additional profile fields are only preserved in JSON");
                    }
                    Ok(Export {
                        content: amnezia::encode(self)?,
                        losses,
                    })
                }
                _ => Err(Error::Field(
                    "AmneziaWG exports require JSON or an AmneziaWG config",
                )),
            };
        }
        if self.protocol == Protocol::Hysteria2 {
            return match format {
                Format::Json => Ok(Export {
                    content: serde_json::to_string_pretty(self).map_err(|_| Error::Syntax)?,
                    losses: vec![],
                }),
                Format::Link => {
                    let mut losses = vec![];
                    if !self.policy.is_null() {
                        losses.push("Routing policy is only preserved in JSON");
                    }
                    if !self.endpoint.certificate.is_empty() {
                        losses.push("Custom CA certificate is only preserved in JSON");
                    }
                    if !self.endpoint.dns_upstreams.is_empty() {
                        losses.push("DNS upstreams are only preserved in JSON");
                    }
                    if !self.endpoint.has_ipv6 {
                        losses.push("IPv6 restriction is only preserved in JSON");
                    }
                    if let Some(h) = &self.hysteria2 {
                        if h.hop_interval_min_ms != 0 {
                            losses.push("Port hopping interval is only preserved in JSON");
                        }
                        if h.up_bps != 0
                            || h.down_bps != 0
                            || !h.congestion.is_empty()
                            || h.quic != Default::default()
                        {
                            losses.push("Bandwidth, congestion and QUIC settings are only preserved in JSON");
                        }
                        if !h.client_certificate.is_empty() {
                            losses.push("Client certificate is only preserved in JSON");
                        }
                        if h.gecko.as_ref().is_some_and(|g| *g != Default::default()) {
                            losses.push("Gecko packet sizes are only preserved in JSON");
                        }
                    }
                    if !self.extensions.is_empty()
                        || !self.endpoint.extra.is_empty()
                        || !self.unknown_tlv.is_empty()
                    {
                        losses.push("Additional profile fields are only preserved in JSON");
                    }
                    Ok(Export {
                        content: hysteria::encode(self)?,
                        losses,
                    })
                }
                _ => Err(Error::Field(
                    "Hysteria 2 exports require JSON or a hy2 link",
                )),
            };
        }
        let mut losses = vec![];
        if format != Format::Json {
            if !self.policy.is_null() {
                losses.push("Application policy is only preserved in R-TrustTunnel JSON");
            }
            if !self.extensions.is_empty() {
                losses.push("Application extensions are only preserved in JSON");
            }
            if !self.unknown_tlv.is_empty() && format != Format::Link {
                losses.push("Unknown tt fields are not representable in TOML");
            }
        }
        let content = match format {
            Format::Json => serde_json::to_string_pretty(self).map_err(|_| Error::Syntax)?,
            Format::Link => {
                if self.original_cli.is_some() {
                    losses.push(
                        "tt links do not contain CLI routing, DNS policy or listener settings",
                    );
                }
                if !self.endpoint.extra.is_empty() {
                    losses.push("Additional endpoint fields have no tt representation");
                }
                link::encode(self)?
            }
            Format::Conf => unreachable!("rejected above"),
            Format::EndpointToml | Format::CliToml => {
                let mut e = toml::Value::try_from(&self.endpoint).map_err(|_| Error::Syntax)?;
                if format == Format::EndpointToml {
                    if self.original_cli.is_some() {
                        losses.push(
                            "Endpoint TOML does not include CLI routing and listener settings",
                        );
                    }
                    e.as_table_mut()
                        .ok_or(Error::Syntax)?
                        .insert("name".into(), self.name.clone().into());
                    toml::to_string_pretty(&e).map_err(|_| Error::Syntax)?
                } else {
                    let table = e.as_table_mut().ok_or(Error::Syntax)?;
                    if let Some(v) = table.remove("client_random_prefix") {
                        table.insert("client_random".into(), v);
                    }
                    let mut root = self.original_cli.clone().unwrap_or_else(|| toml::from_str("vpn_mode = 'general'\nkillswitch_enabled = true\n[listener.tun]\nincluded_routes = ['0.0.0.0/0', '::/0']\nchange_system_dns = true\nmtu_size = 1280\n").expect("static TOML"));
                    root.as_table_mut()
                        .ok_or(Error::Syntax)?
                        .insert("endpoint".into(), e);
                    toml::to_string_pretty(&root).map_err(|_| Error::Syntax)?
                }
            }
        };
        if content.len() > MAX_INPUT {
            return Err(Error::TooLarge);
        }
        Ok(Export { content, losses })
    }
}

pub fn validate_address(s: &str) -> Result<()> {
    if s.len() > 512 || s.contains('@') || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Error::Field("addresses"));
    }
    let a: http::uri::Authority = s.parse().map_err(|_| Error::Field("addresses"))?;
    if a.host().is_empty() || a.port_u16().filter(|p| *p != 0).is_none() {
        return Err(Error::Field("addresses"));
    }
    Ok(())
}
pub(crate) fn pem_der(pem: &str) -> Result<Vec<u8>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut pem.as_bytes())
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| Error::Field("certificate"))?;
    if certs.is_empty() {
        return Err(Error::Field("certificate"));
    }
    let bytes: Vec<_> = certs
        .iter()
        .flat_map(|c| c.as_ref().iter().copied())
        .collect();
    der_pem(&bytes)?;
    Ok(bytes)
}
pub(crate) fn der_pem(mut bytes: &[u8]) -> Result<String> {
    use base64::Engine;
    let mut result = String::new();
    while !bytes.is_empty() {
        if bytes.len() < 2 || bytes[0] != 0x30 {
            return Err(Error::Field("certificate"));
        }
        let (len, header) = if bytes[1] < 128 {
            (bytes[1] as usize, 2)
        } else {
            let n = (bytes[1] & 0x7f) as usize;
            if n == 0 || n > 4 || bytes.len() < 2 + n {
                return Err(Error::Field("certificate"));
            }
            let size = bytes[2..2 + n]
                .iter()
                .fold(0usize, |v, b| (v << 8) | *b as usize);
            (size, 2 + n)
        };
        let total = len
            .checked_add(header)
            .filter(|n| *n <= bytes.len())
            .ok_or(Error::Field("certificate"))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes[..total]);
        result.push_str("-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            result.push_str(std::str::from_utf8(chunk).map_err(|_| Error::Syntax)?);
            result.push('\n');
        }
        result.push_str("-----END CERTIFICATE-----\n");
        bytes = &bytes[total..];
    }
    Ok(result)
}
