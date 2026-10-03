//! Hysteria 2 profile detection. Unknown transport/security options fail closed.
use super::*;
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    TrustTunnel,
    Hysteria2,
    #[serde(rename = "amneziawg")]
    AmneziaWg,
}
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2 {
    #[serde(default)]
    pub salamander: Secret,
    #[serde(default)]
    pub pin_sha256: String,
    /// Port-hopping set such as `443,20000-30000`; empty disables hopping.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hop_ports: String,
    /// Hop interval bounds in milliseconds; zero selects the upstream default.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub hop_interval_min_ms: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub hop_interval_max_ms: u64,
    /// Bandwidth in bits per second; zero leaves congestion control automatic.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub up_bps: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub down_bps: u64,
    /// `bbr` or `reno` when no upload bandwidth is set; empty keeps the engine default.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub congestion: String,
    #[serde(default, skip_serializing_if = "Quic::is_default")]
    pub quic: Quic,
    /// Gecko obfuscation over Salamander with the same password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gecko: Option<Gecko>,
    /// Mutual TLS: PEM certificate chain and private key, embedded in JSON only.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_certificate: String,
    #[serde(default, skip_serializing_if = "Secret::is_empty")]
    pub client_key: Secret,
}
/// Datagram size range for padded Gecko handshake fragments.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gecko {
    pub min_packet_size: u16,
    pub max_packet_size: u16,
}
impl Default for Gecko {
    fn default() -> Self {
        Self {
            min_packet_size: 512,
            max_packet_size: 1200,
        }
    }
}
/// QUIC flow-control and liveness settings. Zero selects the upstream default.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quic {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub stream_receive_window: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub connection_receive_window: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_idle_timeout_ms: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub keep_alive_ms: u64,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_path_mtu_discovery: bool,
}
impl Quic {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("stream receive window", self.stream_receive_window),
            ("connection receive window", self.connection_receive_window),
        ] {
            // Upstream sets only a minimum; the maximum is QUIC's varint range.
            if value != 0 && !(MIN_WINDOW..=MAX_WINDOW).contains(&value) {
                return Err(Error::Field(name));
            }
        }
        // Upstream bounds; the two periods are independent, as in the official client.
        if self.max_idle_timeout_ms != 0 && !(4_000..=120_000).contains(&self.max_idle_timeout_ms) {
            return Err(Error::Field("QUIC idle timeout"));
        }
        if self.keep_alive_ms != 0 && !(2_000..=60_000).contains(&self.keep_alive_ms) {
            return Err(Error::Field("QUIC keep-alive period"));
        }
        Ok(())
    }
    pub fn idle_timeout_ms(&self) -> u64 {
        if self.max_idle_timeout_ms == 0 {
            30_000
        } else {
            self.max_idle_timeout_ms
        }
    }
    /// Upstream default of 10 s, kept below a shorter configured idle timeout.
    pub fn keep_alive_period_ms(&self) -> u64 {
        if self.keep_alive_ms == 0 {
            10_000.min(self.idle_timeout_ms() / 2)
        } else {
            self.keep_alive_ms
        }
    }
}
const MIN_WINDOW: u64 = 16 * 1024;
const MAX_WINDOW: u64 = (1 << 62) - 1;
const MIN_HOP_MS: u64 = 5_000;
const DEFAULT_HOP_MS: u64 = 30_000;
fn is_zero(n: &u64) -> bool {
    *n == 0
}
/// Parses a port set such as `443,20000-30000` into sorted, merged ranges.
pub fn port_ranges(spec: &str) -> Result<Vec<(u16, u16)>> {
    if spec.is_empty() || spec.len() > 1024 {
        return Err(Error::Field("hop ports"));
    }
    let mut ranges = vec![];
    for part in spec.split(',') {
        let (start, end) = part.split_once('-').unwrap_or((part, part));
        let parse = |s: &str| {
            s.parse::<u16>()
                .ok()
                .filter(|p| *p != 0 && s.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(Error::Field("hop ports"))
        };
        let (start, end) = (parse(start)?, parse(end)?);
        ranges.push((start.min(end), start.max(end)));
    }
    if ranges.len() > 64 {
        return Err(Error::Field("hop ports"));
    }
    ranges.sort_unstable();
    let mut merged: Vec<(u16, u16)> = vec![];
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    Ok(merged)
}
/// A lone port is written as `p-p`: upstream treats it as hopping on one
/// port, which still rotates the local socket.
fn format_ports(ranges: &[(u16, u16)]) -> String {
    if let [(a, b)] = ranges
        && a == b
    {
        return format!("{a}-{a}");
    }
    ranges
        .iter()
        .map(|(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}
impl Hysteria2 {
    /// Milliseconds between hops as `(min, max)`; equal values hop at a fixed interval.
    pub fn hop_interval_ms(&self) -> (u64, u64) {
        match (self.hop_interval_min_ms, self.hop_interval_max_ms) {
            (0, 0) => (DEFAULT_HOP_MS, DEFAULT_HOP_MS),
            (min, max) => (min, max),
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.salamander.expose().len() > 4096 {
            return Err(Error::Field("obfuscation password"));
        }
        if self.client_certificate.is_empty() != self.client_key.expose().is_empty()
            || self.client_key.expose().len() > 16 * 1024
        {
            return Err(Error::Field("client certificate"));
        }
        if !self.client_certificate.is_empty() {
            pem_der(&self.client_certificate).map_err(|_| Error::Field("client certificate"))?;
            let mut key = self.client_key.expose().as_bytes();
            if !matches!(rustls_pemfile::private_key(&mut key), Ok(Some(_))) {
                return Err(Error::Field("client key"));
            }
        }
        if let Some(g) = &self.gecko
            && (self.salamander.expose().len() < 4
                || g.min_packet_size == 0
                || g.min_packet_size > g.max_packet_size
                || g.max_packet_size > 2048)
        {
            return Err(Error::Field("gecko"));
        }
        if !self.hop_ports.is_empty() {
            let ranges = port_ranges(&self.hop_ports)?;
            if format_ports(&ranges) != self.hop_ports {
                return Err(Error::Field("hop ports"));
            }
        }
        let (min, max) = self.hop_interval_ms();
        if (self.hop_interval_min_ms == 0) != (self.hop_interval_max_ms == 0)
            || min < MIN_HOP_MS
            || max < min
            || max > 24 * 3600 * 1000
            || (self.hop_ports.is_empty() && self.hop_interval_min_ms != 0)
        {
            return Err(Error::Field("hop interval"));
        }
        // 100 Gbit/s bounds arithmetic in congestion control.
        if self.up_bps > 100_000_000_000
            || self.down_bps > 100_000_000_000
            || (self.up_bps != 0 && self.up_bps < 65_536)
            || (self.down_bps != 0 && self.down_bps < 65_536)
        {
            return Err(Error::Field("bandwidth"));
        }
        if !matches!(self.congestion.as_str(), "" | "bbr" | "reno") {
            return Err(Error::Field("congestion"));
        }
        self.quic.validate()?;
        if !self.pin_sha256.is_empty()
            && (self.pin_sha256.len() != 64
                || !self.pin_sha256.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Error::Field("pinSHA256"));
        }
        Ok(())
    }
}
fn decode(text: &str) -> Result<String> {
    percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .map(|s| s.into_owned())
        .map_err(|_| Error::Syntax)
}
fn base(
    server: &str,
    auth: String,
    sni: String,
    insecure: bool,
    options: Hysteria2,
    name: String,
) -> Result<Profile> {
    let authority: http::uri::Authority = server.parse().map_err(|_| Error::Field("server"))?;
    let port = authority.port_u16().unwrap_or(443);
    if port == 0 || server.contains('@') || server.contains('/') {
        return Err(Error::Field("server"));
    }
    let address = format!("{}:{port}", authority.host());
    // Authority::host retains brackets for IPv6.
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let mut p = Profile::from_endpoint(
        Endpoint {
            hostname: if sni.is_empty() { host.into() } else { sni },
            addresses: vec![address],
            username: Secret::new("hysteria2"),
            password: Secret::new(auth),
            custom_sni: String::new(),
            has_ipv6: true,
            skip_verification: insecure,
            certificate: String::new(),
            upstream_protocol: "http3".into(),
            client_random_prefix: String::new(),
            anti_dpi: false,
            dns_upstreams: vec![],
            extra: BTreeMap::new(),
        },
        name,
    );
    p.protocol = Protocol::Hysteria2;
    p.hysteria2 = Some(options);
    if p.name.is_empty() {
        p.name = host.into()
    }
    p.validate()?;
    Ok(p)
}
pub fn link(input: &str) -> Result<Profile> {
    if input.len() > MAX_LINK {
        return Err(Error::TooLarge);
    }
    let (input, hop_ports) = split_link_ports(input)?;
    let url = url::Url::parse(&input).map_err(|_| Error::Syntax)?;
    if !matches!(url.scheme(), "hy2" | "hysteria2") || !matches!(url.path(), "" | "/") {
        return Err(Error::Syntax);
    }
    let mut params = BTreeMap::new();
    for (k, v) in url.query_pairs() {
        if params.insert(k.into_owned(), v.into_owned()).is_some() {
            return Err(Error::Ambiguous);
        }
    }
    if params.keys().any(|k| {
        !matches!(
            k.as_str(),
            "sni" | "insecure" | "obfs" | "obfs-password" | "pinSHA256"
        )
    }) {
        return Err(Error::Field("Hysteria URI option"));
    }
    let obfs = params.remove("obfs").unwrap_or_default();
    if !matches!(obfs.as_str(), "" | "salamander" | "gecko") {
        return Err(Error::Field("obfs"));
    }
    let password = params.remove("obfs-password").unwrap_or_default();
    if obfs.is_empty() != password.is_empty() {
        return Err(Error::Field("obfs-password"));
    }
    let insecure = match params.remove("insecure").as_deref() {
        None | Some("0") => false,
        Some("1") => true,
        _ => return Err(Error::Field("insecure")),
    };
    let auth = decode(url.username())?;
    let auth = if let Some(password) = url.password() {
        format!("{auth}:{}", decode(password)?)
    } else {
        auth
    };
    let server = format!(
        "{}:{}",
        url.host().ok_or(Error::Field("server"))?,
        url.port().unwrap_or(443)
    );
    let pin = normalize_pin(&params.remove("pinSHA256").unwrap_or_default());
    base(
        &server,
        auth,
        params.remove("sni").unwrap_or_default(),
        insecure,
        Hysteria2 {
            salamander: Secret::new(password),
            pin_sha256: pin,
            hop_ports,
            gecko: (obfs == "gecko").then(Gecko::default),
            ..Default::default()
        },
        decode(url.fragment().unwrap_or_default())?,
    )
}
/// Upstream normalization: lowercase hex with `:` and `-` separators removed.
fn normalize_pin(pin: &str) -> String {
    pin.replace([':', '-'], "").to_ascii_lowercase()
}
/// Replaces a multi-port authority (`host:443,20000-30000`) with its first port
/// so the URL parser accepts it, returning the canonical hop set separately.
fn split_link_ports(input: &str) -> Result<(String, String)> {
    let start = input.find("://").ok_or(Error::Syntax)? + 3;
    let end = input[start..]
        .find(['/', '?', '#'])
        .map_or(input.len(), |n| start + n);
    let authority = &input[start..end];
    let host_start = authority.rfind('@').map_or(0, |n| n + 1);
    let (host, ports) = split_ports(&authority[host_start..])?;
    if ports.is_empty() {
        return Ok((input.into(), String::new()));
    }
    let ranges = port_ranges(&ports)?;
    let first = ranges[0].0;
    Ok((
        format!(
            "{}{}{host}:{first}{}",
            &input[..start],
            &authority[..host_start],
            &input[end..]
        ),
        format_ports(&ranges),
    ))
}
/// Splits `host:ports` when the port part is a multi-port set; plain ports stay attached.
fn split_ports(server: &str) -> Result<(&str, String)> {
    let colon = match server.rfind(':') {
        Some(n) if !server[n..].contains(']') => n,
        _ => return Ok((server, String::new())),
    };
    let ports = &server[colon + 1..];
    if !ports.contains([',', '-']) {
        return Ok((server, String::new()));
    }
    Ok((&server[..colon], ports.into()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ClientConfig {
    server: String,
    #[serde(default)]
    auth: String,
    #[serde(default)]
    tls: Tls,
    #[serde(default)]
    obfs: Option<Obfs>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    transport: Option<Transport>,
    #[serde(default)]
    bandwidth: Option<Bandwidth>,
    #[serde(default)]
    congestion: Option<Congestion>,
    #[serde(default)]
    quic: Option<QuicConfig>,
    // Local listener modes of the official client have no meaning for a system
    // VPN profile and carry no transport or security settings.
    #[serde(default, rename = "socks5")]
    _socks5: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "http")]
    _http: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "tcpForwarding")]
    _tcp_forwarding: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "udpForwarding")]
    _udp_forwarding: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "tcpTProxy")]
    _tcp_tproxy: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "udpTProxy")]
    _udp_tproxy: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "tcpRedirect")]
    _tcp_redirect: Option<serde::de::IgnoredAny>,
    #[serde(default, rename = "tun")]
    _tun: Option<serde::de::IgnoredAny>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    udp: Option<UdpTransport>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct UdpTransport {
    #[serde(default)]
    hop_interval: Option<String>,
    #[serde(default)]
    min_hop_interval: Option<String>,
    #[serde(default)]
    max_hop_interval: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bandwidth {
    #[serde(default)]
    up: Option<Scalar>,
    #[serde(default)]
    down: Option<Scalar>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Congestion {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    bbr_profile: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct QuicConfig {
    #[serde(default)]
    init_stream_receive_window: Option<u64>,
    #[serde(default)]
    max_stream_receive_window: Option<u64>,
    #[serde(default)]
    init_conn_receive_window: Option<u64>,
    #[serde(default)]
    max_conn_receive_window: Option<u64>,
    #[serde(default)]
    max_idle_timeout: Option<String>,
    #[serde(default)]
    keep_alive_period: Option<String>,
    #[serde(default, rename = "disablePathMTUDiscovery")]
    disable_path_mtu_discovery: Option<bool>,
}
/// YAML allows bandwidth as a bare number or a string with units.
#[derive(Deserialize)]
#[serde(untagged)]
enum Scalar {
    Number(u64),
    Text(String),
}
/// Go-style duration (`30s`, `1m30s`, `7.5s`, `500ms`) in whole milliseconds.
fn duration_ms(text: &str, field: &'static str) -> Result<u64> {
    let mut rest = text.trim();
    if rest.is_empty() || rest.len() > 32 {
        return Err(Error::Field(field));
    }
    let mut nanos: u128 = 0;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or(Error::Field(field))?;
        let value: f64 = rest[..digits].parse().map_err(|_| Error::Field(field))?;
        rest = &rest[digits..];
        let unit = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale: f64 = match &rest[..unit] {
            "ns" => 1.0,
            "us" | "µs" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            _ => return Err(Error::Field(field)),
        };
        rest = &rest[unit..];
        nanos += (value * scale) as u128;
    }
    // Sub-millisecond precision has no effect on these timers.
    let ms = (nanos + 500_000) / 1_000_000;
    if ms == 0 || ms > 24 * 3600 * 1000 {
        return Err(Error::Field(field));
    }
    Ok(ms as u64)
}
/// Bandwidth in bits per second; units follow the official client (decimal SI).
fn bandwidth_bps(value: &Scalar) -> Result<u64> {
    let text = match value {
        Scalar::Number(n) => return Ok(*n),
        Scalar::Text(t) => t.trim().to_ascii_lowercase(),
    };
    let split = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let number: f64 = text[..split]
        .parse()
        .map_err(|_| Error::Field("bandwidth"))?;
    let scale: f64 = match text[split..].trim() {
        "" | "b" | "bps" => 1.0,
        "k" | "kb" | "kbps" => 1e3,
        "m" | "mb" | "mbps" => 1e6,
        "g" | "gb" | "gbps" => 1e9,
        "t" | "tb" | "tbps" => 1e12,
        _ => return Err(Error::Field("bandwidth")),
    };
    let bps = number * scale;
    if !bps.is_finite() || bps < 0.0 || bps > u64::MAX as f64 {
        return Err(Error::Field("bandwidth"));
    }
    Ok(bps as u64)
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Tls {
    #[serde(default)]
    sni: String,
    #[serde(default)]
    insecure: bool,
    #[serde(default, rename = "pinSHA256")]
    pin: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Obfs {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    salamander: Option<ObfsSecret>,
    #[serde(default)]
    gecko: Option<GeckoConfig>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct GeckoConfig {
    password: String,
    #[serde(default)]
    min_packet_size: Option<u16>,
    #[serde(default)]
    max_packet_size: Option<u16>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObfsSecret {
    password: String,
}
pub fn config(value: Value) -> Result<Profile> {
    let c: ClientConfig =
        serde_json::from_value(value).map_err(|_| Error::Field("Hysteria client option"))?;
    if c.server.starts_with("hy2://") || c.server.starts_with("hysteria2://") {
        if !c.auth.is_empty()
            || !c.tls.sni.is_empty()
            || c.tls.insecure
            || !c.tls.pin.is_empty()
            || c.obfs.is_some()
        {
            return Err(Error::Ambiguous);
        }
        let mut p = link(&c.server)?;
        if !c.name.is_empty() {
            p.name = c.name.clone();
        }
        extended(&c, p.hysteria2.as_mut().ok_or(Error::Field("hysteria2"))?)?;
        p.validate()?;
        return Ok(p);
    }
    let (password, gecko) = match &c.obfs {
        Some(Obfs {
            kind,
            salamander: Some(s),
            gecko: None,
        }) if kind == "salamander" && !s.password.is_empty() => (s.password.clone(), None),
        Some(Obfs {
            kind,
            salamander: None,
            gecko: Some(g),
        }) if kind == "gecko" && !g.password.is_empty() => {
            let default = Gecko::default();
            (
                g.password.clone(),
                Some(Gecko {
                    min_packet_size: g.min_packet_size.unwrap_or(default.min_packet_size),
                    max_packet_size: g.max_packet_size.unwrap_or(default.max_packet_size),
                }),
            )
        }
        Some(_) => return Err(Error::Field("obfs")),
        None => (String::new(), None),
    };
    let (host, ports) = split_ports(&c.server)?;
    let (server, hop_ports) = if ports.is_empty() {
        (c.server.clone(), String::new())
    } else {
        let ranges = port_ranges(&ports)?;
        (format!("{host}:{}", ranges[0].0), format_ports(&ranges))
    };
    let mut options = Hysteria2 {
        salamander: Secret::new(password),
        pin_sha256: normalize_pin(&c.tls.pin),
        hop_ports,
        gecko,
        ..Default::default()
    };
    extended(&c, &mut options)?;
    base(&server, c.auth, c.tls.sni, c.tls.insecure, options, c.name)
}
/// Transport, bandwidth, congestion and QUIC sections of the official client config.
fn extended(c: &ClientConfig, o: &mut Hysteria2) -> Result<()> {
    if let Some(t) = &c.transport {
        if !matches!(t.kind.as_deref(), None | Some("udp")) {
            return Err(Error::Field("transport"));
        }
        if let Some(u) = &t.udp {
            let field = "hop interval";
            match (&u.hop_interval, &u.min_hop_interval, &u.max_hop_interval) {
                (None, None, None) => {}
                (Some(fixed), None, None) => {
                    o.hop_interval_min_ms = duration_ms(fixed, field)?;
                    o.hop_interval_max_ms = o.hop_interval_min_ms;
                }
                (None, Some(min), Some(max)) => {
                    o.hop_interval_min_ms = duration_ms(min, field)?;
                    o.hop_interval_max_ms = duration_ms(max, field)?;
                }
                _ => return Err(Error::Field(field)),
            }
            // Upstream accepts an interval without hop ports and ignores it.
            if o.hop_ports.is_empty() {
                o.hop_interval_min_ms = 0;
                o.hop_interval_max_ms = 0;
            }
        }
    }
    if let Some(b) = &c.bandwidth {
        o.up_bps = b.up.as_ref().map(bandwidth_bps).transpose()?.unwrap_or(0);
        o.down_bps = b.down.as_ref().map(bandwidth_bps).transpose()?.unwrap_or(0);
    }
    if let Some(cc) = &c.congestion {
        o.congestion = match cc.kind.as_deref() {
            None | Some("") => String::new(),
            Some(kind @ ("bbr" | "reno")) => kind.into(),
            Some(_) => return Err(Error::Field("congestion")),
        };
        // Quinn implements one BBR variant; other profiles are not equivalent.
        if !matches!(
            cc.bbr_profile.as_deref(),
            None | Some("") | Some("standard")
        ) {
            return Err(Error::Field("congestion bbrProfile"));
        }
    }
    if let Some(q) = &c.quic {
        let window = |init: Option<u64>, max: Option<u64>, field| match (init, max) {
            (Some(i), Some(m)) if i > m => Err(Error::Field(field)),
            (i, m) => Ok(m.or(i).unwrap_or(0)),
        };
        o.quic = Quic {
            stream_receive_window: window(
                q.init_stream_receive_window,
                q.max_stream_receive_window,
                "stream receive window",
            )?,
            connection_receive_window: window(
                q.init_conn_receive_window,
                q.max_conn_receive_window,
                "connection receive window",
            )?,
            max_idle_timeout_ms: q
                .max_idle_timeout
                .as_deref()
                .map(|d| duration_ms(d, "QUIC idle timeout"))
                .transpose()?
                .unwrap_or(0),
            keep_alive_ms: q
                .keep_alive_period
                .as_deref()
                .map(|d| duration_ms(d, "QUIC keep-alive period"))
                .transpose()?
                .unwrap_or(0),
            disable_path_mtu_discovery: q.disable_path_mtu_discovery.unwrap_or(false),
        };
    }
    Ok(())
}
pub fn yaml(input: &str) -> Result<Profile> {
    let options = serde_saphyr::options! {with_snippet:false,emit_comments:false,reject_unsupported_tags:true,budget:serde_saphyr::budget!{max_documents:1,max_depth:16,max_nodes:2048,max_aliases:0}};
    let value: Value =
        serde_saphyr::from_str_with_options(input, options).map_err(|_| Error::Syntax)?;
    config(value)
}
pub fn encode(p: &Profile) -> Result<String> {
    if p.endpoint.addresses.len() != 1 {
        return Err(Error::Field("hy2 link requires one server"));
    }
    let mut url = url::Url::parse(&format!("hysteria2://{}/", p.endpoint.addresses[0]))
        .map_err(|_| Error::Syntax)?;
    url.set_username(p.endpoint.password.expose())
        .map_err(|_| Error::Syntax)?;
    let options = p.hysteria2.as_ref().ok_or(Error::Field("hysteria2"))?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("sni", &p.endpoint.hostname);
        if p.endpoint.skip_verification {
            q.append_pair("insecure", "1");
        }
        if !options.pin_sha256.is_empty() {
            q.append_pair("pinSHA256", &options.pin_sha256);
        }
        if !options.salamander.expose().is_empty() {
            q.append_pair(
                "obfs",
                if options.gecko.is_some() {
                    "gecko"
                } else {
                    "salamander"
                },
            );
            q.append_pair("obfs-password", options.salamander.expose());
        }
    }
    url.set_fragment(Some(&p.name));
    let mut text = url.to_string();
    if !options.hop_ports.is_empty() {
        let port = url.port_or_known_default().ok_or(Error::Syntax)?;
        let host = url.host_str().ok_or(Error::Syntax)?;
        let single = format!("@{host}:{port}/");
        let at = text.find(&single).ok_or(Error::Syntax)?;
        text.replace_range(
            at..at + single.len(),
            &format!("@{host}:{}/", options.hop_ports),
        );
    }
    Ok(text)
}

impl Protocol {
    pub fn is_trust_tunnel(&self) -> bool {
        *self == Self::TrustTunnel
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn links_detect_protocol_and_roundtrip_secrets() {
        let p=Profile::import("hy2://user%3Apassword@vpn.example:443/?obfs=salamander&obfs-password=secret&sni=tls.example#Test").unwrap();
        assert_eq!(p.protocol, Protocol::Hysteria2);
        assert_eq!(p.endpoint.password.expose(), "user:password");
        assert!(!format!("{p:?}").contains("password"));
        assert_eq!(
            Profile::import(&p.export(Format::Link).unwrap().content).unwrap(),
            p
        );
        assert_eq!(
            Profile::import(&p.export(Format::Json).unwrap().content).unwrap(),
            p
        );
    }
    #[test]
    fn port_hopping_links_roundtrip() {
        let p =
            Profile::import("hy2://secret@vpn.example:20000-20010,443,20005-20020/#Hop").unwrap();
        let h = p.hysteria2.as_ref().unwrap();
        assert_eq!(h.hop_ports, "443,20000-20020");
        assert_eq!(p.endpoint.addresses, ["vpn.example:443"]);
        assert_eq!(h.hop_interval_ms(), (30_000, 30_000));
        let link = p.export(Format::Link).unwrap().content.clone();
        assert!(link.contains("@vpn.example:443,20000-20020/"), "{link}");
        assert_eq!(Profile::import(&link).unwrap(), p);
        assert_eq!(
            Profile::import(&p.export(Format::Json).unwrap().content).unwrap(),
            p
        );
        // One port in range form keeps upstream's local-socket rotation.
        let single = Profile::import("hy2://secret@[2001:db8::1]:4443-4443/").unwrap();
        assert_eq!(single.hysteria2.as_ref().unwrap().hop_ports, "4443-4443");
        assert_eq!(single.endpoint.addresses, ["[2001:db8::1]:4443"]);
        let link = single.export(Format::Link).unwrap().content.clone();
        assert_eq!(Profile::import(&link).unwrap(), single);
        let plain = Profile::import("hy2://secret@vpn.example:8443/").unwrap();
        assert!(plain.hysteria2.unwrap().hop_ports.is_empty());
        for bad in [
            "hy2://secret@vpn.example:0-10/",
            "hy2://secret@vpn.example:1-2,x/",
            "hy2://secret@vpn.example:443,/",
            "hy2://secret@vpn.example:70000-70001/",
        ] {
            assert!(Profile::import(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn yaml_transport_bandwidth_and_quic() {
        let p = Profile::import(
            "server: vpn.example:443,30000-30100\nauth: secret\ntransport:\n  type: udp\n  udp:\n    minHopInterval: 15s\n    maxHopInterval: 1m\nbandwidth:\n  up: 100 mbps\n  down: 1.5 Gbps\ncongestion:\n  type: reno\nquic:\n  initStreamReceiveWindow: 8388608\n  maxStreamReceiveWindow: 16777216\n  maxConnReceiveWindow: 33554432\n  maxIdleTimeout: 60s\n  keepAlivePeriod: 20s\n  disablePathMTUDiscovery: true\nsocks5:\n  listen: 127.0.0.1:1080\nlazy: false\n",
        );
        assert!(p.is_err(), "lazy is not a client-mode section");
        let p = Profile::import(
            "server: vpn.example:443,30000-30100\nauth: secret\ntransport:\n  type: udp\n  udp:\n    minHopInterval: 15s\n    maxHopInterval: 1m\nbandwidth:\n  up: 100 mbps\n  down: 1.5 Gbps\ncongestion:\n  type: reno\nquic:\n  initStreamReceiveWindow: 8388608\n  maxStreamReceiveWindow: 16777216\n  maxConnReceiveWindow: 33554432\n  maxIdleTimeout: 60s\n  keepAlivePeriod: 20s\n  disablePathMTUDiscovery: true\nsocks5:\n  listen: 127.0.0.1:1080\n",
        )
        .unwrap();
        let h = p.hysteria2.as_ref().unwrap();
        assert_eq!(h.hop_ports, "443,30000-30100");
        assert_eq!(h.hop_interval_ms(), (15_000, 60_000));
        assert_eq!((h.up_bps, h.down_bps), (100_000_000, 1_500_000_000));
        assert_eq!(h.congestion, "reno");
        assert_eq!(
            h.quic,
            Quic {
                stream_receive_window: 16 * 1024 * 1024,
                connection_receive_window: 32 * 1024 * 1024,
                max_idle_timeout_ms: 60_000,
                keep_alive_ms: 20_000,
                disable_path_mtu_discovery: true,
            }
        );
        assert_eq!(
            Profile::import(&p.export(Format::Json).unwrap().content).unwrap(),
            p
        );
        let fixed = Profile::import(
            "server: hy2://secret@vpn.example:443-445/\ntransport:\n  udp:\n    hopInterval: 1m30s\nbandwidth:\n  up: 20m\n",
        )
        .unwrap();
        let h = fixed.hysteria2.as_ref().unwrap();
        assert_eq!(
            (h.hop_interval_ms(), h.up_bps),
            ((90_000, 90_000), 20_000_000)
        );
        for bad in [
            "server: vpn.example:443-445\nauth: x\ntransport:\n  udp:\n    hopInterval: 4s\n",
            "server: vpn.example:443-445\nauth: x\ntransport:\n  udp:\n    hopInterval: 10s\n    minHopInterval: 10s\n    maxHopInterval: 20s\n",
            "server: vpn.example:443-445\nauth: x\ntransport:\n  udp:\n    minHopInterval: 30s\n    maxHopInterval: 10s\n",
            "server: vpn.example:443-445\nauth: x\ntransport:\n  type: wechat-video\n",
            "server: vpn.example\nauth: x\nbandwidth:\n  up: 100 furlongs\n",
            "server: vpn.example\nauth: x\nbandwidth:\n  up: 1 kbps\n",
            "server: vpn.example\nauth: x\ncongestion:\n  type: cubic\n",
            "server: vpn.example\nauth: x\ncongestion:\n  type: bbr\n  bbrProfile: aggressive\n",
            "server: vpn.example\nauth: x\nquic:\n  maxIdleTimeout: 2s\n",
            "server: vpn.example\nauth: x\nquic:\n  keepAlivePeriod: 1s\n",
            "server: vpn.example\nauth: x\nquic:\n  maxStreamReceiveWindow: 1024\n",
            "server: vpn.example\nauth: x\nquic:\n  disableChromeParrot: true\n",
            "server: vpn.example\nauth: x\nrealm:\n  stunTimeout: 5s\n",
        ] {
            assert!(Profile::import(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn certificate_pin_is_normalized_like_upstream() {
        let pin = "BA:88-45:17".to_string() + &":AB".repeat(28);
        let expected = "ba884517".to_string() + &"ab".repeat(28);
        let link = format!("hy2://secret@vpn.example/?pinSHA256={pin}");
        assert_eq!(
            Profile::import(&link)
                .unwrap()
                .hysteria2
                .unwrap()
                .pin_sha256,
            expected
        );
        let yaml = format!("server: vpn.example\nauth: x\ntls:\n  pinSHA256: {pin}\n");
        let p = Profile::import(&yaml).unwrap();
        assert_eq!(p.hysteria2.as_ref().unwrap().pin_sha256, expected);
        assert_eq!(
            Profile::import(&p.export(Format::Link).unwrap().content).unwrap(),
            p
        );
        assert!(Profile::import("hy2://secret@vpn.example/?pinSHA256=abcd").is_err());
    }
    #[test]
    fn upstream_valid_timers_and_windows_are_accepted() {
        let p = Profile::import(
            "server: vpn.example:443-450\nauth: x\ntransport:\n  udp:\n    hopInterval: 7.5s\nquic:\n  keepAlivePeriod: 45s\n  maxIdleTimeout: 2500ms\n  maxConnReceiveWindow: 134217728\n",
        );
        assert!(p.is_err(), "idle timeout below 4 s");
        let p = Profile::import(
            "server: vpn.example:443-450\nauth: x\ntransport:\n  udp:\n    minHopInterval: 7500ms\n    maxHopInterval: 1m0.25s\nquic:\n  keepAlivePeriod: 45s\n  maxStreamReceiveWindow: 268435456\n  maxConnReceiveWindow: 134217728\n",
        )
        .unwrap();
        let h = p.hysteria2.as_ref().unwrap();
        assert_eq!(h.hop_interval_ms(), (7_500, 60_250));
        // A keep-alive longer than the idle timeout is valid upstream.
        assert_eq!(h.quic.keep_alive_period_ms(), 45_000);
        assert_eq!(h.quic.idle_timeout_ms(), 30_000);
        assert_eq!(h.quic.connection_receive_window, 128 * 1024 * 1024);
        assert_eq!(h.quic.stream_receive_window, 256 * 1024 * 1024);
        assert_eq!(
            Profile::import(&p.export(Format::Json).unwrap().content).unwrap(),
            p
        );
    }
    #[test]
    fn gecko_and_client_certificate_options() {
        let p =
            Profile::import("hy2://secret@vpn.example/?obfs=gecko&obfs-password=pass1234").unwrap();
        let h = p.hysteria2.as_ref().unwrap();
        assert_eq!(h.gecko, Some(Gecko::default()));
        let link = p.export(Format::Link).unwrap().content.clone();
        assert!(link.contains("obfs=gecko"), "{link}");
        assert_eq!(Profile::import(&link).unwrap(), p);
        let p = Profile::import(
            "server: vpn.example\nauth: x\nobfs:\n  type: gecko\n  gecko:\n    password: pass1234\n    minPacketSize: 600\n",
        )
        .unwrap();
        assert_eq!(
            p.hysteria2.as_ref().unwrap().gecko,
            Some(Gecko {
                min_packet_size: 600,
                max_packet_size: 1200
            })
        );
        let losses = p.export(Format::Link).unwrap().losses.clone();
        assert!(losses.iter().any(|l| l.contains("Gecko")));
        for bad in [
            "hy2://secret@vpn.example/?obfs=gecko&obfs-password=abc",
            "hy2://secret@vpn.example/?obfs=gecko",
            "server: vpn.example\nauth: x\nobfs:\n  type: gecko\n  gecko:\n    password: pass1234\n    maxPacketSize: 4096\n",
            "server: vpn.example\nauth: x\nobfs:\n  type: gecko\n  gecko:\n    password: pass1234\n    minPacketSize: 900\n    maxPacketSize: 800\n",
            "server: vpn.example\nauth: x\nobfs:\n  type: salamander\n  gecko:\n    password: pass1234\n",
            // Certificate files are never read implicitly.
            "server: vpn.example\nauth: x\ntls:\n  clientCertificate: client.crt\n  clientKey: client.key\n",
        ] {
            assert!(Profile::import(bad).is_err(), "{bad}");
        }
        let mut p = Profile::import("hy2://secret@vpn.example/").unwrap();
        let h = p.hysteria2.as_mut().unwrap();
        h.client_certificate =
            "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n".into();
        assert!(p.validate().is_err(), "certificate without key");
    }
    #[test]
    fn yaml_strict_security_options() {
        let p=Profile::import("server: vpn.example:443\nauth: password\nobfs:\n  type: salamander\n  salamander:\n    password: secret\ntls:\n  sni: tls.example\n").unwrap();
        assert_eq!(p.protocol, Protocol::Hysteria2);
        for raw in [
            "server: vpn.example\nauth: x\nlazy: true",
            "hy2://x@vpn.example/?obfs=unknown",
            "hy2://x@vpn.example/?sni=a&sni=b",
            "server: x\nauth: &a x\nname: *a",
        ] {
            assert!(Profile::import(raw).is_err(), "{raw}")
        }
    }
}
