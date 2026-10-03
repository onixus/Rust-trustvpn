//! AmneziaWG 3 (`awg-quick`) profile detection. Unknown options fail closed.
use super::*;
use base64::Engine;
use std::net::IpAddr;

/// Inclusive `a-b` range of the AmneziaWG configuration; `(0, 0)` means unset.
pub type Range = (u32, u32);

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmneziaWg {
    /// Peer static public key, base64. The interface private key is the
    /// endpoint password.
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Secret::is_empty")]
    pub preshared_key: Secret,
    /// Interface addresses, with or without a prefix length.
    pub addresses: Vec<String>,
    /// Plain DNS servers reached through the tunnel for host name destinations.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    /// Kept for export; routing is decided by the application policy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_ips: Vec<String>,
    /// Zero selects 1280, which every IPv4 and IPv6 path carries.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub mtu: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub persistent_keepalive: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub jc: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub jmin: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub jmax: u32,
    /// S1–S4: random prefix of initiation, response, cookie and transport messages.
    #[serde(default, skip_serializing_if = "is_default")]
    pub paddings: [u32; 4],
    /// H1–H4: message type ranges; empty keeps the WireGuard value.
    #[serde(default, skip_serializing_if = "is_default")]
    pub headers: [String; 4],
    /// I1–I5: signature packets sent before every handshake initiation.
    #[serde(default, skip_serializing_if = "is_default")]
    pub signatures: [String; 5],
    #[serde(default, skip_serializing_if = "Secret::is_empty")]
    pub header_protection_key: Secret,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content_padding_addition: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub random_trailers: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disable_cookies: bool,
    /// Timer ranges in seconds; empty keeps the WireGuard constant.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rekey_after_time: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rekey_timeout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reject_after_time: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub keepalive_timeout: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub max_handshake_attempts: String,
}
fn is_zero(n: &u32) -> bool {
    *n == 0
}
fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// One element of a signature packet (`I1`–`I5`).
#[derive(Clone, Debug, PartialEq)]
pub enum Tag {
    Bytes(Vec<u8>),
    Random(usize),
    Chars(usize),
    Digits(usize),
    Timestamp,
    /// Big-endian length of the (empty) payload.
    DataSize(usize),
}
impl Tag {
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(b) => b.len(),
            Self::Random(n) | Self::Chars(n) | Self::Digits(n) | Self::DataSize(n) => *n,
            Self::Timestamp => 4,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
const MAX_DATAGRAM: usize = 65_507;
/// Parses `<b 0x..><r 16><rc 4><rd 4><t>`; text between tags is ignored, as upstream.
pub fn signature(spec: &str) -> Result<Vec<Tag>> {
    const FIELD: Error = Error::Field("signature packet");
    if spec.len() > 2 * MAX_DATAGRAM + 4096 {
        return Err(FIELD);
    }
    let mut tags = vec![];
    let mut rest = spec;
    while let Some(start) = rest.find('<') {
        let end = rest[start..].find('>').ok_or(FIELD)? + start;
        let mut parts = rest[start + 1..end].split_whitespace();
        let key = parts.next().ok_or(FIELD)?;
        let value = parts.next().unwrap_or("");
        let size = || {
            value
                .parse::<usize>()
                .ok()
                .filter(|n| *n <= MAX_DATAGRAM && value.bytes().all(|b| b.is_ascii_digit()))
                .ok_or(FIELD)
        };
        match key {
            "b" => {
                let hex = value.strip_prefix("0x").unwrap_or(value);
                if hex.is_empty() || !hex.len().is_multiple_of(2) || !hex.is_ascii() {
                    return Err(FIELD);
                }
                let bytes = (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|_| FIELD)?;
                tags.push(Tag::Bytes(bytes));
            }
            "r" => tags.push(Tag::Random(size()?)),
            "rc" => tags.push(Tag::Chars(size()?)),
            "rd" => tags.push(Tag::Digits(size()?)),
            "t" => tags.push(Tag::Timestamp),
            "dz" => tags.push(Tag::DataSize(size()?)),
            // A signature packet carries no payload: both encode zero bytes.
            "d" | "ds" => {}
            _ => return Err(FIELD),
        }
        rest = &rest[end + 1..];
    }
    if tags.iter().map(Tag::len).sum::<usize>() > MAX_DATAGRAM {
        return Err(FIELD);
    }
    Ok(tags)
}

/// `a`, `a-b` or `(off)`; an empty or disabled value is `(0, 0)`.
pub fn range(text: &str, field: &'static str) -> Result<Range> {
    let text = text.trim();
    if text.is_empty() || text == "(off)" {
        return Ok((0, 0));
    }
    let number = |s: &str| {
        s.parse::<u32>()
            .ok()
            .filter(|_| s.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(Error::Field(field))
    };
    let (low, high) = text.split_once('-').unwrap_or((text, text));
    let (low, high) = (number(low)?, number(high)?);
    if high < low {
        return Err(Error::Field(field));
    }
    Ok((low, high))
}
fn format_range((low, high): Range) -> String {
    match (low, high) {
        (0, 0) => String::new(),
        _ if low == high => low.to_string(),
        _ => format!("{low}-{high}"),
    }
}
pub fn key(text: &str, field: &'static str) -> Result<[u8; 32]> {
    let mut bytes = base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| Error::Field(field))?;
    let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| Error::Field(field));
    bytes.zeroize();
    key
}
fn address(text: &str, field: &'static str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = text
        .split_once('/')
        .map_or((text, None), |(i, p)| (i, Some(p)));
    let ip: IpAddr = ip.parse().map_err(|_| Error::Field(field))?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        None => max,
        Some(p) => p
            .parse::<u8>()
            .ok()
            .filter(|n| *n <= max && p.bytes().all(|b| b.is_ascii_digit()))
            .ok_or(Error::Field(field))?,
    };
    Ok((ip, prefix))
}

impl AmneziaWg {
    pub fn mtu(&self) -> usize {
        if self.mtu == 0 {
            1280
        } else {
            self.mtu as usize
        }
    }
    pub fn interface_addresses(&self) -> Vec<(IpAddr, u8)> {
        self.addresses
            .iter()
            .filter_map(|a| address(a, "address").ok())
            .collect()
    }
    /// H1–H4 with the WireGuard message types as defaults.
    pub fn header_ranges(&self) -> Result<[Range; 4]> {
        let mut ranges = [(1, 1), (2, 2), (3, 3), (4, 4)];
        for (range_, text) in ranges.iter_mut().zip(&self.headers) {
            let parsed = range(text, "message header")?;
            if parsed != (0, 0) {
                *range_ = parsed;
            }
        }
        Ok(ranges)
    }
    pub fn validate(&self) -> Result<()> {
        key(&self.public_key, "public key")?;
        if !self.preshared_key.is_empty() {
            key(self.preshared_key.expose(), "preshared key")?;
        }
        let protected = !self.header_protection_key.is_empty();
        if protected
            && key(self.header_protection_key.expose(), "header protection key")? == [0; 32]
        {
            return Err(Error::Field("header protection key"));
        }
        if self.addresses.is_empty() || self.addresses.len() > 8 {
            return Err(Error::Field("address"));
        }
        for a in &self.addresses {
            address(a, "address")?;
        }
        if self.allowed_ips.len() > 4096 {
            return Err(Error::Field("allowed IPs"));
        }
        for a in &self.allowed_ips {
            address(a, "allowed IPs")?;
        }
        if self.dns.len() > 8 || self.dns.iter().any(|d| d.parse::<IpAddr>().is_err()) {
            return Err(Error::Field("DNS"));
        }
        let v6 = self
            .interface_addresses()
            .iter()
            .any(|(ip, _)| ip.is_ipv6());
        if self.mtu != 0 && !(if v6 { 1280 } else { 576 }..=1500).contains(&self.mtu) {
            return Err(Error::Field("MTU"));
        }
        if self.jc > 128 || self.jmin > self.jmax || self.jmax as usize > MAX_DATAGRAM {
            return Err(Error::Field("junk packets"));
        }
        for padding in self.paddings {
            // The reference accepts 16 bits; anything near the MTU cannot be sent.
            if padding > 1024 || (protected && padding < 12) {
                return Err(Error::Field("message padding"));
            }
        }
        let headers = self.header_ranges()?;
        for (i, a) in headers.iter().enumerate() {
            if headers[i + 1..].iter().any(|b| a.0 <= b.1 && b.0 <= a.1) {
                return Err(Error::Field("message header"));
            }
        }
        for spec in &self.signatures {
            signature(spec)?;
        }
        if range(&self.content_padding_addition, "content padding")?.1 > 65_535 {
            return Err(Error::Field("content padding"));
        }
        if range(&self.persistent_keepalive, "persistent keepalive")?.1 > 65_535 {
            return Err(Error::Field("persistent keepalive"));
        }
        for (text, field) in [
            (&self.rekey_after_time, "rekey after time"),
            (&self.rekey_timeout, "rekey timeout"),
            (&self.reject_after_time, "reject after time"),
            (&self.keepalive_timeout, "keepalive timeout"),
            (&self.max_handshake_attempts, "handshake attempts"),
        ] {
            let (low, high) = range(text, field)?;
            // A zero bound would disable the timer the range is meant to tune.
            if (low, high) != (0, 0) && (low == 0 || high > 86_400) {
                return Err(Error::Field(field));
            }
        }
        Ok(())
    }
}

fn switch(text: &str, field: &'static str) -> Result<bool> {
    match text.to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" => Ok(true),
        "off" | "false" | "0" | "no" | "" => Ok(false),
        _ => Err(Error::Field(field)),
    }
}
fn list(text: &str) -> Vec<String> {
    text.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
fn number(text: &str, field: &'static str) -> Result<u32> {
    text.parse::<u32>()
        .ok()
        .filter(|_| text.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(Error::Field(field))
}

/// True for `awg-quick`/`wg-quick` text: an `[Interface]` section header.
pub fn detect(input: &str) -> bool {
    input
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case("[interface]"))
}

/// Imports an `awg-quick` configuration with exactly one peer.
pub fn conf(input: &str) -> Result<Profile> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Interface,
        Peer,
    }
    let mut section = Section::None;
    let mut peers = 0;
    let mut o = AmneziaWg::default();
    let (mut private_key, mut endpoint, mut name) = (String::new(), String::new(), String::new());
    for line in input.lines() {
        let line = line.trim();
        // Amnezia exports carry the profile name as a leading comment.
        if let Some(comment) = line.strip_prefix('#') {
            if section == Section::None && name.is_empty() {
                name = comment.trim().chars().take(256).collect();
            }
            continue;
        }
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            section = match line.to_ascii_lowercase().as_str() {
                "[interface]" => Section::Interface,
                "[peer]" => {
                    peers += 1;
                    Section::Peer
                }
                _ => return Err(Error::Syntax),
            };
            continue;
        }
        let (k, v) = line.split_once('=').ok_or(Error::Syntax)?;
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        match (&section, k.as_str()) {
            (Section::Interface, "privatekey") => private_key = v.into(),
            (Section::Interface, "address") => o.addresses.extend(list(v)),
            // Search domains have no use here; only server addresses are kept.
            (Section::Interface, "dns") => o
                .dns
                .extend(list(v).into_iter().filter(|d| d.parse::<IpAddr>().is_ok())),
            (Section::Interface, "mtu") => o.mtu = number(v, "MTU")?,
            (Section::Interface, "jc") => o.jc = number(v, "junk packets")?,
            (Section::Interface, "jmin") => o.jmin = number(v, "junk packets")?,
            (Section::Interface, "jmax") => o.jmax = number(v, "junk packets")?,
            (Section::Interface, "s1" | "s2" | "s3" | "s4") => {
                o.paddings[(k.as_bytes()[1] - b'1') as usize] = number(v, "message padding")?
            }
            (Section::Interface, "h1" | "h2" | "h3" | "h4") => {
                o.headers[(k.as_bytes()[1] - b'1') as usize] =
                    format_range(range(v, "message header")?)
            }
            (Section::Interface, "i1" | "i2" | "i3" | "i4" | "i5") => {
                o.signatures[(k.as_bytes()[1] - b'1') as usize] = v.into()
            }
            (Section::Interface, "headerprotectionkey") => o.header_protection_key = Secret::new(v),
            (Section::Interface, "contentpaddingaddition") => {
                o.content_padding_addition = format_range(range(v, "content padding")?)
            }
            (Section::Interface, "randomtrailers") => {
                o.random_trailers = switch(v, "random trailers")?
            }
            (Section::Interface, "disablecookies") => {
                o.disable_cookies = switch(v, "disable cookies")?
            }
            (Section::Interface, "rekeyaftertime") => {
                o.rekey_after_time = format_range(range(v, "rekey after time")?)
            }
            (Section::Interface, "rekeytimeout") => {
                o.rekey_timeout = format_range(range(v, "rekey timeout")?)
            }
            (Section::Interface, "rejectaftertime") => {
                o.reject_after_time = format_range(range(v, "reject after time")?)
            }
            (Section::Interface, "keepalivetimeout") => {
                o.keepalive_timeout = format_range(range(v, "keepalive timeout")?)
            }
            (Section::Interface, "maxhandshakeattempts") => {
                o.max_handshake_attempts = format_range(range(v, "handshake attempts")?)
            }
            // A client never listens on a fixed port or marks its own socket here.
            (Section::Interface, "listenport" | "fwmark" | "table" | "saveconfig") => {}
            // Shell hooks are never executed.
            (Section::Interface, "preup" | "postup" | "predown" | "postdown") => {
                return Err(Error::Field("shell hooks"));
            }
            (Section::Peer, "publickey") => o.public_key = v.into(),
            (Section::Peer, "presharedkey") => o.preshared_key = Secret::new(v),
            (Section::Peer, "endpoint") => endpoint = v.into(),
            (Section::Peer, "allowedips") => o.allowed_ips.extend(list(v)),
            (Section::Peer, "persistentkeepalive") => {
                o.persistent_keepalive = format_range(range(v, "persistent keepalive")?)
            }
            _ => return Err(Error::Field("AmneziaWG option")),
        }
    }
    if peers != 1 {
        return Err(Error::Field("peer"));
    }
    validate_address(&endpoint).map_err(|_| Error::Field("endpoint"))?;
    let authority: http::uri::Authority = endpoint.parse().map_err(|_| Error::Field("endpoint"))?;
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let has_ipv6 = o.interface_addresses().iter().any(|(ip, _)| ip.is_ipv6());
    let mut p = Profile::from_endpoint(
        Endpoint {
            hostname: host.clone(),
            addresses: vec![endpoint],
            username: Secret::new("amneziawg"),
            password: Secret::new(private_key),
            custom_sni: String::new(),
            has_ipv6,
            skip_verification: false,
            certificate: String::new(),
            upstream_protocol: "http3".into(),
            client_random_prefix: String::new(),
            anti_dpi: false,
            dns_upstreams: vec![],
            extra: BTreeMap::new(),
        },
        if name.is_empty() { host } else { name },
    );
    p.protocol = Protocol::AmneziaWg;
    p.amneziawg = Some(o);
    p.validate()?;
    Ok(p)
}

/// Writes the `awg-quick` configuration; routing policy is not representable.
pub fn encode(p: &Profile) -> Result<String> {
    use std::fmt::Write;
    let o = p.amneziawg.as_ref().ok_or(Error::Field("protocol"))?;
    let mut s = String::new();
    let mut line = |k: &str, v: &str| {
        if !v.is_empty() {
            let _ = writeln!(s, "{k} = {v}");
        }
    };
    let count = |n: u32| if n == 0 { String::new() } else { n.to_string() };
    line("[Interface]\nPrivateKey", p.endpoint.password.expose());
    line("Address", &o.addresses.join(", "));
    line("DNS", &o.dns.join(", "));
    line("MTU", &count(o.mtu));
    line("Jc", &count(o.jc));
    line("Jmin", &count(o.jmin));
    line("Jmax", &count(o.jmax));
    for (i, padding) in o.paddings.iter().enumerate() {
        line(&format!("S{}", i + 1), &count(*padding));
    }
    for (i, header) in o.headers.iter().enumerate() {
        line(&format!("H{}", i + 1), header);
    }
    for (i, spec) in o.signatures.iter().enumerate() {
        line(&format!("I{}", i + 1), spec);
    }
    line("HeaderProtectionKey", o.header_protection_key.expose());
    line("ContentPaddingAddition", &o.content_padding_addition);
    line("RandomTrailers", if o.random_trailers { "on" } else { "" });
    line("DisableCookies", if o.disable_cookies { "on" } else { "" });
    line("RekeyAfterTime", &o.rekey_after_time);
    line("RekeyTimeout", &o.rekey_timeout);
    line("RejectAfterTime", &o.reject_after_time);
    line("KeepaliveTimeout", &o.keepalive_timeout);
    line("MaxHandshakeAttempts", &o.max_handshake_attempts);
    line("\n[Peer]\nPublicKey", &o.public_key);
    line("PresharedKey", o.preshared_key.expose());
    line("AllowedIPs", &o.allowed_ips.join(", "));
    line("Endpoint", &p.endpoint.addresses[0]);
    line("PersistentKeepalive", &o.persistent_keepalive);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    fn sample(extra: &str) -> String {
        format!(
            "# Home\n[Interface]\nPrivateKey = {KEY}\nAddress = 10.8.1.2/32, fd00::2/128\nDNS = 1.1.1.1, example.lan\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 15\nS2 = 20\nS3 = 12\nS4 = 16\nH1 = 100-200\nH2 = 300\nH3 = 400-500\nH4 = 600-700\nI1 = <b 0xc0ff><r 16><rc 4><rd 4><t>\n{extra}\n[Peer]\nPublicKey = {KEY}\nPresharedKey = {KEY}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.example:51820\nPersistentKeepalive = 22-30\n"
        )
    }
    #[test]
    fn config_is_detected_and_roundtrips() {
        let text = sample(&format!(
            "HeaderProtectionKey = {KEY}\nContentPaddingAddition = 0-64\nRandomTrailers = on\nRekeyAfterTime = 100-140\nMaxHandshakeAttempts = (off)"
        ));
        let p = Profile::import(&text).unwrap();
        assert_eq!(p.protocol, Protocol::AmneziaWg);
        assert_eq!(p.name, "Home");
        assert_eq!(p.transport_name(), "AmneziaWG");
        assert!(p.endpoint.has_ipv6);
        let o = p.amneziawg.as_ref().unwrap();
        assert_eq!(o.dns, ["1.1.1.1"]);
        assert_eq!(o.paddings, [15, 20, 12, 16]);
        assert_eq!(
            o.header_ranges().unwrap(),
            [(100, 200), (300, 300), (400, 500), (600, 700)]
        );
        assert_eq!(o.persistent_keepalive, "22-30");
        assert!(o.random_trailers && !o.disable_cookies);
        assert!(o.max_handshake_attempts.is_empty());
        let q = Profile::import(&p.export(Format::Conf).unwrap().content).unwrap();
        assert!(q.amneziawg == p.amneziawg);
        assert!(q.endpoint == p.endpoint);
        let json = p.export(Format::Json).unwrap().content.clone();
        assert!(Profile::import(&json).unwrap() == p);
        assert!(p.export(Format::Link).is_err());
    }
    #[test]
    fn signature_tags_follow_the_reference_grammar() {
        assert_eq!(
            signature("<b 0xc0ff> <r 16><rc 4><rd 4><t><d><dz 2>").unwrap(),
            [
                Tag::Bytes(vec![0xc0, 0xff]),
                Tag::Random(16),
                Tag::Chars(4),
                Tag::Digits(4),
                Tag::Timestamp,
                Tag::DataSize(2)
            ]
        );
        for bad in [
            "<b 0xc0f>",
            "<b>",
            "<x 1>",
            "<r -1>",
            "<r",
            "<r 70000>",
            "<>",
        ] {
            assert!(signature(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn unsafe_or_inconsistent_options_are_rejected() {
        for extra in [
            "PostUp = iptables -F",
            "Unknown = 1",
            "H2 = 150",
            // Header protection takes its nonce from the first 12 padding bytes.
            &format!("HeaderProtectionKey = {KEY}\nS3 = 11"),
            "HeaderProtectionKey = AAAA",
            "Jmin = 60",
            "MTU = 1000",
            "RekeyTimeout = 0-5",
            "I2 = <q 1>",
        ] {
            assert!(Profile::import(&sample(extra)).is_err(), "{extra}");
        }
        let two_peers = format!("{}[Peer]\nPublicKey = {KEY}\n", sample(""));
        assert!(Profile::import(&two_peers).is_err());
        assert!(Profile::import(&sample("").replace("vpn.example:51820", "vpn.example")).is_err());
    }
}
