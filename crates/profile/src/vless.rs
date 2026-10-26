//! VLESS over a TLS CDN front (WebSocket or XHTTP), as issued by the server's CDN
//! panel. Only the plain `encryption=none` + `security=tls` form is accepted;
//! REALITY, XTLS flows and disabled verification fail closed.
use super::*;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use zeroize::Zeroizing;

/// Links are short: a UUID, a host, a path and a few options.
pub const MAX_VLESS_LINK: usize = 8 * 1024;
const MAX_PATH: usize = 1024;
const MAX_NAME: usize = 256;
/// Every query option the client understands; anything else fails closed.
const OPTIONS: [&str; 9] = [
    "encryption",
    "security",
    "sni",
    "host",
    "fp",
    "type",
    "path",
    "alpn",
    "mode",
];
/// The compatibility username stored for VLESS; the UUID is the credential.
pub const USERNAME: &str = "vless";

#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vless {
    /// `ws` or `xhttp`.
    pub transport: String,
    /// HTTP path of the CDN route; knowing it is enough to reach the origin.
    pub path: Secret,
    /// `chrome` when the link asks for a browser TLS fingerprint. It is kept
    /// for export only: the engine does not emulate TLS fingerprints.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// XHTTP mode (`auto` or `packet-up`); empty for WebSocket.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub xhttp_mode: String,
}
impl fmt::Debug for Vless {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vless")
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}
impl Vless {
    pub fn validate(&self) -> Result<()> {
        match (self.transport.as_str(), self.xhttp_mode.as_str()) {
            ("ws", "") | ("xhttp", "" | "auto" | "packet-up") => {}
            ("ws" | "xhttp", _) => return Err(Error::Field("mode")),
            _ => return Err(Error::Field("type")),
        }
        if !matches!(self.fingerprint.as_str(), "" | "chrome") {
            return Err(Error::Field("fp"));
        }
        path(self.path.expose())
    }
}

/// An absolute request path of RFC 3986 `pchar`s: no query, fragment, escapes,
/// whitespace or control characters, so it is sent exactly as stored.
fn path(path: &str) -> Result<()> {
    if !path.starts_with('/')
        || path.len() > MAX_PATH
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&b))
    {
        return Err(Error::Field("path"));
    }
    Ok(())
}
/// Canonical 8-4-4-4-12 hex form, lower-cased. Other UUID spellings and
/// Xray's name-derived UUIDv5 are rejected rather than guessed.
pub fn uuid(text: &str) -> Result<String> {
    if !canonical_uuid(text) {
        return Err(Error::Field("uuid"));
    }
    Ok(text.to_ascii_lowercase())
}
pub fn canonical_uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
/// A DNS name used as SNI and Host. IP literals have no SNI and are rejected.
pub fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.parse::<std::net::IpAddr>().is_err()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
        && name.contains('.')
}
/// Explicit bidirectional formatting characters can disguise a name in lists.
pub fn bidi(c: char) -> bool {
    matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}
fn decode(text: &str, field: &'static str) -> Result<Zeroizing<String>> {
    percent_encoding::percent_decode_str(text)
        .decode_utf8()
        .map(|s| Zeroizing::new(s.into_owned()))
        .map_err(|_| Error::Field(field))
}
/// Splits `host:port` with a mandatory port; IPv6 hosts stay bracketed.
fn server(text: &str) -> Result<String> {
    let colon = text.rfind(':').ok_or(Error::Field("server"))?;
    let (host, port) = (&text[..colon], &text[colon + 1..]);
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0 && port.bytes().all(|b| b.is_ascii_digit()))
        .ok_or(Error::Field("server"))?;
    let host = if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        let ip: std::net::Ipv6Addr = v6.parse().map_err(|_| Error::Field("server"))?;
        format!("[{ip}]")
    } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        ip.to_string()
    } else if dns_name(host) {
        host.to_ascii_lowercase()
    } else {
        return Err(Error::Field("server"));
    };
    Ok(format!("{host}:{port}"))
}

pub fn link(input: &str) -> Result<Profile> {
    if input.len() > MAX_VLESS_LINK {
        return Err(Error::TooLarge);
    }
    let rest = input.strip_prefix("vless://").ok_or(Error::Syntax)?;
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let (authority, query) = rest.split_once('?').ok_or(Error::Field("encryption"))?;
    let authority = authority.strip_suffix('/').unwrap_or(authority);
    let (user, host) = authority.split_once('@').ok_or(Error::Field("uuid"))?;
    if host.contains(['@', '/']) {
        return Err(Error::Field("server"));
    }
    let id = Zeroizing::new(uuid(user)?);
    let address = server(host)?;
    let mut params: BTreeMap<&str, Zeroizing<String>> = BTreeMap::new();
    for pair in query.split('&') {
        let (key, value) = pair
            .split_once('=')
            .ok_or(Error::Field("VLESS URI option"))?;
        let key = match key {
            "flow" => return Err(Error::Field("flow")),
            "pbk" | "sid" | "spx" | "pqv" => return Err(Error::Field("security")),
            "allowInsecure" | "insecure" => return Err(Error::Field("insecure")),
            _ => *OPTIONS
                .iter()
                .find(|k| **k == key)
                .ok_or(Error::Field("VLESS URI option"))?,
        };
        // An empty value is neither the option nor its absence.
        if value.is_empty() {
            return Err(Error::Field(key));
        }
        if params.insert(key, decode(value, key)?).is_some() {
            return Err(Error::Ambiguous);
        }
    }
    let mut take = |key: &'static str| params.remove(key).unwrap_or_default();
    if take("encryption").as_str() != "none" {
        return Err(Error::Field("encryption"));
    }
    if take("security").as_str() != "tls" {
        return Err(Error::Field("security"));
    }
    let sni = take("sni").to_ascii_lowercase();
    if !dns_name(&sni) {
        return Err(Error::Field("sni"));
    }
    let host = take("host");
    if !host.is_empty() && !host.eq_ignore_ascii_case(&sni) {
        return Err(Error::Field("host"));
    }
    let transport = take("type").to_string();
    let alpn = take("alpn");
    match (transport.as_str(), alpn.as_str()) {
        ("ws", "" | "http/1.1") | ("xhttp", "") => {}
        ("ws" | "xhttp", _) => return Err(Error::Field("alpn")),
        _ => return Err(Error::Field("type")),
    }
    let options = Vless {
        transport,
        path: Secret::new(take("path").as_str()),
        fingerprint: take("fp").to_string(),
        xhttp_mode: take("mode").to_string(),
    };
    options.validate()?;
    let path = options.path.expose();
    let name: String = decode(fragment, "name")?
        .chars()
        .filter(|c| !c.is_control() && !bidi(*c))
        .collect();
    let name = name.trim();
    // A name never carries the credential or the route, even if a link put them there.
    let leaks =
        name.to_ascii_lowercase().contains(id.as_str()) || (path.len() > 1 && name.contains(path));
    let name = if name.is_empty() || leaks {
        sni.clone()
    } else if name.chars().count() > MAX_NAME {
        return Err(Error::Field("name"));
    } else {
        name.to_owned()
    };
    let mut p = Profile::from_endpoint(
        Endpoint {
            hostname: sni,
            addresses: vec![address],
            username: Secret::new(USERNAME),
            password: Secret::new(id.as_str()),
            custom_sni: String::new(),
            // The CDN origin container has no IPv6 egress.
            has_ipv6: false,
            skip_verification: false,
            certificate: String::new(),
            upstream_protocol: "http2".into(),
            client_random_prefix: String::new(),
            anti_dpi: false,
            dns_upstreams: vec![],
            extra: BTreeMap::new(),
        },
        name,
    );
    p.protocol = Protocol::Vless;
    p.vless = Some(options);
    p.validate()?;
    Ok(p)
}

/// Python's `urllib.parse.quote(safe='')`, as the server encodes query values.
const VALUE: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');
/// `urllib.parse.quote` with its default `safe='/'`, as used for the name.
const NAME: &AsciiSet = &VALUE.remove(b'/');

/// The link in the server's own field order, so a re-export matches what it issued.
pub fn encode(p: &Profile) -> Result<String> {
    let [address] = p.endpoint.addresses.as_slice() else {
        return Err(Error::Field("VLESS link requires one server"));
    };
    let options = p.vless.as_ref().ok_or(Error::Field("vless"))?;
    let sni = utf8_percent_encode(&p.endpoint.hostname, VALUE).to_string();
    let mut text = Zeroizing::new(format!(
        "vless://{}@{address}?encryption=none&security=tls&sni={sni}&host={sni}",
        p.endpoint.password.expose()
    ));
    if !options.fingerprint.is_empty() {
        text.push_str("&fp=");
        text.extend(utf8_percent_encode(&options.fingerprint, VALUE));
    }
    text.push_str("&type=");
    text.extend(utf8_percent_encode(&options.transport, VALUE));
    text.push_str("&path=");
    text.extend(utf8_percent_encode(options.path.expose(), VALUE));
    if options.transport == "ws" {
        text.push_str("&alpn=http%2F1.1");
    } else if !options.xhttp_mode.is_empty() {
        text.push_str("&mode=");
        text.extend(utf8_percent_encode(&options.xhttp_mode, VALUE));
    }
    text.push('#');
    text.extend(utf8_percent_encode(&p.name, NAME));
    Ok(std::mem::take(&mut *text))
}

#[cfg(test)]
mod tests {
    use super::*;
    const UUID: &str = "11111111-2222-4333-8444-555555555555";
    const PATH: &str = "/CanaryPath7f3abcdefABCDEF";
    /// The exact shape `render_client` produces for WebSocket.
    fn ws(address: &str, port: u16) -> String {
        format!(
            "vless://{UUID}@{address}:{port}?encryption=none&security=tls&sni=cdn.example.com&host=cdn.example.com&fp=chrome&type=ws&path=%2FCanaryPath7f3abcdefABCDEF&alpn=http%2F1.1#CDN-alice"
        )
    }
    fn xhttp(mode: &str) -> String {
        format!(
            "vless://{UUID}@cdn.example.com:443?encryption=none&security=tls&sni=cdn.example.com&host=cdn.example.com&fp=chrome&type=xhttp&path=%2FCanaryPath7f3abcdefABCDEF&mode={mode}#CDN-bob"
        )
    }
    fn canaries(text: &str) {
        assert!(!text.contains(UUID), "UUID leaked");
        assert!(!text.contains("CanaryPath"), "path leaked");
    }

    #[test]
    fn server_links_import_and_roundtrip_exactly() {
        for port in [443, 2053, 2083, 2087, 2096, 8443] {
            for address in ["cdn.example.com", "192.0.2.10", "[2001:db8::10]"] {
                let link = ws(address, port);
                let p = Profile::import(&link).unwrap();
                assert_eq!(p.protocol, Protocol::Vless);
                assert_eq!(p.endpoint.hostname, "cdn.example.com");
                assert_eq!(p.endpoint.addresses, [format!("{address}:{port}")]);
                assert_eq!(p.endpoint.password.expose(), UUID);
                assert!(!p.endpoint.has_ipv6);
                assert_eq!(p.name, "CDN-alice");
                assert_eq!(p.transport_name(), "VLESS WS");
                assert!(!p.udp_transport());
                let v = p.vless.as_ref().unwrap();
                assert_eq!((v.path.expose(), v.fingerprint.as_str()), (PATH, "chrome"));
                let export = p.export(Format::Link).unwrap();
                assert_eq!(export.content, link);
                assert!(export.losses.is_empty());
                let json = p.export(Format::Json).unwrap();
                let q = Profile::import(&json.content).unwrap();
                assert_eq!(q, p);
                assert_eq!(q.export(Format::Link).unwrap().content, link);
            }
        }
        for mode in ["auto", "packet-up"] {
            let link = xhttp(mode);
            let p = Profile::import(&link).unwrap();
            assert_eq!(p.transport_name(), "VLESS XHTTP");
            assert_eq!(p.vless.as_ref().unwrap().xhttp_mode, mode);
            assert_eq!(p.export(Format::Link).unwrap().content, link);
        }
        let p = Profile::import(&ws("cdn.example.com", 443)).unwrap();
        assert_eq!(p.formats(), [Format::Json, Format::Link]);
        for format in [Format::EndpointToml, Format::CliToml, Format::Conf] {
            assert!(p.export(format).is_err(), "{format}");
        }
    }

    #[test]
    fn minimal_and_case_variants_are_normalized() {
        let p = Profile::import(&format!(
            "vless://{}@CDN.Example.com:443/?type=ws&security=tls&encryption=none&sni=CDN.example.COM&path=%2Fabc",
            UUID.to_ascii_uppercase()
        ))
        .unwrap();
        assert_eq!(p.endpoint.password.expose(), UUID);
        assert_eq!(p.endpoint.hostname, "cdn.example.com");
        assert_eq!(p.endpoint.addresses, ["cdn.example.com:443"]);
        assert_eq!(p.name, "cdn.example.com");
        assert!(p.vless.as_ref().unwrap().fingerprint.is_empty());
        // Host defaults to the SNI and WebSocket always negotiates HTTP/1.1.
        assert_eq!(
            p.export(Format::Link).unwrap().content,
            format!(
                "vless://{UUID}@cdn.example.com:443?encryption=none&security=tls&sni=cdn.example.com&host=cdn.example.com&type=ws&path=%2Fabc&alpn=http%2F1.1#cdn.example.com"
            )
        );
    }

    #[test]
    fn unsafe_or_unknown_links_fail_closed() {
        let good = ws("cdn.example.com", 443);
        let swap = |from: &str, to: &str| {
            assert!(good.contains(from), "{from}");
            good.replacen(from, to, 1)
        };
        let cases = [
            swap("security=tls", "security=none"),
            swap("security=tls", "security=reality"),
            swap("security=tls", "security=xtls"),
            swap("security=tls&", ""),
            swap("encryption=none", "encryption=aes-128-gcm"),
            swap("encryption=none&", ""),
            swap("type=ws", "type=grpc"),
            swap("type=ws", "type=tcp"),
            swap("&type=ws", ""),
            swap("&path=%2FCanaryPath7f3abcdefABCDEF", ""),
            swap("&sni=cdn.example.com", ""),
            swap("sni=cdn.example.com", "sni=192.0.2.1"),
            swap("sni=cdn.example.com", "sni=%5B2001%3Adb8%3A%3A1%5D"),
            swap("sni=cdn.example.com", "sni=localhost"),
            swap("host=cdn.example.com", "host=other.example.com"),
            swap("fp=chrome", "fp=firefox"),
            swap("fp=chrome", "fp=randomized"),
            swap("alpn=http%2F1.1", "alpn=h2"),
            swap("alpn=http%2F1.1", "alpn=h2%2Chttp%2F1.1"),
            swap("alpn=http%2F1.1", "mode=auto"),
            swap("#", "&flow=xtls-rprx-vision#"),
            swap("#", "&pbk=AAAA#"),
            swap("#", "&sid=ab#"),
            swap("#", "&spx=%2F#"),
            swap("#", "&pqv=x#"),
            swap("#", "&allowInsecure=0#"),
            swap("#", "&allowInsecure=1#"),
            swap("#", "&insecure=0#"),
            swap("#", "&headerType=none#"),
            swap("#", "&serviceName=x#"),
            swap("#", "&authority=x#"),
            swap("#", "&ech=x#"),
            swap("#", "&extra=%7B%7D#"),
            swap("#", "&unknown=1#"),
            swap("#", "&fp=chrome#"),
            swap("#", "&#"),
            swap("#", "&novalue#"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=CanaryPath"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%0Db"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%0Ab"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%00b"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%23b"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%20b"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%3Fed%3D2048"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2Fa%2541"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2F%C3%A9"),
            swap("path=%2FCanaryPath7f3abcdefABCDEF", "path=%2F%FF"),
            swap(
                "path=%2FCanaryPath7f3abcdefABCDEF",
                &format!("path=%2F{}", "a".repeat(MAX_PATH)),
            ),
            swap(UUID, "11111111222243338444555555555555"),
            swap(UUID, "{11111111-2222-4333-8444-555555555555}"),
            swap(UUID, "1111111-12222-4333-8444-555555555555"),
            swap(UUID, "alice"),
            swap(UUID, "11111111-2222-4333-8444-55555555555g"),
            swap(UUID, &format!("{UUID}:pass")),
            swap(":443", ""),
            swap(":443", ":0"),
            swap(":443", ":70000"),
            swap(":443", ":+443"),
            swap("cdn.example.com:443", "cdn.example.com%2Fx:443"),
            swap("@cdn.example.com", "@x@cdn.example.com"),
            swap("@cdn.example.com:443", "@[fe80::1%25en0]:443"),
            swap("?", "/path?"),
            swap("vless://", "VLESS://"),
            swap("#CDN-alice", &format!("#{}", "n".repeat(MAX_NAME + 1))),
        ];
        for bad in &cases {
            let error = Profile::import(bad).expect_err(bad);
            canaries(&error.to_string());
            canaries(&format!("{error:?}"));
        }
        let mut duplicate = swap("#", "&sni=cdn.example.com#");
        assert!(matches!(Profile::import(&duplicate), Err(Error::Ambiguous)));
        duplicate = swap("#", &format!("&path={}#", "%2Fother"));
        assert!(matches!(Profile::import(&duplicate), Err(Error::Ambiguous)));
        for mode in ["stream-up", "stream-one", "AUTO", ""] {
            assert!(Profile::import(&xhttp(mode)).is_err(), "{mode}");
        }
        assert!(Profile::import(&xhttp("auto").replace("#", "&alpn=h2#")).is_err());
        let long = format!("{good}{}", "x".repeat(MAX_VLESS_LINK));
        assert!(matches!(Profile::import(&long), Err(Error::TooLarge)));
    }

    #[test]
    fn names_drop_controls_bidi_and_credentials() {
        let good = ws("cdn.example.com", 443);
        let named = |name: &str| Profile::import(&good.replace("CDN-alice", name)).unwrap();
        assert_eq!(named("a%0Ab%E2%80%AEc%E2%81%A6d%09").name, "abcd");
        assert_eq!(named("%D0%9D%D0%BE%D1%83%D1%82").name, "Ноут");
        assert_eq!(named("%0A%E2%80%AE").name, "cdn.example.com");
        assert_eq!(named(&format!("x-{UUID}")).name, "cdn.example.com");
        assert_eq!(named(&UUID.to_ascii_uppercase()).name, "cdn.example.com");
        assert_eq!(
            named("x%2FCanaryPath7f3abcdefABCDEF").name,
            "cdn.example.com"
        );
        // Names round-trip through the server's quoting.
        let p = named("A%20b%2Fc%26d%23e");
        assert_eq!(p.name, "A b/c&d#e");
        let link = p.export(Format::Link).unwrap().content.clone();
        assert!(link.ends_with("#A%20b/c%26d%23e"), "name encoding");
        assert_eq!(Profile::import(&link).unwrap(), p);
    }

    #[test]
    fn diagnostics_never_show_the_uuid_or_path() {
        let p = Profile::import(&ws("[2001:db8::10]", 8443)).unwrap();
        canaries(&format!("{p:?}"));
        canaries(&format!("{:?}", p.endpoint));
        canaries(&format!("{:?}", p.vless.as_ref().unwrap()));
        // What summaries show: name, hostname, addresses and transport.
        canaries(&p.name);
        canaries(&p.endpoint.hostname);
        canaries(&p.endpoint.addresses.join(","));
        canaries(p.transport_name());
    }

    #[test]
    fn json_profiles_are_validated_like_links() {
        let p = Profile::import(&ws("cdn.example.com", 443)).unwrap();
        let json: Value = serde_json::from_str(&p.export(Format::Json).unwrap().content).unwrap();
        assert_eq!(json["protocol"], "vless");
        let edit = |f: &dyn Fn(&mut Value)| {
            let mut v = json.clone();
            f(&mut v);
            Profile::import(&v.to_string())
        };
        assert!(edit(&|_| {}).is_ok());
        let bad: [&dyn Fn(&mut Value); 13] = [
            &|v| v["vless"]["transport"] = "grpc".into(),
            &|v| v["vless"]["path"] = "no-slash".into(),
            &|v| v["vless"]["path"] = "/a b".into(),
            &|v| v["vless"]["fingerprint"] = "firefox".into(),
            &|v| v["vless"]["xhttp_mode"] = "auto".into(),
            &|v| v["vless"]["extra"] = "1".into(),
            &|v| v["endpoint"]["password"] = "not-a-uuid".into(),
            &|v| v["endpoint"]["password"] = "AAAAAAAA-2222-4333-8444-555555555555".into(),
            &|v| v["endpoint"]["username"] = "user".into(),
            &|v| v["endpoint"]["hostname"] = "192.0.2.1".into(),
            &|v| v["endpoint"]["upstream_protocol"] = "http3".into(),
            &|v| v["endpoint"]["custom_sni"] = "other.example.com".into(),
            &|v| {
                v.as_object_mut().unwrap().remove("vless");
            },
        ];
        for (i, f) in bad.iter().enumerate() {
            assert!(edit(f).is_err(), "case {i}");
        }
        // A VLESS block on another protocol is rejected too.
        assert!(edit(&|v| v["protocol"] = "hysteria2".into()).is_err());
    }

    #[test]
    fn json_only_fields_are_reported_as_link_losses() {
        let mut p = Profile::import(&ws("cdn.example.com", 443)).unwrap();
        p.policy = serde_json::json!({"mode": "split"});
        p.endpoint.has_ipv6 = true;
        p.endpoint.dns_upstreams = vec!["tls://1.1.1.1".into()];
        let export = p.export(Format::Link).unwrap();
        assert_eq!(export.losses.len(), 3);
        p.endpoint.addresses.push("192.0.2.11:443".into());
        assert!(p.export(Format::Link).is_err());
    }

    #[test]
    fn arbitrary_links_never_panic() {
        // Deterministic xorshift corpus over the link alphabet; no extra crates.
        let alphabet = b"vles:/@?&=#%[]-.0123456789abcdefABCDEFxyz \n\xc3";
        let base = ws("cdn.example.com", 443).into_bytes();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..20_000 {
            let mut bytes = base.clone();
            for _ in 0..1 + next() % 6 {
                let at = (next() as usize) % bytes.len();
                let b = alphabet[(next() as usize) % alphabet.len()];
                match next() % 3 {
                    0 => bytes[at] = b,
                    1 => bytes.insert(at, b),
                    _ => {
                        bytes.remove(at);
                    }
                }
            }
            if let Ok(text) = std::str::from_utf8(&bytes)
                && let Ok(p) = Profile::import(text)
            {
                p.export(Format::Link).unwrap();
            }
        }
    }
}
