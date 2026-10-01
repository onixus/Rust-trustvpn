//! Hysteria 2 profile detection. Unknown transport/security options fail closed.
use super::*;
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[default]
    TrustTunnel,
    Hysteria2,
}
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2 {
    #[serde(default)]
    pub salamander: Secret,
    #[serde(default)]
    pub pin_sha256: String,
}
impl Hysteria2 {
    pub fn validate(&self) -> Result<()> {
        if self.salamander.expose().len() > 4096 {
            return Err(Error::Field("obfuscation password"));
        }
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
    let url = url::Url::parse(input).map_err(|_| Error::Syntax)?;
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
    if !matches!(obfs.as_str(), "" | "salamander") {
        return Err(Error::Field("obfs"));
    }
    let password = params.remove("obfs-password").unwrap_or_default();
    if (obfs == "salamander") != !password.is_empty() {
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
    let pin = params
        .remove("pinSHA256")
        .unwrap_or_default()
        .replace(':', "")
        .to_ascii_lowercase();
    base(
        &server,
        auth,
        params.remove("sni").unwrap_or_default(),
        insecure,
        Hysteria2 {
            salamander: Secret::new(password),
            pin_sha256: pin,
        },
        decode(url.fragment().unwrap_or_default())?,
    )
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
    salamander: ObfsSecret,
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
            p.name = c.name;
            p.validate()?
        }
        return Ok(p);
    }
    let password = match c.obfs {
        Some(o) if o.kind == "salamander" && !o.salamander.password.is_empty() => {
            o.salamander.password
        }
        Some(_) => return Err(Error::Field("obfs")),
        None => String::new(),
    };
    base(
        &c.server,
        c.auth,
        c.tls.sni,
        c.tls.insecure,
        Hysteria2 {
            salamander: Secret::new(password),
            pin_sha256: c.tls.pin.replace(':', "").to_ascii_lowercase(),
        },
        c.name,
    )
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
            q.append_pair("obfs", "salamander");
            q.append_pair("obfs-password", options.salamander.expose());
        }
    }
    url.set_fragment(Some(&p.name));
    Ok(url.to_string())
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
