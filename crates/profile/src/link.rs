use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

fn varint(input: &mut &[u8]) -> Result<u64> {
    let first = *input.first().ok_or(Error::Link)?;
    let size = 1usize << (first >> 6);
    if input.len() < size {
        return Err(Error::Link);
    }
    let mut value = (first & 63) as u64;
    for b in &input[1..size] {
        value = (value << 8) | *b as u64;
    }
    *input = &input[size..];
    Ok(value)
}
fn put(value: u64, out: &mut Vec<u8>) {
    let (size, prefix) = if value < 64 {
        (1, 0)
    } else if value < 16384 {
        (2, 0x40)
    } else if value < 1 << 30 {
        (4, 0x80)
    } else {
        (8, 0xc0)
    };
    let bytes = value.to_be_bytes();
    let start = out.len();
    out.extend_from_slice(&bytes[8 - size..]);
    out[start] |= prefix;
}
fn field(tag: u64, bytes: &[u8], out: &mut Vec<u8>) {
    put(tag, out);
    put(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}
fn string(b: &[u8]) -> Result<String> {
    String::from_utf8(b.to_vec()).map_err(|_| Error::Link)
}
fn boolean(b: &[u8]) -> Result<bool> {
    match b {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(Error::Link),
    }
}
fn integer(mut b: &[u8]) -> Result<u64> {
    let n = varint(&mut b)?;
    if !b.is_empty() {
        return Err(Error::Link);
    }
    Ok(n)
}

pub fn decode(uri: &str) -> Result<Profile> {
    if uri.len() > MAX_LINK {
        return Err(Error::TooLarge);
    }
    let encoded = uri
        .strip_prefix("tt://?")
        .or_else(|| uri.strip_prefix("tt://"))
        .ok_or(Error::Link)?;
    let bytes = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| Error::Link)?;
    let mut input = bytes.as_slice();
    let mut e = Endpoint {
        hostname: String::new(),
        addresses: vec![],
        username: Secret::default(),
        password: Secret::default(),
        custom_sni: String::new(),
        has_ipv6: true,
        skip_verification: false,
        certificate: String::new(),
        upstream_protocol: http2(),
        client_random_prefix: String::new(),
        anti_dpi: false,
        dns_upstreams: vec![],
        extra: BTreeMap::new(),
    };
    let mut name = String::new();
    let mut unknown = vec![];
    let mut version = 0;
    while !input.is_empty() {
        let tag = varint(&mut input)?;
        let len = usize::try_from(varint(&mut input)?).map_err(|_| Error::Link)?;
        if len > input.len() {
            return Err(Error::Link);
        }
        let (value, rest) = input.split_at(len);
        input = rest;
        match tag {
            0 => version = integer(value)?,
            1 => e.hostname = string(value)?,
            2 => {
                if e.addresses.len() >= 64 {
                    return Err(Error::Field("addresses"));
                }
                e.addresses.push(string(value)?);
            }
            3 => e.custom_sni = string(value)?,
            4 => e.has_ipv6 = boolean(value)?,
            5 => e.username = Secret::new(string(value)?),
            6 => e.password = Secret::new(string(value)?),
            7 => e.skip_verification = boolean(value)?,
            8 => e.certificate = der_pem(value)?,
            9 => {
                e.upstream_protocol = match integer(value)? {
                    1 => "http2",
                    2 => "http3",
                    _ => return Err(Error::Field("upstream_protocol")),
                }
                .into()
            }
            10 => e.anti_dpi = boolean(value)?,
            11 => e.client_random_prefix = string(value)?,
            12 => name = string(value)?,
            13 => {
                let mut v = value;
                let mut dns = vec![];
                while !v.is_empty() {
                    let len = usize::try_from(varint(&mut v)?).map_err(|_| Error::Link)?;
                    if len > v.len() || dns.len() >= 32 {
                        return Err(Error::Link);
                    }
                    dns.push(string(&v[..len])?);
                    v = &v[len..];
                }
                e.dns_upstreams = dns;
            }
            _ => unknown.push((tag, value.to_vec())), // Never truncate u64 tag to u8.
        }
    }
    if version > 1 {
        return Err(Error::Version);
    }
    if name.is_empty() {
        name = e.hostname.clone();
    }
    let mut p = Profile::from_endpoint(e, name);
    p.unknown_tlv = unknown;
    p.validate()?;
    Ok(p)
}
pub fn encode(p: &Profile) -> Result<String> {
    let e = &p.endpoint;
    let mut out = vec![];
    field(0, &[1], &mut out);
    for (tag, s) in [
        (1, e.hostname.as_str()),
        (3, &e.custom_sni),
        (5, e.username.expose()),
        (6, e.password.expose()),
        (11, &e.client_random_prefix),
        (12, &p.name),
    ] {
        field(tag, s.as_bytes(), &mut out);
    }
    for s in &e.addresses {
        field(2, s.as_bytes(), &mut out);
    }
    for (tag, b) in [(4, e.has_ipv6), (7, e.skip_verification), (10, e.anti_dpi)] {
        field(tag, &[u8::from(b)], &mut out);
    }
    field(
        9,
        &[if e.upstream_protocol == "http3" { 2 } else { 1 }],
        &mut out,
    );
    if !e.certificate.is_empty() {
        field(8, &pem_der(&e.certificate)?, &mut out);
    }
    let mut dns = vec![];
    for s in &e.dns_upstreams {
        put(s.len() as u64, &mut dns);
        dns.extend_from_slice(s.as_bytes());
    }
    field(13, &dns, &mut out);
    for (tag, bytes) in &p.unknown_tlv {
        if *tag <= 13 || *tag >= 1 << 62 {
            return Err(Error::Link);
        }
        field(*tag, bytes, &mut out);
    }
    let uri = format!("tt://?{}", URL_SAFE_NO_PAD.encode(out));
    if uri.len() > MAX_LINK {
        return Err(Error::TooLarge);
    }
    Ok(uri)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    const INPUT: &str =
        "hostname='vpn.example'\naddresses=['192.0.2.1:443']\nusername='test'\npassword='secret'\n";
    #[test]
    fn high_tags_do_not_alias_password() {
        let p = Profile::import(INPUT).unwrap();
        let uri = encode(&p).unwrap();
        let mut bytes = URL_SAFE_NO_PAD
            .decode(uri.strip_prefix("tt://?").unwrap())
            .unwrap();
        field(262, b"attacker", &mut bytes);
        let decoded = decode(&format!("tt://?{}", URL_SAFE_NO_PAD.encode(bytes))).unwrap();
        assert_eq!(decoded.endpoint.password.expose(), "secret");
        assert_eq!(decoded.unknown_tlv[0].0, 262);
    }
    #[test]
    fn hostile_lengths_are_errors() {
        assert!(decode("tt://?Ac__________").is_err());
        assert!(
            decode(&format!(
                "tt://?{}",
                URL_SAFE_NO_PAD.encode([1, 255, 255, 255, 255, 255, 255, 255, 255])
            ))
            .is_err()
        );
    }
    #[test]
    fn duplicate_scalar_last_wins() {
        let p = Profile::import(INPUT).unwrap();
        let uri = encode(&p).unwrap();
        let mut bytes = URL_SAFE_NO_PAD.decode(&uri[6..]).unwrap();
        field(6, b"rotated", &mut bytes);
        assert_eq!(
            decode(&format!("tt://?{}", URL_SAFE_NO_PAD.encode(bytes)))
                .unwrap()
                .endpoint
                .password
                .expose(),
            "rotated"
        );
    }
    proptest! {
        #[test] fn decoder_never_panics(bytes in prop::collection::vec(any::<u8>(),0..4096)) { let _=decode(&format!("tt://?{}",URL_SAFE_NO_PAD.encode(bytes))); }
        #[test] fn unicode_roundtrip(name in ".{0,128}") { let mut p=Profile::import(INPUT).unwrap(); p.name=name; let q=decode(&encode(&p).unwrap()).unwrap(); prop_assert_eq!(p.endpoint,q.endpoint); }
    }
}
