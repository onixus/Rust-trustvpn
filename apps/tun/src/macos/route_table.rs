use std::net::{Ipv4Addr, Ipv6Addr};
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
    pub flags: String,
}
pub(super) fn prefix(value: &str, v6: bool) -> Option<String> {
    if value == "default" {
        return Some(if v6 { "::/0" } else { "0.0.0.0/0" }.into());
    }
    let (address, bits) = value
        .split_once('/')
        .map_or((value, None), |(a, b)| (a, Some(b)));
    if v6 {
        let address: Ipv6Addr = address.parse().ok()?;
        let bits = bits.map(str::parse::<u8>).transpose().ok()?.unwrap_or(128);
        if bits > 128 {
            return None;
        }
        return Some(format!("{address}/{bits}"));
    }
    let octets: Vec<_> = address.split('.').collect();
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    let mut bytes = [0; 4];
    for (i, part) in octets.iter().enumerate() {
        bytes[i] = part.parse().ok()?;
    }
    let bits = bits
        .map(str::parse::<u8>)
        .transpose()
        .ok()?
        .unwrap_or(octets.len() as u8 * 8);
    if bits > 32 {
        return None;
    }
    Some(format!("{}/{bits}", Ipv4Addr::from(bytes)))
}
pub(super) fn parse(text: &str) -> Result<Vec<Entry>, String> {
    let mut started = false;
    let mut entries = vec![];
    for line in text.lines() {
        let values: Vec<_> = line.split_whitespace().collect();
        if values.is_empty() {
            continue;
        }
        if values.first() == Some(&"Destination") {
            if values.get(1..4) != Some(&["Gateway", "Flags", "Netif"][..]) {
                return Err("Unsupported macOS routing table format".into());
            }
            started = true;
            continue;
        }
        if !started {
            continue;
        }
        if values.len() < 4 || values.len() > 5 || !valid_interface(values[3]) {
            return Err("Invalid macOS routing table entry".into());
        }
        if entries.len() >= 16384 {
            return Err("Routing table is too large".into());
        }
        entries.push(Entry {
            destination: values[0].into(),
            gateway: values[1].into(),
            flags: values[2].into(),
            interface: values[3].into(),
        });
    }
    if !started {
        return Err("Missing macOS routing table header".into());
    }
    Ok(entries)
}
pub(super) fn valid_interface(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphabetic)
        && value.len() <= 15
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}
pub(super) fn read(v6: bool) -> Result<Vec<Entry>, String> {
    parse(&super::command::run(
        "/usr/sbin/netstat",
        &["-rn", "-f", if v6 { "inet6" } else { "inet" }],
    )?)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compressed_networks_do_not_become_host_routes() {
        assert_eq!(prefix("0/1", false).as_deref(), Some("0.0.0.0/1"));
        assert_eq!(prefix("198.18", false).as_deref(), Some("198.18.0.0/16"));
        assert_eq!(prefix("198.18.1", false).as_deref(), Some("198.18.1.0/24"));
        assert_eq!(
            prefix("2001:db8::/32", true).as_deref(),
            Some("2001:db8::/32")
        );
        assert!(prefix("0/129", true).is_none());
        assert!(prefix("256.1/16", false).is_none());
    }
    #[test]
    fn refuse_changed_columns_instead_of_guessing_interface() {
        assert!(
            parse("Destination Gateway Flags Refs Use Netif\n0/1 link#12 US2 0 1 utun5254")
                .is_err()
        );
        let rows=parse("Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\n0/1 link#12 US2 utun5254\n192.0.2.1 192.168.1.1 UGHS2 en0\n").unwrap();
        assert_eq!(rows[0].interface, "utun5254");
        assert_eq!(rows[1].flags, "UGHS2");
    }
}
