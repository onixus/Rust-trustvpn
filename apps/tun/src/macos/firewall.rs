//! A private PF anchor. Never flush the root ruleset, foreign states or tables.
use super::{command, device::DEVICE};
use std::{io::Write, net::SocketAddrV4, path::Path};
const ANCHOR: &str = "com.apple/zz-rtrust";
fn pf(args: &[&str]) -> Result<String, String> {
    command::run("/sbin/pfctl", args)
}
fn standard_root(lines: &[&str]) -> bool {
    lines == ["anchor \"com.apple/*\" all"]
        || lines
            == [
                "scrub-anchor \"com.apple/*\" all fragment reassemble",
                "anchor \"com.apple/*\" all",
            ]
}
pub(super) fn preflight() -> Result<(), String> {
    let root = pf(&["-sr"])?;
    let lines: Vec<_> = root
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if !standard_root(&lines) {
        return Err("System VPN requires the standard macOS PF anchor; conflicting root rules are left unchanged".into());
    }
    if !pf(&["-a", ANCHOR, "-sr"])?.trim().is_empty() {
        return Err("VPN PF anchor already exists; recovery is required".into());
    }
    for anchor in pf(&["-a", "com.apple", "-s", "Anchors"])?.lines() {
        let anchor = anchor.trim();
        if anchor.is_empty() {
            continue;
        }
        if !anchor
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
            || anchor.len() > 128
        {
            return Err("Unsupported PF anchor name".into());
        }
        let path = if anchor.starts_with("com.apple/") {
            anchor.to_owned()
        } else {
            format!("com.apple/{anchor}")
        };
        if path != ANCHOR && !pf(&["-a", &path, "-sr"])?.trim().is_empty() {
            return Err("Other active PF rules prevent a reliable VPN guard; existing rules are left unchanged".into());
        }
    }
    // Existing state entries bypass new filtering rules. Refuse coexistence,
    // rather than silently flushing states owned by another system component.
    if !pf(&["-ss"])?.trim().is_empty() {
        return Err("Existing PF states prevent a reliable VPN guard; other firewall connections must stop first".into());
    }
    Ok(())
}
pub(super) fn policy(
    uid: u32,
    full: bool,
    networks: &[rtrust_control::Ipv4Net],
    endpoints: &[SocketAddrV4],
    protocol: rtrust_profile::Protocol,
    ports: &[(u16, u16)],
) -> String {
    let mut rules = vec![
        "pass out quick on lo0 all no state".into(),
        format!("pass out quick on {DEVICE} all no state"),
    ];
    if full {
        // Hysteria 2 and AmneziaWG are UDP transports.
        let transport = if protocol == rtrust_profile::Protocol::TrustTunnel {
            "tcp"
        } else {
            "udp"
        };
        let flags = if transport == "tcp" { " flags any" } else { "" };
        // Hysteria port hopping sends to any port of the server's set.
        let hop = ports
            .iter()
            .map(|(a, b)| {
                if a == b {
                    a.to_string()
                } else {
                    format!("{a}:{b}")
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        for endpoint in endpoints {
            let port = if hop.is_empty() {
                endpoint.port().to_string()
            } else {
                format!("{{ {hop} }}")
            };
            rules.push(format!(
                "pass out quick inet proto {transport} to {} port {port} user root{flags} no state",
                endpoint.ip(),
            ));
        }
        rules.push(
            "pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 no state"
                .into(),
        );
        rules.push("pass out quick inet6 proto icmp6 to { fe80::/10, ff02::/16 } icmp6-type { 133, 135, 136 } no state".into());
        rules.push(
            "pass out quick inet6 proto udp from any port 546 to ff02::1:2 port 547 no state"
                .into(),
        );
        rules.push("block drop out quick all".into());
    } else {
        for net in networks {
            rules.push(format!("block drop out quick inet to {net}"));
        }
    }
    rules
        .into_iter()
        .map(|r| format!("{r} label \"rtrust-{uid}\"\n"))
        .collect()
}
/// The caller must persist the token in its root-owned recovery journal.
pub(super) fn install(directory: &Path, script: &str) -> Result<String, String> {
    let mut file =
        tempfile::NamedTempFile::new_in(directory).map_err(|_| "Cannot create PF transaction")?;
    file.write_all(script.as_bytes())
        .map_err(|_| "Cannot write PF transaction")?;
    let path = file.path().to_str().ok_or("Invalid PF transaction path")?;
    pf(&["-n", "-a", ANCHOR, "-f", path])?;
    pf(&["-a", ANCHOR, "-f", path])?;
    let (out, err) = command::capture("/sbin/pfctl", &["-E"])?;
    out.lines()
        .chain(err.lines())
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "Token").then(|| value.trim().to_owned())
        })
        .filter(|v| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            "PF enabled but reference token unavailable; guard retained for recovery".into()
        })
}
pub(super) fn remove(uid: u32, token: Option<&str>) -> Result<(), String> {
    if token.is_some_and(|token| {
        token.is_empty() || token.len() > 20 || !token.bytes().all(|b| b.is_ascii_digit())
    }) {
        return Err("Invalid PF reference token; guard retained".into());
    }
    let label = format!("label \"rtrust-{uid}\"");
    let rules = pf(&["-a", ANCHOR, "-sr"])?;
    if rules
        .lines()
        .any(|line| !line.trim().is_empty() && !line.contains(&label))
        || !pf(&["-a", ANCHOR, "-s", "Anchors"])?.trim().is_empty()
    {
        return Err("VPN PF anchor changed externally; cleanup refused".into());
    }
    pf(&["-a", ANCHOR, "-F", "rules"])?;
    if let Some(token) = token {
        pf(&["-X", token])?;
    } else {
        // A crash between pfctl -E and journal fsync may lose the reference.
        // Explicit recovery may remove our guard, but must never disable PF
        // globally to compensate for an unknown reference owned by this process.
        eprintln!("PF reference unavailable; own rules removed, global PF state retained");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hysteria_hop_ports_open_only_the_server_port_set() {
        let endpoint: SocketAddrV4 = "192.0.2.10:443".parse().unwrap();
        let hysteria = rtrust_profile::Protocol::Hysteria2;
        let plain = policy(501, true, &[], &[endpoint], hysteria, &[]);
        assert!(plain.contains("proto udp to 192.0.2.10 port 443 user root no state"));
        let hop = policy(
            501,
            true,
            &[],
            &[endpoint],
            hysteria,
            &[(443, 443), (20000, 20010)],
        );
        assert!(
            hop.contains("proto udp to 192.0.2.10 port { 443, 20000:20010 } user root no state")
        );
        assert!(!hop.contains("port 443 user"));
        assert!(hop.contains("block drop out quick all"));
    }
    #[test]
    fn accepts_stock_scrub_anchor_but_not_foreign_filter_rules() {
        assert!(standard_root(&[
            "scrub-anchor \"com.apple/*\" all fragment reassemble",
            "anchor \"com.apple/*\" all"
        ]));
        assert!(!standard_root(&[
            "pass out quick all",
            "anchor \"com.apple/*\" all"
        ]));
        assert!(!standard_root(&["anchor \"other/*\" all"]));
    }
}
