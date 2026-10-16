//! A private PF anchor. Never flush the root ruleset, foreign rules or tables.
//! The global state table is flushed once the guard is active (`flush_states`).
use super::{command, device::DEVICE};
use std::{io::Write, path::Path};
pub(super) const ANCHOR: &str = "com.apple/zz-rtrust";
fn pf(args: &[&str]) -> Result<String, String> {
    command::run("/sbin/pfctl", args)
}
pub(super) fn standard_root(lines: &[&str]) -> bool {
    lines == ["anchor \"com.apple/*\" all"]
        || lines
            == [
                "scrub-anchor \"com.apple/*\" all fragment reassemble",
                "anchor \"com.apple/*\" all",
            ]
}
pub(super) fn preflight() -> Result<(), String> {
    preflight_with(pf)
}
fn preflight_with(mut pf: impl FnMut(&[&str]) -> Result<String, String>) -> Result<(), String> {
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
        let Some(path) = anchor_path(anchor) else {
            return Err("Unsupported PF anchor name".into());
        };
        if path != ANCHOR && !pf(&["-a", &path, "-sr"])?.trim().is_empty() {
            return Err("Other active PF rules prevent a reliable VPN guard; existing rules are left unchanged".into());
        }
    }
    // Existing state entries (e.g. left by another VPN client) are not a
    // refusal reason: they bypass new rules, so flush_states clears them once
    // the guard is active.
    Ok(())
}
/// Clears the global PF state table after the guard rules and PF are active,
/// so no pre-existing state can bypass them. pfctl cannot flush states per
/// owner: every PF-tracked connection, including another component's (such as
/// another VPN client), is dropped and must re-establish under the guard. The
/// guard's own rules are `no state`, so the tunnel transport is unaffected.
pub(super) fn flush_states() -> Result<(), String> {
    flush_states_with(pf)
}
fn flush_states_with(mut pf: impl FnMut(&[&str]) -> Result<String, String>) -> Result<(), String> {
    pf(&["-F", "states"])
        .map(|_| ())
        .map_err(|_| "Cannot clear existing PF states; guard retained for recovery".into())
}
pub(super) fn anchor_path(anchor: &str) -> Option<String> {
    if !anchor
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'))
        || anchor.len() > 128
    {
        return None;
    }
    Some(if anchor.starts_with("com.apple/") {
        anchor.to_owned()
    } else {
        format!("com.apple/{anchor}")
    })
}
pub(super) fn policy(
    uid: u32,
    full: bool,
    networks: &[rtrust_control::Ipv4Net],
    permits: &[crate::failover::Permit],
) -> String {
    let mut rules = vec![
        "pass out quick on lo0 all no state".into(),
        format!("pass out quick on {DEVICE} all no state"),
    ];
    if full {
        // QUIC (HTTP/3, Hysteria 2) and AmneziaWG use UDP.
        for permit in permits {
            let endpoint = &permit.address;
            let transport = if permit.udp { "udp" } else { "tcp" };
            let flags = if transport == "tcp" { " flags any" } else { "" };
            // Hysteria port hopping sends to any port of the server's set.
            let hop = permit
                .ports
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
        let endpoint: std::net::SocketAddrV4 = "192.0.2.10:443".parse().unwrap();
        let plain = policy(
            501,
            true,
            &[],
            &[crate::failover::Permit {
                address: endpoint,
                udp: true,
                ports: vec![],
            }],
        );
        assert!(plain.contains("proto udp to 192.0.2.10 port 443 user root no state"));
        let hop = policy(
            501,
            true,
            &[],
            &[crate::failover::Permit {
                address: endpoint,
                udp: true,
                ports: vec![(443, 443), (20000, 20010)],
            }],
        );
        assert!(
            hop.contains("proto udp to 192.0.2.10 port { 443, 20000:20010 } user root no state")
        );
        assert!(!hop.contains("port 443 user"));
        assert!(hop.contains("block drop out quick all"));
    }
    #[test]
    fn mixed_transports_and_hopping_keep_separate_exceptions() {
        use crate::failover::Permit;
        let script = policy(
            501,
            true,
            &[],
            &[
                Permit {
                    address: "192.0.2.1:443".parse().unwrap(),
                    udp: false,
                    ports: vec![],
                },
                Permit {
                    address: "192.0.2.2:8443".parse().unwrap(),
                    udp: true,
                    ports: vec![],
                },
                Permit {
                    address: "192.0.2.3:443".parse().unwrap(),
                    udp: true,
                    ports: vec![(20000, 20010)],
                },
            ],
        );
        assert!(script.contains("proto tcp to 192.0.2.1 port 443 user root flags any"));
        assert!(script.contains("proto udp to 192.0.2.2 port 8443 user root"));
        assert!(script.contains("proto udp to 192.0.2.3 port { 20000:20010 } user root"));
        assert!(!script.contains("proto udp to 192.0.2.1"));
        assert!(!script.contains("proto tcp to 192.0.2.2"));
        assert!(!script.contains("192.0.2.1 port {"));
        assert!(script.contains("block drop out quick all"));
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
    fn stock_pf<'a>(
        foreign_rules: &'static str,
        calls: &'a mut Vec<String>,
    ) -> impl FnMut(&[&str]) -> Result<String, String> + 'a {
        move |args| {
            calls.push(args.join(" "));
            Ok(match args {
                ["-sr"] => "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n",
                ["-a", "com.apple", "-s", "Anchors"] => "  com.apple/200.AirDrop\n  com.apple/250.ApplicationFirewall\n",
                ["-a", "com.apple/250.ApplicationFirewall", "-sr"] => foreign_rules,
                ["-ss"] => "ALL tcp 172.29.60.25:54096 -> 172.28.252.168:443       ESTABLISHED:ESTABLISHED\n",
                _ => "",
            }
            .into())
        }
    }
    #[test]
    fn foreign_states_do_not_refuse_but_foreign_rules_still_do() {
        let mut calls = vec![];
        assert_eq!(preflight_with(stock_pf("", &mut calls)), Ok(()));
        assert!(!calls.iter().any(|c| c == "-ss" || c.starts_with("-F")));
        let mut calls = vec![];
        assert!(
            preflight_with(stock_pf("block drop out all\n", &mut calls))
                .unwrap_err()
                .contains("Other active PF rules")
        );
    }
    #[test]
    fn flush_clears_only_the_state_table() {
        let mut calls = vec![];
        assert_eq!(
            flush_states_with(|args| {
                calls.push(args.join(" "));
                Ok(String::new())
            }),
            Ok(())
        );
        assert_eq!(calls, ["-F states"]);
        assert!(
            flush_states_with(|_| Err("pfctl failed".into()))
                .unwrap_err()
                .contains("guard retained")
        );
    }
}
