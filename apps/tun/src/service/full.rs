//! Whole-host IPv4/IPv6 policy with a persistent nftables guard and link-scoped DNS.
use super::routes::{ADDRESS, DEVICE, ip};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::fs::{MetadataExt, PermissionsExt},
};
const JOURNAL: &str = "/run/rtrust/full.json";
const TABLE: &str = "51830";
const NFT: &str = "rtrust_full";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    uid: u32,
    dns: Ipv4Addr,
    #[serde(default)]
    endpoints: Vec<IpAddr>,
}
pub struct FullRoutes {
    journal: Journal,
    active: bool,
    rollback_on_drop: bool,
}

fn command(path: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    super::routes::command(path, args)
}
fn v6_routes() -> Result<Vec<serde_json::Value>, String> {
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&ip(&["-N", "-j", "-6", "route", "show", "table", "all"])?)
            .map_err(|_| "Invalid IPv6 routes")?;
    Ok(entries
        .into_iter()
        .filter(|r| r["table"].as_u64() == Some(51830) || r["table"].as_str() == Some(TABLE))
        .collect())
}
fn nft_exists() -> Result<bool, String> {
    let value: serde_json::Value =
        serde_json::from_slice(&command("/usr/sbin/nft", &["-j", "list", "tables"])?)
            .map_err(|_| "Cannot inspect nftables")?;
    Ok(value["nftables"]
        .as_array()
        .ok_or("Invalid nftables listing")?
        .iter()
        .any(|entry| entry["table"]["family"] == "inet" && entry["table"]["name"] == NFT))
}
pub(super) fn nft(script: &str) -> Result<(), String> {
    let mut file = tempfile::NamedTempFile::new_in("/run/rtrust")
        .map_err(|_| "Cannot create firewall transaction")?;
    file.write_all(script.as_bytes())
        .map_err(|_| "Cannot write firewall transaction")?;
    command(
        "/usr/sbin/nft",
        &["-f", file.path().to_str().ok_or("Invalid firewall path")?],
    )?;
    Ok(())
}
pub(super) fn guard_script() -> String {
    // No established/related exemption: pre-existing physical connections must
    // not bypass protection. Forwarded/container traffic is blocked in this mode.
    format!(
        r#"add table inet {NFT}
add chain inet {NFT} output {{ type filter hook output priority -10; policy drop; }}
add rule inet {NFT} output oifname "lo" accept
add rule inet {NFT} output meta mark 0x5254 accept
add rule inet {NFT} output oifname "{DEVICE}" accept
add rule inet {NFT} output ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept
add rule inet {NFT} output ip6 hoplimit 255 icmpv6 type {{ nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert }} accept
add rule inet {NFT} output ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept
add chain inet {NFT} forward {{ type filter hook forward priority -10; policy drop; }}
"#
    )
}
impl FullRoutes {
    pub fn pending() -> bool {
        std::path::Path::new(JOURNAL).exists()
    }
    pub fn preflight(dns: Ipv4Addr) -> Result<(), String> {
        rtrust_control::validate_dns(dns)?;
        super::routes::Routes::preflight_common(&[])?;
        let rules: Vec<serde_json::Value> =
            serde_json::from_slice(&ip(&["-N", "-j", "-6", "rule", "show"])?)
                .map_err(|_| "Invalid IPv6 rules")?;
        if rules
            .iter()
            .any(|r| r["priority"].as_u64().is_some_and(|p| p > 0 && p <= 10530))
            || !v6_routes()?.is_empty()
        {
            return Err("Conflicting IPv6 policy or routing table".into());
        }
        if nft_exists()? {
            return Err("Firewall table rtrust_full is already in use".into());
        }
        command("/usr/bin/resolvectl", &["status"])
            .map_err(|_| "Полный туннель требует работающий systemd-resolved и resolvectl")?;
        Ok(())
    }
    pub fn install(uid: u32, dns: Ipv4Addr, addresses: &[String]) -> Result<Self, String> {
        let mut endpoints = addresses
            .iter()
            .map(|address| {
                address
                    .parse::<SocketAddr>()
                    .map(|a| a.ip())
                    .map_err(|_| "Numeric endpoint required")
            })
            .collect::<Result<Vec<_>, _>>()?;
        endpoints.sort();
        endpoints.dedup();
        if endpoints.is_empty() || endpoints.len() > 64 {
            return Err("Invalid endpoint addresses".into());
        }
        let journal = Journal {
            version: 3,
            uid,
            dns,
            endpoints,
        };
        let mut file = tempfile::NamedTempFile::new_in("/run/rtrust")
            .map_err(|_| "Cannot create full-tunnel journal")?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| "Cannot protect journal")?;
        serde_json::to_writer(file.as_file_mut(), &journal).map_err(|_| "Cannot encode journal")?;
        file.flush().map_err(|_| "Cannot write journal")?;
        file.as_file()
            .sync_all()
            .map_err(|_| "Cannot sync journal")?;
        file.persist_noclobber(JOURNAL)
            .map_err(|_| "Recovery journal already exists")?;
        fs::File::open("/run/rtrust")
            .and_then(|f| f.sync_all())
            .map_err(|_| "Cannot sync journal directory")?;
        let mut guard = Self {
            journal,
            active: true,
            rollback_on_drop: true,
        };
        // Atomic firewall transaction precedes every DNS/routing mutation.
        nft(&guard_script())?;
        // Reverse-path validation must find the endpoint through the physical
        // route even when TUN is gone. This route alone grants no direct access:
        // nftables still admits only the marked service transport on that link.
        // Main-table lookup follows physical gateway changes without stale routes.
        for endpoint in &guard.journal.endpoints {
            ip(&[
                family(*endpoint),
                "rule",
                "add",
                "priority",
                "10528",
                "to",
                &endpoint.to_string(),
                "lookup",
                "main",
            ])?;
        }
        for family in ["-4", "-6"] {
            ip(&[
                family, "rule", "add", "priority", "10529", "fwmark", "0x5254", "lookup", "main",
            ])?;
            ip(&[
                family,
                "route",
                "add",
                "unreachable",
                "default",
                "table",
                TABLE,
                "metric",
                "42760",
            ])?;
        }
        guard.reattach()?;
        for family in ["-4", "-6"] {
            ip(&[family, "rule", "add", "priority", "10530", "lookup", TABLE])?;
        }
        // Once committed, only explicit Stop/Recover may remove protection.
        // EOF, task cancellation and orderly service shutdown retain the guard.
        guard.rollback_on_drop = false;
        Ok(guard)
    }
    pub fn reattach(&self) -> Result<(), String> {
        if self.journal.version >= 2 {
            ip(&[
                "-6",
                "route",
                "replace",
                "default",
                "dev",
                DEVICE,
                "src",
                &crate::ipv6::ADDRESS.to_string(),
                "table",
                TABLE,
                "metric",
                "5",
            ])?;
        }
        ip(&[
            "-4", "route", "replace", "default", "dev", DEVICE, "src", ADDRESS, "table", TABLE,
            "metric", "5",
        ])?;
        command(
            "/usr/bin/resolvectl",
            &["dns", DEVICE, &self.journal.dns.to_string()],
        )?;
        command("/usr/bin/resolvectl", &["domain", DEVICE, "~."])?;
        command("/usr/bin/resolvectl", &["default-route", DEVICE, "yes"])?;
        Ok(())
    }
    pub fn recover(uid: u32) -> Result<(), String> {
        if !Self::pending() {
            return Ok(());
        }
        let metadata =
            fs::symlink_metadata(JOURNAL).map_err(|_| "Cannot inspect full-tunnel journal")?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err("Unsafe full-tunnel journal".into());
        }
        let bytes = rtrust_store::read_bounded(std::path::Path::new(JOURNAL), 4096)
            .map_err(|_| "Cannot read journal")?;
        let journal: Journal =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid full-tunnel journal")?;
        if !matches!(journal.version, 1..=3) || journal.uid != uid {
            return Err("Recovery journal owner mismatch".into());
        }
        rtrust_control::validate_dns(journal.dns)?;
        if (journal.version == 3 && journal.endpoints.is_empty()) || journal.endpoints.len() > 64 {
            return Err("Invalid endpoint route journal".into());
        }
        Self {
            journal,
            active: true,
            rollback_on_drop: false,
        }
        .release()
    }
    pub fn release(&mut self) -> Result<(), String> {
        if std::path::Path::new("/sys/class/net").join(DEVICE).exists() {
            command("/usr/bin/resolvectl", &["revert", DEVICE])?;
        }
        for endpoint in &self.journal.endpoints {
            let _ = ip(&[
                family(*endpoint),
                "rule",
                "del",
                "priority",
                "10528",
                "to",
                &endpoint.to_string(),
                "lookup",
                "main",
            ]);
        }
        let families: &[&str] = if self.journal.version >= 2 {
            &["-4", "-6"]
        } else {
            &["-4"]
        };
        for family in families {
            let _ = ip(&[family, "rule", "del", "priority", "10530", "lookup", TABLE]);
            let _ = ip(&[
                family, "rule", "del", "priority", "10529", "fwmark", "0x5254", "lookup", "main",
            ]);
            let rules: Vec<serde_json::Value> =
                serde_json::from_slice(&ip(&["-N", "-j", family, "rule", "show"])?)
                    .map_err(|_| "Invalid policy rules")?;
            if rules.iter().any(|r| {
                r["table"].as_u64() == Some(51830)
                    || r["table"].as_str() == Some(TABLE)
                    || matches!(r["priority"].as_u64(), Some(10528 | 10529))
            }) {
                return Err("Policy cleanup failed; firewall guard retained".into());
            }
            let _ = ip(&[
                family, "route", "del", "default", "table", TABLE, "metric", "5",
            ]);
            let _ = ip(&[
                family,
                "route",
                "del",
                "unreachable",
                "default",
                "table",
                TABLE,
                "metric",
                "42760",
            ]);
        }
        if !super::routes::table_routes()?.is_empty()
            || (self.journal.version >= 2 && !v6_routes()?.is_empty())
        {
            return Err("Route cleanup failed; firewall guard retained".into());
        }
        // Firewall is the final operation: failure elsewhere keeps egress blocked.
        if nft_exists()? {
            nft(&format!("delete table inet {NFT}\n"))?;
        }
        fs::remove_file(JOURNAL).map_err(|_| "Cannot remove full-tunnel journal")?;
        self.active = false;
        Ok(())
    }
}
fn family(address: IpAddr) -> &'static str {
    if address.is_ipv4() { "-4" } else { "-6" }
}
impl Drop for FullRoutes {
    fn drop(&mut self) {
        if self.active && self.rollback_on_drop {
            let _ = self.release();
        }
    }
}
