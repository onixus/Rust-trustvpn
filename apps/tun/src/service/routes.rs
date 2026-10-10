use rtrust_control::{Ipv4Net, validate_routes};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    net::Ipv4Addr,
    os::unix::fs::{MetadataExt, PermissionsExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
pub const DEVICE: &str = "rtrust0";
pub const ADDRESS: &str = "169.254.254.2";
const TABLE: &str = "51830";
const PRIORITY: &str = "10530";
const JOURNAL: &str = "/run/rtrust/lease.json";

pub(super) fn ip(args: &[&str]) -> Result<Vec<u8>, String> {
    command("/usr/sbin/ip", args)
}
pub(super) fn command(path: &str, args: &[&str]) -> Result<Vec<u8>, String> {
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "iproute2 is required")?;
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match child.try_wait().map_err(|_| "iproute2 failed")? {
            Some(status) => {
                let output = child.wait_with_output().map_err(|_| "iproute2 failed")?;
                return if status.success() {
                    Ok(output.stdout)
                } else {
                    Err("Network operation failed".into())
                };
            }
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Network operation timed out".into());
            }
        }
    }
}
fn rules() -> Result<Vec<serde_json::Value>, String> {
    serde_json::from_slice(&ip(&["-N", "-j", "-4", "rule", "show"])?)
        .map_err(|_| "Invalid route listing".into())
}

pub(super) fn table_routes() -> Result<Vec<serde_json::Value>, String> {
    // Listing all tables succeeds even when our table does not exist. Never treat
    // a failed command as an empty table, and request numeric table IDs.
    let entries: Vec<serde_json::Value> =
        serde_json::from_slice(&ip(&["-N", "-j", "-4", "route", "show", "table", "all"])?)
            .map_err(|_| "Invalid routing table")?;
    Ok(entries
        .into_iter()
        .filter(|r| r["table"].as_u64() == Some(51830) || r["table"].as_str() == Some(TABLE))
        .collect())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    uid: u32,
    networks: Vec<Ipv4Net>,
    /// Link-scoped resolver; set only when `networks` route it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<Ipv4Addr>,
}
pub struct Routes {
    journal: Journal,
    active: bool,
}
impl Routes {
    pub fn pending() -> bool {
        std::path::Path::new(JOURNAL).exists()
    }
    pub fn preflight(networks: &[Ipv4Net]) -> Result<(), String> {
        validate_routes(networks)?;
        Self::preflight_common(networks)
    }
    /// Main-table routes and interface subnets: what the user reaches without
    /// the VPN. Policy rules win over the main table, so these must be
    /// subtracted explicitly rather than relying on longest-prefix match.
    pub fn local() -> Result<Vec<Ipv4Net>, String> {
        let routes: Vec<serde_json::Value> =
            serde_json::from_slice(&ip(&["-j", "-4", "route", "show", "table", "main"])?)
                .map_err(|_| "Invalid routing table")?;
        let devices: Vec<serde_json::Value> =
            serde_json::from_slice(&ip(&["-j", "-4", "address", "show"])?)
                .map_err(|_| "Invalid interface listing")?;
        let mut local: Vec<Ipv4Net> = routes
            .iter()
            .filter_map(|r| r["dst"].as_str())
            .filter(|dst| *dst != "default")
            .filter_map(|dst| {
                dst.parse::<Ipv4Net>()
                    .or_else(|_| dst.parse::<std::net::Ipv4Addr>().map(Ipv4Net::from))
                    .ok()
            })
            .collect();
        for device in devices
            .iter()
            .filter(|d| d["ifname"].as_str() != Some(DEVICE))
        {
            for addr in device["addr_info"].as_array().into_iter().flatten() {
                if let (Some(ip), Some(len)) = (
                    addr["local"].as_str().and_then(|s| s.parse().ok()),
                    addr["prefixlen"].as_u64(),
                ) && let Ok(net) = Ipv4Net::new(ip, len as u8)
                {
                    local.push(net.trunc());
                }
            }
        }
        Ok(local)
    }
    pub(super) fn preflight_common(networks: &[Ipv4Net]) -> Result<(), String> {
        if Self::pending() || super::full::FullRoutes::pending() {
            return Err("Осталась блокировка после аварии. Нажмите «Сбросить блокировку».".into());
        }
        if rules()?
            .iter()
            .any(|r| r["priority"].as_u64().is_some_and(|p| p > 0 && p <= 10530))
        {
            return Err("Обнаружены конфликтующие policy rules".into());
        }
        if !table_routes()?.is_empty() {
            return Err("Routing table 51830 is already in use".into());
        }
        let devices: Vec<serde_json::Value> =
            serde_json::from_slice(&ip(&["-j", "-4", "address", "show"])?)
                .map_err(|_| "Invalid interface listing")?;
        for device in devices {
            if device["ifname"].as_str() == Some(DEVICE) {
                return Err("TUN interface already exists".into());
            }
            for addr in device["addr_info"].as_array().into_iter().flatten() {
                if let Some(ip) = addr["local"]
                    .as_str()
                    .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
                    && (networks.iter().any(|net| net.contains(&ip)) || ip.to_string() == ADDRESS)
                {
                    return Err(format!(
                        "Выбранные сети содержат локальный адрес {ip}. Добавьте его сеть в исключения или включите «Исключить локальные сети»"
                    ));
                }
            }
        }
        Ok(())
    }
    /// The tunneled resolver, if `dns` is routed by `networks` and
    /// systemd-resolved can take link-scoped DNS; otherwise none.
    pub fn resolver(networks: &[Ipv4Net], dns: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
        rtrust_control::tunneled_resolver(networks, dns)
            .filter(|_| command("/usr/bin/resolvectl", &["status"]).is_ok())
    }
    pub fn install(
        uid: u32,
        networks: Vec<Ipv4Net>,
        dns: Option<Ipv4Addr>,
    ) -> Result<Self, String> {
        let journal = Journal {
            version: 1,
            uid,
            networks,
            dns,
        };
        let mut file = tempfile::NamedTempFile::new_in("/run/rtrust")
            .map_err(|_| "Cannot create recovery journal")?;
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
        let guard = Self {
            journal,
            active: true,
        };
        ip(&[
            "-4",
            "route",
            "add",
            "unreachable",
            "default",
            "table",
            TABLE,
            "metric",
            "42760",
        ])?;
        guard.reattach()?;
        let uid = format!("{uid}-{uid}");
        for net in &guard.journal.networks {
            ip(&[
                "-4",
                "rule",
                "add",
                "priority",
                PRIORITY,
                "uidrange",
                &uid,
                "to",
                &net.to_string(),
                "lookup",
                TABLE,
            ])?;
        }
        Ok(guard)
    }
    // Recreate only device routes after TUN loss. Rules and the unreachable
    // fallback stay installed for the entire lease, including retries.
    pub fn reattach(&self) -> Result<(), String> {
        for net in &self.journal.networks {
            ip(&[
                "-4",
                "route",
                "add",
                &net.to_string(),
                "dev",
                DEVICE,
                "src",
                ADDRESS,
                "table",
                TABLE,
            ])?;
        }
        // resolved binds link DNS sockets to the device, so queries leave
        // through the tunnel whatever the querying process's uid.
        if let Some(dns) = self.journal.dns {
            command("/usr/bin/resolvectl", &["dns", DEVICE, &dns.to_string()])?;
            command("/usr/bin/resolvectl", &["domain", DEVICE, "~."])?;
            command("/usr/bin/resolvectl", &["default-route", DEVICE, "yes"])?;
        }
        Ok(())
    }
    pub fn recover(uid: u32) -> Result<(), String> {
        if !Self::pending() {
            return Ok(());
        }
        let metadata = fs::symlink_metadata(JOURNAL).map_err(|_| "Cannot read recovery journal")?;
        if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
            return Err("Unsafe recovery journal".into());
        }
        let bytes = rtrust_store::read_bounded(std::path::Path::new(JOURNAL), 16384)
            .map_err(|_| "Cannot read journal")?;
        let journal: Journal =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid recovery journal")?;
        validate_routes(&journal.networks)?;
        if let Some(dns) = journal.dns {
            rtrust_control::validate_dns(dns)?;
        }
        if journal.version != 1 || journal.uid != uid {
            return Err("Recovery journal owner mismatch".into());
        }
        Self {
            journal,
            active: true,
        }
        .release()
    }
    pub fn release(&mut self) -> Result<(), String> {
        // Best effort: link DNS dies with the device anyway, and a failing
        // resolved must not keep the policy rules (and the user) blocked.
        if self.journal.dns.is_some()
            && std::path::Path::new("/sys/class/net").join(DEVICE).exists()
        {
            let _ = command("/usr/bin/resolvectl", &["revert", DEVICE]);
        }
        let uid = format!("{}-{}", self.journal.uid, self.journal.uid);
        for net in &self.journal.networks {
            let _ = ip(&[
                "-4",
                "rule",
                "del",
                "priority",
                PRIORITY,
                "uidrange",
                &uid,
                "to",
                &net.to_string(),
                "lookup",
                TABLE,
            ]);
        }
        // Do not remove the unreachable route if a rule could still select this table.
        if rules()?
            .iter()
            .any(|r| r["table"].as_u64() == Some(51830) || r["table"].as_str() == Some(TABLE))
        {
            return Err("Не удалось удалить policy rules; блокировка сохранена".into());
        }
        for net in &self.journal.networks {
            let _ = ip(&["-4", "route", "del", &net.to_string(), "table", TABLE]);
        }
        let _ = ip(&[
            "-4",
            "route",
            "del",
            "unreachable",
            "default",
            "table",
            TABLE,
            "metric",
            "42760",
        ]);
        if !table_routes()?.is_empty() {
            return Err("Routing cleanup incomplete".into());
        }
        fs::remove_file(JOURNAL).map_err(|_| "Cannot remove recovery journal")?;
        self.active = false;
        Ok(())
    }
}
impl Drop for Routes {
    fn drop(&mut self) {
        if self.active {
            let _ = self.release();
        }
    }
}
