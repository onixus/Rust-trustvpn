use super::{
    command, device, dns, firewall,
    routes::{self, Route},
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};
pub(super) const DIRECTORY: &str = "/Library/Application Support/RTrustTunnel";
const JOURNAL: &str = "/Library/Application Support/RTrustTunnel/route-state.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    uid: u32,
    boot: String,
    dns: Option<Ipv4Addr>,
    networks: Vec<rtrust_control::Ipv4Net>,
    endpoints: Vec<SocketAddrV4>,
    routes: Vec<Route>,
    pf_token: Option<String>,
}
#[derive(Clone)]
pub(super) struct Guard(Journal);
pub(super) fn directory() -> Result<(), String> {
    for parent in ["/Library", "/Library/Application Support"] {
        secure_directory(Path::new(parent))?;
    }
    if !Path::new(DIRECTORY).exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(DIRECTORY)
            .map_err(|_| "Cannot create VPN state directory")?;
    }
    secure_directory(Path::new(DIRECTORY))
}
pub(super) fn secure_directory(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|_| "Cannot inspect privileged directory")?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        Err("Unsafe privileged directory".into())
    } else {
        Ok(())
    }
}
fn boot() -> Result<String, String> {
    let value = command::run("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"])?;
    let value = value.trim();
    if value.len() != 36 || !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') {
        return Err("Cannot identify macOS boot session".into());
    }
    Ok(value.into())
}
pub(super) fn pending() -> bool {
    Path::new(JOURNAL).exists()
}
fn save(j: &Journal, initial: bool) -> Result<(), String> {
    let mut file =
        tempfile::NamedTempFile::new_in(DIRECTORY).map_err(|_| "Cannot create network journal")?;
    serde_json::to_writer(file.as_file_mut(), j).map_err(|_| "Cannot encode network journal")?;
    file.flush()
        .and_then(|_| file.as_file().sync_all())
        .map_err(|_| "Cannot sync network journal")?;
    if initial {
        file.persist_noclobber(JOURNAL)
            .map_err(|_| "Recovery journal already exists")?;
    } else {
        file.persist(JOURNAL)
            .map_err(|_| "Cannot update recovery journal")?;
    }
    fs::File::open(DIRECTORY)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Cannot sync journal directory".into())
}
fn load(uid: u32) -> Result<Journal, String> {
    directory()?;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(JOURNAL)
        .map_err(|_| "Cannot open recovery journal")?;
    let m = file
        .metadata()
        .map_err(|_| "Cannot inspect recovery journal")?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.len() > 65536 {
        return Err("Unsafe recovery journal".into());
    }
    let mut bytes = vec![];
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read recovery journal")?;
    let j: Journal = serde_json::from_slice(&bytes).map_err(|_| "Invalid recovery journal")?;
    if j.version != 1
        || j.uid != uid
        || j.routes.len() > rtrust_control::MAX_ROUTES + 68
        || j.endpoints.len() > 64
        || j.boot.len() != 36
    {
        return Err("Recovery ownership or version mismatch".into());
    }
    for route in &j.routes {
        route.validate()?;
    }
    if let Some(dns) = j.dns {
        rtrust_control::validate_dns(dns)?;
    } else {
        rtrust_control::validate_routes(&j.networks)?;
    }
    Ok(j)
}
pub(super) fn endpoints(profile: &rtrust_profile::Profile) -> Result<Vec<SocketAddrV4>, String> {
    let mut endpoints = vec![];
    for value in &profile.endpoint.addresses {
        let Ok(SocketAddr::V4(value)) = value.parse() else {
            return Err("System VPN requires pinned IPv4 endpoint addresses".into());
        };
        if value.ip().is_loopback()
            || value.ip().is_unspecified()
            || value.ip().is_multicast()
            || value.ip().is_broadcast()
            || value.port() == 0
        {
            return Err("Invalid system VPN endpoint address".into());
        }
        if !endpoints.contains(&value) {
            endpoints.push(value);
        }
    }
    if endpoints.is_empty() || endpoints.len() > 64 {
        return Err("Invalid endpoint count".into());
    }
    Ok(endpoints)
}
impl Guard {
    pub fn preflight(
        networks: &[rtrust_control::Ipv4Net],
        resolver: Option<Ipv4Addr>,
    ) -> Result<(), String> {
        directory()?;
        if pending() {
            return Err("Recovery is required before connecting".into());
        }
        device::unused()?;
        if let Some(resolver) = resolver {
            rtrust_control::validate_dns(resolver)?;
            dns::preflight()?;
            routes::physical_interface()?;
        } else {
            rtrust_control::validate_routes(networks)?;
        }
        for key in ["net.inet.ip.forwarding", "net.inet6.ip6.forwarding"] {
            if command::run("/usr/sbin/sysctl", &["-n", key])?.trim() != "0" {
                return Err("System VPN requires IP forwarding disabled; existing settings are left unchanged".into());
            }
        }
        firewall::preflight()
    }
    pub fn install(
        uid: u32,
        networks: Vec<rtrust_control::Ipv4Net>,
        resolver: Option<Ipv4Addr>,
        endpoints: Vec<SocketAddrV4>,
        udp: bool,
        ports: &[(u16, u16)],
    ) -> Result<Self, String> {
        let mut planned = vec![];
        if resolver.is_some() {
            let physical = routes::physical_interface()?;
            for endpoint in &endpoints {
                let route = routes::endpoint(*endpoint.ip(), &physical)?;
                if !planned.contains(&route) {
                    planned.push(route);
                }
            }
        }
        let prefixes: Vec<(bool, String)> = if resolver.is_some() {
            vec![
                (false, "0.0.0.0/1".into()),
                (false, "128.0.0.0/1".into()),
                (true, "::/1".into()),
                (true, "8000::/1".into()),
            ]
        } else {
            networks.iter().map(|n| (false, n.to_string())).collect()
        };
        for (v6, prefix) in prefixes {
            planned.push(Route {
                v6,
                prefix,
                gateway: device::DEVICE.into(),
                interface: device::DEVICE.into(),
                direct: true,
            });
        }
        for route in &planned {
            route.vacant()?;
        }
        let mut j = Journal {
            version: 1,
            uid,
            boot: boot()?,
            dns: resolver,
            networks,
            endpoints,
            routes: planned,
            pf_token: None,
        };
        save(&j, true)?;
        let script = firewall::policy(
            uid,
            resolver.is_some(),
            &j.networks,
            &j.endpoints,
            udp,
            ports,
        );
        j.pf_token = Some(firewall::install(Path::new(DIRECTORY), &script)?);
        save(&j, false)?;
        for route in &j.routes {
            route.add()?;
        }
        if let Some(resolver) = resolver {
            dns::install(uid, resolver)?;
        }
        Ok(Self(j))
    }
    pub fn refresh(&self) -> Result<(), String> {
        for route in &self.0.routes {
            route.ensure()?;
        }
        if let Some(resolver) = self.0.dns {
            dns::ensure(self.0.uid, resolver)?;
        }
        Ok(())
    }
    pub fn release(self) -> Result<(), String> {
        recover(self.0.uid)
    }
}
pub(super) fn recover(uid: u32) -> Result<(), String> {
    if !pending() {
        return Ok(());
    }
    let j = load(uid)?;
    if let Some(resolver) = j.dns {
        dns::remove(uid, resolver)?;
    }
    for route in j.routes.iter().rev() {
        route.remove()?;
    }
    if j.boot == boot()? {
        firewall::remove(uid, j.pf_token.as_deref())?;
    } else if !command::run("/sbin/pfctl", &["-a", "com.apple/zz-rtrust", "-sr"])?
        .trim()
        .is_empty()
    {
        return Err("PF anchor belongs to a different boot session; refusing removal".into());
    }
    fs::remove_file(JOURNAL).map_err(|_| "Cannot remove recovery journal")?;
    fs::File::open(DIRECTORY)
        .and_then(|f| f.sync_all())
        .map_err(|_| "Cannot sync recovered state".into())
}
