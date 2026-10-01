//! Recovery journal is stored beside the SYSTEM service in its protected directory.
use super::{firewall, routes};
use serde::{Deserialize, Serialize};
use std::{
    io::Write,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::NET_LUID_LH},
    Networking::WinSock::*,
};
const METRIC: u32 = 0x5254;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointRoute {
    ip: Ipv4Addr,
    gateway: Ipv4Addr,
    luid: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    adapter: String,
    routes: Vec<EndpointRoute>,
}
fn path() -> Result<PathBuf, String> {
    Ok(std::env::current_exe()
        .map_err(|_| "Service path unavailable")?
        .with_file_name("full-state.json"))
}
fn check(code: u32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("Windows network operation failed ({code})"))
    }
}
pub fn pending() -> Result<bool, String> {
    Ok(path()?.exists() || firewall::active()?)
}
pub fn endpoints(profile: &rtrust_profile::Profile) -> Result<Vec<SocketAddrV4>, String> {
    let mut result = vec![];
    for address in &profile.endpoint.addresses {
        match address.parse::<SocketAddr>() {
            Ok(SocketAddr::V4(v))
                if !v.ip().is_loopback()
                    && !v.ip().is_unspecified()
                    && !v.ip().is_multicast()
                    && !v.ip().is_broadcast() =>
            {
                if !result.contains(&v) {
                    result.push(v)
                }
            }
            _ => return Err("Full tunnel requires pinned IPv4 endpoint addresses".into()),
        }
    }
    if result.is_empty() || result.len() > 64 {
        return Err("Invalid endpoint count".into());
    }
    Ok(result)
}
fn route(item: &EndpointRoute) -> MIB_IPFORWARD_ROW2 {
    let mut r = routes::row(0, rtrust_control::Ipv4Net::new(item.ip, 32).unwrap());
    r.InterfaceLuid = NET_LUID_LH { Value: item.luid };
    r.NextHop = routes::address(item.gateway);
    r.Metric = METRIC;
    r
}
pub fn install(index: u32, endpoints: &[SocketAddrV4], dns: Ipv4Addr) -> Result<(), String> {
    rtrust_control::validate_dns(dns)?;
    if pending()? {
        return Err("После аварии требуется явный сброс защиты перед подключением".into());
    }
    let mut luid = NET_LUID_LH::default();
    check(unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) })?;
    let mut guid = windows_sys::core::GUID::default();
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    let mut journal = Journal {
        version: 2,
        adapter: format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7]
        ),
        routes: vec![],
    };
    for endpoint in endpoints {
        let mut best = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        check(unsafe {
            GetBestRoute2(
                std::ptr::null(),
                0,
                std::ptr::null(),
                &routes::address(*endpoint.ip()),
                0,
                &mut best,
                &mut source,
            )
        })?;
        if best.InterfaceIndex == index {
            return Err("Endpoint would route into Wintun".into());
        }
        // An existing exact route is borrowed, never recorded for removal.
        if best.DestinationPrefix.PrefixLength == 32 {
            continue;
        }
        if journal.routes.iter().any(|r| r.ip == *endpoint.ip()) {
            continue;
        }
        journal.routes.push(EndpointRoute {
            ip: *endpoint.ip(),
            gateway: Ipv4Addr::from(
                unsafe { best.NextHop.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
            ),
            luid: unsafe { best.InterfaceLuid.Value },
        });
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path()?)
        .map_err(|_| "Cannot create protected recovery journal")?;
    file.write_all(&serde_json::to_vec(&journal).map_err(|_| "Cannot encode recovery journal")?)
        .map_err(|_| "Cannot save recovery journal")?;
    file.sync_all()
        .map_err(|_| "Cannot sync recovery journal")?;
    // No Drop cleanup: once this commits, crashes must retain the blocking policy.
    firewall::install(unsafe { luid.Value }, endpoints)?;
    if firewall::boot_active()? {
        firewall::install_boot(unsafe { luid.Value }, endpoints)?;
    }
    for item in &journal.routes {
        check(unsafe { CreateIpForwardEntry2(&route(item)) })?;
    }
    let mut guid = windows_sys::core::GUID::default();
    check(unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) })?;
    let mut nameserver: Vec<u16> = dns.to_string().encode_utf16().chain(Some(0)).collect();
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: DNS_SETTING_NAMESERVER as u64,
        NameServer: nameserver.as_mut_ptr(),
        ..Default::default()
    };
    check(unsafe { SetInterfaceDnsSettings(guid, &settings) })?;
    Ok(())
}
/// Rebuild only our endpoint exceptions after a physical network handoff.
/// The full WFP guard remains installed throughout. Journal both generations
/// before mutation so a power loss never leaves an untracked route behind.
pub fn refresh(index: u32, endpoints: &[SocketAddrV4]) -> Result<(), String> {
    let bytes =
        rtrust_store::read_bounded(&path()?, 32768).map_err(|_| "Cannot read recovery journal")?;
    let mut journal: Journal =
        serde_json::from_slice(&bytes).map_err(|_| "Invalid recovery journal")?;
    if journal.version != 2 || journal.routes.len() > 128 {
        return Err("Unsupported recovery journal".into());
    }
    let mut table = std::ptr::null_mut();
    check(unsafe { GetIpForwardTable2(AF_INET, &mut table) })?;
    let candidates = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let mut result = vec![];
        for row in rows {
            if row.InterfaceIndex == index || row.Metric == METRIC {
                continue;
            }
            let mut interface = MIB_IPINTERFACE_ROW::default();
            InitializeIpInterfaceEntry(&mut interface);
            interface.Family = AF_INET;
            interface.InterfaceLuid = row.InterfaceLuid;
            if GetIpInterfaceEntry(&mut interface) != 0 || !interface.Connected {
                continue;
            }
            let ip = Ipv4Addr::from(
                row.DestinationPrefix
                    .Prefix
                    .Ipv4
                    .sin_addr
                    .S_un
                    .S_addr
                    .to_ne_bytes(),
            );
            if let Ok(net) = rtrust_control::Ipv4Net::new(ip, row.DestinationPrefix.PrefixLength) {
                result.push((
                    net,
                    row.Metric.saturating_add(interface.Metric),
                    EndpointRoute {
                        ip: Ipv4Addr::UNSPECIFIED,
                        gateway: Ipv4Addr::from(
                            row.NextHop.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes(),
                        ),
                        luid: row.InterfaceLuid.Value,
                    },
                ));
            }
        }
        FreeMibTable(table.cast());
        result
    };
    let mut desired = vec![];
    for endpoint in endpoints {
        let (net, _, next) = candidates
            .iter()
            .filter(|(net, _, _)| net.contains(endpoint.ip()))
            .min_by_key(|(net, metric, _)| (32 - net.prefix_len(), *metric))
            .ok_or("No physical route to VPN endpoint; protection retained")?;
        if net.prefix_len() == 32 {
            continue;
        } // borrowed exact route
        let mut next = next.clone();
        next.ip = *endpoint.ip();
        if !desired.contains(&next) {
            desired.push(next);
        }
    }
    let old = journal.routes.clone();
    for next in &desired {
        if !journal.routes.contains(next) {
            journal.routes.push(next.clone());
        }
    }
    if journal.routes.len() > 128 {
        return Err("Endpoint recovery journal full".into());
    }
    let save = |journal: &Journal| -> Result<(), String> {
        rtrust_store::write_private(
            &path()?,
            &serde_json::to_vec(journal).map_err(|_| "Cannot encode recovery journal")?,
        )
        .map_err(|_| "Cannot save recovery journal".into())
    };
    save(&journal)?;
    for next in &desired {
        let mut row = route(next);
        let code = unsafe { GetIpForwardEntry2(&mut row) };
        if code == 0 {
            if row.Metric != METRIC || row.Protocol != MIB_IPPROTO_NETMGMT {
                return Err("Endpoint route changed externally; protection retained".into());
            }
        } else {
            check(unsafe { CreateIpForwardEntry2(&route(next)) })?;
        }
    }
    for previous in &old {
        if desired.contains(previous) {
            continue;
        }
        let mut row = route(previous);
        let code = unsafe { GetIpForwardEntry2(&mut row) };
        if code == 1168 || code == 87 {
            continue;
        }
        check(code)?;
        if row.Metric != METRIC || row.Protocol != MIB_IPPROTO_NETMGMT {
            return Err("Endpoint route changed externally; protection retained".into());
        }
        check(unsafe { DeleteIpForwardEntry2(&row) })?;
    }
    journal.routes = desired;
    save(&journal)
}
pub fn recover() -> Result<(), String> {
    let journal_path = path()?;
    if journal_path.exists() {
        let bytes = std::fs::read(&journal_path).map_err(|_| "Cannot read recovery journal")?;
        if bytes.len() > 32768 {
            return Err("Invalid recovery journal".into());
        }
        let journal: Journal = serde_json::from_slice(&bytes)
            .map_err(|_| "Invalid recovery journal; protection retained")?;
        if journal.version != 2 || journal.routes.len() > 128 {
            return Err("Unsupported recovery journal".into());
        }
        routes::remove_owned_adapter(&journal.adapter)?;
        for item in &journal.routes {
            let mut current = route(item);
            let code = unsafe { GetIpForwardEntry2(&mut current) };
            if code == 1168 || code == 87 {
                continue;
            }
            check(code)?;
            if current.Metric != METRIC || current.Protocol != MIB_IPPROTO_NETMGMT {
                return Err("Endpoint route changed externally; protection retained".into());
            }
            check(unsafe { DeleteIpForwardEntry2(&current) })?;
        }
    }
    // Keep protection until asynchronous Wintun removal has finished.
    if journal_path.exists() {
        routes::wait_removed()?;
    }
    // Routes are cleaned before lifting the persistent network block.
    firewall::remove()?;
    if journal_path.exists() {
        std::fs::remove_file(journal_path).map_err(|_| "Cannot remove recovery journal")?;
    }
    Ok(())
}
