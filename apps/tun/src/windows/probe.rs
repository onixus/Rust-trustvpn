//! Windows facts for the service probe through native APIs only: the
//! provider's own WFP filters, Wintun DNS, adapters and NRPT, routes and two
//! kinds of datagrams. Read-only; no PowerShell or netsh.
use super::firewall;
use crate::sysprobe::{self, Attempt, Audit, Dns, Foreign, Path, wfp};
use rtrust_control::observations::SystemProbe;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::windows::io::AsRawSocket,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::*},
    Networking::WinSock::*,
    System::Registry::*,
};

#[derive(Clone)]
pub(super) struct Plan {
    pub index: u32,
    pub dns: Ipv4Addr,
    pub endpoints: Vec<IpAddr>,
}
/// IP Helper, BFE and the registry can stall; never stack a second blocked read.
static LANE: sysprobe::Lane = sysprobe::Lane::new();
pub(super) async fn collect(plan: Plan, permits: Vec<crate::failover::Permit>) -> SystemProbe {
    let server = SocketAddr::new(plan.dns.into(), 53);
    let index = plan.index;
    sysprobe::evidence(async move {
        // Dropped with this run (cancel, Stop, EOF, deadline): the detached
        // thread then sends nothing, also after the guard has been removed.
        let (_fence, live) = sysprobe::fence();
        let blocking = LANE.spawn(move || gather(&plan, &permits, &live));
        let (facts, reply) = tokio::join!(
            sysprobe::part(None, async {
                match blocking {
                    Some(work) => work.await.ok(),
                    None => None,
                }
            }),
            async {
                match socket(false, index) {
                    Some(socket) => sysprobe::exchange(socket, server).await,
                    None => sysprobe::Reply::None,
                }
            },
        );
        let (audit, attempts, dns) =
            facts.unwrap_or((Audit::Unknown, vec![Attempt::Unknown], Dns::UNKNOWN));
        (Dns { reply, ..dns }, audit, attempts)
    })
    .await
}
/// Blocking part of a run; nothing after a dropped run sends or reads on.
fn gather(
    plan: &Plan,
    permits: &[crate::failover::Permit],
    live: &sysprobe::Live,
) -> (Audit, Vec<Attempt>, Dns) {
    let luid = luid(plan.index);
    let audit = luid.map_or(Audit::Unknown, |luid| audit(luid, permits));
    let attempts = attempts(plan, live);
    if !live.get() {
        return (audit, attempts, Dns::UNKNOWN);
    }
    (audit, attempts, dns(plan, luid))
}
fn luid(index: u32) -> Option<u64> {
    let mut luid = NET_LUID_LH::default();
    (unsafe { ConvertInterfaceIndexToLuid(index, &mut luid) } == 0).then_some(unsafe { luid.Value })
}
fn audit(luid: u64, permits: &[crate::failover::Permit]) -> Audit {
    let Ok(app) = firewall::app_id() else {
        return Audit::Unknown;
    };
    match firewall::read_back(&app) {
        Ok(Some(found)) => wfp::audit(found, wfp::filter_specs(luid, permits, false)),
        Ok(None) => Audit::Mismatch,
        Err(_) => Audit::Unknown,
    }
}
fn socket(v6: bool, index: u32) -> Option<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    // IPv4 takes the index in network byte order, IPv6 in host order.
    let (level, option, value) = if v6 {
        (IPPROTO_IPV6, IPV6_UNICAST_IF, index)
    } else {
        (IPPROTO_IP, IP_UNICAST_IF, index.to_be())
    };
    if unsafe {
        setsockopt(
            socket.as_raw_socket() as SOCKET,
            level,
            option,
            (&value as *const u32).cast(),
            std::mem::size_of_val(&value) as i32,
        )
    } != 0
    {
        return None;
    }
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}
/// Connected interfaces with a default route, except Wintun.
fn defaults(family: ADDRESS_FAMILY, wintun: u32) -> Option<Vec<u32>> {
    let mut table = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(family, &mut table) } != 0 {
        return None;
    }
    let mut found = Vec::new();
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.DestinationPrefix.PrefixLength != 0
                || row.InterfaceIndex == wintun
                || found.contains(&row.InterfaceIndex)
            {
                continue;
            }
            let mut interface = MIB_IPINTERFACE_ROW::default();
            InitializeIpInterfaceEntry(&mut interface);
            interface.Family = family;
            interface.InterfaceLuid = row.InterfaceLuid;
            if GetIpInterfaceEntry(&mut interface) == 0 && interface.Connected {
                found.push(row.InterfaceIndex);
            }
        }
        FreeMibTable(table.cast());
    }
    (found.len() <= 8).then_some(found)
}
/// A datagram `sendto` accepted, its socket kept open so the local port is
/// not reused before the drop events are read.
struct Pending {
    _socket: std::net::UdpSocket,
    port: u16,
    target: SocketAddr,
}
/// Each physical default-route interface must refuse an unmarked datagram:
/// an errno, or WFP's drop event naming our own block filter, because a UDP
/// send succeeds even when ALE drops it. Windows Firewall or another vendor
/// dropping it proves nothing about our guard; the read-back of our own
/// filters is required as well.
fn attempts(plan: &Plan, live: &sysprobe::Live) -> Vec<Attempt> {
    // Net event timestamps are FILETIMEs; a second of slack for their clock.
    let since = firewall::filetime().saturating_sub(10_000_000);
    let Some(sent) = sends(plan, live) else {
        return vec![Attempt::Unknown];
    };
    // BFE records a drop shortly after it; give it up to half a second.
    let mut dropped = vec![None; sent.len()];
    for round in 0..6 {
        if round > 0 {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !live.get() {
            return vec![Attempt::Unknown];
        }
        for ((_, pending), slot) in sent.iter().zip(&mut dropped) {
            if let Some(p) = pending
                && *slot != Some(true)
            {
                *slot = firewall::drops(p.port, since)
                    .ok()
                    .map(|events| wfp::refused(&events, p.port, p.target));
            }
        }
        if sent
            .iter()
            .zip(&dropped)
            .all(|((_, pending), d)| pending.is_none() || *d == Some(true))
        {
            break;
        }
    }
    sent.iter()
        .zip(dropped)
        .map(|((errno, _), dropped)| wfp::verdict(*errno, dropped))
        .collect()
}
fn sends(plan: &Plan, live: &sysprobe::Live) -> Option<Vec<(Attempt, Option<Pending>)>> {
    if sysprobe::collides(&plan.endpoints) || !live.get() {
        return None;
    }
    let v4 = defaults(AF_INET, plan.index)?;
    let v6 = defaults(AF_INET6, plan.index)?;
    let absent = [WSAENETUNREACH, WSAEHOSTUNREACH, WSAEADDRNOTAVAIL];
    let mut sent = Vec::new();
    for index in v4 {
        // The run may have been dropped while IP Helper was read.
        if !live.get() {
            return None;
        }
        sent.push(match socket(false, index) {
            Some(socket) => send(socket, sysprobe::TARGET_V4, |result| {
                sysprobe::attempt(result, &[WSAEACCES], &[])
            }),
            None => (Attempt::Unknown, None),
        });
        if !live.get() {
            return None;
        }
        let default = v6.contains(&index);
        sent.push(match socket(true, index) {
            Some(socket) => send(socket, sysprobe::TARGET_V6, |result| {
                sysprobe::v6_attempt(default, Some(result), &[WSAEACCES], &absent)
            }),
            None => (
                sysprobe::v6_attempt(default, None, &[WSAEACCES], &absent),
                None,
            ),
        });
    }
    Some(sent)
}
/// Only a datagram `sendto` accepted (`Leaked` by errno) waits for WFP.
fn send(
    socket: std::net::UdpSocket,
    target: SocketAddr,
    errno: impl FnOnce(Result<(), i32>) -> Attempt,
) -> (Attempt, Option<Pending>) {
    let errno = errno(sysprobe::send(&socket, target));
    if errno != Attempt::Leaked {
        return (errno, None);
    }
    match socket.local_addr() {
        Ok(local) => (
            errno,
            Some(Pending {
                port: local.port(),
                target,
                _socket: socket,
            }),
        ),
        Err(_) => (Attempt::Unknown, None),
    }
}
fn wide(text: *const u16) -> Option<String> {
    if text.is_null() {
        return Some(String::new());
    }
    let len = (0..4096).find(|&i| unsafe { *text.add(i) } == 0)?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) }).ok()
}
fn interface_servers(luid: u64) -> Option<Vec<String>> {
    let luid = NET_LUID_LH { Value: luid };
    let mut guid = windows_sys::core::GUID::default();
    if unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) } != 0 {
        return None;
    }
    let mut settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        ..Default::default()
    };
    if unsafe { GetInterfaceDnsSettings(guid, &mut settings) } != 0 {
        return None;
    }
    let text = wide(settings.NameServer);
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    Some(
        wfp::servers(&text?)
            .into_iter()
            .map(str::to_owned)
            .collect(),
    )
}
/// Any other up adapter with a resolver can be selected by Windows.
fn other_adapters(wintun: u64) -> Option<bool> {
    let mut size = 16 * 1024u32;
    for _ in 0..3 {
        let mut buffer = vec![0u64; size as usize / 8 + 1];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        match unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME,
                std::ptr::null(),
                first,
                &mut size,
            )
        } {
            0 => {
                let mut found = false;
                let mut adapter = first;
                while !adapter.is_null() {
                    let a = unsafe { &*adapter };
                    found |= unsafe { a.Luid.Value } != wintun
                        && a.OperStatus == IfOperStatusUp
                        && !a.FirstDnsServerAddress.is_null();
                    adapter = a.Next;
                }
                return Some(found);
            }
            111 => continue, // ERROR_BUFFER_OVERFLOW: size was updated.
            _ => return None,
        }
    }
    None
}
/// NRPT rules (local or policy) can send names to other resolvers.
fn nrpt() -> Option<bool> {
    let mut found = false;
    for path in [
        "SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\\DnsPolicyConfig",
        "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\DnsPolicyConfig",
    ] {
        let path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        let mut key = std::ptr::null_mut();
        match unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) } {
            0 => {}
            2 => continue, // ERROR_FILE_NOT_FOUND: no rules.
            _ => return None,
        }
        let mut subkeys = 0u32;
        let code = unsafe {
            RegQueryInfoKeyW(
                key,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut subkeys,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        unsafe { RegCloseKey(key) };
        if code != 0 {
            return None;
        }
        found |= subkeys > 0;
    }
    Some(found)
}
fn dns(plan: &Plan, luid: Option<u64>) -> Dns {
    let Some(luid) = luid else {
        return Dns::UNKNOWN;
    };
    let address = plan.dns.to_string();
    let config = match interface_servers(luid) {
        Some(servers) if servers == [address.as_str()] => Audit::Match,
        Some(_) => Audit::Mismatch,
        None => Audit::Unknown,
    };
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let destination = super::routes::address(plan.dns);
    let path = if unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &destination,
            0,
            &mut best,
            &mut source,
        )
    } != 0
    {
        Path::Unknown
    } else if best.InterfaceIndex == plan.index {
        Path::Tunnel
    } else {
        Path::Outside
    };
    Dns {
        config,
        path,
        reply: sysprobe::Reply::None,
        foreign: match (other_adapters(luid), nrpt()) {
            (Some(true), _) | (_, Some(true)) => Foreign::Present,
            (Some(false), Some(false)) => Foreign::None,
            _ => Foreign::Unknown,
        },
    }
}
