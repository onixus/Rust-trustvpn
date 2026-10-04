use rtrust_control::Ipv4Net;
use std::net::Ipv4Addr;
use windows_sys::Win32::{NetworkManagement::IpHelper::*, Networking::WinSock::*};

pub(super) fn address(ip: Ipv4Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv4: SOCKADDR_IN {
            sin_family: AF_INET,
            sin_addr: IN_ADDR {
                S_un: IN_ADDR_0 {
                    S_addr: u32::from_ne_bytes(ip.octets()),
                },
            },
            ..Default::default()
        },
    }
}
pub(super) fn address6(ip: std::net::Ipv6Addr) -> SOCKADDR_INET {
    SOCKADDR_INET {
        Ipv6: SOCKADDR_IN6 {
            sin6_family: AF_INET6,
            sin6_addr: IN6_ADDR {
                u: IN6_ADDR_0 { Byte: ip.octets() },
            },
            ..Default::default()
        },
    }
}
pub(super) fn row(index: u32, net: Ipv4Net) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceIndex = index;
    row.DestinationPrefix = IP_ADDRESS_PREFIX {
        Prefix: address(net.network()),
        PrefixLength: net.prefix_len(),
    };
    row.NextHop = address(Ipv4Addr::UNSPECIFIED);
    row.Metric = 5;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}
pub struct Routes(Vec<MIB_IPFORWARD_ROW2>);
impl Routes {
    pub fn install(index: u32, networks: &[Ipv4Net]) -> Result<Self, String> {
        let mut guard = Self(Vec::new());
        for net in networks {
            let row = row(index, *net);
            let code = unsafe { CreateIpForwardEntry2(&row) };
            if code != 0 {
                return Err(format!("Cannot add Windows route ({code})"));
            }
            guard.0.push(row);
        }
        Ok(guard)
    }
    pub fn full_ipv6(&mut self, index: u32) -> Result<(), String> {
        for ip in [std::net::Ipv6Addr::UNSPECIFIED, "8000::".parse().unwrap()] {
            let mut row = MIB_IPFORWARD_ROW2::default();
            unsafe { InitializeIpForwardEntry(&mut row) };
            row.InterfaceIndex = index;
            row.DestinationPrefix = IP_ADDRESS_PREFIX {
                Prefix: address6(ip),
                PrefixLength: 1,
            };
            row.NextHop = address6(std::net::Ipv6Addr::UNSPECIFIED);
            row.Metric = 5;
            row.Protocol = MIB_IPPROTO_NETMGMT;
            let code = unsafe { CreateIpForwardEntry2(&row) };
            if code != 0 {
                return Err(format!("Cannot add IPv6 route ({code})"));
            }
            self.0.push(row);
        }
        Ok(())
    }
    pub fn release(&mut self) -> Result<(), String> {
        self.0.retain(|row| {
            let code = unsafe { DeleteIpForwardEntry2(row) };
            code != 0 && code != 1168
        });
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("Windows route cleanup incomplete".into())
        }
    }
}
impl Drop for Routes {
    fn drop(&mut self) {
        let _ = self.release();
    }
}

pub fn preflight(networks: &[Ipv4Net]) -> Result<(), String> {
    rtrust_control::validate_networks(networks)?;
    settled_adapter()?;
    // Reject overlaps with existing non-default routes, including LAN and VPNs.
    let mut table = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(AF_INET, &mut table) } != 0 {
        return Err("Cannot inspect Windows routes".into());
    }
    let conflict = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let conflict = rows.iter().any(|r| {
            let p = &r.DestinationPrefix;
            if p.PrefixLength == 0 {
                return false;
            }
            let addr = Ipv4Addr::from(p.Prefix.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes());
            Ipv4Net::new(addr, p.PrefixLength).is_ok_and(|other| {
                networks
                    .iter()
                    .any(|n| n.contains(&other.network()) || other.contains(&n.network()))
            })
        });
        FreeMibTable(table.cast());
        conflict
    };
    if conflict {
        Err("Выбранные сети пересекаются с существующими LAN/VPN маршрутами".into())
    } else {
        Ok(())
    }
}
/// CreateUnicastIpAddressEntry returns before Windows completes DAD. Do not
/// advertise Connected until the address can actually source packets.
pub async fn ready(index: u32, ip: Ipv4Addr) -> Result<(), String> {
    ready_address(index, address(ip)).await
}
pub async fn ready6(index: u32) -> Result<(), String> {
    ready_address(index, address6(crate::ipv6::ADDRESS)).await
}
async fn ready_address(index: u32, address: SOCKADDR_INET) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let mut row = MIB_UNICASTIPADDRESS_ROW {
            InterfaceIndex: index,
            Address: address,
            ..Default::default()
        };
        let code = unsafe { GetUnicastIpAddressEntry(&mut row) };
        if code == 0 && row.DadState == IpDadStatePreferred && !row.SkipAsSource {
            return Ok(());
        }
        if code == 0 && row.DadState == IpDadStateDuplicate {
            return Err("Wintun address is already in use".into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "Wintun address not ready (status {code}, DAD {})",
                row.DadState
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub fn unused_adapter() -> Result<(), String> {
    // Alias -> LUID conversion is an identity lookup, not a device-presence
    // check: Windows can retain the identity after PnP removal. Enumerate the
    // current interface table before deciding whether an adapter is still live.
    let mut table = std::ptr::null_mut();
    let code = unsafe { GetIfTable2(&mut table) };
    if code != 0 || table.is_null() {
        return Err(format!("Cannot inspect network interfaces ({code})"));
    }
    let present = unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        let present = rows.iter().find(|row| {
            let end = row
                .Alias
                .iter()
                .position(|v| *v == 0)
                .unwrap_or(row.Alias.len());
            row.Alias[..end]
                .iter()
                .copied()
                .eq("RTrustTunnel".encode_utf16())
        });
        let present = present.map(|row| (row.InterfaceIndex, row.OperStatus));
        FreeMibTable(table.cast());
        present
    };
    if let Some((index, status)) = present {
        Err(format!(
            "RTrustTunnel interface {index} still present (operational status {status}); refusing reuse"
        ))
    } else {
        Ok(())
    }
}

/// Enumerates `MSFT_NetAdapter`, as `Get-NetAdapter` does. Windows can keep
/// the row of an adapter that is already closed and gone from PnP in the
/// interface table for minutes, until its adapter list is enumerated this
/// way; lighter queries (`GetIfTable2Ex`, `GetAdaptersAddresses`,
/// `Win32_NetworkAdapter`, `MSNdis_EnumerateAdapter`, a PnP enumeration) leave
/// it there. Read-only: it changes no adapter and the caller still verifies
/// absence afterwards.
fn refresh_adapters() -> Result<(), String> {
    use windows::{
        Win32::System::{Com::*, Wmi::*},
        core::BSTR,
    };
    // Own thread: the COM apartment must not leak into a runtime worker.
    std::thread::spawn(|| unsafe {
        CoInitializeEx(None, COINIT_MULTITHREADED)
            .ok()
            .map_err(|_| "Cannot initialise COM")?;
        let result = (|| -> windows::core::Result<()> {
            let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
            let services = locator.ConnectServer(
                &BSTR::from("ROOT\\StandardCimv2"),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )?;
            // The process default is identification only, which a provider
            // refuses with WBEM_E_ACCESS_DENIED. Impersonation is set on the two
            // proxies used here, not for the whole service. A blanket belongs
            // to one interface proxy: pass the interface in use, not an
            // IUnknown queried from it.
            fn impersonate<T: windows::core::Param<windows::core::IUnknown>>(
                proxy: T,
            ) -> windows::core::Result<()> {
                unsafe {
                    CoSetProxyBlanket(
                        proxy,
                        10, // RPC_C_AUTHN_WINNT
                        0,  // RPC_C_AUTHZ_NONE
                        windows::core::PCWSTR::null(),
                        RPC_C_AUTHN_LEVEL_CALL,
                        RPC_C_IMP_LEVEL_IMPERSONATE,
                        None,
                        EOAC_NONE,
                    )
                }
            }
            impersonate(&services)?;
            let rows = services.CreateInstanceEnum(
                &BSTR::from("MSFT_NetAdapter"),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )?;
            impersonate(&rows)?;
            // The provider refreshes its list while the rows are produced.
            for _ in 0..4096 {
                let mut row = [None];
                let mut returned = 0;
                let code = rows.Next(10_000, &mut row, &mut returned);
                if code.is_err() || returned == 0 {
                    // WBEM_S_FALSE ends the enumeration; anything else is a failure.
                    return code.ok();
                }
            }
            Ok(())
        })();
        CoUninitialize();
        result.map_err(|_| "Cannot enumerate network adapters".to_string())
    })
    .join()
    .map_err(|_| "Adapter enumeration failed")?
}

/// `unused_adapter` with one adapter-list refresh if the name is still listed.
/// For the checks before a new adapter is created.
pub fn settled_adapter() -> Result<(), String> {
    if unused_adapter().is_ok() {
        return Ok(());
    }
    let _ = refresh_adapters();
    unused_adapter()
}

/// `unused_adapter` for a polling loop: once the row has lingered for two
/// seconds, refresh the adapter list, then at most every five seconds.
fn settling() -> impl FnMut() -> Result<(), String> {
    let started = std::time::Instant::now();
    let mut refreshed: Option<std::time::Instant> = None;
    move || {
        let result = unused_adapter();
        let due = match refreshed {
            None => started.elapsed() >= std::time::Duration::from_secs(2),
            Some(at) => at.elapsed() >= std::time::Duration::from_secs(5),
        };
        if result.is_ok() || !due {
            return result;
        }
        refreshed = Some(std::time::Instant::now());
        let _ = refresh_adapters();
        unused_adapter()
    }
}

/// Wintun closes synchronously, but Windows may finish removing its interface
/// asynchronously. Never reuse or delete an adapter whose ownership is unknown.
pub fn wait_removed() -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut absent = settling();
    while let Err(reason) = absent() {
        if std::time::Instant::now() >= deadline {
            return Err(format!("Wintun adapter removal is still pending: {reason}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Ok(())
}

/// Resolve the network GUID in the administrator-owned journal to its actual
/// PnP instance. Wintun's NetCfgInstanceId and SWD instance ID are not equivalent.
/// Enumeration is restricted to Wintun; never remove by display name or driver.
pub fn recover_owned_adapter(guid: &str) -> Result<(), String> {
    crate::adapter_cleanup::remove_until_absent(
        || remove_owned_adapter(guid),
        settling(),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_millis(500),
    )
}

/// Returns a summary for diagnostics; success does not prove removal.
fn remove_owned_adapter(guid: &str) -> Result<String, String> {
    use windows_sys::Win32::{
        Devices::DeviceAndDriverInstallation::*,
        Foundation::{ERROR_NO_MORE_ITEMS, GetLastError},
        System::Registry::*,
    };
    if guid.len() != 36
        || !guid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err("Invalid adapter identity in recovery journal".into());
    }
    let enumerator: Vec<u16> = "SWD\\Wintun\0".encode_utf16().collect();
    let property: Vec<u16> = "NetCfgInstanceId\0".encode_utf16().collect();
    let expected = format!("{{{guid}}}");
    unsafe {
        let set = SetupDiGetClassDevsW(
            std::ptr::null(),
            enumerator.as_ptr(),
            std::ptr::null_mut(),
            // Not DIGCF_PRESENT: a crashed owner can leave the device in
            // surprise removal while its interface is still listed.
            DIGCF_ALLCLASSES,
        );
        if set == -1 {
            return Err("Cannot enumerate Wintun devices".into());
        }
        let (mut matched, mut unreadable, mut reboot) = (0u32, 0u32, false);
        let result = (|| {
            for index in 0..4096 {
                let mut data = SP_DEVINFO_DATA {
                    cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
                    ..Default::default()
                };
                if SetupDiEnumDeviceInfo(set, index, &mut data) == 0 {
                    return if GetLastError() == ERROR_NO_MORE_ITEMS {
                        Ok(format!(
                            "matched {matched}, unreadable {unreadable}, reboot required {reboot}"
                        ))
                    } else {
                        Err("Wintun enumeration failed".into())
                    };
                }
                let key = SetupDiOpenDevRegKey(
                    set,
                    &data,
                    DICS_FLAG_GLOBAL,
                    0,
                    DIREG_DRV,
                    KEY_QUERY_VALUE,
                );
                if key == -1isize as HKEY {
                    unreadable += 1;
                    continue;
                }
                let mut value = [0u16; 40];
                let mut size = std::mem::size_of_val(&value) as u32;
                let code = RegGetValueW(
                    key,
                    std::ptr::null(),
                    property.as_ptr(),
                    RRF_RT_REG_SZ,
                    std::ptr::null_mut(),
                    value.as_mut_ptr().cast(),
                    &mut size,
                );
                RegCloseKey(key);
                if code != 0 {
                    unreadable += 1;
                    continue;
                }
                let end = value.iter().position(|v| *v == 0).unwrap_or(value.len());
                let value = String::from_utf16(&value[..end])
                    .map_err(|_| "Invalid Wintun network identity")?;
                if !value.eq_ignore_ascii_case(&expected) {
                    continue;
                }
                matched += 1;
                if SetupDiCallClassInstaller(DIF_REMOVE, set, &data) == 0 {
                    return Err(format!(
                        "Cannot remove owned Wintun device ({})",
                        GetLastError()
                    ));
                }
                let mut params = SP_DEVINSTALL_PARAMS_W {
                    cbSize: std::mem::size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
                    ..Default::default()
                };
                if SetupDiGetDeviceInstallParamsW(set, &data, &mut params) != 0
                    && params.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) != 0
                {
                    reboot = true;
                }
                // Keep enumerating: never let an earlier matching instance
                // hide another still-present instance during PnP teardown.
            }
            Err("Too many Wintun devices".into())
        })();
        SetupDiDestroyDeviceInfoList(set);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn route_byte_order_and_scope() {
        let r = row(42, "198.18.0.0/24".parse().unwrap());
        assert_eq!(r.InterfaceIndex, 42);
        assert_eq!(r.DestinationPrefix.PrefixLength, 24);
        assert_eq!(
            unsafe {
                r.DestinationPrefix
                    .Prefix
                    .Ipv4
                    .sin_addr
                    .S_un
                    .S_addr
                    .to_ne_bytes()
            },
            [198, 18, 0, 0]
        );
        assert_eq!(r.Metric, 5);
    }
}
