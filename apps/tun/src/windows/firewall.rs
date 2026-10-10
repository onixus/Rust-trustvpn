//! Persistent, transactionally installed WFP policy. Only our provider is removed.
use std::{net::SocketAddrV4, ptr};
use windows_sys::{
    Win32::{Foundation::HANDLE, NetworkManagement::WindowsFilteringPlatform::*},
    core::GUID,
};
const PROVIDER: GUID = GUID::from_u128(0xd358e5b4_9891_4b22_b071_d95fef406791);
const SUBLAYER: GUID = GUID::from_u128(0xcfc0c428_2f61_40ab_a359_d63976d75f1e);
#[derive(Clone, Copy)]
struct Space {
    provider: GUID,
    sublayer: GUID,
}
const FULL: Space = Space {
    provider: PROVIDER,
    sublayer: SUBLAYER,
};
const BOOT: Space = Space {
    provider: GUID::from_u128(0x9b93baf4_7dd4_47b6_8b24_32497ba29261),
    sublayer: GUID::from_u128(0xc70c12a7_3e5b_4f9e_a6b9_0ea14bbcc303),
};
const NOT_FOUND: u32 = 0x80320005; // FWP_E_PROVIDER_NOT_FOUND
fn check(code: u32) -> Result<(), String> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("WFP operation failed (0x{code:08x})"))
    }
}
struct Engine(HANDLE);
impl Engine {
    fn open() -> Result<Self, String> {
        let mut h = ptr::null_mut();
        check(unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut h) })?;
        Ok(Self(h))
    }
    fn transaction(&self, operation: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        check(unsafe { FwpmTransactionBegin0(self.0, 0) })?;
        let result = operation().and_then(|()| check(unsafe { FwpmTransactionCommit0(self.0) }));
        if result.is_err() {
            unsafe { FwpmTransactionAbort0(self.0) };
        }
        result
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}
struct Blob(*mut FWP_BYTE_BLOB);
impl Drop for Blob {
    fn drop(&mut self) {
        unsafe { FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast()) };
    }
}
pub fn active() -> Result<bool, String> {
    active_in(FULL)
}
pub fn boot_active() -> Result<bool, String> {
    active_in(BOOT)
}
fn active_in(space: Space) -> Result<bool, String> {
    let engine = Engine::open()?;
    let mut provider = ptr::null_mut();
    let code = unsafe { FwpmProviderGetByKey0(engine.0, &space.provider, &mut provider) };
    if code == NOT_FOUND {
        return Ok(false);
    }
    check(code)?;
    unsafe { FwpmFreeMemory0((&mut provider as *mut *mut FWPM_PROVIDER0).cast()) };
    Ok(true)
}
fn condition(
    key: GUID,
    kind: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: key,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}
fn u32_condition(key: GUID, value: u32) -> FWPM_FILTER_CONDITION0 {
    condition(key, FWP_UINT32, FWP_CONDITION_VALUE0_0 { uint32: value })
}
fn add_in(
    engine: &Engine,
    space: Space,
    flags: u32,
    layer: GUID,
    permit: bool,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<(), String> {
    let mut provider = space.provider;
    let mut name: Vec<u16> = "R-TrustTunnel full tunnel\0".encode_utf16().collect();
    let filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        },
        flags,
        providerKey: &mut provider,
        layerKey: layer,
        subLayerKey: space.sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 {
                uint8: if permit { 15 } else { 0 },
            },
        },
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: if permit {
                FWP_ACTION_PERMIT
            } else {
                FWP_ACTION_BLOCK
            },
            ..Default::default()
        },
        ..Default::default()
    };
    check(unsafe { FwpmFilterAdd0(engine.0, &filter, ptr::null_mut(), ptr::null_mut()) })
}
/// Split-mode DNS lock: port 53 leaves only through `luid` or loopback. The filters live
/// in a dynamic session, so they vanish with this handle or the process and
/// never outlive the lease; Windows would otherwise race every adapter's DNS.
pub struct DnsLock(#[allow(dead_code)] Engine);
// The WFP engine handle is not tied to the opening thread.
unsafe impl Send for DnsLock {}
pub fn lock_dns(mut luid: u64) -> Result<DnsLock, String> {
    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let mut h = ptr::null_mut();
    check(unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), &session, &mut h) })?;
    let engine = Engine(h);
    engine.transaction(|| {
        let mut name: Vec<u16> = "R-TrustTunnel DNS\0".encode_utf16().collect();
        for layer in [
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            // Local resolvers (dnscrypt-proxy, Docker, WSL) listen on loopback.
            let mut loopback = u32_condition(FWPM_CONDITION_FLAGS, FWP_CONDITION_FLAG_IS_LOOPBACK);
            loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
            let tunnel = condition(
                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                FWP_UINT64,
                FWP_CONDITION_VALUE0_0 { uint64: &mut luid },
            );
            for extra in [Some(tunnel), Some(loopback), None] {
                let permit = extra.is_some();
                let mut conditions = vec![condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: 53 },
                )];
                conditions.extend(extra);
                let filter = FWPM_FILTER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: name.as_mut_ptr(),
                        description: ptr::null_mut(),
                    },
                    layerKey: layer,
                    subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
                    weight: FWP_VALUE0 {
                        r#type: FWP_UINT8,
                        Anonymous: FWP_VALUE0_0 {
                            uint8: if permit { 15 } else { 0 },
                        },
                    },
                    numFilterConditions: conditions.len() as u32,
                    filterCondition: conditions.as_mut_ptr(),
                    action: FWPM_ACTION0 {
                        r#type: if permit {
                            FWP_ACTION_PERMIT
                        } else {
                            FWP_ACTION_BLOCK
                        },
                        ..Default::default()
                    },
                    ..Default::default()
                };
                check(unsafe {
                    FwpmFilterAdd0(engine.0, &filter, ptr::null_mut(), ptr::null_mut())
                })?;
            }
        }
        Ok(())
    })?;
    Ok(DnsLock(engine))
}
/// `ports` replaces each endpoint's own port with these ranges (Hysteria port hopping).
pub fn install(
    luid: u64,
    endpoints: &[SocketAddrV4],
    udp: bool,
    ports: &[(u16, u16)],
) -> Result<(), String> {
    install_in(luid, endpoints, FULL, false, udp, ports)
}
pub fn install_boot(
    luid: u64,
    endpoints: &[SocketAddrV4],
    udp: bool,
    ports: &[(u16, u16)],
) -> Result<(), String> {
    install_in(luid, endpoints, BOOT, true, udp, ports)
}
fn install_in(
    mut luid: u64,
    endpoints: &[SocketAddrV4],
    space: Space,
    boot: bool,
    udp: bool,
    ports: &[(u16, u16)],
) -> Result<(), String> {
    if ports.len() > 64 {
        return Err("Too many endpoint port ranges".into());
    }
    let existed = active_in(space)?;
    if !boot && existed {
        return Err("WFP guard already active; explicitly recover before reconnecting".into());
    }
    let engine = Engine::open()?;
    let exe = std::env::current_exe().map_err(|_| "Service path unavailable")?;
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut blob = Blob(ptr::null_mut());
    check(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob.0) })?;
    engine.transaction(|| {
        if boot && existed {
            remove_in(&engine, space)?;
        }
        let add = |engine: &Engine,
                   layer: GUID,
                   permit: bool,
                   conditions: &mut [FWPM_FILTER_CONDITION0]| {
            add_in(
                engine,
                space,
                FWPM_FILTER_FLAG_PERSISTENT,
                layer,
                permit,
                conditions,
            )
        };
        let mut name: Vec<u16> = "R-TrustTunnel full tunnel\0".encode_utf16().collect();
        let mut provider = space.provider;
        let data = FWPM_DISPLAY_DATA0 {
            name: name.as_mut_ptr(),
            description: ptr::null_mut(),
        };
        check(unsafe {
            FwpmProviderAdd0(
                engine.0,
                &FWPM_PROVIDER0 {
                    providerKey: provider,
                    displayData: data,
                    flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                    ..Default::default()
                },
                ptr::null_mut(),
            )
        })?;
        check(unsafe {
            FwpmSubLayerAdd0(
                engine.0,
                &FWPM_SUBLAYER0 {
                    subLayerKey: space.sublayer,
                    displayData: data,
                    flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                    providerKey: &mut provider,
                    weight: 0xffff,
                    ..Default::default()
                },
                ptr::null_mut(),
            )
        })?;
        // Packet filters cover existing flows and raw packets as well as new connects.
        for (layer, v4, ale) in [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, true, true),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, false, true),
            (FWPM_LAYER_OUTBOUND_IPPACKET_V4, true, false),
            (FWPM_LAYER_OUTBOUND_IPPACKET_V6, false, false),
        ] {
            let mut loopback = u32_condition(FWPM_CONDITION_FLAGS, FWP_CONDITION_FLAG_IS_LOOPBACK);
            loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
            add(&engine, layer, true, &mut [loopback])?;
            if luid != 0 {
                add(
                    &engine,
                    layer,
                    true,
                    &mut [condition(
                        FWPM_CONDITION_IP_LOCAL_INTERFACE,
                        FWP_UINT64,
                        FWP_CONDITION_VALUE0_0 { uint64: &mut luid },
                    )],
                )?;
            }
            if v4 {
                for endpoint in endpoints {
                    let mut conditions = vec![u32_condition(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        u32::from(*endpoint.ip()),
                    )];
                    if ale {
                        conditions.push(condition(
                            FWPM_CONDITION_ALE_APP_ID,
                            FWP_BYTE_BLOB_TYPE,
                            FWP_CONDITION_VALUE0_0 { byteBlob: blob.0 },
                        ));
                        conditions.push(condition(
                            FWPM_CONDITION_IP_PROTOCOL,
                            FWP_UINT8,
                            FWP_CONDITION_VALUE0_0 {
                                // QUIC (HTTP/3, Hysteria 2) and AmneziaWG use UDP.
                                uint8: if udp { 17 } else { 6 },
                            },
                        ));
                        if !ports.is_empty() {
                            for (low, high) in ports {
                                let mut range = FWP_RANGE0 {
                                    valueLow: FWP_VALUE0 {
                                        r#type: FWP_UINT16,
                                        Anonymous: FWP_VALUE0_0 { uint16: *low },
                                    },
                                    valueHigh: FWP_VALUE0 {
                                        r#type: FWP_UINT16,
                                        Anonymous: FWP_VALUE0_0 { uint16: *high },
                                    },
                                };
                                let mut port = condition(
                                    FWPM_CONDITION_IP_REMOTE_PORT,
                                    FWP_RANGE_TYPE,
                                    FWP_CONDITION_VALUE0_0 {
                                        rangeValue: &mut range,
                                    },
                                );
                                port.matchType = FWP_MATCH_RANGE;
                                let mut ranged = conditions.clone();
                                ranged.push(port);
                                add(&engine, layer, true, &mut ranged)?;
                            }
                            continue;
                        }
                        conditions.push(condition(
                            FWPM_CONDITION_IP_REMOTE_PORT,
                            FWP_UINT16,
                            FWP_CONDITION_VALUE0_0 {
                                uint16: endpoint.port(),
                            },
                        ));
                    }
                    add(&engine, layer, true, &mut conditions)?;
                }
                let mut dhcp = vec![u32_condition(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    u32::from(std::net::Ipv4Addr::BROADCAST),
                )];
                if ale {
                    dhcp.push(condition(
                        FWPM_CONDITION_IP_PROTOCOL,
                        FWP_UINT8,
                        FWP_CONDITION_VALUE0_0 { uint8: 17 },
                    ));
                    dhcp.push(condition(
                        FWPM_CONDITION_IP_LOCAL_PORT,
                        FWP_UINT16,
                        FWP_CONDITION_VALUE0_0 { uint16: 68 },
                    ));
                    dhcp.push(condition(
                        FWPM_CONDITION_IP_REMOTE_PORT,
                        FWP_UINT16,
                        FWP_CONDITION_VALUE0_0 { uint16: 67 },
                    ));
                }
                add(&engine, layer, true, &mut dhcp)?;
            }
            add(&engine, layer, false, &mut [])?;
        }
        for layer in [FWPM_LAYER_IPFORWARD_V4, FWPM_LAYER_IPFORWARD_V6] {
            add(&engine, layer, false, &mut [])?;
        }
        if boot {
            // Separate flags on the SAME provider: WFP transitions atomically at BFE startup.
            for layer in [
                FWPM_LAYER_OUTBOUND_IPPACKET_V4,
                FWPM_LAYER_OUTBOUND_IPPACKET_V6,
                FWPM_LAYER_IPFORWARD_V4,
                FWPM_LAYER_IPFORWARD_V6,
            ] {
                add_in(
                    &engine,
                    space,
                    FWPM_FILTER_FLAG_BOOTTIME,
                    layer,
                    false,
                    &mut [],
                )?;
            }
        }
        Ok(())
    })
}
pub fn remove() -> Result<(), String> {
    remove_space(FULL)
}
pub fn remove_boot() -> Result<(), String> {
    remove_space(BOOT)
}
fn remove_space(space: Space) -> Result<(), String> {
    if !active_in(space)? {
        return Ok(());
    }
    let engine = Engine::open()?;
    engine.transaction(|| remove_in(&engine, space))
}
fn remove_in(engine: &Engine, space: Space) -> Result<(), String> {
    // Enumerate all layers, but constrain deletion to our unique provider key.
    let mut provider = space.provider;
    for layer in [
        FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        FWPM_LAYER_IPFORWARD_V4,
        FWPM_LAYER_IPFORWARD_V6,
    ] {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: layer,
            providerKey: &mut provider,
            actionMask: u32::MAX,
            flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
            ..Default::default()
        };
        let mut enumeration = ptr::null_mut();
        check(unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut enumeration) })?;
        let result: Result<(), String> = (|| {
            loop {
                let mut entries = ptr::null_mut();
                let mut count = 0;
                check(unsafe {
                    FwpmFilterEnum0(engine.0, enumeration, 256, &mut entries, &mut count)
                })?;
                let ids = if count == 0 {
                    vec![]
                } else {
                    unsafe { std::slice::from_raw_parts(entries, count as usize) }
                        .iter()
                        .map(|p| unsafe { (**p).filterId })
                        .collect::<Vec<_>>()
                };
                if !entries.is_null() {
                    unsafe {
                        FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast())
                    };
                }
                if ids.is_empty() {
                    break;
                }
                for id in ids {
                    check(unsafe { FwpmFilterDeleteById0(engine.0, id) })?;
                }
            }
            Ok(())
        })();
        unsafe { FwpmFilterDestroyEnumHandle0(engine.0, enumeration) };
        result?;
    }
    check(unsafe { FwpmSubLayerDeleteByKey0(engine.0, &space.sublayer) })?;
    check(unsafe { FwpmProviderDeleteByKey0(engine.0, &space.provider) })
}

/// Harmless canary exercises persistent-provider cleanup before destructive CI.
pub fn self_test() -> Result<(), String> {
    if active()? || boot_active()? {
        return Err("Refusing canary while a full/boot tunnel guard exists".into());
    }
    for space in [FULL, BOOT] {
        let engine = Engine::open()?;
        engine.transaction(|| {
            let mut name: Vec<u16> = "R-TrustTunnel recovery canary\0".encode_utf16().collect();
            let mut provider = space.provider;
            let data = FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: ptr::null_mut(),
            };
            check(unsafe {
                FwpmProviderAdd0(
                    engine.0,
                    &FWPM_PROVIDER0 {
                        providerKey: provider,
                        displayData: data,
                        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                        ..Default::default()
                    },
                    ptr::null_mut(),
                )
            })?;
            check(unsafe {
                FwpmSubLayerAdd0(
                    engine.0,
                    &FWPM_SUBLAYER0 {
                        subLayerKey: space.sublayer,
                        displayData: data,
                        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
                        providerKey: &mut provider,
                        weight: 0xffff,
                        ..Default::default()
                    },
                    ptr::null_mut(),
                )
            })?;
            for flags in [FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER_FLAG_BOOTTIME] {
                add_in(
                    &engine,
                    space,
                    flags,
                    FWPM_LAYER_OUTBOUND_IPPACKET_V4,
                    false,
                    &mut [u32_condition(
                        FWPM_CONDITION_IP_REMOTE_ADDRESS,
                        u32::from(std::net::Ipv4Addr::new(192, 0, 2, 254)),
                    )],
                )?;
            }
            Ok(())
        })?;
        let found = active_in(space)?;
        remove_space(space)?;
        if !found || active_in(space)? {
            return Err("Persistent/boot WFP canary cleanup failed".into());
        }
    }
    Ok(())
}
