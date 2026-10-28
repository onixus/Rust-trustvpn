//! Persistent, transactionally installed WFP policy. Only our provider is removed.
use crate::sysprobe::wfp::{self, Condition, Layer, Spec};
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
/// Preserve each candidate's own protocol and port set in the guard.
pub fn install(luid: u64, permits: &[crate::failover::Permit]) -> Result<(), String> {
    install_in(luid, permits, FULL, false)
}
pub fn install_boot(
    luid: u64,
    endpoints: &[SocketAddrV4],
    udp: bool,
    ports: &[(u16, u16)],
) -> Result<(), String> {
    let permits: Vec<_> = endpoints
        .iter()
        .map(|&address| crate::failover::Permit {
            address,
            udp,
            ports: ports.to_vec(),
        })
        .collect();
    install_boot_permits(luid, &permits)
}
pub fn install_boot_permits(luid: u64, permits: &[crate::failover::Permit]) -> Result<(), String> {
    install_in(luid, permits, BOOT, true)
}
pub(super) fn layer_key(layer: Layer) -> GUID {
    match layer {
        Layer::ConnectV4 => FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        Layer::ConnectV6 => FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        Layer::PacketV4 => FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        Layer::PacketV6 => FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        Layer::ForwardV4 => FWPM_LAYER_IPFORWARD_V4,
        Layer::ForwardV6 => FWPM_LAYER_IPFORWARD_V6,
    }
}
type Ranges = Vec<Box<FWP_RANGE0>>;
/// WFP conditions point into `luid`, `blob` and the returned range storage;
/// keep all of them alive until the filter is added.
fn conditions(
    specs: &[Condition],
    luid: &mut u64,
    blob: *mut FWP_BYTE_BLOB,
) -> Result<(Vec<FWPM_FILTER_CONDITION0>, Ranges), String> {
    let mut ranges = Vec::new();
    let conditions = specs
        .iter()
        .map(|spec| {
            Ok(match *spec {
                Condition::Loopback => {
                    let mut loopback =
                        u32_condition(FWPM_CONDITION_FLAGS, FWP_CONDITION_FLAG_IS_LOOPBACK);
                    loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    loopback
                }
                Condition::LocalInterface(_) => condition(
                    FWPM_CONDITION_IP_LOCAL_INTERFACE,
                    FWP_UINT64,
                    FWP_CONDITION_VALUE0_0 {
                        uint64: luid as *mut u64,
                    },
                ),
                Condition::RemoteAddress(address) => {
                    u32_condition(FWPM_CONDITION_IP_REMOTE_ADDRESS, address)
                }
                Condition::AppId => condition(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_BYTE_BLOB_TYPE,
                    FWP_CONDITION_VALUE0_0 { byteBlob: blob },
                ),
                Condition::Protocol(protocol) => condition(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_UINT8,
                    FWP_CONDITION_VALUE0_0 { uint8: protocol },
                ),
                Condition::RemotePort(port) => condition(
                    FWPM_CONDITION_IP_REMOTE_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: port },
                ),
                Condition::RemotePorts(low, high) => {
                    let mut range = Box::new(FWP_RANGE0 {
                        valueLow: FWP_VALUE0 {
                            r#type: FWP_UINT16,
                            Anonymous: FWP_VALUE0_0 { uint16: low },
                        },
                        valueHigh: FWP_VALUE0 {
                            r#type: FWP_UINT16,
                            Anonymous: FWP_VALUE0_0 { uint16: high },
                        },
                    });
                    let mut port = condition(
                        FWPM_CONDITION_IP_REMOTE_PORT,
                        FWP_RANGE_TYPE,
                        FWP_CONDITION_VALUE0_0 {
                            rangeValue: &mut *range,
                        },
                    );
                    port.matchType = FWP_MATCH_RANGE;
                    ranges.push(range);
                    port
                }
                Condition::LocalPort(port) => condition(
                    FWPM_CONDITION_IP_LOCAL_PORT,
                    FWP_UINT16,
                    FWP_CONDITION_VALUE0_0 { uint16: port },
                ),
                Condition::Other => return Err("Invalid WFP policy".to_owned()),
            })
        })
        .collect::<Result<_, String>>()?;
    Ok((conditions, ranges))
}
fn install_in(
    mut luid: u64,
    permits: &[crate::failover::Permit],
    space: Space,
    boot: bool,
) -> Result<(), String> {
    if permits.iter().any(|p| p.ports.len() > 64) {
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
        // The same data the probe audits; see sysprobe::wfp::filter_specs.
        for spec in crate::sysprobe::wfp::filter_specs(luid, permits, boot) {
            let (mut conditions, _ranges) = conditions(&spec.conditions, &mut luid, blob.0)?;
            let flags = if spec.boottime {
                FWPM_FILTER_FLAG_BOOTTIME
            } else {
                FWPM_FILTER_FLAG_PERSISTENT
            };
            add_in(
                &engine,
                space,
                flags,
                layer_key(spec.layer),
                spec.permit,
                &mut conditions,
            )?;
        }
        Ok(())
    })
}
fn same(a: &GUID, b: &GUID) -> bool {
    (a.data1, a.data2, a.data3, a.data4) == (b.data1, b.data2, b.data3, b.data4)
}
/// The service executable's WFP app id bytes.
pub fn app_id() -> Result<Vec<u8>, String> {
    let exe = std::env::current_exe().map_err(|_| "Service path unavailable")?;
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut blob = Blob(ptr::null_mut());
    check(unsafe { FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob.0) })?;
    if blob.0.is_null() {
        return Err("WFP app id unavailable".into());
    }
    let blob = unsafe { &*blob.0 };
    Ok(unsafe { std::slice::from_raw_parts(blob.data, blob.size as usize) }.to_vec())
}
fn read_condition(c: &FWPM_FILTER_CONDITION0, app: &[u8]) -> Condition {
    let value = &c.conditionValue;
    let (key, kind, equal) = (&c.fieldKey, value.r#type, c.matchType == FWP_MATCH_EQUAL);
    unsafe {
        if same(key, &FWPM_CONDITION_FLAGS)
            && c.matchType == FWP_MATCH_FLAGS_ALL_SET
            && kind == FWP_UINT32
            && value.Anonymous.uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK
        {
            Condition::Loopback
        } else if same(key, &FWPM_CONDITION_IP_LOCAL_INTERFACE)
            && equal
            && kind == FWP_UINT64
            && !value.Anonymous.uint64.is_null()
        {
            Condition::LocalInterface(*value.Anonymous.uint64)
        } else if same(key, &FWPM_CONDITION_IP_REMOTE_ADDRESS) && equal && kind == FWP_UINT32 {
            Condition::RemoteAddress(value.Anonymous.uint32)
        } else if same(key, &FWPM_CONDITION_ALE_APP_ID)
            && equal
            && kind == FWP_BYTE_BLOB_TYPE
            && !value.Anonymous.byteBlob.is_null()
            && {
                let blob = &*value.Anonymous.byteBlob;
                !blob.data.is_null()
                    && std::slice::from_raw_parts(blob.data, blob.size as usize) == app
            }
        {
            Condition::AppId
        } else if same(key, &FWPM_CONDITION_IP_PROTOCOL) && equal && kind == FWP_UINT8 {
            Condition::Protocol(value.Anonymous.uint8)
        } else if same(key, &FWPM_CONDITION_IP_REMOTE_PORT) && equal && kind == FWP_UINT16 {
            Condition::RemotePort(value.Anonymous.uint16)
        } else if same(key, &FWPM_CONDITION_IP_REMOTE_PORT)
            && c.matchType == FWP_MATCH_RANGE
            && kind == FWP_RANGE_TYPE
            && !value.Anonymous.rangeValue.is_null()
            && (*value.Anonymous.rangeValue).valueLow.r#type == FWP_UINT16
            && (*value.Anonymous.rangeValue).valueHigh.r#type == FWP_UINT16
        {
            let range = &*value.Anonymous.rangeValue;
            Condition::RemotePorts(
                range.valueLow.Anonymous.uint16,
                range.valueHigh.Anonymous.uint16,
            )
        } else if same(key, &FWPM_CONDITION_IP_LOCAL_PORT) && equal && kind == FWP_UINT16 {
            Condition::LocalPort(value.Anonymous.uint16)
        } else {
            Condition::Other
        }
    }
}
/// Read-only: every filter of the full-tunnel provider and every filter of
/// any provider in its sublayer, as policy data. None when the provider or
/// its sublayer is gone. Filters the service may not enumerate are not seen.
pub fn read_back(app: &[u8]) -> Result<Option<Vec<Spec>>, String> {
    if !active()? {
        return Ok(None);
    }
    let engine = Engine::open()?;
    let mut sublayer = ptr::null_mut();
    let code = unsafe { FwpmSubLayerGetByKey0(engine.0, &SUBLAYER, &mut sublayer) };
    if code == 0x80320007 {
        return Ok(None); // FWP_E_SUBLAYER_NOT_FOUND
    }
    check(code)?;
    unsafe { FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast()) };
    // Bounds on what one read-back walks and keeps; beyond them it is Unknown.
    const SCANNED: usize = 1 << 16;
    const KEPT: usize = 4096;
    let mut scanned = 0usize;
    let mut specs = Vec::new();
    for layer in [
        Layer::ConnectV4,
        Layer::ConnectV6,
        Layer::PacketV4,
        Layer::PacketV6,
        Layer::ForwardV4,
        Layer::ForwardV6,
    ] {
        let template = FWPM_FILTER_ENUM_TEMPLATE0 {
            layerKey: layer_key(layer),
            // All providers: a template cannot select a sublayer.
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
                scanned += count as usize;
                if count > 0 {
                    for filter in unsafe { std::slice::from_raw_parts(entries, count as usize) } {
                        let filter = unsafe { &**filter };
                        let permit = filter.action.r#type == FWP_ACTION_PERMIT;
                        let read = wfp::classify(
                            !filter.providerKey.is_null()
                                && same(unsafe { &*filter.providerKey }, &PROVIDER),
                            same(&filter.subLayerKey, &SUBLAYER),
                            permit || filter.action.r#type == FWP_ACTION_BLOCK,
                        );
                        if read == wfp::Read::Skip {
                            continue;
                        }
                        let mut conditions: Vec<_> = if filter.numFilterConditions == 0 {
                            vec![]
                        } else {
                            unsafe {
                                std::slice::from_raw_parts(
                                    filter.filterCondition,
                                    filter.numFilterConditions as usize,
                                )
                            }
                            .iter()
                            .map(|c| read_condition(c, app))
                            .collect()
                        };
                        if read == wfp::Read::Foreign {
                            conditions.push(Condition::Other);
                        }
                        specs.push(Spec {
                            layer,
                            boottime: filter.flags & FWPM_FILTER_FLAG_BOOTTIME != 0,
                            permit,
                            conditions,
                        });
                    }
                }
                if !entries.is_null() {
                    unsafe {
                        FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast())
                    };
                }
                if scanned > SCANNED || specs.len() > KEPT {
                    return Err("WFP read-back too large".into());
                }
                if count == 0 {
                    break;
                }
            }
            Ok(())
        })();
        unsafe { FwpmFilterDestroyEnumHandle0(engine.0, enumeration) };
        result?;
    }
    Ok(Some(specs))
}
/// Now as a FILETIME (100 ns since 1601), the clock of WFP net events.
pub fn filetime() -> u64 {
    let unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    116_444_736_000_000_000 + (unix.as_nanos() / 100) as u64
}
/// Read-only: classify-drop net events since `since` for UDP to `port`, each
/// marked whether our own outbound block dropped it. One engine and one
/// enumeration serve every pending datagram of a round. BFE keeps these
/// without any audit policy; nothing is enabled or changed here.
pub fn drops(port: u16, since: u64) -> Result<Vec<wfp::Drop>, String> {
    let engine = Engine::open()?;
    let time = |t: u64| windows_sys::Win32::Foundation::FILETIME {
        dwLowDateTime: t as u32,
        dwHighDateTime: (t >> 32) as u32,
    };
    let mut conditions = [
        condition(
            FWPM_CONDITION_IP_PROTOCOL,
            FWP_UINT8,
            FWP_CONDITION_VALUE0_0 { uint8: 17 },
        ),
        condition(
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_UINT16,
            FWP_CONDITION_VALUE0_0 { uint16: port },
        ),
    ];
    let template = FWPM_NET_EVENT_ENUM_TEMPLATE0 {
        startTime: time(since),
        endTime: time(filetime() + 600_000_000),
        numFilterConditions: conditions.len() as u32,
        filterCondition: conditions.as_mut_ptr(),
    };
    let mut enumeration = ptr::null_mut();
    check(unsafe { FwpmNetEventCreateEnumHandle0(engine.0, &template, &mut enumeration) })?;
    let mut owners: Vec<(u64, bool)> = Vec::new();
    let mut found = Vec::new();
    let result: Result<(), String> = (|| {
        // The window is a second or two of one host's drops; bound it anyway.
        for _ in 0..16 {
            let mut entries = ptr::null_mut();
            let mut count = 0;
            check(unsafe {
                FwpmNetEventEnum0(engine.0, enumeration, 256, &mut entries, &mut count)
            })?;
            if count > 0 {
                for event in unsafe { std::slice::from_raw_parts(entries, count as usize) } {
                    let event = unsafe { &**event };
                    if event.r#type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP {
                        continue;
                    }
                    let drop = unsafe { event.Anonymous.classifyDrop };
                    if drop.is_null() {
                        continue;
                    }
                    let id = unsafe { (*drop).filterId };
                    let ours = match owners.iter().find(|(known, _)| *known == id) {
                        Some(&(_, ours)) => ours,
                        None => {
                            let ours = own_block(&engine, id);
                            owners.push((id, ours));
                            ours
                        }
                    };
                    found.push(reduce(&event.header, ours));
                }
            }
            if !entries.is_null() {
                unsafe { FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_NET_EVENT0).cast()) };
            }
            if count == 0 {
                return Ok(());
            }
        }
        Err("WFP net events too many".into())
    })();
    unsafe { FwpmNetEventDestroyEnumHandle0(engine.0, enumeration) };
    result.map(|()| found)
}
/// Read-only: whether BFE collects net events at all. Policy or another
/// vendor may turn collection off; then no drop event will ever appear.
pub fn net_events() -> Option<bool> {
    let engine = Engine::open().ok()?;
    let mut value: *mut FWP_VALUE0 = ptr::null_mut();
    if unsafe { FwpmEngineGetOption0(engine.0, FWPM_ENGINE_COLLECT_NET_EVENTS, &mut value) } != 0
        || value.is_null()
    {
        return None;
    }
    let v = unsafe { &*value };
    let collects = (v.r#type == FWP_UINT32).then(|| unsafe { v.Anonymous.uint32 } != 0);
    unsafe { FwpmFreeMemory0((&mut value as *mut *mut FWP_VALUE0).cast()) };
    collects
}
fn reduce(header: &FWPM_NET_EVENT_HEADER0, ours: bool) -> wfp::Drop {
    let set = |flag| header.flags & flag != 0;
    let remote = match (
        set(FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET) && set(FWPM_NET_EVENT_FLAG_IP_VERSION_SET),
        header.ipVersion,
    ) {
        (true, FWP_IP_VERSION_V4) => {
            Some(std::net::IpAddr::from(std::net::Ipv4Addr::from(unsafe {
                header.Anonymous2.remoteAddrV4
            })))
        }
        (true, FWP_IP_VERSION_V6) => Some(std::net::IpAddr::from(unsafe {
            header.Anonymous2.remoteAddrV6.byteArray16
        })),
        _ => None,
    };
    let at = &header.timeStamp;
    wfp::Drop {
        at: u64::from(at.dwHighDateTime) << 32 | u64::from(at.dwLowDateTime),
        protocol: set(FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET).then_some(header.ipProtocol),
        local_port: set(FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET).then_some(header.localPort),
        remote,
        remote_port: set(FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET).then_some(header.remotePort),
        ours,
    }
}
/// A plain block of our provider in our sublayer at an outbound layer the
/// probe datagram crosses. A filter gone since the event is not ours.
fn own_block(engine: &Engine, id: u64) -> bool {
    let mut filter = ptr::null_mut();
    if unsafe { FwpmFilterGetById0(engine.0, id, &mut filter) } != 0 || filter.is_null() {
        return false;
    }
    let f = unsafe { &*filter };
    let ours = !f.providerKey.is_null()
        && same(unsafe { &*f.providerKey }, &PROVIDER)
        && same(&f.subLayerKey, &SUBLAYER)
        && f.action.r#type == FWP_ACTION_BLOCK
        && [
            Layer::ConnectV4,
            Layer::ConnectV6,
            Layer::PacketV4,
            Layer::PacketV6,
        ]
        .iter()
        .any(|&layer| same(&f.layerKey, &layer_key(layer)));
    unsafe { FwpmFreeMemory0((&mut filter as *mut *mut FWPM_FILTER0).cast()) };
    ours
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
