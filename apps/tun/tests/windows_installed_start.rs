//! Opt-in installed-service acceptance. Never invoked by ordinary CI.
//! Read-only snapshots do NOT prove absence of transient changes or leaks.
#![cfg(windows)]

use rtrust_control::{Capabilities, Command, Request, Response, Selection, State, VERSION};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf, ptr, time::Duration};
use windows_sys::{
    core::GUID,
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::{IpHelper::*, WindowsFilteringPlatform::*},
        Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET},
    },
};

// Keep identical to apps/tun/src/windows/firewall.rs. The orchestrator also
// checks the frozen source before it permits a service swap.
const FULL: GUID = GUID::from_u128(0xd358e5b4_9891_4b22_b071_d95fef406791);
const BOOT: GUID = GUID::from_u128(0x9b93baf4_7dd4_47b6_8b24_32497ba29261);
const PROVIDER_NOT_FOUND: u32 = 0x80320005;

fn require(ok: bool) {
    assert!(ok, "FAIL: installed Start acceptance");
}
fn checked<T, E>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|_| panic!("FAIL: installed Start acceptance"))
}
fn initialize() -> (String, PathBuf) {
    std::panic::set_hook(Box::new(|_| eprintln!("FAIL: installed Start acceptance")));
    let nonce = env::var("RTRUST_INSTALLED_ACCEPTANCE").unwrap_or_else(|_| {
        eprintln!("NOT RUN: installed authorization required");
        panic!("NOT RUN: installed authorization required")
    });
    require(nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    let stage = PathBuf::from(checked(env::var("RTRUST_INSTALLED_STAGE")));
    require(stage.is_absolute());
    require(
        stage
            .file_name()
            .is_some_and(|n| n == format!("RTrustAcceptance-{nonce}").as_str()),
    );
    require(checked(fs::symlink_metadata(&stage)).is_dir());
    (nonce, stage)
}
fn digest(mut rows: Vec<String>) -> u64 {
    rows.sort_unstable();
    rows.into_iter()
        .flat_map(|s| s.into_bytes().into_iter().chain([0]))
        .fold(0xcbf29ce484222325, |h, byte| {
            (h ^ u64::from(byte)).wrapping_mul(0x100000001b3)
        })
}
struct Mib<T>(*mut T);
impl<T> Drop for Mib<T> {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0.cast()) };
    }
}
struct Engine(HANDLE);
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe { FwpmEngineClose0(self.0) };
    }
}
struct Enumeration<'a>(&'a Engine, HANDLE);
impl Drop for Enumeration<'_> {
    fn drop(&mut self) {
        unsafe { FwpmFilterDestroyEnumHandle0(self.0 .0, self.1) };
    }
}
fn provider(engine: &Engine, mut key: GUID) -> (bool, u32) {
    let mut p = ptr::null_mut();
    let code = unsafe { FwpmProviderGetByKey0(engine.0, &key, &mut p) };
    require(code == 0 || code == PROVIDER_NOT_FOUND);
    let present = code == 0;
    if !p.is_null() {
        unsafe { FwpmFreeMemory0((&mut p as *mut *mut FWPM_PROVIDER0).cast()) };
    }
    // Never enumerate foreign providers or serialize any filter contents.
    let template = FWPM_FILTER_ENUM_TEMPLATE0 {
        providerKey: &mut key,
        flags: FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED,
        actionMask: u32::MAX,
        ..Default::default()
    };
    let mut enumeration = ptr::null_mut();
    let code = unsafe { FwpmFilterCreateEnumHandle0(engine.0, &template, &mut enumeration) };
    if !present && code == PROVIDER_NOT_FOUND {
        return (false, 0);
    }
    require(code == 0 && !enumeration.is_null());
    let enumeration = Enumeration(engine, enumeration);
    let mut total = 0u32;
    for _ in 0..1024 {
        let mut entries = ptr::null_mut();
        let mut count = 0;
        let code =
            unsafe { FwpmFilterEnum0(engine.0, enumeration.1, 256, &mut entries, &mut count) };
        if code != 0 {
            if !entries.is_null() {
                unsafe { FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast()) };
            }
            require(false);
        }
        require(count <= 256);
        if !entries.is_null() {
            unsafe { FwpmFreeMemory0((&mut entries as *mut *mut *mut FWPM_FILTER0).cast()) };
        }
        total = checked(total.checked_add(count).ok_or(()));
        if count < 256 {
            return (present, total);
        }
    }
    panic!("FAIL: bounded own-provider enumeration");
}
fn address(value: &SOCKADDR_INET) -> String {
    unsafe {
        match value.si_family {
            AF_INET => format!("4:{:?}", value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()),
            AF_INET6 => format!(
                "6:{:?}:{}",
                value.Ipv6.sin6_addr.u.Byte, value.Ipv6.Anonymous.sin6_scope_id
            ),
            _ => panic!("FAIL: route address family"),
        }
    }
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
struct Snapshot {
    routes_v4: u64,
    routes_v6: u64,
    adapters: u64,
    alias_count: u32,
    alias_up: bool,
    alias_routes: u32,
    alias_default: bool,
    full_present: bool,
    full_filters: u32,
    boot_present: bool,
    boot_filters: u32,
}
fn snapshot() -> Snapshot {
    let mut interfaces = ptr::null_mut();
    require(unsafe { GetIfTable2(&mut interfaces) } == 0 && !interfaces.is_null());
    let interfaces = Mib(interfaces);
    let table = unsafe { &*interfaces.0 };
    require(table.NumEntries <= 4096);
    let rows =
        unsafe { std::slice::from_raw_parts(table.Table.as_ptr(), table.NumEntries as usize) };
    let mut aliases = Vec::new();
    let mut adapter_rows = Vec::new();
    let mut alias_up = false;
    for row in rows {
        let length = row
            .Alias
            .iter()
            .position(|&x| x == 0)
            .unwrap_or(row.Alias.len());
        if String::from_utf16_lossy(&row.Alias[..length]) == "RTrustTunnel" {
            aliases.push(row.InterfaceIndex);
            alias_up |= row.OperStatus == 1;
        }
        // Deliberately exclude traffic counters, link-speed estimates and ages.
        adapter_rows.push(format!(
            "{}:{}:{}:{}:{:?}",
            row.InterfaceIndex,
            row.OperStatus,
            row.AdminStatus,
            row.Type,
            &row.Alias[..length]
        ));
    }
    let mut route_hashes = Vec::new();
    let mut alias_routes = 0u32;
    let mut alias_default = false;
    for family in [AF_INET, AF_INET6] {
        let mut table = ptr::null_mut();
        require(unsafe { GetIpForwardTable2(family, &mut table) } == 0 && !table.is_null());
        let table = Mib(table);
        let header = unsafe { &*table.0 };
        require(header.NumEntries <= 65536);
        let rows = unsafe {
            std::slice::from_raw_parts(header.Table.as_ptr(), header.NumEntries as usize)
        };
        let mut routes = Vec::new();
        for row in rows {
            let prefix = row.DestinationPrefix.PrefixLength;
            if aliases.contains(&row.InterfaceIndex) {
                alias_routes += 1;
                alias_default |= prefix <= 1;
            }
            routes.push(format!(
                "{}:{}/{}:{}:{}:{}:{}:{}:{}",
                row.InterfaceIndex,
                address(&row.DestinationPrefix.Prefix),
                prefix,
                address(&row.NextHop),
                row.Metric,
                row.Protocol,
                row.Loopback,
                row.Publish,
                row.Origin
            ));
        }
        route_hashes.push(digest(routes));
    }
    let mut engine = ptr::null_mut();
    require(
        unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), ptr::null(), &mut engine) } == 0,
    );
    let engine = Engine(engine);
    let (full_present, full_filters) = provider(&engine, FULL);
    let (boot_present, boot_filters) = provider(&engine, BOOT);
    Snapshot {
        routes_v4: route_hashes[0],
        routes_v6: route_hashes[1],
        adapters: digest(adapter_rows),
        alias_count: aliases.len() as u32,
        alias_up,
        alias_routes,
        alias_default,
        full_present,
        full_filters,
        boot_present,
        boot_filters,
    }
}
fn idle(value: &Snapshot) {
    require(
        value.alias_count <= 1
            && !value.alias_up
            && value.alias_routes == 0
            && !value.alias_default,
    );
    require(
        !value.full_present
            && !value.boot_present
            && value.full_filters == 0
            && value.boot_filters == 0,
    );
}
async fn request(command: Command) -> Response {
    checked(
        tokio::time::timeout(Duration::from_secs(10), async {
            // This public connector authenticates the server's actual SCM PID and SYSTEM token.
            let mut pipe = rtrust_control::windows::connect()?;
            rtrust_control::write(
                &mut pipe,
                &Request {
                    version: VERSION,
                    command,
                },
            )
            .await?;
            rtrust_control::read::<Response>(&mut pipe).await
        })
        .await,
    )
    .unwrap_or_else(|_| panic!("FAIL: authenticated installed IPC"))
}
async fn always_off() {
    let response = request(Command::AlwaysOnStatus { viewed: false }).await;
    require(response.version == VERSION && response.always_on == Some(false));
    require(response.state == State::Idle && response.owner.is_none());
}
fn runtime() -> tokio::runtime::Runtime {
    checked(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build(),
    )
}
#[test]
#[ignore = "explicit installed-service authorization and protected staging required"]
fn wfp_net_snapshot() {
    let (_, stage) = initialize();
    runtime().block_on(always_off());
    let value = snapshot();
    idle(&value);
    let path = stage.join("network-baseline.json");
    match checked(env::var("RTRUST_INSTALLED_SNAPSHOT")).as_str() {
        "capture" => {
            use std::io::Write;
            let mut out = checked(
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path),
            );
            checked(out.write_all(&checked(serde_json::to_vec(&value))));
            checked(out.sync_all());
        }
        "compare" => {
            let bytes = checked(fs::read(path));
            require(bytes.len() <= 4096);
            let baseline: Snapshot = checked(serde_json::from_slice(&bytes));
            require(value == baseline);
        }
        _ => panic!("NOT RUN: snapshot mode required"),
    }
    println!("PASS: INSTALLED_IDLE_NETWORK_EQUAL");
}
#[test]
#[ignore = "real installed Start failure; only explicitly authorized orchestrator"]
fn start_validation() {
    let (nonce, stage) = initialize();
    runtime().block_on(async {
        always_off().await;
        let capabilities = request(Command::Capabilities).await;
        require(
            capabilities.version == VERSION
                && capabilities.state == State::Idle
                && capabilities.capabilities == Capabilities::current(),
        );
        println!("PASS: B_CAPS_MATCH");
        let before = snapshot();
        idle(&before);
        let baseline: Snapshot = checked(serde_json::from_slice(&checked(fs::read(
            stage.join("network-baseline.json"),
        ))));
        require(before == baseline);
        let profile = checked(serde_json::from_value::<rtrust_profile::Profile>(
            serde_json::json!({
                "schema_version": 1, "name": "", "endpoint": {
                    "hostname": format!("canary-{nonce}.invalid"), "addresses": [],
                    "username": format!("canary-{nonce}-u"), "password": ""
                }
            }),
        ));
        let expected = Selection {
            include: vec![],
            exclude: vec![],
            exclude_lan: false,
        };
        let message = expected
            .validate()
            .err()
            .unwrap_or_else(|| panic!("FAIL: empty selection invariant"));
        let reply = request(Command::Start {
            profile: Box::new(profile),
            networks: vec![],
            exclude: vec![],
            exclude_lan: false,
            dns: None,
            fallbacks: vec![],
        })
        .await;
        // A busy lease is never accepted as a validation failure, and produces no record.
        if reply.message == "Служба уже обслуживает подключение" {
            println!("BLOCKED: B_ACTIVE_LEASE");
            panic!("BLOCKED: active lease; no validation record claimed");
        }
        require(
            reply.version == VERSION && reply.state == State::Error && reply.message == message,
        );
        require(
            reply.owner.is_none() && reply.always_on.is_none() && reply.active_profile.is_none(),
        );
        println!("PASS: B_REPLY_ERROR");
        println!("PASS: B_MESSAGE_MATCH");
        println!("PASS: B_NO_OWNER");
        require(snapshot() == before);
        println!("PASS: B_NO_OS_MUTATION");
    });
}
