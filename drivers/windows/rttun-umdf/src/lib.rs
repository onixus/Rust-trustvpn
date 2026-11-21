//! UMDF entry for the R-TrustTunnel adapter.
//!
//! This binary is the driver host. It does not load `wintun.dll`. After the WDF
//! device exists it calls the WDK 2.5 user-mode NetAdapter
//! (`NetAdapterInitAllocate`, datapath callbacks, `NetAdapterCreate`,
//! `NetAdapterStart`). It also creates the DOS device `\DosDevices\RTrustTunnel`,
//! which is the handle the service opens. Queue advance does not move packets
//! yet. `NET_FRAGMENT` in this WDK is only lengths and an offset. The bytes
//! are in `NET_FRAGMENT_VIRTUAL_ADDRESS`, which this crate does not query, so
//! it does not copy or deliver a packet.

use wdk_sys::{
    call_unsafe_wdf_function_binding, NTSTATUS, PCUNICODE_STRING, PDRIVER_OBJECT, ULONG,
    WDFDEVICE, WDFDEVICE_INIT, WDFDRIVER, WDF_DRIVER_CONFIG, WDF_NO_HANDLE,
    WDF_NO_OBJECT_ATTRIBUTES,
};

#[cfg_attr(not(test), unsafe(export_name = "DriverEntry"))]
pub unsafe extern "system" fn driver_entry(
    driver: PDRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    wdk_panic::install_panic_hook();
    let mut config = WDF_DRIVER_CONFIG {
        Size: core::mem::size_of::<WDF_DRIVER_CONFIG>() as ULONG,
        EvtDriverDeviceAdd: Some(device_add),
        ..WDF_DRIVER_CONFIG::default()
    };
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDriverCreate,
            driver,
            registry_path,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut config,
            WDF_NO_HANDLE.cast::<WDFDRIVER>(),
        )
    }
}

extern "C" fn device_add(_driver: WDFDRIVER, mut device_init: *mut WDFDEVICE_INIT) -> NTSTATUS {
    let mut device: WDFDEVICE = WDF_NO_HANDLE.cast();
    let created = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfDeviceCreate,
            &mut device_init,
            WDF_NO_OBJECT_ATTRIBUTES,
            &mut device,
        )
    };
    if created < 0 {
        return created;
    }
    let linked = unsafe { create_service_link(device) };
    if linked < 0 {
        return linked;
    }
    let queued = unsafe { create_read_queue(device) };
    if queued < 0 {
        return queued;
    }
    // Indexes from um\netcx\umdf\adapter\2.5\netfuncenum.h. The calls match
    // the inline wrappers: the driver globals pointer is the first argument.
    unsafe { start_net_adapter(device) }
}

unsafe fn create_service_link(device: WDFDEVICE) -> NTSTATUS {
    let mut name: [u16; 25] = [
        b'\\' as u16, b'D' as u16, b'o' as u16, b's' as u16, b'D' as u16, b'e' as u16, b'v' as u16,
        b'i' as u16, b'c' as u16, b'e' as u16, b's' as u16, b'\\' as u16, b'R' as u16, b'T' as u16,
        b'r' as u16, b'u' as u16, b's' as u16, b't' as u16, b'T' as u16, b'u' as u16, b'n' as u16,
        b'n' as u16, b'e' as u16, b'l' as u16, 0,
    ];
    let link = wdk_sys::UNICODE_STRING {
        Length: 48,
        MaximumLength: 50,
        Buffer: name.as_mut_ptr(),
    };
    unsafe {
        call_unsafe_wdf_function_binding!(WdfDeviceCreateSymbolicLink, device, &link)
    }
}

unsafe extern "C" fn on_read(
    _queue: wdk_sys::WDFQUEUE,
    request: wdk_sys::WDFREQUEST,
    _length: usize,
) {
    let packet = held().lock().ok().and_then(|mut slot| slot.take());
    let Some(packet) = packet else {
        let _ = unsafe {
            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                wdk_sys::STATUS_NO_MORE_ENTRIES,
                0
            )
        };
        return;
    };
    let mut buffer = core::ptr::null_mut();
    let status = unsafe {
        call_unsafe_wdf_function_binding!(
            WdfRequestRetrieveOutputBuffer,
            request,
            packet.len as usize,
            &mut buffer,
            core::ptr::null_mut::<usize>()
        )
    };
    if status < 0 || buffer.is_null() {
        let _ = unsafe {
            call_unsafe_wdf_function_binding!(
                WdfRequestCompleteWithInformation,
                request,
                status,
                0
            )
        };
        return;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(packet.bytes.as_ptr(), buffer.cast(), packet.len as usize);
        let _ = call_unsafe_wdf_function_binding!(
            WdfRequestCompleteWithInformation,
            request,
            0,
            packet.len as u64
        );
    }
}

unsafe fn create_read_queue(device: WDFDEVICE) -> NTSTATUS {
    let mut config = wdk_sys::WDF_IO_QUEUE_CONFIG {
        Size: core::mem::size_of::<wdk_sys::WDF_IO_QUEUE_CONFIG>() as u32,
        DispatchType: 1,
        PowerManaged: 2,
        DefaultQueue: 1,
        EvtIoRead: Some(on_read),
        ..Default::default()
    };
    let mut queue = core::ptr::null_mut();
    unsafe {
        call_unsafe_wdf_function_binding!(
            WdfIoQueueCreate,
            device,
            &mut config,
            WDF_NO_OBJECT_ATTRIBUTES,
            &raw mut queue
        )
    }
}

const INIT_ALLOCATE: usize = 0;
const SET_DATAPATH: usize = 2;
const CREATE: usize = 3;
const START: usize = 4;
const SET_MTU: usize = 7;
const RX_QUEUE_CREATE: usize = 49;
const TX_QUEUE_CREATE: usize = 54;
const TX_RING_COLLECTION: usize = 57;
const TX_EXTENSION: usize = 58;

#[link(name = "netadaptercxstub", kind = "static")]
unsafe extern "C" {
    static NetFunctions: [*mut core::ffi::c_void; 113];
    static mut NetDriverGlobals: *mut core::ffi::c_void;
}

unsafe fn start_net_adapter(device: WDFDEVICE) -> NTSTATUS {
    type SetDatapath = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *const DatapathCallbacks,
    );
    type Allocate = unsafe extern "system" fn(*mut core::ffi::c_void, WDFDEVICE) -> *mut core::ffi::c_void;
    type Create = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut *mut core::ffi::c_void,
    ) -> NTSTATUS;
    type Start = unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> NTSTATUS;
    type SetMtu = unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void, ULONG);

    let globals = unsafe { NetDriverGlobals };
    let table = &raw const NetFunctions;
    let allocate: Allocate = unsafe { core::mem::transmute((*table)[INIT_ALLOCATE]) };
    let init = unsafe { allocate(globals, device) };
    if init.is_null() {
        return wdk_sys::STATUS_UNSUCCESSFUL;
    }
    let callbacks = DatapathCallbacks {
        size: core::mem::size_of::<DatapathCallbacks>() as u32,
        tx: Some(create_tx_queue),
        rx: Some(create_rx_queue),
    };
    let set_datapath: SetDatapath = unsafe { core::mem::transmute((*table)[SET_DATAPATH]) };
    unsafe { set_datapath(globals, init, &callbacks) };
    let mut adapter = core::ptr::null_mut();
    let create: Create = unsafe { core::mem::transmute((*table)[CREATE]) };
    let created = unsafe { create(globals, init, core::ptr::null_mut(), &mut adapter) };
    if created < 0 || adapter.is_null() {
        return created;
    }
    let set_mtu: SetMtu = unsafe { core::mem::transmute((*table)[SET_MTU]) };
    unsafe { set_mtu(globals, adapter, 1500) };
    let start: Start = unsafe { core::mem::transmute((*table)[START]) };
    unsafe { start(globals, adapter) }
}

#[repr(C)]
struct DatapathCallbacks {
    size: u32,
    tx: Option<unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> NTSTATUS>,
    rx: Option<unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> NTSTATUS>,
}

unsafe extern "system" fn create_tx_queue(
    _adapter: *mut core::ffi::c_void,
    init: *mut core::ffi::c_void,
) -> NTSTATUS {
    unsafe { create_queue(init, TX_QUEUE_CREATE) }
}

unsafe extern "system" fn create_rx_queue(
    _adapter: *mut core::ffi::c_void,
    init: *mut core::ffi::c_void,
) -> NTSTATUS {
    unsafe { create_queue(init, RX_QUEUE_CREATE) }
}

unsafe extern "system" fn queue_advance(queue: *mut core::ffi::c_void) {
    // Index 57 returns a ring collection, not a ring. Packet and fragment
    // rings are slots 0 and 1. Bytes are not copied: the virtual-address
    // extension has to be queried at passive level before advance runs.
    type Rings = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
    ) -> *const RingCollection;
    let globals = unsafe { NetDriverGlobals };
    let table = &raw const NetFunctions;
    let rings: Rings = unsafe { core::mem::transmute((*table)[TX_RING_COLLECTION]) };
    let collection = unsafe { rings(globals, queue) };
    if collection.is_null() {
        return;
    }
    let collection = unsafe { &*collection };
    let packet = collection.rings[0];
    if packet.is_null() {
        return;
    }
    let packet = unsafe { &*packet };
    if packet.begin_index == packet.end_index {
        return;
    }
    let Some(extension) = extension().lock().ok().and_then(|guard| *guard) else {
        return;
    };
    if !extension.enabled || extension.base == 0 || extension.stride < 8 {
        return;
    }
    let fragment = (unsafe { &*collection }).rings[1];
    if fragment.is_null() {
        return;
    }
    copy_one(packet, unsafe { &*fragment }, &extension);
}

fn copy_one(packet_ring: &NetRing, fragment_ring: &NetRing, extension: &SharedExtension) {
    if packet_ring.element_stride < 4 || fragment_ring.element_stride < 8 {
        return;
    }
    let index = packet_ring.begin_index & packet_ring.element_index_mask;
    let packet = unsafe {
        packet_ring.buffer().add(index as usize * packet_ring.element_stride as usize)
    };
    let fragment_index = unsafe { packet.cast::<u32>().read_unaligned() } as usize;
    if fragment_index >= fragment_ring.number_of_elements as usize {
        return;
    }
    let fragment = unsafe {
        fragment_ring
            .buffer()
            .add(fragment_index * fragment_ring.element_stride as usize)
            .cast::<u64>()
            .read_unaligned()
    };
    let len = (fragment & 0x03ff_ffff) as usize;
    let offset = ((fragment >> 52) & 0x3ff) as usize;
    if !(20..=2048).contains(&len) {
        return;
    }
    let address = unsafe {
        (extension.base as *const u8)
            .add(extension.stride * fragment_index)
            .cast::<*mut u8>()
            .read_unaligned()
    };
    if address.is_null() {
        return;
    }
    let source = unsafe { address.add(offset) };
    let mut bytes = [0; 2048];
    unsafe { source.copy_to_nonoverlapping(bytes.as_mut_ptr(), len) };
    if bytes[0] >> 4 != 4 && bytes[0] >> 4 != 6 {
        return;
    }
    if let Ok(mut slot) = held().lock() {
        *slot = Some(HeldPacket {
            len: len as u16,
            bytes,
        });
    }
}

unsafe extern "system" fn queue_notify(_queue: *mut core::ffi::c_void, _enabled: u8) {}

unsafe extern "system" fn queue_cancel(_queue: *mut core::ffi::c_void) {
    // A cancelled queue must not keep a packet for a later read.
    if let Ok(mut slot) = held().lock() {
        *slot = None;
    }
}

#[repr(C)]
struct RingCollection {
    rings: [*const NetRing; 3],
}

#[repr(C)]
struct NetRing {
    os_reserved1: u16,
    element_stride: u16,
    number_of_elements: u32,
    element_index_mask: u32,
    end_index: u32,
    reserved: [u64; 4],
    begin_index: u32,
    next_index: u32,
    scratch: *mut core::ffi::c_void,
    buffer: [u8; 0],
}

impl NetRing {
    fn buffer(&self) -> *const u8 {
        self.buffer.as_ptr()
    }
}

#[repr(C)]
struct QueueConfig {
    size: u32,
    start: *mut core::ffi::c_void,
    stop: *mut core::ffi::c_void,
    advance: Option<unsafe extern "system" fn(*mut core::ffi::c_void)>,
    notify: Option<unsafe extern "system" fn(*mut core::ffi::c_void, u8)>,
    cancel: Option<unsafe extern "system" fn(*mut core::ffi::c_void)>,
    execution: *mut core::ffi::c_void,
}

unsafe fn create_queue(init: *mut core::ffi::c_void, index: usize) -> NTSTATUS {
    type CreateQueue = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *const QueueConfig,
        *mut *mut core::ffi::c_void,
    ) -> NTSTATUS;
    let globals = unsafe { NetDriverGlobals };
    let table = &raw const NetFunctions;
    let create: CreateQueue = unsafe { core::mem::transmute((*table)[index]) };
    let config = QueueConfig {
        size: core::mem::size_of::<QueueConfig>() as u32,
        start: core::ptr::null_mut(),
        stop: core::ptr::null_mut(),
        advance: Some(queue_advance),
        notify: Some(queue_notify),
        cancel: Some(queue_cancel),
        execution: core::ptr::null_mut(),
    };
    let mut queue = core::ptr::null_mut();
    let created = unsafe { create(globals, init, core::ptr::null_mut(), &config, &mut queue) };
    if created >= 0 && index == TX_QUEUE_CREATE && !queue.is_null() {
        query_fragment_address(queue);
    }
    created
}

// Consumed when a service read is completed. That queue is not wired yet.
#[allow(dead_code)]
struct HeldPacket {
    len: u16,
    bytes: [u8; 2048],
}

fn held() -> &'static std::sync::Mutex<Option<HeldPacket>> {
    static HELD: std::sync::OnceLock<std::sync::Mutex<Option<HeldPacket>>> = std::sync::OnceLock::new();
    HELD.get_or_init(|| std::sync::Mutex::new(None))
}

#[derive(Clone, Copy)]
struct SharedExtension {
    base: usize,
    stride: usize,
    enabled: bool,
}

unsafe impl Send for SharedExtension {}

fn extension() -> &'static std::sync::Mutex<Option<SharedExtension>> {
    static EXTENSION: std::sync::OnceLock<std::sync::Mutex<Option<SharedExtension>>> =
        std::sync::OnceLock::new();
    EXTENSION.get_or_init(|| std::sync::Mutex::new(None))
}

#[repr(C)]
struct ExtensionQuery {
    size: u32,
    _pad: u32,
    name: *const u16,
    version: u32,
    kind: u32,
}

#[repr(C)]
struct Extension {
    reserved: [*mut core::ffi::c_void; 4],
    enabled: u64,
}

fn query_fragment_address(queue: *mut core::ffi::c_void) {
    type GetExtension = unsafe extern "system" fn(
        *mut core::ffi::c_void,
        *mut core::ffi::c_void,
        *const ExtensionQuery,
        *mut Extension,
    );
    let name: [u16; 28] = [
        b'm' as u16, b's' as u16, b'_' as u16, b'f' as u16, b'r' as u16, b'a' as u16, b'g' as u16,
        b'm' as u16, b'e' as u16, b'n' as u16, b't' as u16, b'_' as u16, b'v' as u16, b'i' as u16,
        b'r' as u16, b't' as u16, b'u' as u16, b'a' as u16, b'l' as u16, b'a' as u16, b'd' as u16,
        b'd' as u16, b'r' as u16, b'e' as u16, b's' as u16, b's' as u16, 0, 0,
    ];
    let query = ExtensionQuery {
        size: core::mem::size_of::<ExtensionQuery>() as u32,
        _pad: 0,
        name: name.as_ptr(),
        version: 1,
        kind: 2,
    };
    let mut found = Extension {
        reserved: [core::ptr::null_mut(); 4],
        enabled: 0,
    };
    let globals = unsafe { NetDriverGlobals };
    let table = &raw const NetFunctions;
    let get: GetExtension = unsafe { core::mem::transmute((*table)[TX_EXTENSION]) };
    unsafe { get(globals, queue, &query, &mut found) };
    if let Ok(mut slot) = extension().lock() {
        *slot = Some(SharedExtension {
            base: found.reserved[0] as usize,
            stride: found.reserved[1] as usize,
            enabled: found.enabled != 0,
        });
    }
}
