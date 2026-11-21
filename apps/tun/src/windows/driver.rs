//! Service-side client for the Rttun adapter.
//!
//! The SCM service used to load `wintun.dll`. That load is gone. This module
//! creates one `SWD\Rttun` device, opens `\\.\RTrustTunnel`, and fails if that
//! handle does not speak raw IP. There is no in-memory stand-in and no Wintun
//! fallback. A failure before the recovery journal is written closes only the
//! device this attempt created.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use rttun_proto::{validate, ADAPTER_NAME, ENUMERATOR, HARDWARE_ID, MAX_PACKET};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};

/// A kernel handle owned by this process. Windows exposes it as a pointer,
/// which Rust will not send between threads. The service shares the adapter
/// across the data-plane tasks, so ownership is stated here.
struct OwnedHandle(HANDLE);
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

pub use crate::adapter_package::{parse_signature_status, require_package};

const DEVICE_PATH: &str = "\\\\.\\RTrustTunnel";

pub fn package_dir() -> Result<PathBuf, String> {
    std::env::current_exe()
        .map(|path| path.parent().unwrap_or(Path::new(".")).to_path_buf())
        .map_err(|_| "Service path unavailable".to_owned())
}

pub struct Adapter {
    index: u32,
    software: OwnedHandle,
    io: Mutex<DeviceIo>,
    closed: std::sync::atomic::AtomicBool,
}

struct DeviceIo {
    handle: HANDLE,
    read_event: HANDLE,
    write_event: HANDLE,
    read_pending: bool,
    read_overlapped: windows_sys::Win32::System::IO::OVERLAPPED,
    read_buf: Box<[u8]>,
}
unsafe impl Send for DeviceIo {}

impl Adapter {
    pub fn index(&self) -> u32 {
        self.index
    }

    /// One raw IP packet from the host stack. `WouldBlock` leaves the read
    /// pending, so a later call still receives the same packet. Close cancels
    /// it and does not deliver the cancel as data.
    pub fn pop_from_host(&self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.is_closed() {
            return Err(std::io::Error::other("Rttun adapter closed"));
        }
        if out.len() < 20 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "adapter receive buffer shorter than an IP header",
            ));
        }
        let mut io = self.io.lock().expect("adapter io");
        let already = if io.read_pending {
            false
        } else {
            start_read(&mut io)?
        };
        if !already && !wait_ready(io.read_event)? {
            return Err(std::io::ErrorKind::WouldBlock.into());
        }
        let n = finish_read(&mut io)?;
        validate(&io.read_buf[..n])?;
        out[..n].copy_from_slice(&io.read_buf[..n]);
        Ok(n)
    }

    pub fn push_from_tunnel(&self, packet: &[u8]) -> std::io::Result<()> {
        if self.is_closed() {
            return Err(std::io::Error::other("Rttun adapter closed"));
        }
        validate(packet)?;
        let io = self.io.lock().expect("adapter io");
        write_packet(io.handle, io.write_event, packet)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        self.close();
        let io = self.io.get_mut().expect("adapter io");
        if io.read_pending {
            unsafe {
                windows_sys::Win32::System::IO::CancelIoEx(io.handle, &io.read_overlapped);
            }
        }
        close_handle(io.read_event);
        close_handle(io.write_event);
        close_handle(io.handle);
        if !self.software.0.is_null() {
            unsafe {
                windows_sys::Win32::Devices::Enumeration::Pnp::SwDeviceClose(self.software.0.cast())
            };
        }
    }
}

pub fn create() -> Result<Arc<Adapter>, String> {
    let dir = package_dir()?;
    require_package(&dir)?;
    create_windows(&dir)
}

fn create_windows(dir: &Path) -> Result<Arc<Adapter>, String> {
    verify_catalog(dir)?;
    install_package(dir)?;
    let software = match create_software_device() {
        Ok(handle) => handle,
        Err(error) => return Err(error),
    };
    let index = match interface_index_by_alias(ADAPTER_NAME) {
        Ok(index) => index,
        Err(error) => {
            unsafe { windows_sys::Win32::Devices::Enumeration::Pnp::SwDeviceClose(software.0.cast()) };
            return Err(error);
        }
    };
    let io = match open_packet_device() {
        Ok(io) => io,
        Err(error) => {
            unsafe { windows_sys::Win32::Devices::Enumeration::Pnp::SwDeviceClose(software.0.cast()) };
            return Err(error.to_string());
        }
    };
    Ok(Arc::new(Adapter {
        index,
        software,
        io: Mutex::new(io),
        closed: std::sync::atomic::AtomicBool::new(false),
    }))
}

fn verify_catalog(dir: &Path) -> Result<(), String> {
    let catalog = dir.join("rttun.cat");
    let output = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-AuthenticodeSignature -LiteralPath $args[0] | Select-Object -ExpandProperty Status",
        ])
        .arg(&catalog)
        .output()
        .map_err(|_| "Cannot verify rttun.cat signature".to_owned())?;
    if !output.status.success() {
        return Err("rttun.cat signature check failed".into());
    }
    let status = parse_signature_status(&String::from_utf8_lossy(&output.stdout));
    if !status.trusted() {
        return Err(format!(
            "rttun.cat signature is {status:?}; refusing to install an unsigned or test-signed driver"
        ));
    }
    Ok(())
}

fn install_package(dir: &Path) -> Result<(), String> {
    let inf = dir.join("rttun.inf");
    let status = std::process::Command::new("pnputil.exe")
        .args(["/add-driver", &inf.to_string_lossy(), "/install"])
        .status()
        .map_err(|_| "Cannot register the Rttun driver package".to_owned())?;
    if !status.success() {
        return Err("Rttun driver package was not registered".into());
    }
    Ok(())
}

struct CreateCtx {
    event: OwnedHandle,
    result: AtomicI32,
}

unsafe extern "system" fn on_created(
    _device: windows_sys::Win32::Devices::Enumeration::Pnp::HSWDEVICE,
    result: windows_sys::core::HRESULT,
    context: *const core::ffi::c_void,
    _instance: windows_sys::core::PCWSTR,
) {
    let ctx = unsafe { &*(context as *const CreateCtx) };
    ctx.result.store(result, Ordering::Relaxed);
    unsafe { windows_sys::Win32::System::Threading::SetEvent(ctx.event.0) };
}

fn create_software_device() -> Result<OwnedHandle, String> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Devices::Enumeration::Pnp::{
        SwDeviceCreate, SWDeviceLifetimeHandle, SW_DEVICE_CREATE_INFO,
        SWDeviceCapabilitiesDriverRequired, SWDeviceCapabilitiesSilentInstall,
    };
    let event = OwnedHandle(create_event().map_err(|error| error.to_string())?);
    let ctx = CreateCtx {
        event,
        result: AtomicI32::new(-1),
    };
    let enumerator = wide("Rttun");
    let parent = wide("HTREE\\ROOT\\0");
    let instance = wide(ADAPTER_NAME);
    let description = wide(ADAPTER_NAME);
    // Multi-sz: one hardware id and an extra NUL.
    let mut hardware: Vec<u16> = std::ffi::OsStr::new(HARDWARE_ID)
        .encode_wide()
        .chain([0, 0])
        .collect();
    let info = SW_DEVICE_CREATE_INFO {
        cbSize: std::mem::size_of::<SW_DEVICE_CREATE_INFO>() as u32,
        pszInstanceId: instance.as_ptr(),
        pszzHardwareIds: hardware.as_mut_ptr(),
        CapabilityFlags: (SWDeviceCapabilitiesSilentInstall | SWDeviceCapabilitiesDriverRequired) as u32,
        pszDeviceDescription: description.as_ptr(),
        ..Default::default()
    };
    let mut created = std::ptr::null_mut();
    let hr = unsafe {
        SwDeviceCreate(
            enumerator.as_ptr(),
            parent.as_ptr(),
            &info,
            0,
            std::ptr::null(),
            Some(on_created),
            &ctx as *const CreateCtx as *const _,
            &mut created,
        )
    };
    if hr < 0 {
        close_handle(ctx.event.0);
        return Err(format!("Cannot create Rttun device ({hr})"));
    }
    let waited = unsafe { windows_sys::Win32::System::Threading::WaitForSingleObject(ctx.event.0, 10_000) };
    close_handle(ctx.event.0);
    let result = ctx.result.load(Ordering::Relaxed);
    if waited != windows_sys::Win32::Foundation::WAIT_OBJECT_0 || result < 0 || created.is_null() {
        if !created.is_null() {
            unsafe { windows_sys::Win32::Devices::Enumeration::Pnp::SwDeviceClose(created) };
        }
        return Err(format!(
            "Rttun device was not created under {ENUMERATOR} ({result})"
        ));
    }
    unsafe {
        windows_sys::Win32::Devices::Enumeration::Pnp::SwDeviceSetLifetime(
            created,
            SWDeviceLifetimeHandle,
        )
    };
    Ok(OwnedHandle(created.cast()))
}

fn interface_index_by_alias(alias: &str) -> Result<u32, String> {
    use windows_sys::Win32::NetworkManagement::{
        IpHelper::{ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex},
        Ndis::NET_LUID_LH,
    };
    let wide = wide(alias);
    let mut luid = NET_LUID_LH::default();
    let code = unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) };
    if code != 0 {
        return Err("Rttun interface LUID unavailable".into());
    }
    let mut index = 0u32;
    let code = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
    if code != 0 || index == 0 {
        return Err("Rttun interface index unavailable".into());
    }
    Ok(index)
}

fn open_packet_device() -> std::io::Result<DeviceIo> {
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
        OPEN_EXISTING,
    };
    let wide = wide(DEVICE_PATH);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0x8000_0000 | 0x4000_0000,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::other(
            "Rttun packet device did not open; the driver is not loaded",
        ));
    }
    let read_event = match create_event() {
        Ok(event) => event,
        Err(error) => {
            close_handle(handle);
            return Err(error);
        }
    };
    let write_event = match create_event() {
        Ok(event) => event,
        Err(error) => {
            close_handle(read_event);
            close_handle(handle);
            return Err(error);
        }
    };
    let mut read_overlapped = windows_sys::Win32::System::IO::OVERLAPPED::default();
    read_overlapped.hEvent = read_event;
    Ok(DeviceIo {
        handle,
        read_event,
        write_event,
        read_pending: false,
        read_overlapped,
        read_buf: vec![0; MAX_PACKET].into_boxed_slice(),
    })
}

/// Starts one overlapped read. `Ok(true)` means the driver already completed
/// it, so the caller must not wait for the event.
fn start_read(io: &mut DeviceIo) -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let mut read = 0u32;
    let started = unsafe {
        ReadFile(
            io.handle,
            io.read_buf.as_mut_ptr().cast(),
            io.read_buf.len() as u32,
            &mut read,
            &mut io.read_overlapped,
        )
    };
    if started == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error);
        }
        io.read_pending = true;
        return Ok(false);
    }
    io.read_pending = true;
    Ok(true)
}

fn finish_read(io: &mut DeviceIo) -> std::io::Result<usize> {
    let mut transferred = 0u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::GetOverlappedResult(
            io.handle,
            &io.read_overlapped,
            &mut transferred,
            0,
        )
    };
    io.read_pending = false;
    unsafe { windows_sys::Win32::System::Threading::ResetEvent(io.read_event) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let n = transferred as usize;
    if n == 0 || n > io.read_buf.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Rttun read was not one packet",
        ));
    }
    Ok(n)
}

fn write_packet(handle: HANDLE, event: HANDLE, packet: &[u8]) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::ERROR_IO_PENDING;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    unsafe { windows_sys::Win32::System::Threading::ResetEvent(event) };
    let mut overlapped = windows_sys::Win32::System::IO::OVERLAPPED::default();
    overlapped.hEvent = event;
    let mut written = 0u32;
    let started = unsafe {
        WriteFile(
            handle,
            packet.as_ptr().cast(),
            packet.len() as u32,
            &mut written,
            &mut overlapped,
        )
    };
    if started == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
            return Err(error);
        }
        if !wait_ready(event)? {
            unsafe { windows_sys::Win32::System::IO::CancelIoEx(handle, &overlapped) };
            return Err(std::io::Error::other("Rttun write timed out"));
        }
    }
    let mut transferred = 0u32;
    let ok = unsafe {
        windows_sys::Win32::System::IO::GetOverlappedResult(handle, &overlapped, &mut transferred, 0)
    };
    if ok == 0 || transferred as usize != packet.len() {
        return Err(std::io::Error::other("Rttun write was not accepted"));
    }
    Ok(())
}

fn wait_ready(event: HANDLE) -> std::io::Result<bool> {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    match unsafe { WaitForSingleObject(event, 2) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(std::io::Error::last_os_error()),
    }
}

fn wide(text: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(text).encode_wide().chain(Some(0)).collect()
}

fn create_event() -> std::io::Result<HANDLE> {
    let event = unsafe {
        windows_sys::Win32::System::Threading::CreateEventW(
            std::ptr::null(),
            1,
            0,
            std::ptr::null(),
        )
    };
    if event.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(event)
}

fn close_handle(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
}
