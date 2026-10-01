//! Local-only IPC. The desktop SID can read/write but cannot create pipe instances.
use std::{
    fs::OpenOptions,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle},
    },
    ptr,
};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{HANDLE, LocalFree},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        },
        GetTokenInformation, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    Storage::FileSystem::{FILE_FLAG_OVERLAPPED, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT},
    System::{
        Pipes::GetNamedPipeServerProcessId,
        Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
    },
};
pub const PIPE: &str = r"\\.\pipe\RTrustTunnel.Control.v1";
pub const SERVICE: &str = "RTrustTunnel";
const CLIENT_ACCESS: u32 = 0x12019b;

pub fn valid_sid(sid: &str) -> bool {
    sid.starts_with("S-1-5-21-")
        && sid.len() <= 184
        && sid
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
}
pub fn process_sid(pid: u32) -> Result<String, String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return Err("Cannot verify IPC process".into());
        }
        let process = OwnedHandle::from_raw_handle(handle);
        let mut raw: HANDLE = ptr::null_mut();
        if OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut raw) == 0 {
            return Err("Cannot verify IPC token".into());
        }
        let token = OwnedHandle::from_raw_handle(raw);
        let mut size = 0;
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut size,
        );
        if size == 0 || size > 65536 {
            return Err("Invalid IPC token size".into());
        }
        // usize allocation guarantees TOKEN_USER alignment.
        let mut bytes = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
        if GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            bytes.as_mut_ptr().cast(),
            size,
            &mut size,
        ) == 0
        {
            return Err("Cannot read IPC identity".into());
        }
        let user = &*bytes.as_ptr().cast::<TOKEN_USER>();
        let mut text = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err("Invalid IPC SID".into());
        }
        let mut len = 0;
        while *text.add(len) != 0 {
            len += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Ok(value)
    }
}
pub fn connect() -> Result<NamedPipeClient, String> {
    let file = OpenOptions::new().access_mode(CLIENT_ACCESS)
        .custom_flags(FILE_FLAG_OVERLAPPED | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT)
        .open(PIPE).map_err(|_| "Служба R-TrustTunnel недоступна. Установите Windows-службу для текущего пользователя.")?;
    let mut pid = 0;
    // Authenticate before sending a profile, including its credentials.
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|_| "Cannot authenticate SCM service")?;
    let service = manager
        .open_service(
            SERVICE,
            ServiceAccess::QUERY_STATUS | ServiceAccess::QUERY_CONFIG,
        )
        .map_err(|_| "Cannot authenticate R-TrustTunnel SCM service; check installation and account permissions")?;
    let status = service
        .query_status()
        .map_err(|_| "Cannot query service identity")?;
    let config = service
        .query_config()
        .map_err(|_| "Cannot query service account")?;
    if unsafe { GetNamedPipeServerProcessId(file.as_raw_handle(), &mut pid) } == 0
        || status.process_id != Some(pid)
        || config.account_name.as_deref() != Some(std::ffi::OsStr::new("LocalSystem"))
    {
        return Err("IPC server identity does not match the LocalSystem SCM service".into());
    }
    unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }
        .map_err(|_| "Cannot open asynchronous IPC".into())
}
pub fn listen(sid: &str, first: bool) -> Result<NamedPipeServer, String> {
    if !valid_sid(sid) {
        return Err("Expected a desktop account SID".into());
    }
    // Never grant GENERIC_WRITE: it includes FILE_CREATE_PIPE_INSTANCE.
    let sddl: Vec<u16> = format!("D:P(A;;GA;;;SY)(A;;0x12019b;;;{sid})\0")
        .encode_utf16()
        .collect();
    unsafe {
        let mut descriptor = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err("Cannot build IPC ACL".into());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .max_instances(16)
            .create_with_security_attributes_raw(
                PIPE,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(descriptor);
        result.map_err(|_| "Cannot create protected IPC pipe".into())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acl_input_cannot_inject_aces() {
        assert!(valid_sid("S-1-5-21-123-456-789-1001"));
        for s in [
            "SY",
            "S-1-5-18",
            "S-1-5-21-123)(A;;GA;;;WD)",
            "S-1-5-21-1\0",
        ] {
            assert!(!valid_sid(s));
        }
        assert_eq!(
            CLIENT_ACCESS & 4,
            0,
            "desktop must not create server instances"
        );
    }
    #[tokio::test]
    async fn rejects_unprivileged_impostor_before_credentials() {
        if process_sid(std::process::id()).unwrap() == "S-1-5-18" {
            return;
        }
        // Only run when the real service is absent; never take over its pipe.
        let Ok(_pipe) = ServerOptions::new().first_pipe_instance(true).create(PIPE) else {
            return;
        };
        assert!(connect().is_err());
    }
}
