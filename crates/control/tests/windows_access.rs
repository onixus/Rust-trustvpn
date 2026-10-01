#![cfg(target_os = "windows")]
//! Executed against the temporary installed service by Windows E2E.
use std::{
    fs::OpenOptions,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    ptr,
};
use windows_sys::Win32::{
    Security::*,
    Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
struct Revert;
impl Drop for Revert {
    fn drop(&mut self) {
        assert_ne!(unsafe { RevertToSelf() }, 0);
    }
}
fn restricted(deny_admin: bool) -> OwnedHandle {
    unsafe {
        let mut raw = ptr::null_mut();
        assert_ne!(
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE,
                &mut raw
            ),
            0
        );
        let token = OwnedHandle::from_raw_handle(raw);
        let mut sid = [0usize; 16];
        let mut size = size_of_val(&sid) as u32;
        assert_ne!(
            CreateWellKnownSid(
                if deny_admin {
                    WinBuiltinAdministratorsSid
                } else {
                    WinWorldSid
                },
                ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut size
            ),
            0
        );
        let entry = SID_AND_ATTRIBUTES {
            Sid: sid.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let mut result = ptr::null_mut();
        assert_ne!(
            CreateRestrictedToken(
                token.as_raw_handle(),
                DISABLE_MAX_PRIVILEGE,
                u32::from(deny_admin),
                if deny_admin { &entry } else { ptr::null() },
                0,
                ptr::null(),
                u32::from(!deny_admin),
                if deny_admin { ptr::null() } else { &entry },
                &mut result
            ),
            0
        );
        OwnedHandle::from_raw_handle(result)
    }
}
#[tokio::test(flavor = "current_thread")]
async fn desktop_without_admin_can_authenticate_service_but_unauthorized_token_cannot_open_pipe() {
    if std::env::var("RTRUST_INSTALLED_SERVICE_TEST").as_deref() != Ok("1") {
        return;
    }
    let token = restricted(true);
    assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
    let revert = Revert;
    let mut pipe = rtrust_control::windows::connect()
        .expect("ordinary desktop token must authenticate SCM and open IPC");
    drop(revert);
    rtrust_control::write(
        &mut pipe,
        &rtrust_control::Request {
            version: rtrust_control::VERSION,
            command: rtrust_control::Command::Recover,
        },
    )
    .await
    .unwrap();
    let response: rtrust_control::Response = rtrust_control::read(&mut pipe).await.unwrap();
    assert_eq!(response.state, rtrust_control::State::Idle);
    drop(pipe);
    let token = restricted(false);
    assert_ne!(unsafe { ImpersonateLoggedOnUser(token.as_raw_handle()) }, 0);
    let revert = Revert;
    let result = OpenOptions::new()
        .access_mode(0x12019b)
        .custom_flags(SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT)
        .open(rtrust_control::windows::PIPE);
    drop(revert);
    assert_eq!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
}
