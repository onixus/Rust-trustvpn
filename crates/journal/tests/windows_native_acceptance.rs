//! Opt-in synthetic native gates. Run only through the protected-stage launcher.
//! Restricted-token checks are effective-access checks, NOT another user's login.
#![cfg(windows)]

use rtrust_journal::{Config, Journal, Owner};
use std::{
    ffi::{OsStr, c_void},
    fs,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        IO::DeviceIoControl,
        Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
    },
};

const PRIVATE: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const ROOT: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
const SYNTHETIC: &str = "S-1-5-21-424242421-424242422-424242423-424242424";
const SY: &str = "S-1-5-18";
const BA: &str = "S-1-5-32-544";
const BU: &str = "S-1-5-32-545";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
// WinNT.h group attributes; avoid expanding production windows-sys features.
const SE_GROUP_ENABLED: u32 = 0x4;
const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
const SE_GROUP_INTEGRITY: u32 = 0x20;

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}
fn require(value: bool) {
    assert!(value, "native fixture assertion=false (details suppressed)");
}
fn checked<T, E>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|_| panic!("native fixture operation=false (details suppressed)"))
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn sid(text: &str) -> Local {
    let mut result = null_mut();
    require(unsafe { ConvertStringSidToSidW(wide(OsStr::new(text)).as_ptr(), &mut result) } != 0);
    Local(result)
}
fn descriptor(text: &str) -> Local {
    let mut result = null_mut();
    require(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(text)).as_ptr(),
                1,
                &mut result,
                null_mut(),
            )
        } != 0,
    );
    Local(result)
}
fn sid_bytes(value: PSID) -> Vec<u8> {
    require(!value.is_null() && unsafe { IsValidSid(value) } != 0);
    unsafe { std::slice::from_raw_parts(value.cast::<u8>(), GetLengthSid(value) as usize).to_vec() }
}
fn same_sid(value: PSID, expected: &str) -> bool {
    unsafe { EqualSid(value, sid(expected).0) != 0 }
}
fn process_token(access: u32) -> Handle {
    let mut token = null_mut();
    require(unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } != 0);
    Handle(token)
}
fn information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
    let mut size = 0;
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut size);
    }
    require(size != 0);
    let mut data = vec![0u64; (size as usize).div_ceil(8)];
    require(
        unsafe { GetTokenInformation(token, class, data.as_mut_ptr().cast(), size, &mut size) }
            != 0,
    );
    data
}
fn system(token: HANDLE) -> bool {
    let data = information(token, TokenUser);
    same_sid(
        unsafe { (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid },
        SY,
    )
}
fn duplicate(token: HANDLE) -> Handle {
    let mut result = null_mut();
    require(
        unsafe {
            DuplicateTokenEx(
                token,
                TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_ADJUST_DEFAULT,
                null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut result,
            )
        } != 0,
    );
    Handle(result)
}
fn member(token: HANDLE, group: &str) -> bool {
    let mut result = 0;
    require(unsafe { CheckTokenMembership(token, sid(group).0, &mut result) } != 0);
    result != 0
}
fn privilege(name: &str) -> LUID {
    let mut value = unsafe { zeroed() };
    require(
        unsafe { LookupPrivilegeValueW(null(), wide(OsStr::new(name)).as_ptr(), &mut value) } != 0,
    );
    value
}
fn same_luid(left: LUID, right: LUID) -> bool {
    left.LowPart == right.LowPart && left.HighPart == right.HighPart
}
/// Changes only an already-present privilege in this process; exact prior state restored.
struct Privilege {
    token: Handle,
    previous: TOKEN_PRIVILEGES,
}
impl Privilege {
    fn enable(name: &str) -> Self {
        let token = process_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES);
        let state = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: privilege(name),
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = unsafe { zeroed() };
        let mut size = 0;
        unsafe {
            SetLastError(0);
        }
        let ok = unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &state,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut size,
            )
        };
        let error = unsafe { GetLastError() };
        // Missing privileges are NOT an ignored/green native gate.
        assert!(
            ok != 0 && error == 0,
            "NOT RUN: required process privilege unavailable"
        );
        Self { token, previous }
    }
}
impl Drop for Privilege {
    fn drop(&mut self) {
        let ok = unsafe {
            AdjustTokenPrivileges(self.token.0, 0, &self.previous, 0, null_mut(), null_mut())
        };
        require(ok != 0);
        let actual = information(self.token.0, TokenPrivileges);
        let actual = unsafe { &*actual.as_ptr().cast::<TOKEN_PRIVILEGES>() };
        let entries = unsafe {
            std::slice::from_raw_parts(actual.Privileges.as_ptr(), actual.PrivilegeCount as usize)
        };
        for prior in &self.previous.Privileges[..self.previous.PrivilegeCount as usize] {
            require(
                entries
                    .iter()
                    .any(|p| same_luid(p.Luid, prior.Luid) && p.Attributes == prior.Attributes),
            );
        }
    }
}
fn open(path: &Path, access: u32, disposition: u32) -> Result<Handle, u32> {
    let raw = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            access,
            SHARE,
            null(),
            disposition,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(Handle(raw))
    }
}
#[derive(PartialEq, Eq)]
struct Ace {
    flags: u8,
    mask: u32,
    owner: Vec<u8>,
}
#[derive(PartialEq, Eq)]
struct Snapshot {
    owner: Vec<u8>,
    dacl: Vec<u8>,
    aces: Vec<Ace>,
    protected: bool,
    identity: (u32, u32, u32),
    links: u32,
    attributes: u32,
}
fn snapshot(path: &Path) -> Snapshot {
    let handle = checked(open(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES,
        OPEN_EXISTING,
    ));
    unsafe {
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut security = null_mut();
        require(
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut security,
            ) == 0,
        );
        let _allocation = Local(security);
        require(!acl.is_null());
        let mut control = 0;
        let mut revision = 0;
        require(GetSecurityDescriptorControl(security, &mut control, &mut revision) != 0);
        let mut aces = Vec::new();
        for index in 0..(*acl).AceCount {
            let mut raw = null_mut();
            require(GetAce(acl, u32::from(index), &mut raw) != 0);
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            require(ace.Header.AceType == 0);
            aces.push(Ace {
                flags: ace.Header.AceFlags,
                mask: ace.Mask,
                owner: sid_bytes(std::ptr::addr_of!(ace.SidStart).cast_mut().cast()),
            });
        }
        let mut info = zeroed();
        require(GetFileInformationByHandle(handle.0, &mut info) != 0);
        Snapshot {
            owner: sid_bytes(owner),
            dacl: std::slice::from_raw_parts(acl.cast::<u8>(), usize::from((*acl).AclSize))
                .to_vec(),
            aces,
            protected: control & SE_DACL_PROTECTED != 0,
            identity: (
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ),
            links: info.nNumberOfLinks,
            attributes: info.dwFileAttributes,
        }
    }
}
// NTFS keeps OI|CI only on containers; file ACEs carry no inheritance flags.
fn inheritance(directory: bool) -> u8 {
    if directory { 3 } else { 0 }
}
fn grants(aces: &[Ace]) -> Vec<(&[u8], u32)> {
    aces.iter()
        .map(|ace| (ace.owner.as_slice(), ace.mask))
        .collect()
}
fn canonical(path: &Path, directory: bool) {
    let value = snapshot(path);
    require(value.owner == sid_bytes(sid(SY).0) && value.protected);
    require(value.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0);
    require((value.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory);
    if !directory {
        require(value.links == 1);
    }
    require(value.aces.len() == 3);
    for (actual, (name, mask)) in
        value
            .aces
            .iter()
            .zip([(SY, 0x1f01ff), (BA, 0x1f01ff), (BU, 0x1200a9)])
    {
        require(
            actual.owner == sid_bytes(sid(name).0)
                && actual.mask == mask
                && actual.flags == inheritance(directory),
        );
    }
}
fn secure_directory(path: &Path, text: &str) {
    let descriptor = descriptor(text);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    require(unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &attributes) } != 0);
}
fn set_security(path: &Path, text: &str) {
    let descriptor = descriptor(text);
    // SetSecurityInfo reads the current descriptor to merge a protected DACL;
    // without READ_CONTROL it fails with ERROR_ACCESS_DENIED even for SYSTEM.
    let handle = checked(open(
        path,
        READ_CONTROL | WRITE_OWNER | WRITE_DAC,
        OPEN_EXISTING,
    ));
    unsafe {
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut ignored = 0;
        require(GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut ignored) != 0);
        require(GetSecurityDescriptorDacl(descriptor.0, &mut ignored, &mut acl, &mut ignored) != 0);
        require(
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                owner,
                null_mut(),
                acl,
                null(),
            ) == 0,
        );
    }
}
fn set_owner(path: &Path, owner: &str) {
    let handle = checked(open(path, WRITE_OWNER, OPEN_EXISTING));
    require(
        unsafe {
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                sid(owner).0,
                null_mut(),
                null_mut(),
                null(),
            )
        } == 0,
    );
}
fn base(expect_system: bool) -> PathBuf {
    let token = process_token(TOKEN_QUERY | TOKEN_DUPLICATE);
    assert!(
        system(token.0) == expect_system,
        "NOT RUN: incorrect native phase identity"
    );
    if !expect_system {
        let admin = duplicate(token.0);
        assert!(
            member(admin.0, BA),
            "NOT RUN: elevated administrator required"
        );
        let elevation = information(token.0, TokenElevation);
        assert!(
            unsafe { (*elevation.as_ptr().cast::<TOKEN_ELEVATION>()).TokenIsElevated } != 0,
            "NOT RUN: elevation required"
        );
    }
    let exe = checked(std::env::current_exe());
    let stage = checked(exe.parent().ok_or(()));
    let fixture = stage.join("fixture");
    for path in [stage, fixture.as_path()] {
        let meta = snapshot(path);
        require(
            meta.protected
                && meta.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
                && meta.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
                && meta.aces.len() == 2,
        );
        require(meta.owner == sid_bytes(sid(SY).0) || meta.owner == sid_bytes(sid(BA).0));
        for (ace, name) in meta.aces.iter().zip([SY, BA]) {
            require(ace.owner == sid_bytes(sid(name).0) && ace.mask == 0x1f01ff && ace.flags == 3);
        }
    }
    fixture
}
fn case(base: &Path, name: &str) -> PathBuf {
    let parent = base.join(name);
    secure_directory(&parent, PRIVATE);
    parent.join("R-TrustTunnel").join("logs")
}
fn write_event(path: &Path, owner: Owner, file: &'static str) -> bool {
    let directory = path.to_owned();
    let journal = Journal::spawn(move || {
        Some(Config {
            directory,
            owner,
            file,
        })
    });
    journal.lifecycle("sleep");
    journal.flush(Duration::from_secs(3))
}
fn fresh(base: &Path, name: &str) -> PathBuf {
    let leaf = case(base, name);
    require(write_event(&leaf, Owner::Root, "events.log"));
    require(!checked(fs::read(leaf.join("events.log"))).is_empty());
    leaf
}
fn untouched(path: &Path, before: &Snapshot, bytes: Option<&[u8]>) {
    require(snapshot(path) == *before);
    if let Some(bytes) = bytes {
        require(checked(fs::read(path)) == bytes);
    }
}
fn junction(path: &Path, target: &Path) {
    secure_directory(path, PRIVATE);
    let handle = checked(open(path, GENERIC_WRITE, OPEN_EXISTING));
    let substitute = wide(OsStr::new(&format!("\\??\\{}", target.display())));
    let print = wide(target.as_os_str());
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&0xa0000003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
    buffer.extend_from_slice(&((8 + (substitute.len() + print.len()) * 2) as u16).to_le_bytes());
    buffer.extend_from_slice(&0u16.to_le_bytes());
    for value in [
        0,
        ((substitute.len() - 1) * 2) as u16,
        (substitute.len() * 2) as u16,
        ((print.len() - 1) * 2) as u16,
    ] {
        buffer.extend_from_slice(&value.to_le_bytes());
    }
    for value in substitute.into_iter().chain(print) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }
    let mut returned = 0;
    require(
        unsafe {
            DeviceIoControl(
                handle.0,
                0x000900a4,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        } != 0,
    ); // FSCTL_SET_REPARSE_POINT
}
/// Removes only a known fixture link itself, never its target or a recursive tree.
struct Link {
    path: PathBuf,
    directory: bool,
}
impl Drop for Link {
    fn drop(&mut self) {
        let ok = unsafe {
            if self.directory {
                RemoveDirectoryW(wide(self.path.as_os_str()).as_ptr())
            } else {
                DeleteFileW(wide(self.path.as_os_str()).as_ptr())
            }
        };
        require(ok != 0);
    }
}
#[test]
#[ignore = "native SYSTEM only; explicit protected-stage launcher required"]
fn system_matrix() {
    let base = base(true);
    let leaf = fresh(&base, "r1");
    for directory in [leaf.parent().unwrap(), leaf.as_path()] {
        canonical(directory, true);
    }
    for name in ["events.log", "events.lock"] {
        canonical(&leaf.join(name), false);
    }
    println!("PASS: R1 fresh Root canonical owner and exact ACEs");

    {
        let _restore = Privilege::enable("SeRestorePrivilege");
        let leaf = fresh(&base, "r2");
        let parent = snapshot(leaf.parent().unwrap());
        set_security(
            &leaf,
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;AU)",
        );
        set_security(&leaf.join("events.log"), PRIVATE);
        require(write_event(&leaf, Owner::Root, "events.log"));
        // Existing Administrator owner remains trusted; repair changes only DACL.
        let repaired = snapshot(&leaf);
        require(repaired.owner == sid_bytes(sid(BA).0) && repaired.protected);
        let root_file = snapshot(&leaf.join("events.log"));
        require(grants(&repaired.aces) == grants(&root_file.aces));
        canonical(&leaf.join("events.log"), false);
        require(snapshot(leaf.parent().unwrap()).dacl == parent.dacl);
    }
    println!("PASS: R2 trusted leaf repair; OBSERVED Root file repair restores Users read");

    {
        let _restore = Privilege::enable("SeRestorePrivilege");
        for (owner_index, owner) in [SYNTHETIC, BU].into_iter().enumerate() {
            for (index, name) in ["app", "leaf", "events.log", "events.lock", "events.log.1"]
                .into_iter()
                .enumerate()
            {
                let leaf = fresh(&base, &format!("r3-{owner_index}-{index}"));
                let target = match name {
                    "app" => leaf.parent().unwrap().to_owned(),
                    "leaf" => leaf.clone(),
                    _ => leaf.join(name),
                };
                if name == "events.log.1" {
                    checked(fs::write(&target, b"1 synthetic archive\n"));
                }
                set_owner(&target, owner);
                let before = snapshot(&target);
                let bytes = if name.starts_with("events.") {
                    Some(checked(fs::read(&target)))
                } else {
                    None
                };
                let current = checked(fs::read(leaf.join("events.log")));
                let _ = write_event(&leaf, Owner::Root, "events.log");
                untouched(&target, &before, bytes.as_deref());
                require(checked(fs::read(leaf.join("events.log"))) == current);
            }
        }
    }
    println!("PASS: R3 synthetic and Users owners rejected without takeover");

    for (index, position) in ["intermediate", "app", "leaf"].into_iter().enumerate() {
        let leaf = case(&base, &format!("r4-dir-{index}"));
        let parent = leaf.parent().unwrap().parent().unwrap();
        let target = parent.join("canary");
        secure_directory(&target, PRIVATE);
        let before = snapshot(&target);
        let (link, destination) = match position {
            "intermediate" => {
                let link = parent.join("middle");
                let destination = link.join("R-TrustTunnel/logs");
                (link, destination)
            }
            "app" => (leaf.parent().unwrap().to_owned(), leaf.clone()),
            _ => {
                secure_directory(leaf.parent().unwrap(), ROOT);
                (leaf.clone(), leaf.clone())
            }
        };
        junction(&link, &target);
        let _link = Link {
            path: link,
            directory: true,
        };
        require(!write_event(&destination, Owner::Root, "events.log"));
        untouched(&target, &before, None);
        require(checked(fs::read_dir(&target)).next().is_none());
    }
    {
        let _symbolic = Privilege::enable("SeCreateSymbolicLinkPrivilege");
        for (index, name) in ["events.log", "events.lock", "events.tmp", "events.log.1"]
            .into_iter()
            .enumerate()
        {
            let leaf = fresh(&base, &format!("r4-file-{index}"));
            let canary = leaf.parent().unwrap().parent().unwrap().join("canary");
            checked(fs::write(&canary, b"synthetic canary\n"));
            let before = snapshot(&canary);
            let bytes = checked(fs::read(&canary));
            let link = leaf.join(name);
            if link.exists() {
                checked(fs::remove_file(&link));
            }
            require(unsafe {
                CreateSymbolicLinkW(
                    wide(link.as_os_str()).as_ptr(),
                    wide(canary.as_os_str()).as_ptr(),
                    0,
                )
            });
            let _link = Link {
                path: link,
                directory: false,
            };
            let current = if name != "events.log" {
                Some(checked(fs::read(leaf.join("events.log"))))
            } else {
                None
            };
            let _ = write_event(&leaf, Owner::Root, "events.log");
            untouched(&canary, &before, Some(&bytes));
            if let Some(current) = current {
                require(checked(fs::read(leaf.join("events.log"))) == current);
            }
        }
    }
    println!("PASS: R4 junction and file-symlink rejection; canaries unchanged");

    {
        let leaf = fresh(&base, "r5");
        let log = leaf.join("events.log");
        let canary = leaf.parent().unwrap().parent().unwrap().join("canary");
        checked(fs::hard_link(&log, &canary));
        let before = snapshot(&canary);
        let bytes = checked(fs::read(&canary));
        require(before.links == 2);
        let _ = write_event(&leaf, Owner::Root, "events.log");
        untouched(&canary, &before, Some(&bytes));
        checked(fs::remove_file(&canary));
        require(snapshot(&log).links == 1);
    }
    println!("PASS: R5 hardlink rejection; canary unchanged");

    {
        let leaf = fresh(&base, "r6");
        let log = leaf.join("events.log");
        let now = checked(SystemTime::now().duration_since(UNIX_EPOCH)).as_millis();
        checked(fs::write(
            &log,
            format!("1 synthetic expired\n{now} synthetic recent\n"),
        ));
        checked(fs::write(leaf.join("events.tmp"), b"stale synthetic\n"));
        let before = snapshot(&log);
        require(write_event(&leaf, Owner::Root, "events.log"));
        require(snapshot(&log).identity != before.identity);
        require(!leaf.join("events.tmp").exists());
        let retained = checked(fs::read_to_string(&log));
        require(!retained.starts_with("1 "));
        require(retained.contains(&format!("{now} synthetic recent\n")));
        require(retained.lines().any(|line| line.ends_with(" sleep")));
        canonical(&log, false);
        // Remainder is shorter than the public lifecycle record, guaranteeing rotation.
        let line = format!("{now} x\n");
        checked(fs::write(&log, line.repeat(1_000_000 / line.len())));
        let before_rotation = snapshot(&log);
        require(write_event(&leaf, Owner::Root, "events.log"));
        require(snapshot(&log).identity != before_rotation.identity);
        require(snapshot(&leaf.join("events.log.1")).identity == before_rotation.identity);
        canonical(&log, false);
        canonical(&leaf.join("events.log.1"), false);
    }
    println!("PASS: R6 retention stale-temp cleanup and rotation");
    let private = base.join("system-current-user");
    require(write_event(
        &private,
        Owner::CurrentUser,
        "socks-events.log",
    ));
    for (path, directory) in [
        (private.clone(), true),
        (private.join("socks-events.log"), false),
    ] {
        let meta = snapshot(&path);
        require(meta.protected && meta.owner == sid_bytes(sid(SY).0));
        require(
            !meta.aces.is_empty()
                && meta.aces.iter().all(|ace| {
                    ace.owner == sid_bytes(sid(SY).0)
                        && ace.mask == 0x1f01ff
                        && ace.flags == inheritance(directory)
                }),
        );
    }
    read_sink(&private.join("socks-events.log"));
    println!("PASS: SYSTEM_PRIVATE_POSITIVE public CurrentUser fixture");
    println!("PASS: SYSTEM_MATRIX_COMPLETE");
}

fn system_private(path: &Path, directory: bool) {
    let meta = snapshot(path);
    require(meta.protected && meta.owner == sid_bytes(sid(SY).0));
    require(meta.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0);
    require((meta.attributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory);
    require(directory || meta.links == 1);
    require(
        !meta.aces.is_empty()
            && meta.aces.iter().all(|ace| {
                ace.owner == sid_bytes(sid(SY).0)
                    && ace.mask == 0x1f01ff
                    && ace.flags == inheritance(directory)
            }),
    );
}

/// Cleanup-only phase: no acceptance claim and no recursive deletion or ACL changes.
#[test]
#[ignore = "temporary SYSTEM task only; exact protected-stage fixture cleanup"]
fn system_cleanup() {
    let base = base(true);
    let private = base.join("system-current-user");
    match open(&private, READ_CONTROL | FILE_READ_ATTRIBUTES, OPEN_EXISTING) {
        Ok(handle) => drop(handle),
        Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) => {
            println!("PASS: SYSTEM_CLEANUP_COMPLETE private fixture absent (cleanup only)");
            return;
        }
        Err(_) => panic!("FAIL: cleanup fixture unavailable (details suppressed)"),
    }
    system_private(&private, true);
    let mut files = Vec::new();
    for entry in checked(fs::read_dir(&private)) {
        let entry = checked(entry);
        let name = entry.file_name();
        require(name == OsStr::new("socks-events.log") || name == OsStr::new("events.lock"));
        require(files.len() < 2);
        system_private(&entry.path(), false);
        files.push(entry.path());
    }
    // Validate the entire exact namespace BEFORE deleting anything.
    for file in files {
        checked(fs::remove_file(file));
    }
    checked(fs::remove_dir(&private));
    require(matches!(
        open(&private, READ_CONTROL | FILE_READ_ATTRIBUTES, OPEN_EXISTING),
        Err(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
    ));
    println!("PASS: SYSTEM_CLEANUP_COMPLETE known private fixture removed (cleanup only)");
}

fn restricted() -> Handle {
    let source = process_token(TOKEN_QUERY | TOKEN_DUPLICATE);
    let admin = sid(BA);
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admin.0,
        Attributes: 0,
    };
    let mut raw = null_mut();
    require(
        unsafe {
            CreateRestrictedToken(
                source.0,
                DISABLE_MAX_PRIVILEGE,
                1,
                &disabled,
                0,
                null(),
                0,
                null(),
                &mut raw,
            )
        } != 0,
    );
    let primary = Handle(raw);
    let token = duplicate(primary.0);
    let medium = sid("S-1-16-8192");
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium.0,
            Attributes: SE_GROUP_INTEGRITY,
        },
    };
    require(
        unsafe {
            SetTokenInformation(
                token.0,
                TokenIntegrityLevel,
                std::ptr::addr_of!(label).cast(),
                (size_of::<TOKEN_MANDATORY_LABEL>() + GetLengthSid(medium.0) as usize) as u32,
            )
        } != 0,
    );
    prove_restricted(token.0);
    token
}
fn prove_restricted(token: HANDLE) {
    require(!system(token) && !member(token, BA) && !member(token, SY) && member(token, BU));
    let groups = information(token, TokenGroups);
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    let groups =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    require(groups.iter().any(|g| {
        same_sid(g.Sid, BA)
            && g.Attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0
            && g.Attributes & SE_GROUP_ENABLED == 0
    }));
    let integrity = information(token, TokenIntegrityLevel);
    require(same_sid(
        unsafe {
            (*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
                .Label
                .Sid
        },
        "S-1-16-8192",
    ));
    let privileges = information(token, TokenPrivileges);
    let privileges = unsafe { &*privileges.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    let entries = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    let notify = privilege("SeChangeNotifyPrivilege");
    require(
        entries.len() == 1
            && same_luid(entries[0].Luid, notify)
            && entries[0].Attributes & SE_PRIVILEGE_ENABLED != 0,
    );
    let restrictions = information(token, TokenRestrictedSids);
    let restrictions = unsafe { &*restrictions.as_ptr().cast::<TOKEN_GROUPS>() };
    require(restrictions.GroupCount == 0);
}
struct Impersonation;
impl Impersonation {
    fn begin(token: HANDLE) -> Self {
        require(unsafe { ImpersonateLoggedOnUser(token) } != 0);
        let guard = Self;
        let mut actual = null_mut();
        require(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut actual) } != 0);
        let actual = Handle(actual);
        prove_restricted(actual.0);
        let expected = information(token, TokenUser);
        let observed = information(actual.0, TokenUser);
        require(
            unsafe {
                EqualSid(
                    (*expected.as_ptr().cast::<TOKEN_USER>()).User.Sid,
                    (*observed.as_ptr().cast::<TOKEN_USER>()).User.Sid,
                )
            } != 0,
        );
        guard
    }
}
impl Drop for Impersonation {
    fn drop(&mut self) {
        require(unsafe { RevertToSelf() } != 0);
    }
}
fn denied(result: Result<Handle, u32>) {
    require(matches!(result, Err(ERROR_ACCESS_DENIED)));
}
fn read_sink(path: &Path) {
    let file = checked(open(path, GENERIC_READ, OPEN_EXISTING));
    let mut buffer = [0u8; 4096];
    let mut total = 0;
    loop {
        let mut read = 0;
        require(
            unsafe {
                ReadFile(
                    file.0,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut read,
                    null_mut(),
                )
            } != 0,
        );
        if read == 0 {
            break;
        }
        total += read;
        require(total <= 1_000_000);
    }
    require(total != 0);
}
#[test]
#[ignore = "native elevated-admin only; run after SYSTEM matrix in same protected stage"]
fn restricted_admin_matrix() {
    let base = base(false);
    let leaf = base.join("r1/R-TrustTunnel/logs");
    canonical(&leaf.join("events.log"), false);
    let token = restricted();
    {
        let _impersonation = Impersonation::begin(token.0);
        read_sink(&leaf.join("events.log"));
        for access in [
            GENERIC_WRITE,
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            denied(open(&leaf.join("events.log"), access, OPEN_EXISTING));
        }
        for access in [FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD] {
            denied(open(&leaf, access, OPEN_EXISTING));
        }
        denied(open(&leaf.join("denied-new"), GENERIC_WRITE, CREATE_NEW));
        let ok = unsafe { DeleteFileW(wide(leaf.join("events.log").as_os_str()).as_ptr()) };
        let error = unsafe { GetLastError() };
        require(ok == 0 && error == ERROR_ACCESS_DENIED);
        let ok =
            unsafe { CreateDirectoryW(wide(leaf.join("denied-dir").as_os_str()).as_ptr(), null()) };
        let error = unsafe { GetLastError() };
        require(ok == 0 && error == ERROR_ACCESS_DENIED);
        let ok = unsafe {
            MoveFileExW(
                wide(leaf.join("events.log").as_os_str()).as_ptr(),
                wide(leaf.join("denied-rename").as_os_str()).as_ptr(),
                0,
            )
        };
        let error = unsafe { GetLastError() };
        require(ok == 0 && error == ERROR_ACCESS_DENIED);
    }
    require(!leaf.join("denied-new").exists() && !leaf.join("denied-rename").exists());
    println!(
        "PASS: R7 medium deny-only-admin effective read yes mutations error5; not another login"
    );
    let private = base.join("system-current-user");
    // The persisted positive control ran as SYSTEM. Its public CurrentUser
    // descriptor names SYSTEM only; this desktop TokenUser is genuinely different.
    // This is NOT another desktop-user login or a same-user SID-disable trick.
    {
        let _impersonation = Impersonation::begin(token.0);
        denied(open(
            &private.join("socks-events.log"),
            GENERIC_READ,
            OPEN_EXISTING,
        ));
    }
    println!("PASS: R8 SYSTEM CurrentUser vs desktop medium token; not another desktop login");
    println!("PASS: ADMIN_MATRIX_COMPLETE");
}
