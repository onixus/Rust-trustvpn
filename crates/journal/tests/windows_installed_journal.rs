//! Read-only installed journal acceptance; no Journal writer or privilege changes.
//! Real Explorer-derived medium token, never a synthetic restricted-token substitute.
#![cfg(windows)]

use std::{
    env,
    ffi::{OsStr, c_void},
    fs,
    mem::zeroed,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::Threading::*,
};

const SY: &str = "S-1-5-18";
const BA: &str = "S-1-5-32-544";
const BU: &str = "S-1-5-32-545";
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const GROUP_ENABLED: u32 = 4;
const GROUP_DENY_ONLY: u32 = 16;
fn require(ok: bool) {
    assert!(ok, "FAIL: installed journal acceptance");
}
fn denied(code: u32) {
    if code != ERROR_ACCESS_DENIED {
        println!("BLOCKED: C_REAL_OPEN_INCONCLUSIVE");
        panic!("BLOCKED: denied open did not return access denied");
    }
}
fn checked<T, E>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|_| panic!("FAIL: installed journal acceptance"))
}
fn number(name: &str) -> u64 {
    checked(checked(env::var(name)).parse())
}
fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
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
fn sid(value: &str) -> Local {
    let mut p = null_mut();
    require(unsafe { ConvertStringSidToSidW(wide(OsStr::new(value)).as_ptr(), &mut p) } != 0);
    Local(p)
}
fn same_sid(left: PSID, text: &str) -> bool {
    unsafe { EqualSid(left, sid(text).0) != 0 }
}
fn sid_bytes(value: PSID) -> Vec<u8> {
    require(!value.is_null() && unsafe { IsValidSid(value) } != 0);
    unsafe { std::slice::from_raw_parts(value.cast(), GetLengthSid(value) as usize).to_vec() }
}
fn info(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> Vec<u64> {
    let mut bytes = 0;
    unsafe {
        GetTokenInformation(token, class, null_mut(), 0, &mut bytes);
    }
    require(bytes != 0 && bytes <= 1024 * 1024);
    // Keep complete fixed headers addressable even for zero variable entries.
    let mut data = vec![0u64; (bytes as usize).max(128).div_ceil(8)];
    require(
        unsafe { GetTokenInformation(token, class, data.as_mut_ptr().cast(), bytes, &mut bytes) }
            != 0,
    );
    data
}
fn user(token: HANDLE) -> Vec<u8> {
    let data = info(token, TokenUser);
    sid_bytes(unsafe { (*data.as_ptr().cast::<TOKEN_USER>()).User.Sid })
}
fn process_token(process: HANDLE) -> Handle {
    let mut result = null_mut();
    require(unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut result) } != 0);
    Handle(result)
}
fn limited(token: HANDLE, session: u32) {
    let elevation = info(token, TokenElevationType);
    require(elevation[0] as u32 == TokenElevationTypeLimited as u32);
    require(unsafe { IsTokenRestricted(token) } == 0);
    require(info(token, TokenSessionId)[0] as u32 == session);
    let integrity = info(token, TokenIntegrityLevel);
    let label = unsafe { &*integrity.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    require(
        count > 0 && unsafe { *GetSidSubAuthority(label.Label.Sid, u32::from(count - 1)) } == 8192,
    );
    let groups = info(token, TokenGroups);
    let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    require(groups.GroupCount <= 4096);
    let groups =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    require(groups.iter().any(|g| {
        same_sid(g.Sid, BA)
            && g.Attributes & GROUP_DENY_ONLY != 0
            && g.Attributes & GROUP_ENABLED == 0
    }));
    let privileges = info(token, TokenPrivileges);
    let privileges = unsafe { &*privileges.as_ptr().cast::<TOKEN_PRIVILEGES>() };
    require(privileges.PrivilegeCount <= 4096);
    let privileges = unsafe {
        std::slice::from_raw_parts(
            privileges.Privileges.as_ptr(),
            privileges.PrivilegeCount as usize,
        )
    };
    for name in [
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeSecurityPrivilege",
        "SeDebugPrivilege",
        "SeTcbPrivilege",
        "SeLoadDriverPrivilege",
        "SeManageVolumePrivilege",
        "SeImpersonatePrivilege",
    ] {
        let mut id = unsafe { zeroed() };
        require(
            unsafe { LookupPrivilegeValueW(null(), wide(OsStr::new(name)).as_ptr(), &mut id) } != 0,
        );
        require(
            !privileges
                .iter()
                .any(|p| p.Luid.LowPart == id.LowPart && p.Luid.HighPart == id.HighPart),
        );
    }
}
fn explorer_token() -> Handle {
    let pid = checked(u32::try_from(number("RTRUST_EXPLORER_PID")));
    let process = Handle(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
    require(!process.0.is_null());
    let mut length = 32768u32;
    let mut path = vec![0u16; length as usize];
    require(
        unsafe { QueryFullProcessImageNameW(process.0, 0, path.as_mut_ptr(), &mut length) } != 0,
    );
    let expected = PathBuf::from(checked(env::var("SystemRoot"))).join("explorer.exe");
    require(
        checked(String::from_utf16(&path[..length as usize]))
            .eq_ignore_ascii_case(&expected.to_string_lossy()),
    );
    let (mut creation, mut exit, mut kernel, mut user_time) =
        unsafe { (zeroed(), zeroed(), zeroed(), zeroed()) };
    require(
        unsafe {
            GetProcessTimes(
                process.0,
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user_time,
            )
        } != 0,
    );
    require(
        (u64::from(creation.dwHighDateTime) << 32 | u64::from(creation.dwLowDateTime))
            == number("RTRUST_EXPLORER_CREATED"),
    );
    let token = process_token(process.0);
    require(user(token.0) == user(process_token(unsafe { GetCurrentProcess() }).0));
    limited(
        token.0,
        checked(u32::try_from(number("RTRUST_EXPLORER_SESSION"))),
    );
    token
}
fn duplicate(token: HANDLE, level: SECURITY_IMPERSONATION_LEVEL) -> Handle {
    let mut result = null_mut();
    require(
        unsafe {
            DuplicateTokenEx(
                token,
                TOKEN_QUERY | TOKEN_IMPERSONATE,
                null(),
                level,
                TokenImpersonation,
                &mut result,
            )
        } != 0,
    );
    Handle(result)
}
fn open(path: &Path, access: u32) -> Result<Handle, u32> {
    let result = unsafe {
        CreateFileW(
            wide(path.as_os_str()).as_ptr(),
            access,
            SHARE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
            null_mut(),
        )
    };
    if result == INVALID_HANDLE_VALUE {
        Err(unsafe { GetLastError() })
    } else {
        Ok(Handle(result))
    }
}
fn final_path(handle: HANDLE, path: &Path) {
    let mut text = vec![0u16; 32768];
    let n = unsafe { GetFinalPathNameByHandleW(handle, text.as_mut_ptr(), text.len() as u32, 0) };
    require(n > 0 && (n as usize) < text.len());
    let actual = checked(String::from_utf16(&text[..n as usize]));
    let actual = actual.strip_prefix("\\\\?\\").unwrap_or(&actual);
    let requested = path.to_string_lossy();
    let requested = requested.strip_prefix("\\\\?\\").unwrap_or(&requested);
    require(actual.eq_ignore_ascii_case(requested));
}
struct Object {
    path: PathBuf,
    handle: Handle,
    descriptor: Local,
    directory: bool,
    size: u64,
}
fn object(path: &Path, directory: bool, canonical: bool) -> Object {
    let handle = checked(open(
        path,
        READ_CONTROL | FILE_READ_ATTRIBUTES | if directory { 0 } else { FILE_READ_DATA },
    ));
    let mut facts: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    require(unsafe { GetFileInformationByHandle(handle.0, &mut facts) } != 0);
    require(facts.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0);
    require((facts.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory);
    if !directory {
        require(facts.nNumberOfLinks == 1);
    }
    final_path(handle.0, path);
    let mut owner = null_mut();
    let mut group = null_mut();
    let mut acl = null_mut();
    let mut sacl = null_mut();
    let mut descriptor = null_mut();
    require(
        unsafe {
            GetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION
                    | GROUP_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | LABEL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut acl,
                &mut sacl,
                &mut descriptor,
            )
        } == 0,
    );
    let descriptor = Local(descriptor);
    require(!owner.is_null() && !group.is_null() && !acl.is_null());
    require(unsafe { IsValidSecurityDescriptor(descriptor.0) } != 0);
    let mut control = 0;
    let mut revision = 0;
    require(
        unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } != 0,
    );
    require(same_sid(owner, SY) || (!canonical && same_sid(owner, BA)));
    if canonical {
        require(same_sid(group, SY));
    }
    let mut expected = vec![(SY, 0x1f01ff), (BA, 0x1f01ff), (BU, 0x1200a9)];
    for i in 0..unsafe { (*acl).AceCount } {
        let mut entry = null_mut();
        require(unsafe { GetAce(acl, u32::from(i), &mut entry) } != 0);
        let ace = unsafe { &*entry.cast::<ACCESS_ALLOWED_ACE>() };
        if !canonical && ace.Header.AceType == 1 {
            continue;
        } // deny ACE never broadens access
        require(ace.Header.AceType == 0);
        let principal = std::ptr::addr_of!(ace.SidStart).cast_mut().cast();
        if canonical {
            let index = expected
                .iter()
                .position(|(s, m)| same_sid(principal, s) && ace.Mask == *m);
            require(index.is_some());
            expected.remove(index.unwrap_or(0));
            if directory {
                require(ace.Header.AceFlags == 3);
            }
        } else if !same_sid(principal, SY) && !same_sid(principal, BA) {
            require(ace.Mask & 0x500d0156 == 0);
        }
    }
    if canonical {
        require(control & SE_DACL_PROTECTED != 0 && expected.is_empty());
    }
    Object {
        path: path.to_owned(),
        handle,
        descriptor,
        directory,
        size: u64::from(facts.nFileSizeHigh) << 32 | u64::from(facts.nFileSizeLow),
    }
}
fn read(object: &Object) -> Vec<u8> {
    require(!object.directory && object.size <= 1_000_000);
    let mut data = vec![0; object.size as usize];
    let mut n = 0;
    require(
        unsafe {
            ReadFile(
                object.handle.0,
                data.as_mut_ptr(),
                data.len() as u32,
                &mut n,
                null_mut(),
            )
        } != 0,
    );
    require(n as usize == data.len());
    data
}
fn matrix(objects: &[Object], token: HANDLE) {
    let identification = duplicate(token, SecurityIdentification);
    for object in objects {
        let read = if object.directory {
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE
        } else {
            FILE_GENERIC_READ
        };
        let mut rights = vec![
            (read, true),
            (FILE_WRITE_DATA, false),
            (FILE_APPEND_DATA, false),
            (FILE_WRITE_EA, false),
            (FILE_WRITE_ATTRIBUTES, false),
            (DELETE, false),
            (WRITE_DAC, false),
            (WRITE_OWNER, false),
        ];
        if object.directory {
            rights.push((FILE_DELETE_CHILD, false));
        }
        for (access, expected) in rights {
            let mapping = GENERIC_MAPPING {
                GenericRead: FILE_GENERIC_READ,
                GenericWrite: FILE_GENERIC_WRITE,
                GenericExecute: FILE_GENERIC_EXECUTE,
                GenericAll: FILE_ALL_ACCESS,
            };
            let mut length = 4096;
            let mut privileges = vec![0u64; length as usize / 8];
            let mut granted = 0;
            let mut status = 0;
            require(
                unsafe {
                    AccessCheck(
                        object.descriptor.0,
                        identification.0,
                        access,
                        &mapping,
                        privileges.as_mut_ptr().cast(),
                        &mut length,
                        &mut granted,
                        &mut status,
                    )
                } != 0,
            );
            require((status != 0 && granted & access == access) == expected);
        }
    }
    println!("PASS: C_FILTERED_READ_GRANTED");
    println!("PASS: C_FILTERED_WRITE_DENIED");
    let paths = objects
        .iter()
        .map(|o| (o.path.clone(), o.directory, o.size))
        .collect();
    actual_thread(token, paths);
    println!("PASS: C_GENUINE_MEDIUM_REAL_OPENS");
}
fn actual_thread(token: HANDLE, paths: Vec<(PathBuf, bool, u64)>) {
    let impersonation = duplicate(token, SecurityImpersonation);
    let raw = impersonation.0 as usize;
    let result = std::thread::spawn(move || {
        require(unsafe { SetThreadToken(null(), raw as HANDLE) } != 0);
        struct Revert;
        impl Drop for Revert {
            fn drop(&mut self) {
                if unsafe { RevertToSelf() } == 0 {
                    std::process::abort();
                }
            }
        }
        let _revert = Revert;
        let mut actual = null_mut();
        require(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut actual) } != 0);
        let actual = Handle(actual);
        require(user(actual.0) == user(raw as HANDLE));
        require(info(actual.0, TokenType)[0] as u32 == TokenImpersonation as u32);
        limited(
            actual.0,
            checked(u32::try_from(number("RTRUST_EXPLORER_SESSION"))),
        );
        for (path, directory, size) in paths {
            let read_access = if directory {
                FILE_LIST_DIRECTORY | FILE_TRAVERSE | READ_CONTROL | SYNCHRONIZE
            } else {
                FILE_GENERIC_READ
            };
            let read_handle = checked(open(&path, read_access));
            if !directory && size != 0 {
                let mut byte = 0;
                let mut count = 0;
                require(
                    unsafe { ReadFile(read_handle.0, &mut byte, 1, &mut count, null_mut()) } != 0
                        && count == 1,
                );
            }
            for access in [
                FILE_WRITE_DATA,
                FILE_APPEND_DATA,
                FILE_WRITE_EA,
                FILE_WRITE_ATTRIBUTES,
                DELETE,
                WRITE_DAC,
                WRITE_OWNER,
            ] {
                match open(&path, access) {
                    Ok(handle) => {
                        drop(handle);
                        panic!("FAIL: genuine medium write unexpectedly granted");
                    }
                    Err(code) => denied(code),
                }
            }
            if directory {
                match open(&path, FILE_DELETE_CHILD) {
                    Ok(handle) => {
                        drop(handle);
                        panic!("FAIL: genuine medium delete-child granted");
                    }
                    Err(code) => denied(code),
                }
            }
        }
    })
    .join();
    require(result.is_ok());
}
fn hash(lines: &[String]) -> u64 {
    let mut sorted = lines.to_vec();
    sorted.sort_unstable();
    sorted
        .iter()
        .flat_map(|s| s.bytes().chain(*b"\n"))
        .fold(0xcbf29ce484222325, |h, b| {
            (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
        })
}
fn numeric(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|x| x.is_ascii_digit()) && value.parse::<u64>().is_ok()
}
fn field<'a>(text: &'a str, prefix: &str) -> &'a str {
    text.strip_prefix(prefix)
        .unwrap_or_else(|| panic!("FAIL: closed journal schema"))
}
fn record(line: &str) -> Option<(u64, u32)> {
    let p: Vec<_> = line.split(' ').collect();
    require(!p.is_empty() && numeric(p[0]));
    if p.len() == 3 && p[1] == "journal_dropped" {
        require(numeric(field(p[2], "count=")));
        return None;
    }
    require(p.len() == 9 && p[2] == "connect_failed");
    let pid = field(p[1], "pid=");
    require(numeric(pid));
    require(
        ["start", "reconnect", "wake_reconnect", "socks_recovery"].contains(&field(p[3], "path=")),
    );
    require(
        [
            "endpoint_unreachable",
            "tls",
            "authentication",
            "profile",
            "timeout",
            "local_bind",
            "protocol",
            "cancelled",
            "other",
        ]
        .contains(&field(p[4], "class=")),
    );
    require(["h2", "h3", "hysteria", "amneziawg", "unknown"].contains(&field(p[5], "transport=")));
    require(
        numeric(field(p[6], "attempt="))
            && ["burst", "cooldown"].contains(&field(p[7], "budget="))
            && numeric(field(p[8], "duration_ms=")),
    );
    // A fresh candidate-created journal must contain only these synthetic B events.
    require(
        p[3] == "path=start"
            && p[4] == "class=profile"
            && p[5] == "transport=h2"
            && p[6] == "attempt=1"
            && p[7] == "budget=burst",
    );
    Some((checked(p[0].parse()), checked(pid.parse())))
}
struct Collected {
    objects: Vec<Object>,
    lines: Vec<String>,
    first: Vec<String>,
    second: Vec<String>,
}
fn collect(root: &Path, nonce: &str, p1: u32, p2: u32, trigger: u64) -> Option<Collected> {
    let leaf = root.join("logs");
    match fs::symlink_metadata(&leaf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => panic!("FAIL: installed journal metadata"),
    }
    let mut objects = vec![object(root, true, false), object(&leaf, true, true)];
    let mut names = Vec::new();
    for entry in checked(fs::read_dir(&leaf)) {
        require(names.len() < 32);
        let entry = checked(entry);
        let name = checked(entry.file_name().into_string().map_err(|_| ()));
        require(
            name == "events.log"
                || name == "events.lock"
                || name
                    .strip_prefix("events.log.")
                    .is_some_and(|s| numeric(s) && s.parse::<u64>().is_ok_and(|n| n < u64::MAX)),
        );
        names.push(name);
    }
    names.sort_unstable();
    let mut lines = Vec::new();
    let mut total = 0u64;
    for name in names {
        let object = object(&leaf.join(&name), false, true);
        require(object.size <= 1_000_000);
        total += object.size;
        require(total <= 15_000_000);
        if name == "events.lock" {
            require(object.size == 0);
        } else {
            let data = read(&object);
            require(!data.windows(nonce.len()).any(|w| w == nonce.as_bytes()));
            let text = checked(String::from_utf8(data));
            if !text.is_empty() && !text.ends_with('\n') {
                return None;
            }
            lines.extend(text.lines().map(str::to_owned));
        }
        objects.push(object);
    }
    let mut first = Vec::new();
    let mut second = Vec::new();
    for line in &lines {
        if let Some((time, pid)) = record(line) {
            require(time >= trigger);
            if pid == p1 {
                first.push(line.clone());
            } else if p2 != 0 && pid == p2 {
                second.push(line.clone());
            } else {
                panic!("FAIL: unexpected journal process");
            }
        } else {
            panic!("FAIL: unexpected dropped record");
        }
    }
    Some(Collected {
        objects,
        lines,
        first,
        second,
    })
}
fn authorization() -> (String, PathBuf) {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("FAIL: installed journal acceptance")
    }));
    let nonce = env::var("RTRUST_INSTALLED_ACCEPTANCE").unwrap_or_else(|_| {
        eprintln!("NOT RUN: installed authorization required");
        panic!("NOT RUN: installed authorization required")
    });
    require(nonce.len() == 32 && nonce.bytes().all(|b| b.is_ascii_hexdigit()));
    let stage = PathBuf::from(checked(env::var("RTRUST_INSTALLED_STAGE")));
    require(
        stage.is_absolute()
            && stage
                .file_name()
                .is_some_and(|n| n == format!("RTrustAcceptance-{nonce}").as_str()),
    );
    (nonce, stage)
}
#[test]
#[ignore = "explicit read-only installed Explorer preflight; never ordinary CI"]
fn installed_explorer_preflight() {
    let _authorized = authorization();
    let proof = std::panic::catch_unwind(|| {
        let token = explorer_token();
        let identification = duplicate(token.0, SecurityIdentification);
        require(info(identification.0, TokenType)[0] as u32 == TokenImpersonation as u32);
        actual_thread(token.0, Vec::new());
    });
    if proof.is_err() {
        println!("BLOCKED: GENUINE_EXPLORER_TOKEN_UNAVAILABLE");
        panic!("BLOCKED: genuine Explorer source/actual thread proof");
    }
    // No object access is claimed here: only genuine source/actual-thread proof.
    println!("PASS: GENUINE_EXPLORER_TOKEN_AND_ACTUAL_THREAD");
}
#[test]
#[ignore = "explicit installed-service authorization; never ordinary CI"]
fn installed_journal() {
    let (nonce, stage) = authorization();
    let phase = checked(env::var("RTRUST_INSTALLED_PHASE"));
    require(["first", "persisted", "appended"].contains(&phase.as_str()));
    let p1 = checked(u32::try_from(number("RTRUST_INSTALLED_PID1")));
    let p2 = checked(u32::try_from(number("RTRUST_INSTALLED_PID2")));
    require(p1 != 0 && (phase == "first" || (p2 != 0 && p2 != p1)));
    let trigger = number("RTRUST_INSTALLED_TRIGGER");
    let config = rtrust_journal::Config::service()
        .unwrap_or_else(|| panic!("NOT RUN: canonical folder unavailable"));
    let root = config
        .directory
        .parent()
        .unwrap_or_else(|| panic!("FAIL: canonical folder"))
        .to_owned();
    let expected = if phase == "appended" { 2 } else { 1 };
    let deadline = Instant::now() + Duration::from_secs(15);
    let collected = loop {
        if let Some(value) = collect(&root, &nonce, p1, p2, trigger) {
            require(value.lines.len() <= expected);
            if value.lines.len() == expected {
                break value;
            }
        }
        require(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(100));
    };
    require(collected.first.len() == 1 && collected.second.len() == expected - 1);
    let state = format!(
        "1 {} {} {}\n",
        collected.lines.len(),
        hash(&collected.first),
        hash(&collected.lines)
    );
    let state_path = stage.join("journal-first.state");
    if phase == "first" {
        use std::io::Write;
        let mut out = checked(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(state_path),
        );
        checked(out.write_all(state.as_bytes()));
        checked(out.sync_all());
    } else {
        let original = checked(fs::read_to_string(state_path));
        require(original.len() <= 256);
        let fields: Vec<_> = original.split_whitespace().collect();
        require(fields.len() == 4 && fields[0] == "1" && fields[1] == "1");
        require(checked(fields[2].parse::<u64>()) == hash(&collected.first));
        if phase == "persisted" {
            require(checked(fields[3].parse::<u64>()) == hash(&collected.lines));
            println!("PASS: C_RESTART_PERSISTED");
        } else {
            println!("PASS: C_APPEND_AFTER_RESTART");
        }
    }
    let token = explorer_token();
    matrix(&collected.objects, token.0);
    println!(
        "PASS: C_LINES={} C_NONMATCH=0 C_B_RECORDS={}",
        collected.lines.len(),
        expected
    );
    println!("PASS: C_CANARY_ABSENT");
    println!("PASS: INSTALLED_JOURNAL_COMPLETE");
}
