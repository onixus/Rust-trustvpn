//! Native path and ACL handling. Never use environment ProgramData or follow reparses.
use crate::Owner;
use std::{
    ffi::{OsStr, OsString, c_void},
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, INVALID_HANDLE_VALUE, LocalFree},
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        Com::CoTaskMemFree,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
    UI::Shell::{FOLDERID_LocalAppData, FOLDERID_ProgramData, SHGetKnownFolderPath},
};
fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe journal object")
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
unsafe fn sid_text(sid: PSID) -> io::Result<String> {
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = Local(text.cast());
    let mut n = 0;
    while unsafe { *text.add(n) } != 0 {
        n += 1;
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(text, n)
    }))
}
fn user_sid() -> io::Result<String> {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut size = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
        // u64 backing gives TOKEN_USER its required alignment.
        let mut data = vec![0u64; (size as usize).div_ceil(8)];
        let ok = GetTokenInformation(token, TokenUser, data.as_mut_ptr().cast(), size, &mut size);
        CloseHandle(token);
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        sid_text((*(data.as_ptr().cast::<TOKEN_USER>())).User.Sid)
    }
}
pub fn known_folder(user: bool) -> Option<PathBuf> {
    unsafe {
        let mut p = null_mut();
        let id = if user {
            &FOLDERID_LocalAppData
        } else {
            &FOLDERID_ProgramData
        };
        if SHGetKnownFolderPath(id, 0, null_mut(), &mut p) < 0 {
            return None;
        }
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        let path = PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(p, n)));
        CoTaskMemFree(p.cast());
        Some(path)
    }
}
struct Security {
    descriptor: Local,
    user: Option<String>,
}
impl Security {
    fn new(owner: Owner) -> io::Result<Self> {
        let user = if matches!(owner, Owner::CurrentUser) {
            Some(user_sid()?)
        } else {
            None
        };
        let sddl = match &user {
            Some(sid) => format!("O:{sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"),
            None => "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)".into(),
        };
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(&sddl)).as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: Local(descriptor),
            user,
        })
    }
    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: 0,
        }
    }
    fn open_file(
        &self,
        path: &Path,
        access: u32,
        share: u32,
        disposition: u32,
    ) -> io::Result<File> {
        let attributes = self.attributes();
        let handle = unsafe {
            CreateFileW(
                wide(path.as_os_str()).as_ptr(),
                access,
                share,
                &attributes,
                disposition,
                FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }
    fn verify_repair(&self, file: &File, repair: bool) -> io::Result<()> {
        unsafe {
            let mut owner = null_mut();
            let mut descriptor = null_mut();
            let code = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            );
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            let _allocation = Local(descriptor);
            let sid = sid_text(owner)?;
            let trusted = match &self.user {
                Some(user) => sid == *user,
                None => sid == "S-1-5-18" || sid == "S-1-5-32-544",
            };
            if !trusted {
                return Err(denied());
            }
            if !repair {
                return Ok(());
            }
            let mut present = 0;
            let mut defaulted = 0;
            let mut acl = null_mut();
            if GetSecurityDescriptorDacl(self.descriptor.0, &mut present, &mut acl, &mut defaulted)
                == 0
                || present == 0
                || acl.is_null()
            {
                return Err(denied());
            }
            let code = SetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl,
                null(),
            );
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            Ok(())
        }
    }
}
fn info(file: &File, dir: bool) -> io::Result<()> {
    let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let info = unsafe { info.assume_init() };
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != dir
        || (!dir && info.nNumberOfLinks != 1)
    {
        return Err(denied());
    }
    Ok(())
}
pub(crate) struct Directory {
    path: PathBuf,
    security: Security,
    _parents: Vec<File>,
}
pub(crate) struct Lock {
    _file: File,
}
impl Directory {
    pub fn open(path: &Path, owner: Owner) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(denied());
        }
        let security = Security::new(owner)?;
        let mut parents = Vec::new();
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            if current.parent().is_none() {
                continue;
            }
            if !current.exists() {
                let attrs = security.attributes();
                if unsafe { CreateDirectoryW(wide(current.as_os_str()).as_ptr(), &attrs) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let application =
                current == path || current.file_name() == Some(OsStr::new("R-TrustTunnel"));
            let file = OpenOptions::new()
                .access_mode(
                    FILE_READ_ATTRIBUTES
                        | FILE_LIST_DIRECTORY
                        | if application { READ_CONTROL } else { 0 }
                        | if current == path { WRITE_DAC } else { 0 },
                )
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&current)?;
            info(&file, true)?;
            if application {
                security.verify_repair(&file, current == path)?;
            }
            parents.push(file);
        }
        Ok(Self {
            path: path.into(),
            security,
            _parents: parents,
        })
    }
    fn checked(&self, file: File) -> io::Result<File> {
        info(&file, false)?;
        self.security.verify_repair(&file, true)?;
        Ok(file)
    }
    pub fn file(&self, name: &str, create: bool) -> io::Result<File> {
        let file = self.security.open_file(
            &self.path.join(name),
            FILE_GENERIC_READ | FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create { OPEN_ALWAYS } else { OPEN_EXISTING },
        )?;
        self.checked(file)
    }
    pub fn names(&self) -> io::Result<Vec<String>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            if out.len() >= 4096 {
                return Err(denied());
            }
            if let Some(s) = entry?.file_name().to_str() {
                out.push(s.to_owned());
            }
        }
        Ok(out)
    }
    pub fn lock(&self) -> io::Result<Lock> {
        let f = self.security.open_file(
            &self.path.join("events.lock"),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
            0,
            OPEN_ALWAYS,
        )?;
        Ok(Lock {
            _file: self.checked(f)?,
        })
    }
    pub fn remove(&self, name: &str) -> io::Result<()> {
        drop(self.file(name, false)?);
        std::fs::remove_file(self.path.join(name))
    }
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        drop(self.file(from, false)?);
        if std::fs::symlink_metadata(self.path.join(to)).is_ok() {
            return Err(denied());
        }
        std::fs::rename(self.path.join(from), self.path.join(to))
    }
    pub fn replace(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let tmp = "events.tmp";
        match self.file(tmp, false) {
            Ok(f) => {
                drop(f);
                self.remove(tmp)?;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let file = self.security.open_file(
            &self.path.join(tmp),
            FILE_GENERIC_WRITE | FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            CREATE_NEW,
        )?;
        let mut file = self.checked(file)?;
        file.write_all(bytes)?;
        file.sync_data()?;
        drop(file);
        drop(self.file(name, false)?);
        // MoveFileEx supports atomic replacement while retained directory handles
        // prevent directory substitution. Only verified owned files are touched.
        if unsafe {
            MoveFileExW(
                wide(self.path.join(tmp).as_os_str()).as_ptr(),
                wide(self.path.join(name).as_os_str()).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::MetadataExt;
    fn inspect(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
    }
    fn security_info(file: &File) -> io::Result<(String, bool, Vec<u8>)> {
        unsafe {
            let mut owner = null_mut();
            let mut acl = null_mut();
            let mut descriptor = null_mut();
            let code = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            );
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code as i32));
            }
            let _allocation = Local(descriptor);
            let mut control = 0;
            let mut revision = 0;
            if GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) == 0 {
                return Err(io::Error::last_os_error());
            }
            let acl = if acl.is_null() {
                Vec::new()
            } else {
                std::slice::from_raw_parts(acl.cast::<u8>(), (*acl).AclSize as usize).to_vec()
            };
            Ok((sid_text(owner)?, control & SE_DACL_PROTECTED != 0, acl))
        }
    }
    fn token_owner() -> io::Result<String> {
        unsafe {
            let mut token = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut size = 0;
            GetTokenInformation(token, TokenOwner, null_mut(), 0, &mut size);
            let mut data = vec![0u64; (size as usize).div_ceil(8)];
            let ok =
                GetTokenInformation(token, TokenOwner, data.as_mut_ptr().cast(), size, &mut size);
            CloseHandle(token);
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            sid_text((*(data.as_ptr().cast::<TOKEN_OWNER>())).Owner)
        }
    }
    fn custom_security(sddl: &str) -> Security {
        let mut descriptor = null_mut();
        assert!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(OsStr::new(sddl)).as_ptr(),
                    1,
                    &mut descriptor,
                    null_mut(),
                )
            } != 0,
            "synthetic descriptor construction failed"
        );
        Security {
            descriptor: Local(descriptor),
            user: Some(user_sid().unwrap()),
        }
    }
    #[test]
    fn native_creation_owner_diagnostics_and_protected_leaf_files() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let user = user_sid().unwrap();
        let default_owner = token_owner().unwrap();
        let default_leaf = base.join("default-owner");
        std::fs::create_dir(&default_leaf).unwrap();
        let (owner, _, _) = security_info(&inspect(&default_leaf).unwrap()).unwrap();
        let any_ancestor_reparse = base
            .ancestors()
            .filter_map(|p| std::fs::symlink_metadata(p).ok())
            .any(|m| m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0);
        eprintln!(
            "token_owner_is_token_user={} default_leaf_owner_is_token_user={} default_leaf_owner_is_token_owner={} any_ancestor_reparse={}",
            default_owner == user,
            owner == user,
            owner == default_owner,
            any_ancestor_reparse
        );
        let path = base.join("journal");
        let result = Directory::open(&path, Owner::CurrentUser);
        let leaf = inspect(&path).unwrap();
        let (owner, protected, _) = security_info(&leaf).unwrap();
        eprintln!(
            "fresh_leaf_owner_is_token_user={} fresh_leaf_owner_is_token_owner={} reject_was_owner={} reject_was_attr={}",
            owner == user,
            owner == default_owner,
            result.is_err() && owner != user,
            result.is_err() && info(&leaf, true).is_err()
        );
        let dir = result.unwrap();
        assert!(owner == user, "fresh journal owner must be TokenUser");
        assert!(protected);
        let event = dir.file("events.log", true).unwrap();
        let lock = dir.lock().unwrap();
        let temporary = dir
            .security
            .open_file(
                &path.join("events.tmp"),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                CREATE_NEW,
            )
            .unwrap();
        let temporary = dir.checked(temporary).unwrap();
        for file in [&event, &lock._file, &temporary] {
            let (owner, protected, _) = security_info(file).unwrap();
            assert!(owner == user, "new journal file owner must be TokenUser");
            assert!(protected);
        }
    }
    #[test]
    fn native_parent_acl_is_unchanged_and_parent_rename_is_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let app = base.join("R-TrustTunnel");
        let user = user_sid().unwrap();
        let parent_security = custom_security(&format!(
            "O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})(A;OICI;FR;;;BA)"
        ));
        assert!(
            unsafe {
                CreateDirectoryW(
                    wide(app.as_os_str()).as_ptr(),
                    &parent_security.attributes(),
                )
            } != 0
        );
        let parent = inspect(&app).unwrap();
        let (_, protected_before, acl_before) = security_info(&parent).unwrap();
        let dir = Directory::open(&app.join("journal"), Owner::CurrentUser).unwrap();
        let (_, protected_after, acl_after) = security_info(&parent).unwrap();
        assert!(
            protected_before && protected_after && acl_before == acl_after,
            "journal must not repair ancestor ACLs"
        );
        assert!(
            std::fs::rename(&app, base.join("moved")).is_err(),
            "retained directory handles must prevent parent rename"
        );
        drop(dir);
        std::fs::rename(&app, base.join("moved")).unwrap();
    }
    #[test]
    fn native_foreign_owner_is_rejected_without_taking_ownership() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().canonicalize().unwrap().join("foreign");
        let user = user_sid().unwrap();
        let security = custom_security(&format!("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"));
        if unsafe { CreateDirectoryW(wide(path.as_os_str()).as_ptr(), &security.attributes()) } == 0
        {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(5 | 1307 | 1314)) {
                eprintln!(
                    "NOT RUN: creating synthetic foreign-owner directory requires unavailable token privilege"
                );
                return;
            }
            panic!("foreign-owner fixture creation failed: {error}");
        }
        let file = inspect(&path).unwrap();
        let (before, _, acl_before) = security_info(&file).unwrap();
        assert!(
            before != user,
            "foreign fixture must actually have foreign owner"
        );
        assert!(Directory::open(&path, Owner::CurrentUser).is_err());
        let (after, _, acl_after) = security_info(&file).unwrap();
        assert!(
            before == after && acl_before == acl_after,
            "foreign objects must remain untouched"
        );
        let directory = Directory::open(
            &tmp.path().canonicalize().unwrap().join("safe"),
            Owner::CurrentUser,
        )
        .unwrap();
        let file = security
            .open_file(
                &directory.path.join("events.log"),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                CREATE_NEW,
            )
            .unwrap();
        let (before, _, acl_before) = security_info(&file).unwrap();
        assert!(
            before != user,
            "foreign file fixture must have foreign owner"
        );
        assert!(directory.file("events.log", false).is_err());
        let (after, _, acl_after) = security_info(&file).unwrap();
        assert!(
            before == after && acl_before == acl_after,
            "foreign files must remain untouched"
        );
    }
}
