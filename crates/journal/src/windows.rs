//! Native path and ACL handling. Never use environment ProgramData or follow reparses.
use crate::Owner;
use std::{
    ffi::{OsStr, OsString, c_void},
    fs::{File, OpenOptions},
    io::{self, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
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
            Some(sid) => format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{sid})"),
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
    fn verify_repair(&self, file: &File) -> io::Result<()> {
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
                        | if application {
                            READ_CONTROL | WRITE_DAC
                        } else {
                            0
                        },
                )
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&current)?;
            info(&file, true)?;
            if application {
                security.verify_repair(&file)?;
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
        self.security.verify_repair(&file)?;
        Ok(file)
    }
    pub fn file(&self, name: &str, create: bool) -> io::Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(create)
            .access_mode(FILE_GENERIC_READ | FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(name))?;
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
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .share_mode(0)
            .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | READ_CONTROL | WRITE_DAC)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join("events.lock"))?;
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
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .access_mode(FILE_GENERIC_WRITE | FILE_GENERIC_READ | READ_CONTROL | WRITE_DAC)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(self.path.join(tmp))?;
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
