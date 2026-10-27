use crate::Owner;
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "unsafe journal object")
}
// Root-managed intermediate groups (e.g. root:syslog /var/log 0775)
// already control that namespace. Never accept foreign owners, other-write,
// symlinks, or group-write on the final journal directory.
fn trusted_root_component(uid: u32, mode: u32, leaf: bool) -> bool {
    uid == 0 && mode & (if leaf { 0o7022 } else { 0o002 }) == 0
}
fn c(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| denied())
}
fn opened(fd: i32) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}
// Never widen a relocated private object's permissions in a group-managed namespace.
fn tighten(file: &File, desired: libc::mode_t) -> io::Result<()> {
    // mode_t is u16 on macOS and u32 on Linux; keep this mask portable.
    #[allow(clippy::unnecessary_cast)]
    let mode = (file.metadata()?.mode() & desired as u32) as libc::mode_t;
    if unsafe { libc::fchmod(file.as_raw_fd(), mode) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
pub(crate) struct Directory {
    dir: File,
    uid: u32,
    mode: libc::mode_t,
}
pub(crate) struct Lock(File);
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
impl Directory {
    pub fn open(path: &Path, owner: Owner) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(denied());
        }
        let uid = match owner {
            Owner::Root => 0,
            Owner::CurrentUser => unsafe { libc::geteuid() },
        };
        if unsafe { libc::geteuid() } != uid {
            return Err(denied());
        }
        let dmode = if matches!(owner, Owner::Root) {
            0o755
        } else {
            0o700
        };
        let mut dir = opened(unsafe {
            libc::open(
                c("/")?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let components: Vec<_> = path
            .components()
            .filter(|c| !matches!(c, Component::RootDir))
            .collect();
        for (i, part) in components.iter().enumerate() {
            let Component::Normal(part) = part else {
                return Err(denied());
            };
            let name = CString::new(part.as_bytes()).map_err(|_| denied())?;
            let mut fd = unsafe {
                libc::openat(
                    dir.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                let parent = dir.metadata()?;
                if parent.uid() != uid
                    || (matches!(owner, Owner::Root)
                        && !trusted_root_component(parent.uid(), parent.mode(), false))
                {
                    return Err(denied());
                }
                if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), dmode) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                fd = unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
            }
            let next = opened(fd)?;
            let parent = dir.metadata()?;
            if matches!(owner, Owner::Root)
                && !trusted_root_component(parent.uid(), parent.mode(), false)
            {
                return Err(denied());
            }
            let meta = next.metadata()?;
            if matches!(owner, Owner::Root)
                && !trusted_root_component(meta.uid(), meta.mode(), i + 1 == components.len())
            {
                return Err(denied());
            }
            if i + 1 == components.len() {
                if meta.uid() != uid {
                    return Err(denied());
                }
                tighten(&next, dmode)?;
            }
            dir = next;
        }
        if components.is_empty() {
            return Err(denied());
        }
        Ok(Self {
            dir,
            uid,
            mode: if matches!(owner, Owner::Root) {
                0o644
            } else {
                0o600
            },
        })
    }
    fn checked(&self, file: File) -> io::Result<File> {
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != self.uid || m.nlink() != 1 || m.mode() & 0o7000 != 0 {
            return Err(denied());
        }
        tighten(&file, self.mode)?;
        Ok(file)
    }
    pub fn file(&self, name: &str, create: bool) -> io::Result<File> {
        let flags = libc::O_RDWR
            | libc::O_APPEND
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_CLOEXEC
            | if create { libc::O_CREAT } else { 0 };
        self.checked(opened(unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c(name)?.as_ptr(),
                flags,
                self.mode as libc::c_uint,
            )
        })?)
    }
    pub fn names(&self) -> io::Result<Vec<String>> {
        // An independent open description: readdir must not retain an old offset.
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c(".")?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { libc::fdopendir(fd) };
        if stream.is_null() {
            unsafe {
                libc::close(fd);
            }
            return Err(io::Error::last_os_error());
        }
        let mut names = Vec::new();
        loop {
            let entry = unsafe { libc::readdir(stream) };
            if entry.is_null() {
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if let Ok(name) = name.to_str() {
                names.push(name.to_owned());
            }
            if names.len() > 4096 {
                unsafe {
                    libc::closedir(stream);
                }
                return Err(denied());
            }
        }
        unsafe {
            libc::closedir(stream);
        }
        Ok(names)
    }
    pub fn lock(&self) -> io::Result<Lock> {
        let file = self.file("events.lock", true)?;
        // No unbounded wait. A busy cross-process writer simply drops this event.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Lock(file))
    }
    pub fn remove(&self, name: &str) -> io::Result<()> {
        let _verified = self.file(name, false)?;
        if unsafe { libc::unlinkat(self.dir.as_raw_fd(), c(name)?.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        let _verified = self.file(from, false)?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                self.dir.as_raw_fd(),
                c(to)?.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(denied());
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::NotFound {
            return Err(io::Error::last_os_error());
        }
        self.rename_inner(from, to)
    }
    fn rename_inner(&self, from: &str, to: &str) -> io::Result<()> {
        if unsafe {
            libc::renameat(
                self.dir.as_raw_fd(),
                c(from)?.as_ptr(),
                self.dir.as_raw_fd(),
                c(to)?.as_ptr(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    pub fn replace(&self, name: &str, bytes: &[u8]) -> io::Result<()> {
        let temp = "events.tmp";
        // Only a verified regular, same-owner, single-link stale temp is removed.
        match self.file(temp, false) {
            Ok(_) => self.remove(temp)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let fd = unsafe {
            libc::openat(
                self.dir.as_raw_fd(),
                c(temp)?.as_ptr(),
                libc::O_WRONLY
                    | libc::O_CREAT
                    | libc::O_EXCL
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                self.mode as libc::c_uint,
            )
        };
        let mut file = self.checked(opened(fd)?)?;
        file.write_all(bytes)?;
        file.sync_data()?;
        let _target = self.file(name, false)?;
        self.rename_inner(temp, name)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trusted_root_policy_accepts_group_managed_intermediates_not_leaves() {
        assert!(trusted_root_component(0, 0o775, false));
        assert!(trusted_root_component(0, 0o755, true));
        assert!(trusted_root_component(0, 0o700, true));
        assert!(!trusted_root_component(0, 0o2755, true));
        assert!(!trusted_root_component(0, 0o1755, true));
        assert!(!trusted_root_component(0, 0o4755, true));
        assert!(!trusted_root_component(0, 0o775, true));
        assert!(!trusted_root_component(501, 0o755, false));
        assert!(!trusted_root_component(0, 0o777, false));
    }
    #[test]
    fn relocated_private_objects_are_never_made_more_readable() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let private = tmp.path().join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = File::open(&private).unwrap();
        tighten(&dir, 0o755).unwrap();
        assert_eq!(dir.metadata().unwrap().mode() & 0o777, 0o700);
        let private_file = private.join("events.log");
        let file = File::create(private_file).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        tighten(&file, 0o644).unwrap();
        assert_eq!(file.metadata().unwrap().mode() & 0o777, 0o600);
    }
    #[test]
    fn real_intermediate_permissions_are_not_repaired() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let intermediate = tmp.path().canonicalize().unwrap().join("group-managed");
        std::fs::create_dir(&intermediate).unwrap();
        std::fs::set_permissions(&intermediate, std::fs::Permissions::from_mode(0o775)).unwrap();
        let _dir = Directory::open(&intermediate.join("journal"), Owner::CurrentUser).unwrap();
        assert_eq!(
            std::fs::metadata(intermediate).unwrap().mode() & 0o777,
            0o775
        );
    }
}
