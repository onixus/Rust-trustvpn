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
                    || (matches!(owner, Owner::Root) && parent.mode() & 0o022 != 0)
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
            let meta = next.metadata()?;
            if matches!(owner, Owner::Root) && (meta.uid() != 0 || meta.mode() & 0o022 != 0) {
                return Err(denied());
            }
            if i + 1 == components.len() {
                if meta.uid() != uid {
                    return Err(denied());
                }
                if unsafe { libc::fchmod(next.as_raw_fd(), dmode) } != 0 {
                    return Err(io::Error::last_os_error());
                }
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
        if !m.is_file() || m.uid() != self.uid || m.nlink() != 1 {
            return Err(denied());
        }
        if unsafe { libc::fchmod(file.as_raw_fd(), self.mode) } != 0 {
            return Err(io::Error::last_os_error());
        }
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
