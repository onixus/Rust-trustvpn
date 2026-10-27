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
fn set_mode(file: &File, mode: u32) -> io::Result<()> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
// Existing objects may only lose permissions, even after relocation.
fn tighten(file: &File, desired: u32) -> io::Result<()> {
    set_mode(file, file.metadata()?.mode() & desired)
}
struct Policy {
    uid: u32,
    root: bool,
    directory_mode: u32,
    file_mode: u32,
}
fn replacement_mode(desired: u32, target: u32) -> u32 {
    desired & target & 0o777
}
fn exact_directory_mode(
    created: bool,
    parent_uid: u32,
    parent_mode: u32,
    uid: u32,
    mode: u32,
    desired: u32,
) -> bool {
    created && parent_uid == uid && parent_mode & 0o022 == 0 && mode & 0o7777 & !desired == 0
}
pub(crate) struct Directory {
    dir: File,
    uid: u32,
    // Desired mode for provably new files, derived from the pinned leaf.
    mode: u32,
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
        let root = matches!(owner, Owner::Root);
        Self::open_with(
            path,
            Policy {
                uid: if root { 0 } else { unsafe { libc::geteuid() } },
                root,
                directory_mode: if root { 0o755 } else { 0o700 },
                file_mode: if root { 0o644 } else { 0o600 },
            },
        )
    }
    fn open_with(path: &Path, policy: Policy) -> io::Result<Self> {
        if !path.is_absolute() || unsafe { libc::geteuid() } != policy.uid {
            return Err(denied());
        }
        let uid = policy.uid;
        let dmode = policy.directory_mode;
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
            let mut created = false;
            if fd < 0 && io::Error::last_os_error().kind() == io::ErrorKind::NotFound {
                let parent = dir.metadata()?;
                if parent.uid() != uid
                    || (policy.root && !trusted_root_component(parent.uid(), parent.mode(), false))
                {
                    return Err(denied());
                }
                if unsafe { libc::mkdirat(dir.as_raw_fd(), name.as_ptr(), dmode as libc::mode_t) }
                    == 0
                {
                    created = true;
                } else {
                    let error = io::Error::last_os_error();
                    if error.kind() != io::ErrorKind::AlreadyExists {
                        return Err(error);
                    }
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
            if policy.root && !trusted_root_component(parent.uid(), parent.mode(), false) {
                return Err(denied());
            }
            let meta = next.metadata()?;
            if policy.root
                && !trusted_root_component(meta.uid(), meta.mode(), i + 1 == components.len())
            {
                return Err(denied());
            }
            // Only an immediate parent pinned against untrusted renames proves
            // that mkdirat's entry is still the inode we just created.
            if exact_directory_mode(
                created,
                parent.uid(),
                parent.mode(),
                uid,
                meta.mode(),
                dmode,
            ) {
                if !meta.is_dir() || meta.uid() != uid {
                    return Err(denied());
                }
                set_mode(&next, dmode)?;
            } else if i + 1 == components.len() {
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
        let mode = if dir.metadata()?.mode() & 0o055 == 0o055 {
            policy.file_mode
        } else {
            0o600
        };
        Ok(Self { dir, uid, mode })
    }
    fn verify(&self, file: &File) -> io::Result<()> {
        let m = file.metadata()?;
        if !m.is_file() || m.uid() != self.uid || m.nlink() != 1 || m.mode() & 0o7000 != 0 {
            return Err(denied());
        }
        Ok(())
    }
    fn checked(&self, file: File) -> io::Result<File> {
        self.verify(&file)?;
        tighten(&file, self.mode)?;
        Ok(file)
    }
    fn created(&self, file: File, mode: u32) -> io::Result<File> {
        self.verify(&file)?;
        set_mode(&file, mode)?;
        if file.metadata()?.mode() & 0o7777 != mode {
            return Err(denied());
        }
        Ok(file)
    }
    pub fn file(&self, name: &str, create: bool) -> io::Result<File> {
        let flags =
            libc::O_RDWR | libc::O_APPEND | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC;
        let name = c(name)?;
        if create {
            let file = opened(unsafe {
                libc::openat(
                    self.dir.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_CREAT | libc::O_EXCL,
                    self.mode,
                )
            });
            match file {
                Ok(file) => return self.created(file, self.mode),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        // Existing objects never gain permission bits. A racing disappearance
        // or symlink replacement fails without a create/retry fallback.
        self.checked(opened(unsafe {
            libc::openat(self.dir.as_raw_fd(), name.as_ptr(), flags)
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
        // Rewriting private contents into a new inode must not make them public.
        // Keep the verified target pinned through the replacement, and set the
        // temporary file's final permissions before writing any copied bytes.
        let target = self.file(name, false)?;
        let mode = replacement_mode(self.mode, target.metadata()?.mode());
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
                mode,
            )
        };
        let mut file = self.created(opened(fd)?, mode)?;
        file.write_all(bytes)?;
        file.sync_data()?;
        self.rename_inner(temp, name)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{fs::PermissionsExt, process::CommandExt};

    const UMASK_PASS: &str = "PASS: restrictive umask child completed";
    const ROOT_PASS: &str =
        "PASS: opted-in native Root umask fixture and supplementary-group-free reader";

    #[test]
    fn restrictive_umask_subprocess() {
        assert_child(
            subprocess(
                "unix::tests::restrictive_umask_child",
                "RTRUST_JOURNAL_UMASK_FIXTURE",
            ),
            UMASK_PASS,
        );
    }
    #[test]
    #[ignore = "controlled child fixture, invoked by restrictive_umask_subprocess; not a native root gate"]
    fn restrictive_umask_child() {
        assert_eq!(
            std::env::var("RTRUST_JOURNAL_UMASK_FIXTURE").as_deref(),
            Ok("1")
        );
        assert_eq!(unsafe { libc::umask(0o077) }, 0o077);
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().canonicalize().unwrap();
        let path = base.join("new-parent/journal");
        let dir = Directory::open_with(&path, fixture_policy()).unwrap();
        assert_eq!(mode(path.parent().unwrap()), 0o755);
        assert_eq!(mode(&path), 0o755);
        assert_eq!(
            dir.file("events.log", true)
                .unwrap()
                .metadata()
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
        let _lock = dir.lock().unwrap();
        assert_eq!(mode(&path.join("events.lock")), 0o644);
        // A fresh public target's replacement is public too (rename preserves
        // the exact mode applied to the exclusive temporary inode).
        dir.replace("events.log", b"public synthetic\n").unwrap();
        assert_eq!(mode(&path.join("events.log")), 0o644);
        assert_eq!(
            dir.replace("missing.log", b"synthetic replacement\n")
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        assert!(!path.join("events.tmp").exists());
        std::fs::set_permissions(
            path.join("events.log"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        assert_eq!(
            dir.file("events.log", true)
                .unwrap()
                .metadata()
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        let old_inode = std::fs::metadata(path.join("events.log")).unwrap().ino();
        dir.replace("events.log", b"private synthetic\n").unwrap();
        assert_eq!(mode(&path.join("events.log")), 0o600);
        assert_ne!(
            std::fs::metadata(path.join("events.log")).unwrap().ino(),
            old_inode
        );
        assert_eq!(
            std::fs::read(path.join("events.log")).unwrap(),
            b"private synthetic\n"
        );
        let archived_inode = std::fs::metadata(path.join("events.log")).unwrap().ino();
        dir.rename("events.log", "events.old").unwrap();
        assert_eq!(mode(&path.join("events.old")), 0o600);
        assert_eq!(
            std::fs::metadata(path.join("events.old")).unwrap().ino(),
            archived_inode
        );
        dir.replace("events.old", b"private archive\n").unwrap();
        assert_eq!(mode(&path.join("events.old")), 0o600);
        assert_eq!(
            std::fs::read(path.join("events.old")).unwrap(),
            b"private archive\n"
        );
        assert_eq!(
            dir.file("events.log", true)
                .unwrap()
                .metadata()
                .unwrap()
                .mode()
                & 0o777,
            0o644
        );
        assert!(!path.join("events.tmp").exists());
        if unsafe { libc::geteuid() } != 0 {
            for restricted in [0o400, 0o000] {
                let target = path.join("restricted.log");
                std::fs::write(&target, b"private canary\n").unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(restricted))
                    .unwrap();
                assert_eq!(
                    dir.replace("restricted.log", b"must not copy\n")
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::PermissionDenied
                );
                assert_eq!(mode(&target), restricted);
                assert!(!path.join("events.tmp").exists());
                // Owner restores only this fixture to inspect the unchanged bytes.
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
                assert_eq!(std::fs::read(&target).unwrap(), b"private canary\n");
            }
        }
        for group_managed in [false, true] {
            let parent = base.join(if group_managed {
                "group-managed"
            } else {
                "protected"
            });
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(
                &parent,
                std::fs::Permissions::from_mode(if group_managed { 0o775 } else { 0o755 }),
            )
            .unwrap();
            let leaf = parent.join("private");
            if !group_managed {
                std::fs::create_dir(&leaf).unwrap();
            }
            let private = Directory::open_with(&leaf, fixture_policy()).unwrap();
            assert_eq!(mode(&leaf), 0o700);
            assert_eq!(
                private
                    .file("events.log", true)
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .mode()
                    & 0o777,
                0o600
            );
            let _lock = private.lock().unwrap();
            std::fs::set_permissions(
                leaf.join("events.log"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            private
                .replace("events.log", b"private synthetic\n")
                .unwrap();
            assert_eq!(mode(&leaf.join("events.log")), 0o600);
            assert_eq!(mode(&leaf.join("events.lock")), 0o600);
            assert_eq!(mode(&parent), if group_managed { 0o775 } else { 0o755 });
        }
        // Real public CurrentUser writer; no service/root path or global sink.
        let public = base.join("public-user");
        let destination = public.clone();
        let journal = crate::Journal::spawn(move || {
            Some(crate::Config {
                directory: destination,
                file: "events.log",
                owner: Owner::CurrentUser,
            })
        });
        journal.lifecycle("sleep");
        assert!(journal.flush(std::time::Duration::from_secs(2)));
        assert_eq!(mode(&public), 0o700);
        assert_eq!(mode(&public.join("events.log")), 0o600);
        assert_eq!(mode(&public.join("events.lock")), 0o600);
        println!("{UMASK_PASS}");
    }
    // Share the real creation/mode logic without claiming to emulate Root
    // authorization. Public Root always retains uid=0 and strict traversal.
    fn fixture_policy() -> Policy {
        Policy {
            uid: unsafe { libc::geteuid() },
            root: false,
            directory_mode: 0o755,
            file_mode: 0o644,
        }
    }
    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().mode() & 0o7777
    }
    #[test]
    fn public_root_rejects_nonroot() {
        if unsafe { libc::geteuid() } != 0 {
            let tmp = tempfile::tempdir().unwrap();
            assert_eq!(
                Directory::open(
                    &tmp.path().canonicalize().unwrap().join("root"),
                    Owner::Root
                )
                .err()
                .unwrap()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
            assert!(!tmp.path().join("root").exists());
        } else {
            eprintln!("NOT RUN: nonroot rejection assertion requires a nonroot caller");
        }
    }
    #[test]
    fn replacement_mode_decision_table() {
        for (desired, target, expected) in [
            (0o644, 0o600, 0o600),
            (0o644, 0o644, 0o644),
            (0o600, 0o644, 0o600),
            (0o644, 0o640, 0o640),
            (0o600, 0o640, 0o600),
            (0o644, 0o400, 0o400),
            (0o644, 0o000, 0o000),
            (0o644, 0o100600, 0o600),
        ] {
            assert_eq!(replacement_mode(desired, target), expected);
        }
    }
    #[test]
    fn exact_directory_decision_table() {
        for (created, parent_uid, parent_mode, new_mode, desired, expected) in [
            (true, 7, 0o755, 0o700, 0o755, true),
            (true, 7, 0o755, 0o755, 0o755, true),
            (false, 7, 0o755, 0o700, 0o755, false),
            (true, 8, 0o755, 0o700, 0o755, false),
            (true, 7, 0o775, 0o700, 0o755, false),
            (true, 7, 0o757, 0o700, 0o755, false),
            (true, 7, 0o755, 0o775, 0o755, false),
            (true, 7, 0o755, 0o2755, 0o755, false),
            (true, 7, 0o755, 0o1700, 0o755, false),
            (true, 7, 0o755, 0o4700, 0o755, false),
            (true, 7, 0o700, 0o700, 0o700, true),
            (true, 7, 0o755, 0o755, 0o700, false),
        ] {
            assert_eq!(
                exact_directory_mode(created, parent_uid, parent_mode, 7, new_mode, desired),
                expected
            );
        }
    }
    #[test]
    fn unsafe_existing_links_preserve_canary() {
        for (hardlink, name) in [false, true].into_iter().flat_map(|hardlink| {
            ["events.log", "events.lock", "events.tmp"].map(|name| (hardlink, name))
        }) {
            let tmp = tempfile::tempdir().unwrap();
            let base = tmp.path().canonicalize().unwrap();
            let path = base.join("journal");
            let dir = Directory::open_with(&path, fixture_policy()).unwrap();
            let canary = base.join("canary");
            std::fs::write(&canary, b"synthetic canary\n").unwrap();
            std::fs::set_permissions(&canary, std::fs::Permissions::from_mode(0o666)).unwrap();
            if name != "events.log" {
                dir.file("events.log", true).unwrap();
            }
            if hardlink {
                std::fs::hard_link(&canary, path.join(name)).unwrap();
            } else {
                std::os::unix::fs::symlink(&canary, path.join(name)).unwrap();
            }
            let before = std::fs::metadata(&canary).unwrap();
            match name {
                "events.log" => assert!(dir.file(name, true).is_err()),
                "events.lock" => assert!(dir.lock().is_err()),
                "events.tmp" => assert!(dir.replace("events.log", b"must not replace\n").is_err()),
                _ => unreachable!(),
            }
            let after = std::fs::metadata(&canary).unwrap();
            assert_eq!(
                (after.ino(), after.mode(), after.nlink(), after.uid()),
                (before.ino(), before.mode(), before.nlink(), before.uid())
            );
            assert_eq!(std::fs::read(&canary).unwrap(), b"synthetic canary\n");
        }
    }

    fn subprocess(name: &str, flag: &str) -> std::process::Output {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                name,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(flag, "1")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Only a syscall runs between fork and exec; never change parent umask.
        unsafe {
            child.pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
        bounded_output(child)
    }
    fn bounded_output(mut command: std::process::Command) -> std::process::Output {
        let mut child = command.spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if child.try_wait().unwrap().is_some() {
                return child.wait_with_output().unwrap();
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("fixture subprocess exceeded 30-second bound");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
    fn child_evidence(success: bool, stdout: &str, marker: &str) -> bool {
        success
            && stdout.contains("running 1 test")
            && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
            && stdout.contains(marker)
            && !stdout.contains("NOT RUN:")
    }
    fn assert_child(output: std::process::Output, marker: &str) {
        assert!(
            child_evidence(
                output.status.success(),
                &String::from_utf8_lossy(&output.stdout),
                marker,
            ),
            "child fixture lacks successful exact-one-test evidence:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    #[test]
    fn child_evidence_rejects_zero_tests_missing_marker_and_failure() {
        let complete = format!(
            "running 1 test\n{UMASK_PASS}\ntest result: ok. 1 passed; 0 failed; 0 ignored;"
        );
        assert!(child_evidence(true, &complete, UMASK_PASS));
        assert!(!child_evidence(false, &complete, UMASK_PASS));
        assert!(!child_evidence(true, &complete, ROOT_PASS));
        assert!(!child_evidence(
            true,
            &format!(
                "running 0 tests\n{UMASK_PASS}\ntest result: ok. 0 passed; 0 failed; 0 ignored;"
            ),
            UMASK_PASS,
        ));
        assert!(!child_evidence(
            true,
            &format!("{complete}\nNOT RUN:"),
            UMASK_PASS
        ));
        let output = subprocess(
            "unix::tests::nonexistent_child_filter",
            "RTRUST_JOURNAL_UNUSED",
        );
        assert!(output.status.success());
        assert!(!child_evidence(
            true,
            &String::from_utf8_lossy(&output.stdout),
            UMASK_PASS
        ));
    }
    fn native_root_ancestor(uid: u32, mode: u32, directory: bool) -> bool {
        directory && uid == 0 && matches!(mode & 0o7777, 0o555 | 0o755)
    }
    #[test]
    fn native_root_ancestor_accepts_readonly_root_without_repair() {
        assert!(native_root_ancestor(0, 0o40555, true));
        assert!(native_root_ancestor(0, 0o40755, true));
        for mode in [0o775, 0o777, 0o700, 0o1755, 0o4755] {
            assert!(!native_root_ancestor(0, mode, true));
        }
        assert!(!native_root_ancestor(1000, 0o755, true));
        assert!(!native_root_ancestor(0, 0o755, false));
    }
    #[test]
    #[ignore = "native Root fixture: requires explicit pre-existing root-owned 0755 RTRUST_JOURNAL_ROOT_BASE and euid 0"]
    fn native_root_umask_gate() {
        let _base = native_root_base();
        assert_child(
            subprocess(
                "unix::tests::native_root_umask_child",
                "RTRUST_JOURNAL_NATIVE_ROOT_CHILD",
            ),
            ROOT_PASS,
        );
    }
    fn native_root_base() -> std::path::PathBuf {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "NOT RUN: native Root fixture requires euid 0"
        );
        let base = std::path::PathBuf::from(
            std::env::var_os("RTRUST_JOURNAL_ROOT_BASE")
                .expect("NOT RUN: explicit RTRUST_JOURNAL_ROOT_BASE is missing"),
        );
        assert!(base.is_absolute(), "NOT RUN: Root base must be absolute");
        let meta = std::fs::symlink_metadata(&base).expect("NOT RUN: Root base must already exist");
        assert!(
            meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o7777 == 0o755,
            "NOT RUN: base must be a root-owned 0755 directory, not a symlink"
        );
        for ancestor in base.ancestors() {
            let meta = std::fs::symlink_metadata(ancestor).unwrap();
            assert!(
                native_root_ancestor(meta.uid(), meta.mode(), meta.is_dir()),
                "NOT RUN: ancestors must be existing root-owned, non-symlink 0555/0755 directories"
            );
        }
        // Every component is protected against unprivileged renames. Do not
        // call Directory::open on the supplied base: even a same-mode tighten
        // would fchmod an operator-owned object outside the unique fixture.
        base
    }
    fn root_append(path: &Path) {
        let mut store = crate::storage::Store::open(crate::Config {
            directory: path.to_owned(),
            file: "events.log",
            owner: Owner::Root,
        })
        .unwrap();
        let now = crate::now_ms();
        store
            .append(&format!("{now} synthetic_root_fixture\n"), now)
            .unwrap();
    }
    fn unprivileged_reader(path: &Path) -> bool {
        // Numeric synthetic test identities, not an account lookup or account
        // creation. No supplementary root/operator groups may survive.
        const UID: libc::uid_t = 60001;
        const GID: libc::gid_t = 60001;
        let mut reader = std::process::Command::new("/bin/cat");
        reader
            .arg(path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            reader.pre_exec(|| {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(GID) != 0
                    || libc::setuid(UID) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::geteuid() != UID
                    || libc::getegid() != GID
                    || libc::getgroups(0, std::ptr::null_mut()) != 0
                {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                Ok(())
            });
        }
        bounded_output(reader).status.success()
    }
    #[test]
    #[ignore = "controlled child of native_root_umask_gate; not runnable without both Root opt-in gates"]
    fn native_root_umask_child() {
        assert_eq!(
            std::env::var("RTRUST_JOURNAL_NATIVE_ROOT_CHILD").as_deref(),
            Ok("1"),
            "NOT RUN: native child requires its gated parent"
        );
        let base = native_root_base();
        assert_eq!(unsafe { libc::umask(0o077) }, 0o077);
        // Only this newly allocated unique subtree is automatically removed;
        // never recursively delete or chmod the operator-provided base.
        let fixture = tempfile::Builder::new()
            .prefix("rtrust-native-umask-")
            .tempdir_in(&base)
            .unwrap();
        std::fs::set_permissions(fixture.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let fresh = fixture.path().join("fresh");
        root_append(&fresh);
        assert_eq!(mode(&fresh), 0o755);
        for name in ["events.log", "events.lock"] {
            assert_eq!(mode(&fresh.join(name)), 0o644);
            assert!(unprivileged_reader(&fresh.join(name)));
        }
        // Private content in an otherwise public leaf remains private through
        // retention replacement; an unrelated uid must now fail to read it.
        std::fs::set_permissions(
            fresh.join("events.log"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Directory::open(&fresh, Owner::Root)
            .unwrap()
            .replace("events.log", b"private synthetic\n")
            .unwrap();
        assert_eq!(mode(&fresh.join("events.log")), 0o600);
        assert!(!unprivileged_reader(&fresh.join("events.log")));
        for group_managed in [false, true] {
            let parent = fixture
                .path()
                .join(if group_managed { "group" } else { "protected" });
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(
                &parent,
                std::fs::Permissions::from_mode(if group_managed { 0o775 } else { 0o755 }),
            )
            .unwrap();
            let leaf = parent.join("private");
            if !group_managed {
                std::fs::create_dir(&leaf).unwrap();
                std::fs::write(leaf.join("events.log"), b"private synthetic\n").unwrap();
                std::fs::write(leaf.join("events.lock"), b"").unwrap();
            }
            root_append(&leaf);
            assert_eq!(mode(&leaf), 0o700);
            for name in ["events.log", "events.lock"] {
                assert_eq!(mode(&leaf.join(name)), 0o600);
                assert!(!unprivileged_reader(&leaf.join(name)));
            }
            assert_eq!(mode(&parent), if group_managed { 0o775 } else { 0o755 });
        }
        println!("{ROOT_PASS}");
    }
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
