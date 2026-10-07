//! Bounded local diagnostics. Never log profiles, requests, or credentials.
use std::{
    fs::{OpenOptions, Permissions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
static WRITER: Mutex<()> = Mutex::new(());
pub(super) fn record(event: &str) {
    if unsafe { libc::geteuid() } != 0 {
        return;
    }
    let Ok(_lock) = WRITER.lock() else {
        return;
    };
    let Ok(mut file) = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open("/private/var/run/rtrust/events.log")
    else {
        return;
    };
    let Ok(metadata) = file.metadata() else {
        return;
    };
    if !metadata.is_file() || metadata.uid() != 0 || metadata.nlink() != 1 {
        return;
    }
    // launchd uses umask 0077. Diagnostics contain only redacted lifecycle
    // events and must be readable by the desktop user after an IPC failure.
    if file.set_permissions(Permissions::from_mode(0o644)).is_err() {
        return;
    }
    if metadata.len() > 262144 && file.set_len(0).is_err() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let event: String = event
        .chars()
        .take(1024)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let _ = writeln!(file, "{now} pid={} {event}", std::process::id());
}
