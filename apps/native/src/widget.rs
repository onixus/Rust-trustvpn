//! Status for the macOS widget extension (apps/macos/Widget).
//! The sandboxed widget can only read one directory, so the app publishes a
//! small JSON file there: phase, mode label and a per-launch token, never
//! profile data. Widget buttons are rtrust-widget:// links; connect and
//! disconnect require the token so a web page cannot switch the VPN.
//! The Control Center toggle posts Darwin notifications whose names contain
//! the token, so only readers of the 0600 status file can switch it.
use std::{
    fs,
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::PathBuf,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Off,
    Connecting,
    On,
    Problem,
    Disconnecting,
    Closed,
}
impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Connecting => "connecting",
            Self::On => "on",
            Self::Problem => "problem",
            Self::Disconnecting => "disconnecting",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    Open,
    Connect,
    Disconnect,
}

pub struct Publisher {
    token: String,
    last: Option<(Phase, Option<&'static str>)>,
    since: u64,
    /// Set from TUN health checks; a SOCKS failure ends the session instead.
    pub problem: bool,
    /// notify(3) registrations for the connect/disconnect names, made lazily.
    signals: Option<[i32; 2]>,
}
impl Default for Publisher {
    fn default() -> Self {
        Self {
            token: token(),
            last: None,
            since: 0,
            problem: false,
            signals: None,
        }
    }
}
impl Publisher {
    /// The toggle's request since the last call; both at once are ignored.
    pub fn signal(&mut self) -> Option<Action> {
        if self.token.is_empty() {
            return None;
        }
        let signals = *self.signals.get_or_insert_with(|| {
            ["connect", "disconnect"].map(|a| register(&notification_name(&self.token, a)))
        });
        match signals.map(posted) {
            [true, false] => Some(Action::Connect),
            [false, true] => Some(Action::Disconnect),
            _ => None,
        }
    }
    /// Cheap when unchanged; called from the UI tick.
    pub fn publish(&mut self, phase: Phase, mode: Option<&'static str>) {
        if self.last == Some((phase, mode)) {
            return;
        }
        // Keep the connection start time across On <-> Problem flaps.
        let connected = |p: Option<Phase>| matches!(p, Some(Phase::On | Phase::Problem));
        if !(connected(Some(phase)) && connected(self.last.map(|l| l.0))) {
            self.since = now();
        }
        self.last = Some((phase, mode));
        if write(&status_json(phase, mode, self.since, &self.token)).is_ok() {
            PUBLISHED.store(true, std::sync::atomic::Ordering::Relaxed);
            reload();
        }
    }
    /// None for malformed links and actions with a wrong token.
    pub fn action(&self, link: &str) -> Option<Action> {
        let url = url::Url::parse(link).ok()?;
        if url.scheme() != "rtrust-widget" {
            return None;
        }
        let token = url.query_pairs().find(|(k, _)| k == "t").map(|(_, v)| v);
        let valid = token.is_some_and(|t| same(t.as_bytes(), self.token.as_bytes()));
        match url.host_str()? {
            "open" => Some(Action::Open),
            "connect" if valid => Some(Action::Connect),
            "disconnect" if valid => Some(Action::Disconnect),
            _ => None,
        }
    }
}

fn status_json(phase: Phase, mode: Option<&str>, since: u64, token: &str) -> String {
    // Mode labels are fixed strings without quotes; no escaping is needed.
    let mode = mode.map_or("null".into(), |m| format!("\"{m}\""));
    format!(
        "{{\"version\":1,\"phase\":\"{}\",\"mode\":{mode},\"since\":{since},\"token\":\"{token}\"}}",
        phase.name()
    )
}

unsafe extern "C" {
    fn syslog(priority: i32, format: *const std::ffi::c_char, ...);
}

/// Unified log entry (process rtrust-native) for widget actions; never the token.
pub fn log(message: &str) {
    if let Ok(message) = std::ffi::CString::new(format!("widget: {message}")) {
        unsafe { syslog(5, c"%s".as_ptr(), message.as_ptr()) }; // LOG_NOTICE
    }
}

/// Must match SetVPNIntent.perform in VPNWidget.swift.
fn notification_name(token: &str, action: &str) -> String {
    format!("org.rtrusttunnel.Native.{token}.{action}")
}

unsafe extern "C" {
    fn notify_register_check(name: *const std::ffi::c_char, token: *mut i32) -> u32;
    fn notify_check(token: i32, check: *mut i32) -> u32;
}

fn register(name: &str) -> i32 {
    let Ok(name) = std::ffi::CString::new(name) else {
        return -1;
    };
    let mut token = -1;
    if unsafe { notify_register_check(name.as_ptr(), &mut token) } != 0 {
        return -1;
    }
    posted(token); // The first check always reports a change.
    token
}

fn posted(token: i32) -> bool {
    let mut check = 0;
    token >= 0 && unsafe { notify_check(token, &mut check) } == 0 && check != 0
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn token() -> String {
    let mut bytes = [0u8; 16];
    // Without randomness the token stays empty and every action is refused.
    if fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut bytes))
        .is_err()
    {
        return String::new();
    }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && !b.is_empty() && a.iter().zip(b).fold(0, |d, (x, y)| d | (x ^ y)) == 0
}

/// Must match StatusFile.url in VPNWidget.swift and the widget entitlement.
fn directory() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/Application Support/org.rtrusttunnel.Native/Widget"))
}

fn write(contents: &str) -> std::io::Result<()> {
    let directory = directory().ok_or(std::io::ErrorKind::NotFound)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)?;
    let temporary = directory.join(".status.json.tmp");
    let _ = fs::remove_file(&temporary);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(contents.as_bytes())?;
    drop(file);
    fs::rename(temporary, directory.join("status.json"))
}

static PUBLISHED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Marks the widget as closed when the app exits normally; CI and preview
/// runs never published anything and leave the file alone.
pub fn closed() {
    if PUBLISHED.load(std::sync::atomic::Ordering::Relaxed)
        && write(&status_json(Phase::Closed, None, now(), "")).is_ok()
    {
        reload();
    }
}

unsafe extern "C" {
    fn dlopen(path: *const std::ffi::c_char, mode: i32) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, name: *const std::ffi::c_char)
    -> *mut std::ffi::c_void;
}

/// WidgetKit is Swift-only; the packaged app carries a tiny Swift bridge in
/// Contents/Frameworks. Without it (cargo run, older packages) the widget
/// still refreshes on its own schedule.
fn reload() {
    static BRIDGE: std::sync::OnceLock<Option<extern "C" fn()>> = std::sync::OnceLock::new();
    let bridge = BRIDGE.get_or_init(|| {
        let path = std::env::current_exe()
            .ok()?
            .parent()?
            .join("../Frameworks/libRTrustWidgetBridge.dylib");
        let path = std::ffi::CString::new(path.into_os_string().into_encoded_bytes()).ok()?;
        unsafe {
            let handle = dlopen(path.as_ptr(), 2); // RTLD_NOW
            if handle.is_null() {
                return None;
            }
            let symbol = dlsym(handle, c"rtrust_widget_reload".as_ptr());
            (!symbol.is_null())
                .then(|| std::mem::transmute::<*mut std::ffi::c_void, extern "C" fn()>(symbol))
        }
    });
    if let Some(reload) = bridge {
        reload();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publisher() -> Publisher {
        Publisher {
            token: "0123456789abcdef0123456789abcdef".into(),
            last: None,
            since: 0,
            problem: false,
            signals: None,
        }
    }

    #[test]
    fn toggle_notifications_carry_the_token() {
        unsafe extern "C" {
            fn notify_post(name: *const std::ffi::c_char) -> u32;
        }
        let post = |name: &str| unsafe {
            notify_post(std::ffi::CString::new(name).unwrap().as_ptr());
        };
        // notifyd delivers asynchronously; the app polls every 250 ms anyway.
        let settle = |p: &mut Publisher| {
            std::thread::sleep(std::time::Duration::from_millis(200));
            p.signal()
        };
        let mut p = Publisher {
            token: token(),
            ..publisher()
        };
        assert_eq!(p.signal(), None);
        post(&notification_name(&p.token, "connect"));
        post(&notification_name(
            "0123456789abcdef0123456789abcdef",
            "disconnect",
        ));
        assert_eq!(settle(&mut p), Some(Action::Connect));
        assert_eq!(p.signal(), None);
        post(&notification_name(&p.token, "disconnect"));
        assert_eq!(settle(&mut p), Some(Action::Disconnect));
        post(&notification_name(&p.token, "connect"));
        post(&notification_name(&p.token, "disconnect"));
        assert_eq!(settle(&mut p), None);
    }

    #[test]
    fn actions_require_the_launch_token() {
        let p = publisher();
        let t = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            p.action(&format!("rtrust-widget://connect?t={t}")),
            Some(Action::Connect)
        );
        assert_eq!(
            p.action(&format!("rtrust-widget://disconnect?t={t}")),
            Some(Action::Disconnect)
        );
        assert_eq!(
            p.action("rtrust-widget://connect?t=00000000000000000000000000000000"),
            None
        );
        assert_eq!(p.action("rtrust-widget://disconnect"), None);
        assert_eq!(p.action(&format!("tt://connect?t={t}")), None);
        assert_eq!(p.action("rtrust-widget://open"), Some(Action::Open));
        assert_eq!(p.action("rtrust-widget://unknown"), None);
        let empty = Publisher {
            token: String::new(),
            ..publisher()
        };
        assert_eq!(empty.action("rtrust-widget://connect?t="), None);
    }

    #[test]
    fn status_has_no_profile_fields() {
        let json = status_json(Phase::On, Some("Весь компьютер"), 7, "ab");
        assert_eq!(
            json,
            r#"{"version":1,"phase":"on","mode":"Весь компьютер","since":7,"token":"ab"}"#
        );
        assert!(status_json(Phase::Off, None, 0, "").contains(r#""mode":null"#));
        assert_eq!(token().len(), 32);
    }
}
