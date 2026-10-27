//! Best-effort local diagnostics. Connection failures have a closed, typed schema.
//! No filesystem operations, waits for locks, or raw error formatting on producers.
use std::{
    error::Error,
    path::PathBuf,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
mod storage;
#[cfg(test)]
mod tests;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
pub use rtrust_engine::PlannedTransport as Transport;

macro_rules! tokens {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $name { $($variant),+ }
        impl $name { pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $text),+ } } }
    }
}
tokens!(Class {
    EndpointUnreachable => "endpoint_unreachable", Tls => "tls", Authentication => "authentication",
    Profile => "profile", Timeout => "timeout", LocalBind => "local_bind", Protocol => "protocol",
    Cancelled => "cancelled", Other => "other"
});
tokens!(Path { Start => "start", Reconnect => "reconnect", WakeReconnect => "wake_reconnect", SocksRecovery => "socks_recovery" });
tokens!(Budget { Burst => "burst", Cooldown => "cooldown" });
impl Budget {
    pub fn from_cooling(cooling: bool) -> Self {
        if cooling { Self::Cooldown } else { Self::Burst }
    }
}
pub fn transport_token(transport: Transport) -> &'static str {
    match transport {
        Transport::H2 => "h2",
        Transport::H3 => "h3",
        Transport::Hysteria => "hysteria",
        Transport::AmneziaWg => "amneziawg",
        Transport::Unknown => "unknown",
    }
}
/// Exhaustive match: new engine errors require an explicit privacy-safe decision.
pub fn classify(error: &rtrust_engine::Error) -> Class {
    use rtrust_engine::{Close, Error as E};
    match error {
        E::LocalBind => Class::LocalBind,
        E::Profile | E::Unsupported(_) | E::Destination => Class::Profile,
        E::Trust | E::Tls | E::Closed(Close::Tls) => Class::Tls,
        E::Authentication => Class::Authentication,
        E::ConnectIo(std::io::ErrorKind::TimedOut)
        | E::Closed(Close::Io(std::io::ErrorKind::TimedOut)) => Class::Timeout,
        E::Connect | E::ConnectIo(_) => Class::EndpointUnreachable,
        E::Closed(Close::QuicTransport { code, .. }) if (0x100..=0x1ff).contains(code) => {
            Class::Tls
        }
        E::Closed(
            Close::GoAway { .. } | Close::QuicApplication(_) | Close::QuicTransport { .. },
        ) => Class::Protocol,
        E::Timeout | E::Closed(Close::IdleTimeout) => Class::Timeout,
        E::Protocol | E::Rejected(_) | E::Credit => Class::Protocol,
        E::Closed(Close::Local) => Class::Cancelled,
        E::Io | E::Degraded { .. } | E::Closed(_) => Class::Other,
    }
}
pub fn classify_boxed(error: &(dyn Error + 'static)) -> Class {
    if let Some(e) = error.downcast_ref::<rtrust_engine::Error>() {
        return classify(e);
    }
    if let Some(e) = error.downcast_ref::<std::io::Error>() {
        return match e.kind() {
            std::io::ErrorKind::TimedOut => Class::Timeout,
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::NotConnected
            | std::io::ErrorKind::AddrNotAvailable => Class::EndpointUnreachable,
            std::io::ErrorKind::AddrInUse => Class::LocalBind,
            _ => Class::Other,
        };
    }
    Class::Other
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub time: u64,
    pub pid: u32,
    pub path: Path,
    pub class: Class,
    pub transport: Transport,
    pub attempt: u32,
    pub budget: Budget,
    pub duration_ms: u64,
}
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}
impl Record {
    pub fn failure(
        path: Path,
        class: Class,
        transport: Transport,
        attempt: u32,
        budget: Budget,
        duration: Duration,
    ) -> Self {
        Self {
            time: now_ms(),
            pid: std::process::id(),
            path,
            class,
            transport,
            attempt,
            budget,
            duration_ms: duration.as_millis().min(u64::MAX as u128) as u64,
        }
    }
    fn line(self) -> String {
        format!(
            "{} pid={} connect_failed path={} class={} transport={} attempt={} budget={} duration_ms={}\n",
            self.time,
            self.pid,
            self.path.as_str(),
            self.class.as_str(),
            transport_token(self.transport),
            self.attempt,
            self.budget.as_str(),
            self.duration_ms
        )
    }
}
/// Records once on explicit failure or cancellation/drop; successful and superseded
/// attempts are disarmed. The guard contains no credentials or error strings.
pub struct Attempt {
    record: Option<Record>,
    started: Instant,
    sink: Option<Arc<Journal>>,
}
impl Attempt {
    pub fn new(path: Path, transport: Transport, attempt: u32, budget: Budget) -> Self {
        Self {
            record: Some(Record::failure(
                path,
                Class::Other,
                transport,
                attempt,
                budget,
                Duration::ZERO,
            )),
            started: Instant::now(),
            sink: None,
        }
    }
    pub fn with_sink(
        path: Path,
        transport: Transport,
        attempt: u32,
        budget: Budget,
        sink: Arc<Journal>,
    ) -> Self {
        let mut guard = Self::new(path, transport, attempt, budget);
        guard.sink = Some(sink);
        guard
    }
    pub fn class(&mut self, class: Class) {
        if let Some(r) = &mut self.record {
            r.class = class;
        }
    }
    pub fn metadata(&mut self, transport: Transport, attempt: u32) {
        if let Some(r) = &mut self.record {
            r.transport = transport;
            r.attempt = attempt;
        }
    }
    pub fn success(&mut self) {
        self.record = None;
    }
    pub fn cancelled(&mut self) {
        self.class(Class::Cancelled);
    }
}
impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(mut r) = self.record.take() {
            r.time = now_ms();
            r.duration_ms = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            self.sink.as_deref().unwrap_or_else(|| service()).submit(r);
        }
    }
}
#[derive(Clone, Copy)]
pub enum Owner {
    Root,
    CurrentUser,
}
#[derive(Clone)]
pub struct Config {
    pub directory: PathBuf,
    pub file: &'static str,
    pub owner: Owner,
}
impl Config {
    pub fn service() -> Option<Self> {
        #[cfg(target_os = "macos")]
        let directory = PathBuf::from("/Library/Logs/R-TrustTunnel");
        #[cfg(target_os = "linux")]
        let directory = PathBuf::from("/var/log/rtrust");
        #[cfg(windows)]
        let directory = windows::known_folder(false)?
            .join("R-TrustTunnel")
            .join("logs");
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        return None;
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some(Self {
            directory,
            file: "events.log",
            owner: Owner::Root,
        })
    }
    pub fn user() -> Option<Self> {
        #[cfg(target_os = "macos")]
        let directory = directories::BaseDirs::new()?
            .home_dir()
            .join("Library/Logs/R-TrustTunnel");
        #[cfg(target_os = "linux")]
        let directory = directories::BaseDirs::new()?
            .state_dir()?
            .join("rtrust/logs");
        #[cfg(windows)]
        let directory = windows::known_folder(true)?
            .join("R-TrustTunnel")
            .join("logs");
        #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
        return None;
        #[cfg(any(target_os = "macos", target_os = "linux", windows))]
        Some(Self {
            directory,
            file: "socks-events.log",
            owner: Owner::CurrentUser,
        })
    }
}
enum Message {
    Line(String),
    Flush(mpsc::SyncSender<()>),
}
pub struct Journal {
    tx: Option<mpsc::SyncSender<Message>>,
    dropped: Arc<AtomicU64>,
}
impl Journal {
    pub fn disabled() -> Self {
        Self {
            tx: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }
    /// Path discovery and all filesystem initialization happen on the writer thread.
    pub fn spawn(config: impl FnOnce() -> Option<Config> + Send + 'static) -> Self {
        Self::spawn_with_clock(config, now_ms, Duration::from_secs(60))
    }
    fn spawn_with_clock(
        config: impl FnOnce() -> Option<Config> + Send + 'static,
        clock: impl Fn() -> u64 + Send + 'static,
        idle: Duration,
    ) -> Self {
        let (tx, rx) = mpsc::sync_channel(256);
        let dropped = Arc::new(AtomicU64::new(0));
        let count = dropped.clone();
        let worker = std::thread::Builder::new()
            .name("event-journal".into())
            .spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let Some(config) = config() else {
                        return;
                    };
                    let Ok(mut store) = storage::Store::open(config) else {
                        return;
                    };
                    let _ = store.prune(clock());
                    loop {
                        match rx.recv_timeout(idle) {
                            Ok(Message::Line(line)) => {
                                let n = count.swap(0, Ordering::Relaxed);
                                if n != 0
                                    && store
                                        .append(
                                            &format!("{} journal_dropped count={n}\n", clock()),
                                            clock(),
                                        )
                                        .is_err()
                                {
                                    count.fetch_add(n, Ordering::Relaxed);
                                }
                                if store.append(&line, clock()).is_err() {
                                    count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Ok(Message::Flush(done)) => {
                                let _ = done.try_send(());
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => {
                                let _ = store.prune(clock());
                            }
                            Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        }
                    }
                }));
            });
        Self {
            tx: worker.ok().map(|_| tx),
            dropped,
        }
    }
    pub fn submit(&self, record: Record) {
        self.enqueue(record.line());
    }
    /// Only existing, redacted lifecycle messages belong here. New failures use Record.
    pub fn lifecycle(&self, event: &str) {
        let clean: String = event
            .chars()
            .take(900)
            .map(|c| {
                if c.is_ascii() && !c.is_control() {
                    c
                } else {
                    ' '
                }
            })
            .collect();
        self.enqueue(format!("{} pid={} {clean}\n", now_ms(), std::process::id()));
    }
    fn enqueue(&self, line: String) {
        if let Some(tx) = &self.tx
            && tx.try_send(Message::Line(line)).is_err()
        {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
    /// Synchronous shutdown/test hook only, never used by async connection code.
    pub fn flush(&self, bound: Duration) -> bool {
        let Some(tx) = &self.tx else {
            return false;
        };
        let (done, rx) = mpsc::sync_channel(1);
        tx.try_send(Message::Flush(done)).is_ok() && rx.recv_timeout(bound).is_ok()
    }
}
pub fn service() -> &'static Journal {
    static LOG: OnceLock<Journal> = OnceLock::new();
    LOG.get_or_init(|| {
        if cfg!(test) {
            Journal::disabled()
        } else {
            Journal::spawn(Config::service)
        }
    })
}
pub fn user() -> &'static Journal {
    static LOG: OnceLock<Journal> = OnceLock::new();
    LOG.get_or_init(|| {
        if cfg!(test) {
            Journal::disabled()
        } else {
            Journal::spawn(Config::user)
        }
    })
}
