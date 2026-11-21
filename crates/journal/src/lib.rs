//! Best-effort local diagnostics. Connection failures have a closed, typed schema.
//! No filesystem operations, waits for locks, or raw error formatting on producers.
use std::{
    error::Error,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex, OnceLock,
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

/// How long a record of each level is kept. Fixed; not configurable.
pub const DEBUG_RETENTION_MS: u64 = 15 * 60 * 1000;
pub const WARNING_RETENTION_MS: u64 = 30 * 60 * 1000;
pub const ERROR_RETENTION_MS: u64 = 60 * 60 * 1000;
pub const CRITICAL_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Debug,
    Warning,
    Error,
    Critical,
}
impl Level {
    pub const fn retention_ms(self) -> u64 {
        match self {
            Self::Debug => DEBUG_RETENTION_MS,
            Self::Warning => WARNING_RETENTION_MS,
            Self::Error => ERROR_RETENTION_MS,
            Self::Critical => CRITICAL_RETENTION_MS,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
    /// Closed token only. Anything else is not a level.
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "level=debug" => Some(Self::Debug),
            "level=warning" => Some(Self::Warning),
            "level=error" => Some(Self::Error),
            "level=critical" => Some(Self::Critical),
            _ => None,
        }
    }
}

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
        // VLESS Unanswered cannot tell a revoked UUID from unreachable targets.
        E::Io | E::Degraded { .. } | E::Unanswered | E::Closed(_) => Class::Other,
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
            "{} pid={} level=error connect_failed path={} class={} transport={} attempt={} budget={} duration_ms={}\n",
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
    recorder: Option<fn(Record)>,
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
            recorder: None,
        }
    }
    /// Inject a typed, nonblocking recorder (for isolated caller harnesses).
    /// The recorder must not panic or perform filesystem I/O. Default guards
    /// still exclusively submit to the bounded, best-effort service queue.
    pub fn with_recorder(
        path: Path,
        transport: Transport,
        attempt: u32,
        budget: Budget,
        recorder: fn(Record),
    ) -> Self {
        let mut guard = Self::new(path, transport, attempt, budget);
        guard.recorder = Some(recorder);
        guard
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
            if let Some(recorder) = self.recorder {
                recorder(r);
            } else {
                self.sink.as_deref().unwrap_or_else(|| service()).submit(r);
            }
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
    /// A stop record. A full queue drops one ordinary line to admit it; it is
    /// never summarized away by `journal_dropped`.
    Critical(String),
    Flush(mpsc::SyncSender<()>),
}
pub struct Journal {
    tx: Option<mpsc::SyncSender<Message>>,
    /// One reserved slot. A critical line and a flush acknowledgement enter
    /// here when the bounded queue is full, so a stop is not dropped to make
    /// room and never displaces another queued record.
    urgent: Option<Arc<Urgent>>,
    dropped: Arc<AtomicU64>,
}
struct Urgent {
    slot: Mutex<Option<Message>>,
    pending: Condvar,
    /// Lines accepted into the queue and not yet taken by the writer.
    queued: AtomicU64,
}
impl Journal {
    pub fn disabled() -> Self {
        Self {
            tx: None,
            urgent: None,
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
        let urgent = Arc::new(Urgent {
            slot: Mutex::new(None),
            pending: Condvar::new(),
            queued: AtomicU64::new(0),
        });
        let dropped = Arc::new(AtomicU64::new(0));
        let count = dropped.clone();
        let reserved = Arc::clone(&urgent);
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
                        // Both producers notify this condvar. The predicate
                        // covers a line that arrived before the wait, so a
                        // notify is never lost between the check and it.
                        let guard = reserved.slot.lock().unwrap_or_else(|e| e.into_inner());
                        let (mut guard, waited) = reserved
                            .pending
                            .wait_timeout_while(guard, idle, |slot| {
                                slot.is_none() && reserved.queued.load(Ordering::Acquire) == 0
                            })
                            .unwrap_or_else(|e| e.into_inner());
                        if let Some(message) = guard.take() {
                            drop(guard);
                            deliver(&mut store, &count, &clock, message);
                            continue;
                        }
                        drop(guard);
                        if waited.timed_out() {
                            let _ = store.prune(clock());
                        }
                        loop {
                            match rx.try_recv() {
                                Ok(message) => {
                                    deliver(&mut store, &count, &clock, message);
                                    reserved.queued.fetch_sub(1, Ordering::Release);
                                }
                                // Empty and every sender is gone: stop. Checked
                                // here, not by a second recv, so a line that
                                // arrives in between is never consumed and lost.
                                Err(mpsc::TryRecvError::Disconnected) => return,
                                Err(mpsc::TryRecvError::Empty) => break,
                            }
                        }
                    }
                }));
            });
        Self {
            tx: worker.is_ok().then_some(tx),
            urgent: worker.is_ok().then_some(urgent),
            dropped,
        }
    }
    pub fn submit(&self, record: Record) {
        self.enqueue(record.line());
    }
    /// One reconnect episode. `line` is a finished record, already checked by
    /// the caller to contain only closed tokens. It is queued like any other
    /// line; the writer keeps the ten newest `keep=reconnect` lines.
    pub fn reconnect(&self, line: String) {
        if line.len() > 1024 || !line.ends_with('\n') || !line.contains("keep=reconnect") {
            return;
        }
        self.enqueue(line);
    }
    /// State changes. Kept 15 minutes. New failures use [`Record`] (error, 60 minutes).
    pub fn lifecycle(&self, event: &str) {
        self.lifecycle_at(Level::Debug, event);
    }
    /// Only existing, redacted lifecycle messages belong here.
    pub fn lifecycle_at(&self, level: Level, event: &str) {
        let line = self.lifecycle_line(level, event);
        if level == Level::Critical {
            self.enqueue_critical(line);
        } else {
            self.enqueue(line);
        }
    }
    fn lifecycle_line(&self, level: Level, event: &str) -> String {
        let clean: String = event
            .chars()
            .take(880)
            .map(|c| {
                if c.is_ascii() && !c.is_control() {
                    c
                } else {
                    ' '
                }
            })
            .collect();
        format!(
            "{} pid={} level={} {clean}\n",
            now_ms(),
            std::process::id(),
            level.as_str()
        )
    }
    fn enqueue(&self, line: String) {
        let Some(tx) = &self.tx else { return };
        if self.send(tx, Message::Line(line)) {
            return;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    /// Admit one critical line even when the bounded queue is full, through the
    /// reserved slot. Still non-blocking: a second critical line finds the slot
    /// taken and counts as dropped rather than waiting.
    fn enqueue_critical(&self, line: String) {
        let Some(tx) = &self.tx else { return };
        if self.send(tx, Message::Critical(line.clone())) {
            return;
        }
        if self.offer(Message::Critical(line)) {
            return;
        }
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
    /// Count before the send, so the writer cannot see a queued line whose
    /// count is still zero and sleep past it.
    fn send(&self, tx: &mpsc::SyncSender<Message>, message: Message) -> bool {
        if let Some(urgent) = &self.urgent {
            urgent.queued.fetch_add(1, Ordering::Release);
        }
        if tx.try_send(message).is_err() {
            if let Some(urgent) = &self.urgent {
                urgent.queued.fetch_sub(1, Ordering::Release);
            }
            return false;
        }
        if let Some(urgent) = &self.urgent {
            urgent.pending.notify_one();
        }
        true
    }
    fn offer(&self, message: Message) -> bool {
        let Some(urgent) = &self.urgent else {
            return false;
        };
        let mut slot = urgent.slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return false;
        }
        *slot = Some(message);
        drop(slot);
        urgent.pending.notify_one();
        true
    }
    /// Synchronous shutdown/test hook only, never used by async connection code.
    /// The reserved slot is kept for a critical line, so a full queue is
    /// retried until the writer drains it. The wait stays bounded by `bound`.
    pub fn flush(&self, bound: Duration) -> bool {
        let Some(tx) = &self.tx else {
            return false;
        };
        let (done, rx) = mpsc::sync_channel(1);
        // The reserved slot belongs to a critical line already waiting. Keep
        // retrying the queue until the writer has drained enough to take the
        // acknowledgement; the wait stays bounded by `bound`.
        let deadline = Instant::now() + bound;
        loop {
            if self.send(tx, Message::Flush(done.clone())) {
                return rx
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .is_ok();
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn deliver(
    store: &mut storage::Store,
    count: &AtomicU64,
    clock: &impl Fn() -> u64,
    message: Message,
) {
    match message {
        Message::Line(line) => write(store, count, clock, &line),
        Message::Critical(line) => {
            // Ahead of any drop marker: a stop must not be buried under the
            // count of whatever the queue could not hold.
            let _ = store.append(&line, clock());
            write_drops(store, count, clock);
        }
        Message::Flush(done) => {
            let _ = done.try_send(());
        }
    }
}
fn write_drops(store: &mut storage::Store, count: &AtomicU64, clock: &impl Fn() -> u64) {
    let n = count.swap(0, Ordering::Relaxed);
    if n != 0
        && store
            .append(&format!("{} journal_dropped count={n}\n", clock()), clock())
            .is_err()
    {
        count.fetch_add(n, Ordering::Relaxed);
    }
}
fn write(store: &mut storage::Store, count: &AtomicU64, clock: &impl Fn() -> u64, line: &str) {
    write_drops(store, count, clock);
    if store.append(line, clock()).is_err() {
        count.fetch_add(1, Ordering::Relaxed);
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
