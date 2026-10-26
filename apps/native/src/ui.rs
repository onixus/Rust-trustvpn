//! Window shell, theme tokens and the honest connection state model (UI variant 3).
//! Presentation only: every action below sends an existing message; nothing here
//! starts probes, changes routes, DNS, the guard, the vault or IPC.
use super::*;
use iced::widget::{Space, column};
use rtrust_control::observations::{
    Mode as ObservationMode, Observation, Outcome, PROBE_TTL_MS, Reason as ObservationReason,
    Snapshot, Source, ttl_cap,
};

// ---------------------------------------------------------------- language

/// Russian unless the system clearly prefers another language; the previous
/// UI was Russian-only, so an undetected locale keeps that behaviour.
pub(super) fn ru() -> bool {
    static RUSSIAN: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *RUSSIAN.get_or_init(|| is_russian(system_language().as_deref()))
}
pub(super) fn is_russian(tag: Option<&str>) -> bool {
    match tag.map(str::trim).filter(|t| !t.is_empty()) {
        None => true,
        Some(tag) => {
            let tag = tag.to_ascii_lowercase();
            tag == "c" || tag == "posix" || tag.starts_with("ru")
        }
    }
}
pub(super) fn t(ru: &'static str, en: &'static str) -> &'static str {
    if self::ru() { ru } else { en }
}
#[cfg(target_os = "macos")]
fn system_language() -> Option<String> {
    use objc2::{msg_send, runtime::AnyClass, runtime::AnyObject};
    unsafe {
        let class = AnyClass::get(c"NSLocale")?;
        let list: *mut AnyObject = msg_send![class, preferredLanguages];
        if list.is_null() {
            return None;
        }
        let first: *mut AnyObject = msg_send![list, firstObject];
        if first.is_null() {
            return None;
        }
        let utf8: *const std::ffi::c_char = msg_send![first, UTF8String];
        if utf8.is_null() {
            return None;
        }
        Some(
            std::ffi::CStr::from_ptr(utf8)
                .to_string_lossy()
                .into_owned(),
        )
    }
}
#[cfg(target_os = "windows")]
fn system_language() -> Option<String> {
    use winreg::{RegKey, enums::HKEY_CURRENT_USER};
    let user = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(key) = user.open_subkey("Control Panel\\Desktop")
        && let Ok(list) = key.get_value::<Vec<String>, _>("PreferredUILanguages")
        && let Some(first) = list.into_iter().find(|l| !l.is_empty())
    {
        return Some(first);
    }
    user.open_subkey("Control Panel\\International")
        .ok()?
        .get_value::<String, _>("LocaleName")
        .ok()
}
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn system_language() -> Option<String> {
    ["LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .find(|value| !value.is_empty())
}

// ---------------------------------------------------------------- theme

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ThemeChoice {
    System,
    Dark,
    Light,
}
impl ThemeChoice {
    pub(super) fn parse(value: &str) -> Self {
        match value.trim() {
            "dark" => Self::Dark,
            "light" => Self::Light,
            _ => Self::System,
        }
    }
    fn key(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Dark => "dark",
            Self::Light => "light",
        }
    }
}
/// Appearance is not secret and lives outside the encrypted vault.
fn theme_path() -> Option<std::path::PathBuf> {
    directories::ProjectDirs::from("org", "RTrustTunnel", "Native")
        .map(|dirs| dirs.config_dir().join("appearance"))
}
pub(super) fn load_theme() -> ThemeChoice {
    if cfg!(test) || std::env::args().any(|arg| arg.starts_with("--ci-")) {
        return ThemeChoice::System;
    }
    theme_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .map(|value| ThemeChoice::parse(&value))
        .unwrap_or(ThemeChoice::System)
}
fn save_theme(choice: ThemeChoice) {
    if std::env::args().any(|arg| arg.starts_with("--ci-")) || cfg!(test) {
        return;
    }
    if let Some(path) = theme_path() {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, choice.key());
    }
}
/// Read by the window-open hook, which has no access to the App.
static DARK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);
pub(super) fn remember_dark(dark: bool) {
    DARK.store(dark, std::sync::atomic::Ordering::Relaxed);
}
#[cfg(target_os = "macos")]
pub(super) fn dark_now() -> bool {
    DARK.load(std::sync::atomic::Ordering::Relaxed)
}

const fn rgb(hex: u32) -> Color {
    Color::from_rgb8((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}
const fn rgba(hex: u32, alpha: f32) -> Color {
    Color::from_rgba8((hex >> 16) as u8, (hex >> 8) as u8, hex as u8, alpha)
}
/// Colours of Android variant 3 (Palette.java); light is the "frosted" look.
#[derive(Clone, Copy)]
pub(super) struct Tokens {
    pub(super) dark: bool,
    pub(super) bg: Color,
    pub(super) text: Color,
    pub(super) muted: Color,
    pub(super) card: Color,
    pub(super) stroke: Color,
    pub(super) chip: Color,
    pub(super) field: Color,
    pub(super) rule: Color,
    pub(super) empty: Color,
    pub(super) side: Color,
    pub(super) nav_active: Color,
    pub(super) link: Color,
    pub(super) blue: Color,
    pub(super) on_blue: Color,
    pub(super) blue_soft: Color,
    pub(super) violet: Color,
    pub(super) violet_soft: Color,
    pub(super) orange: Color,
    pub(super) orange_soft: Color,
    pub(super) warn: Color,
    pub(super) warn_soft: Color,
    pub(super) danger: Color,
    pub(super) danger_soft: Color,
}
pub(super) const DARK_TOKENS: Tokens = Tokens {
    dark: true,
    bg: rgb(0x08090B),
    text: rgb(0xF4F5F7),
    muted: rgb(0x8A93A0),
    card: rgb(0x121418),
    stroke: rgb(0x1B1E24),
    chip: rgb(0x15181D),
    field: rgb(0x1A1D23),
    rule: rgb(0x1E2128),
    empty: rgb(0x4A515C),
    side: rgb(0x0C0D10),
    nav_active: rgb(0x1A1D23),
    link: rgb(0x9CCBFF),
    blue: rgb(0x4DA3FF),
    on_blue: rgb(0x06213D),
    blue_soft: rgb(0x14243A),
    violet: rgb(0xB9A6FF),
    violet_soft: rgb(0x2A2340),
    orange: rgb(0xFFB27A),
    orange_soft: rgb(0x3A2A1C),
    warn: rgb(0xE0A526),
    warn_soft: rgba(0xE0A526, 0.15),
    danger: rgb(0xFF6B70),
    danger_soft: rgba(0xE5484D, 0.16),
};
pub(super) const LIGHT_TOKENS: Tokens = Tokens {
    dark: false,
    bg: rgb(0xE8EDF5),
    text: rgb(0x0E1726),
    muted: rgb(0x4A566B),
    // Translucent everywhere so the colour fields show through, as in the
    // mockups; without macOS glass the fields are simply not blurred again.
    card: rgba(0xFFFFFF, 0.55),
    stroke: rgba(0xFFFFFF, 0.85),
    chip: rgba(0xFFFFFF, 0.6),
    field: rgba(0xFFFFFF, 0.8),
    rule: rgba(0x0E1726, 0.08),
    empty: rgb(0x8C97A8),
    side: rgba(0xFFFFFF, 0.4),
    nav_active: rgba(0xFFFFFF, 0.85),
    link: rgb(0x1F6FE0),
    blue: rgb(0x1F6FE0),
    on_blue: rgb(0xFFFFFF),
    blue_soft: rgb(0xDCE9FF),
    violet: rgb(0x5B48C9),
    violet_soft: rgb(0xE6E0FF),
    orange: rgb(0x9A4A0C),
    orange_soft: rgb(0xFFE6D3),
    warn: rgb(0x8F6200),
    warn_soft: rgba(0xE0A526, 0.18),
    danger: rgb(0xC2272D),
    danger_soft: rgba(0xE5484D, 0.14),
};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Hue {
    Grey,
    Blue,
    Green,
    Yellow,
    Red,
}
impl Hue {
    pub(super) fn fill(self, dark: bool) -> Color {
        match (self, dark) {
            (Self::Grey, true) => rgb(0x6B7A8C),
            (Self::Grey, false) => rgb(0x8C97A8),
            (Self::Blue, _) => rgb(0x4DA3FF),
            (Self::Green, _) => rgb(0x3DD68C),
            (Self::Yellow, _) => rgb(0xE0A526),
            (Self::Red, _) => rgb(0xE5484D),
        }
    }
    pub(super) fn text(self, dark: bool) -> Color {
        match (self, dark) {
            (Self::Grey, true) => rgb(0x9AA6B4),
            (Self::Grey, false) => rgb(0x5B6678),
            (Self::Blue, true) => rgb(0x4DA3FF),
            (Self::Blue, false) => rgb(0x1F6FE0),
            (Self::Green, true) => rgb(0x3DD68C),
            (Self::Green, false) => rgb(0x138A4E),
            (Self::Yellow, true) => rgb(0xE0A526),
            (Self::Yellow, false) => rgb(0x8F6200),
            (Self::Red, true) => rgb(0xFF6B70),
            (Self::Red, false) => rgb(0xC2272D),
        }
    }
}
pub(super) fn theme(tokens: &Tokens) -> Theme {
    Theme::custom(
        if tokens.dark {
            "R-TrustTunnel Dark"
        } else {
            "R-TrustTunnel Light"
        },
        iced::theme::Palette {
            background: tokens.bg,
            text: tokens.text,
            primary: tokens.blue,
            success: Hue::Green.text(tokens.dark),
            warning: Hue::Yellow.fill(tokens.dark),
            danger: Hue::Red.fill(tokens.dark),
        },
    )
}

// ---------------------------------------------------------------- state model

/// UI states of variant 3. Green (Verified) only when every check passed and is fresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Level {
    Off,
    Connecting,
    Disconnecting,
    Running,
    Verified,
    Warning,
    Error,
    /// Always-on is enabled but the service could not be reached: nothing is known.
    #[cfg_attr(
        not(any(target_os = "linux", target_os = "windows")),
        expect(dead_code, reason = "always-on runs only on Linux and Windows")
    )]
    Unknown,
}
impl Level {
    pub(super) fn hue(self) -> Hue {
        match self {
            Self::Off | Self::Unknown => Hue::Grey,
            Self::Connecting | Self::Disconnecting | Self::Running => Hue::Blue,
            Self::Verified => Hue::Green,
            Self::Warning => Hue::Yellow,
            Self::Error => Hue::Red,
        }
    }
    fn outlined(self) -> bool {
        matches!(self, Self::Connecting | Self::Disconnecting)
    }
    pub(super) fn short(self) -> &'static str {
        match self {
            Self::Off => t("VPN выключен", "VPN is off"),
            Self::Connecting => t("Подключение…", "Connecting…"),
            Self::Disconnecting => t("Отключение…", "Disconnecting…"),
            Self::Running => t("Туннель работает", "Tunnel is up"),
            Self::Verified => t("Туннель проверен", "Tunnel verified"),
            Self::Warning => t("Нужно внимание", "Needs attention"),
            Self::Error => t("Нет подключения", "Not connected"),
            Self::Unknown => t("Нет связи со службой", "No contact with the service"),
        }
    }
    fn headline(self) -> (&'static str, &'static str) {
        match self {
            Self::Off => ("VPN", t("выключен", "is off")),
            Self::Connecting => (t("Туннель", "Tunnel"), t("подключается", "connecting")),
            Self::Disconnecting => (t("Туннель", "Tunnel"), t("отключается", "disconnecting")),
            Self::Running => (t("Туннель", "Tunnel"), t("работает", "is up")),
            Self::Verified => (t("Туннель", "Tunnel"), t("проверен", "verified")),
            Self::Warning => (t("Нужно", "Needs"), t("внимание", "attention")),
            Self::Error => (t("Нет", "Not"), t("подключения", "connected")),
            Self::Unknown => (t("Состояние", "State"), t("неизвестно", "unknown")),
        }
    }
}
/// Five checks of the observation snapshot (schema 2), in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Check {
    Transport,
    Route,
    Dns,
    Guard,
    Connectivity,
}
pub(super) const CHECKS: [Check; 5] = [
    Check::Transport,
    Check::Route,
    Check::Dns,
    Check::Guard,
    Check::Connectivity,
];
impl Check {
    pub(super) fn of(self, snapshot: &Snapshot) -> &Observation {
        match self {
            Self::Transport => &snapshot.transport,
            Self::Route => &snapshot.route,
            Self::Dns => &snapshot.dns,
            Self::Guard => &snapshot.guard,
            Self::Connectivity => &snapshot.connectivity,
        }
    }
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Transport => t("Транспорт", "Transport"),
            Self::Route => t("Маршрут", "Route"),
            Self::Dns => "DNS",
            Self::Guard => t("Защита", "Guard"),
            Self::Connectivity => t("Доступность", "Connectivity"),
        }
    }
    fn note(self) -> &'static str {
        match self {
            Self::Transport => t("соединение с сервером", "connection to the server"),
            Self::Route => t("маршруты совпадают с профилем", "routes match the profile"),
            Self::Dns => t(
                "ответы резолвера через туннель",
                "resolver answers via the tunnel",
            ),
            Self::Guard => t("блокировка трафика без VPN", "blocks traffic without VPN"),
            Self::Connectivity => t("один адрес через VPN-сеть", "one address via the VPN"),
        }
    }
    /// What a passed result of this check means; split TUN covers only the
    /// selected networks, so it never reads as whole-computer protection.
    fn meaning(self, mode: ObservationMode) -> &'static str {
        if mode == ObservationMode::Split {
            match self {
                Self::Route => {
                    return t(
                        "Выбранные сети направлены в VPN; остальной трафик идёт вне VPN.",
                        "Selected networks are routed into the VPN; other traffic bypasses it.",
                    );
                }
                Self::Dns => {
                    return t(
                        "Результат относится только к выбранным сетям; системный DNS не меняется.",
                        "Applies only to the selected networks; the system DNS is unchanged.",
                    );
                }
                Self::Guard => {
                    return t(
                        "Защита относится только к выбранным сетям, не ко всему компьютеру.",
                        "Protection covers only the selected networks, not the whole computer.",
                    );
                }
                _ => {}
            }
        }
        match self {
            Self::Transport => t(
                "Соединение с сервером профиля установлено.",
                "The connection to the profile's server is up.",
            ),
            Self::Route => t(
                "Маршруты VPN совпадают с профилем.",
                "VPN routes match the profile.",
            ),
            Self::Dns => t(
                "Имена сайтов разрешаются через сеть VPN.",
                "Site names resolve through the VPN network.",
            ),
            Self::Guard => t(
                "Трафик блокируется, если VPN отключится.",
                "Traffic is blocked if the VPN drops.",
            ),
            Self::Connectivity => t(
                "Запрос через туннель получил ответ.",
                "A request through the tunnel got an answer.",
            ),
        }
    }
}
/// How often the app repeats its own system path check while TUN is up.
pub(super) const PROBE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
/// A probe result stays fresh until the next run is overdue: runs start
/// PROBE_INTERVAL apart and each may take up to TOTAL, plus a few seconds of
/// scheduling slack. Measured from `finished_at_ms`.
pub(super) const PROBE_FRESH_MS: u64 =
    (PROBE_INTERVAL.as_millis() + rtrust_desktop::diagnostics::TOTAL.as_millis()) as u64 + 5_000;
/// Fold the app's own path check (one destination: route to the VPN interface,
/// then HTTPS through it) into the service snapshot it was taken against.
/// DNS and the guard are not inferred: a system lookup does not prove the DNS
/// path and the check never tests the firewall.
pub(super) fn apply_probe(
    snapshot: &mut Snapshot,
    report: &rtrust_desktop::diagnostics::Report,
    now: u64,
) {
    use rtrust_desktop::diagnostics::Fact;
    use rtrust_profile::routing::Action;
    if report.finished_at_ms == 0 || report.lifecycle.generation != snapshot.generation {
        return;
    }
    let probe = |outcome| Observation {
        outcome,
        source: Source::AppProbe,
        observed_at_ms: Some(report.finished_at_ms),
        valid_for_ms: PROBE_FRESH_MS,
        mode: snapshot.transport.mode,
        reason: ObservationReason::NotChecked,
    };
    // Fresh service evidence wins; the probe only fills checks the service
    // left open, including results that have since expired.
    let open = |o: &Observation| {
        // A service probe's own row is never replaced while it is current.
        let current = o.source == Source::SystemProbe
            && o.observed_at_ms
                .is_some_and(|time| now >= time && now - time <= PROBE_TTL_MS);
        !current
            && matches!(
                normalized(o, now),
                Outcome::Unknown | Outcome::Stale | Outcome::Configured
            )
    };
    // The destination is user-chosen: a route outside the VPN is a tunnel
    // failure only when the policy sends it into the tunnel (or, in full
    // mode, does not explicitly exclude it). Split rules may bypass it on purpose.
    let expected_tunnel = match report.policy.as_ref().map(|d| d.action) {
        Some(Action::Tunnel) => true,
        Some(Action::Direct | Action::Block) => false,
        _ => snapshot.transport.mode == ObservationMode::Full,
    };
    let route = match report.route {
        Fact::Passed => Some(Outcome::Passed),
        Fact::RouteMismatch if expected_tunnel => Some(Outcome::Failed),
        _ => None,
    };
    if let Some(outcome) = route.filter(|_| open(&snapshot.route)) {
        snapshot.route = probe(outcome);
    }
    // One site answering proves the path; one site failing is about that site
    // (down, blocked, bad TLS), so failures stay on the path check page.
    let connectivity = match report.https {
        Fact::Passed => Some(Outcome::Passed),
        _ => None,
    };
    if let Some(outcome) = connectivity.filter(|_| open(&snapshot.connectivity)) {
        let generation = snapshot.generation;
        let observation = probe(outcome);
        snapshot.apply_connectivity(generation, observation);
    }
}
/// Passed and configured results expire after their TTL (at most FRESH_MS,
/// or the probe TTL for repeated probes), as Android ObservationStatus does.
pub(super) fn normalized(observation: &Observation, now: u64) -> Outcome {
    match observation.outcome {
        Outcome::Passed | Outcome::Configured => {
            let cap = if observation.source == Source::AppProbe {
                PROBE_FRESH_MS
            } else {
                ttl_cap(observation.source)
            };
            let ttl = observation.valid_for_ms.min(cap);
            match observation.observed_at_ms {
                Some(time) if now >= time && now - time <= ttl => observation.outcome,
                _ => Outcome::Stale,
            }
        }
        // The app's own check is repeated; its failure must not outlive the
        // runs that stopped confirming it.
        Outcome::Failed if observation.source == Source::AppProbe => {
            match observation.observed_at_ms {
                Some(time) if now >= time && now - time <= PROBE_FRESH_MS => Outcome::Failed,
                _ => Outcome::Stale,
            }
        }
        Outcome::Failed if observation.source == Source::SystemProbe => {
            match observation.observed_at_ms {
                Some(time) if now >= time && now - time <= PROBE_TTL_MS => Outcome::Failed,
                _ => Outcome::Stale,
            }
        }
        other => other,
    }
}
/// Level of a live tunnel from its snapshot: any failure is a warning, only
/// every check passed and fresh in whole-computer mode is verified, everything
/// else is running. Split TUN and proxy never turn green.
pub(super) fn tunnel_level(snapshot: &Snapshot, now: u64) -> Level {
    let outcomes = CHECKS.map(|check| normalized(check.of(snapshot), now));
    if outcomes.contains(&Outcome::Failed) {
        Level::Warning
    } else if snapshot.transport.mode == ObservationMode::Full
        && outcomes.iter().all(|o| *o == Outcome::Passed)
    {
        Level::Verified
    } else {
        Level::Running
    }
}
/// Name of the profile actually carrying traffic: after an opt-in failover the
/// service reports the backup's index among the candidates sent with Start.
pub(super) fn live_name(
    active: Option<u8>,
    candidates: &[String],
    requested: &str,
) -> (String, bool) {
    match active.and_then(|i| candidates.get(i as usize).map(|name| (i, name))) {
        Some((index, name)) => (name.clone(), index > 0),
        None => (requested.to_owned(), false),
    }
}
/// Description of a running tunnel built from the actual outcomes.
pub(super) fn running_text(snapshot: &Snapshot, now: u64, proxy_port: &str) -> String {
    let ru = ru();
    if snapshot.transport.mode == ObservationMode::Proxy {
        return if ru {
            format!(
                "SOCKS5-прокси запущен на 127.0.0.1:{proxy_port}. Через туннель идут только приложения, настроенные на этот прокси; остальной трафик и DNS системы идут как обычно."
            )
        } else {
            format!(
                "The SOCKS5 proxy runs on 127.0.0.1:{proxy_port}. Only apps configured to use it go through the tunnel; other traffic and system DNS are unchanged."
            )
        };
    }
    let mut parts = vec![
        match normalized(&snapshot.transport, now) {
            Outcome::Passed | Outcome::Configured => {
                t("Транспорт запущен.", "The transport is up.")
            }
            Outcome::Stale => t(
                "Результат транспорта устарел.",
                "The transport result is stale.",
            ),
            _ => t(
                "Транспорт не подтверждён.",
                "The transport is not confirmed.",
            ),
        }
        .to_owned(),
    ];
    if snapshot.transport.mode == ObservationMode::Split {
        parts.push(
            t(
                "Через VPN идут только выбранные сети; остальной трафик идёт вне VPN. Системный DNS в этом режиме не проверяется.",
                "Only the selected networks use the VPN; other traffic bypasses it. System DNS is not checked in this mode.",
            )
            .to_owned(),
        );
    }
    let names = |want: &dyn Fn(Outcome) -> bool| {
        CHECKS[1..]
            .iter()
            .filter(|c| want(normalized(c.of(snapshot), now)))
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .join(", ")
    };
    for (label, list) in [
        (t("Пройдено", "Passed"), names(&|o| o == Outcome::Passed)),
        (
            t("Не проверяется в этом режиме", "Not checked in this mode"),
            names(&|o| o == Outcome::Unsupported),
        ),
        (
            t("Пока без результата", "No result yet"),
            names(&|o| matches!(o, Outcome::Unknown | Outcome::Stale | Outcome::Configured)),
        ),
    ] {
        if !list.is_empty() {
            parts.push(format!("{label}: {list}."));
        }
    }
    parts.join(" ")
}
/// Split DNS is not probed (a selection may or may not carry the resolver)
/// and split TUN has no kill switch: neither is a missing feature nor a result.
pub(super) fn check_value(
    check: Check,
    mode: ObservationMode,
    outcome: Outcome,
) -> (&'static str, Option<Hue>) {
    match (mode, check, outcome) {
        (ObservationMode::Split, Check::Dns, Outcome::Unsupported) => {
            (t("не проверяется", "not checked"), None)
        }
        (ObservationMode::Split, Check::Guard, Outcome::Unsupported) => {
            (t("не включена", "off"), None)
        }
        _ => row_value(outcome),
    }
}
/// Display of one check row: label, hue (None = empty ring) and muted flag.
pub(super) fn row_value(outcome: Outcome) -> (&'static str, Option<Hue>) {
    match outcome {
        Outcome::Passed => (t("пройдено", "passed"), Some(Hue::Green)),
        Outcome::Failed => (t("не пройдено", "failed"), Some(Hue::Yellow)),
        Outcome::Configured => (t("запущен", "running"), Some(Hue::Blue)),
        Outcome::Stale => (t("устарело", "stale"), Some(Hue::Grey)),
        Outcome::Unsupported => (t("не поддерживается", "unsupported"), None),
        Outcome::Unknown => (t("нет данных", "no data"), None),
    }
}
fn reason_text(reason: ObservationReason) -> &'static str {
    use ObservationReason as R;
    match reason {
        R::NotChecked => t("Проверка не выполнялась.", "Not checked."),
        R::SessionRunning => t(
            "Служба сообщает, что сеанс запущен.",
            "The service reports a running session.",
        ),
        R::WorkerStopped => t("Рабочий процесс остановлен.", "The worker stopped."),
        R::ConfigurationApplied => t(
            "Конфигурация применена; результат не измерялся.",
            "Configuration applied; not measured.",
        ),
        R::CheckUnavailable => t(
            "Проверка недоступна на этой системе.",
            "The check is unavailable on this system.",
        ),
        R::ObservationExpired => t(
            "Результат устарел; повторите проверку.",
            "The result expired; check again.",
        ),
        R::LifecycleGap => t(
            "Был перерыв в наблюдении за сеансом.",
            "There was a gap in session monitoring.",
        ),
        R::SessionChanged => t("Сеанс изменился.", "The session changed."),
        R::ControlLost => t(
            "Связь со службой потеряна.",
            "Contact with the service was lost.",
        ),
        R::SessionStopped => t("Сеанс остановлен.", "The session stopped."),
        R::NetworkChanged => t(
            "Сеть изменилась; прежние результаты сброшены.",
            "The network changed; earlier results were reset.",
        ),
        R::SystemResumed => t(
            "Система вышла из сна; прежние результаты сброшены.",
            "The system resumed; earlier results were reset.",
        ),
    }
}
/// The service owned Always-on connection as last reported by its status poll.
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub(super) type ServiceState = Option<(rtrust_control::State, Snapshot)>;

pub(super) fn protocol_label(p: &Profile) -> String {
    match p.protocol {
        rtrust_profile::Protocol::TrustTunnel => {
            let upstream = match p.endpoint.upstream_protocol.as_str() {
                "http3" => "HTTP/3",
                "http2" => "HTTP/2",
                other => other,
            };
            format!("TrustTunnel {upstream}").trim().to_owned()
        }
        _ => p.transport_name().to_owned(),
    }
}
fn badge(p: &Profile, tk: Tokens) -> (&'static str, Color, Color) {
    match p.protocol {
        rtrust_profile::Protocol::TrustTunnel => ("TT", tk.blue, tk.blue_soft),
        rtrust_profile::Protocol::Hysteria2 => ("H2", tk.violet, tk.violet_soft),
        rtrust_profile::Protocol::AmneziaWg => ("AW", tk.orange, tk.orange_soft),
        // Placeholder until the VLESS transport and its badge land.
        rtrust_profile::Protocol::Vless => ("VL", tk.blue, tk.blue_soft),
    }
}

// ---------------------------------------------------------------- widgets

/// System UI families with real bold faces; cosmic-text's generic sans-serif
/// ("Open Sans") is often missing, and its bold fallback can be monospaced.
#[cfg(target_os = "macos")]
const FAMILY: iced::font::Family = iced::font::Family::Name("Helvetica Neue");
#[cfg(target_os = "windows")]
const FAMILY: iced::font::Family = iced::font::Family::Name("Segoe UI");
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const FAMILY: iced::font::Family = iced::font::Family::SansSerif;
pub(super) const REGULAR: iced::Font = iced::Font {
    family: FAMILY,
    ..iced::Font::DEFAULT
};
pub(super) const BOLD: iced::Font = iced::Font {
    weight: iced::font::Weight::Bold,
    ..REGULAR
};
const SEMIBOLD: iced::Font = iced::Font {
    weight: iced::font::Weight::Semibold,
    ..REGULAR
};
fn card<'a>(
    tk: Tokens,
    content: impl Into<Element<'a, Message>>,
) -> container::Container<'a, Message> {
    container(content)
        .padding(18)
        .width(Length::Fill)
        .style(move |_| container::Style {
            text_color: Some(tk.text),
            background: Some(tk.card.into()),
            border: iced::Border {
                color: tk.stroke,
                width: 1.0,
                radius: 22.0.into(),
            },
            shadow: lift(tk),
            ..Default::default()
        })
}
/// Light theme cards float on a soft shadow; dark cards rely on their stroke.
/// tiny-skia (Windows, Linux) leaves stale pixels of blurred shadows behind:
/// its damage tracking covers only the quad, not the shadow around it.
fn lift(tk: Tokens) -> iced::Shadow {
    if tk.dark || cfg!(not(target_os = "macos")) {
        iced::Shadow::default()
    } else {
        iced::Shadow {
            color: rgba(0x0E1726, 0.08),
            offset: iced::Vector::new(0.0, 4.0),
            blur_radius: 18.0,
        }
    }
}
// ---------------------------------------------------------------- backdrop
/// Standard deviation of the mockups' `filter: blur(90px)`.
const BLOB_SIGMA: f32 = 90.0;
/// Logical pixels per backdrop texel. The fields are blurred by BLOB_SIGMA, so
/// neighbouring texels differ by about one 8-bit level and nearest filtering
/// shows no steps; on tiny-skia it costs half as much as bilinear.
const BLOB_TEXEL: f32 = 4.0;
/// A field: centre in logical pixels, disk radius, colour and peak opacity.
type Field = (f32, f32, f32, Color, f32);
/// Light theme colour fields behind the frosted cards (mockup variant 3): the
/// first takes `state`, the other two are fixed violet and sky. Placed as in
/// the 1280×800 mockups, anchored to the same window edges.
///
/// The fields are rasterised once per texel grid and state colour, and drawn
/// as one image. Layered translucent shapes would be re-blended on every
/// scroll frame by tiny-skia (Windows, Linux), which renders on the CPU; a
/// shadow blur would also leave stale pixels outside its quad's damage.
fn backdrop<'a>(state: Color) -> Element<'a, Message> {
    iced::widget::responsive(move |size| {
        let (handle, snapped) = backdrop_image(size, state);
        // One texel per BLOB_TEXEL exactly: the image may overhang the window
        // by less than a texel, which the container clips.
        container(
            iced::widget::image(handle)
                .width(snapped.width)
                .height(snapped.height)
                .content_fit(iced::ContentFit::Fill)
                .filter_method(iced::widget::image::FilterMethod::Nearest),
        )
        .width(Length::Fill)
        .height(Length::Fill)
        .clip(true)
        .into()
    })
    .into()
}
/// The fields for a window of `size`, anchored as in the mockups.
fn backdrop_fields(size: iced::Size, state: Color) -> [Field; 3] {
    // (left, top, diameter) as in the mockups, converted to centre and radius.
    let field = |diameter: f32, color: Color, opacity: f32, x: f32, y: f32| -> Field {
        let r = diameter / 2.0;
        (x + r, y + r, r, color, opacity)
    };
    [
        field(520.0, state, 0.35, 180.0, -120.0),
        field(440.0, rgb(0xB9AEFF), 0.4, size.width + 60.0 - 440.0, 260.0),
        field(
            420.0,
            rgb(0x9FDCFF),
            0.4,
            520.0,
            size.height + 200.0 - 420.0,
        ),
    ]
}
/// The raster for `size` snapped up to whole texels, and that snapped size.
/// The fields are placed for the snapped size, so the cache key (texel counts
/// and state colour) determines the image completely; a new handle (and
/// upload) only when the key changes, so redraws reuse the renderer's copy.
fn backdrop_image(size: iced::Size, state: Color) -> (iced::widget::image::Handle, iced::Size) {
    use std::cell::RefCell;
    type Key = (u32, u32, [u32; 4]);
    thread_local! {
        static CACHE: RefCell<Option<(Key, iced::widget::image::Handle)>> =
            const { RefCell::new(None) };
    }
    let texels = |v: f32| (v / BLOB_TEXEL).ceil().clamp(1.0, 2048.0) as u32;
    let (width, height) = (texels(size.width), texels(size.height));
    let snapped = iced::Size::new(width as f32 * BLOB_TEXEL, height as f32 * BLOB_TEXEL);
    let key = (
        width,
        height,
        [state.r, state.g, state.b, state.a].map(f32::to_bits),
    );
    let handle = CACHE.with_borrow_mut(|cache| match cache {
        Some((cached, handle)) if *cached == key => handle.clone(),
        _ => {
            let fields = backdrop_fields(snapped, state);
            let pixels = backdrop_pixels(width, height, snapped, &fields);
            let handle = iced::widget::image::Handle::from_rgba(width, height, pixels);
            *cache = Some((key, handle.clone()));
            handle
        }
    });
    (handle, snapped)
}
/// Straight-alpha RGBA texels of `fields` composed in order over transparency.
/// Each field is `opacity` × a disk blurred with BLOB_SIGMA, sampled at the
/// texel centres of a `width`×`height` grid stretched over `size`.
fn backdrop_pixels(width: u32, height: u32, size: iced::Size, fields: &[Field]) -> Vec<u8> {
    // Φ((radius - d) / σ) tabulated per logical pixel of (radius - d): one
    // lookup per texel and field instead of an exp, so a resize of a large
    // window stays cheap. A pixel of offset changes the alpha by under 0.002.
    const REACH: i32 = (4.0 * BLOB_SIGMA) as i32;
    let profile: Vec<f32> = (-REACH..=REACH)
        .map(|offset| normal_cdf(offset as f32 / BLOB_SIGMA))
        .collect();
    let cdf = |offset: f32| match offset.round() as i32 {
        o if o < -REACH => 0.0,
        o if o > REACH => 1.0,
        o => profile[(o + REACH) as usize],
    };
    let (sx, sy) = (size.width / width as f32, size.height / height as f32);
    let mut pixels = Vec::with_capacity(width as usize * height as usize * 4);
    for j in 0..height {
        let y = (j as f32 + 0.5) * sy;
        for i in 0..width {
            let x = (i as f32 + 0.5) * sx;
            let (mut a, mut rgb) = (0.0_f32, [0.0_f32; 3]);
            for &(cx, cy, radius, color, opacity) in fields {
                let d = (x - cx).hypot(y - cy);
                let fa = opacity * cdf(radius - d);
                let out = fa + a * (1.0 - fa);
                if out > 0.0 {
                    for (c, f) in rgb.iter_mut().zip([color.r, color.g, color.b]) {
                        *c = (f * fa + *c * a * (1.0 - fa)) / out;
                    }
                }
                a = out;
            }
            let byte = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
            pixels.extend([byte(rgb[0]), byte(rgb[1]), byte(rgb[2]), byte(a)]);
        }
    }
    pixels
}
/// Standard normal CDF (Abramowitz–Stegun 7.1.26, error below 1.5e-7).
fn normal_cdf(x: f32) -> f32 {
    let z = x.abs() / std::f32::consts::SQRT_2;
    let t = 1.0 / (1.0 + 0.327_591_1 * z);
    let poly = t
        * (0.254_829_6
            + t * (-0.284_496_74 + t * (1.421_413_7 + t * (-1.453_152_1 + t * 1.061_405_4))));
    let erf = 1.0 - poly * (-z * z).exp();
    if x >= 0.0 {
        0.5 * (1.0 + erf)
    } else {
        0.5 * (1.0 - erf)
    }
}
fn soft<'a>(
    background: Color,
    radius: f32,
    content: impl Into<Element<'a, Message>>,
) -> container::Container<'a, Message> {
    container(content).style(move |_| container::Style {
        background: Some(background.into()),
        border: iced::Border {
            radius: radius.into(),
            ..Default::default()
        },
        ..Default::default()
    })
}
fn dot<'a>(fill: Option<Color>, ring: Color, size: f32) -> Element<'a, Message> {
    container(Space::new())
        .width(size)
        .height(size)
        .style(move |_| container::Style {
            background: fill.map(Into::into),
            border: iced::Border {
                color: fill.unwrap_or(ring),
                width: if fill.is_some() { 0.0 } else { 2.0 },
                radius: (size / 2.0).into(),
            },
            ..Default::default()
        })
        .into()
}
fn divider<'a>(tk: Tokens) -> Element<'a, Message> {
    container(Space::new())
        .width(Length::Fill)
        .height(1)
        .style(move |_| container::Style {
            background: Some(tk.rule.into()),
            ..Default::default()
        })
        .into()
}
fn caps<'a>(tk: Tokens, label: impl Into<String>) -> iced::widget::Text<'a> {
    text(label.into().to_uppercase())
        .size(11)
        .font(BOLD)
        .color(tk.muted)
}
fn muted<'a>(
    tk: Tokens,
    label: impl iced::widget::text::IntoFragment<'a>,
) -> iced::widget::Text<'a> {
    text(label).size(13).color(tk.muted)
}
fn title<'a>(label: &'a str) -> iced::widget::Text<'a> {
    text(label).size(30).font(BOLD)
}
#[derive(Clone, Copy)]
pub(super) enum Kind {
    Primary,
    Chip,
    Danger,
    Ghost,
}
pub(super) fn pill<'a>(
    tk: Tokens,
    kind: Kind,
    content: impl Into<Element<'a, Message>>,
) -> buttons::Button<'a, Message> {
    buttons::Button::new(content)
        .padding([10, 16])
        .style(move |_, status| pill_style(tk, kind, status))
}
/// Tokens of the theme being drawn (built by `theme`), for widgets made without them.
pub(super) fn tokens_of(theme: &Theme) -> Tokens {
    if theme.palette().background == DARK_TOKENS.bg {
        DARK_TOKENS
    } else {
        LIGHT_TOKENS
    }
}
pub(super) fn pill_style(tk: Tokens, kind: Kind, status: buttons::Status) -> buttons::Style {
    let (background, text_color) = match kind {
        Kind::Primary => (Some(tk.blue), tk.on_blue),
        Kind::Chip => (Some(tk.chip), tk.text),
        Kind::Danger => (Some(tk.danger_soft), tk.danger),
        Kind::Ghost => (None, tk.muted),
    };
    let disabled = matches!(status, buttons::Status::Disabled);
    let hovered = matches!(status, buttons::Status::Hovered | buttons::Status::Pressed);
    let background = background.map(|mut c| {
        if disabled {
            c.a *= 0.5;
        }
        c
    });
    let background = match (background, hovered) {
        (None, true) => Some(tk.chip),
        (b, _) => b,
    };
    buttons::Style {
        background: background.map(Into::into),
        text_color: if disabled {
            Color {
                a: 0.5,
                ..text_color
            }
        } else {
            text_color
        },
        border: iced::Border {
            color: if !matches!(kind, Kind::Chip) {
                Color::TRANSPARENT
            } else if tk.dark {
                tk.stroke
            } else {
                rgba(0x0E1726, 0.14)
            },
            width: if matches!(kind, Kind::Chip) { 1.0 } else { 0.0 },
            radius: 22.0.into(),
        },
        ..Default::default()
    }
}
fn field_style(
    tk: Tokens,
) -> impl Fn(&Theme, iced::widget::text_input::Status) -> iced::widget::text_input::Style {
    move |theme, status| {
        let mut style = iced::widget::text_input::default(theme, status);
        style.background = tk.field.into();
        style.border.radius = 14.0.into();
        style.border.color = if matches!(status, iced::widget::text_input::Status::Focused { .. }) {
            tk.blue
        } else {
            tk.stroke
        };
        style.value = tk.text;
        style.placeholder = tk.muted;
        style
    }
}
fn kv<'a>(tk: Tokens, key: &'a str, value: String) -> Element<'a, Message> {
    column![
        divider(tk),
        row![
            muted(tk, key).width(Length::FillPortion(2)),
            text(value)
                .size(13)
                .font(SEMIBOLD)
                .width(Length::FillPortion(3))
                .align_x(iced::Alignment::End)
        ]
        .spacing(12)
        .padding([9, 0])
    ]
    .into()
}

// ---------------------------------------------------------------- app views

#[derive(Clone, Copy, PartialEq)]
enum Columns {
    Two,
    One,
}
impl App {
    pub(super) fn dark(&self) -> bool {
        match self.theme_choice {
            ThemeChoice::System => self.system_dark,
            ThemeChoice::Dark => true,
            ThemeChoice::Light => false,
        }
    }
    pub(super) fn tokens(&self) -> Tokens {
        if self.dark() {
            DARK_TOKENS
        } else {
            LIGHT_TOKENS
        }
    }
    /// Re-apply the native window appearance after a theme change.
    pub(super) fn appearance_changed(&mut self, before: bool) -> Task<Message> {
        let dark = self.dark();
        remember_dark(dark);
        if before == dark {
            return Task::none();
        }
        #[cfg(target_os = "macos")]
        {
            iced::window::oldest().then(move |id| match id {
                Some(id) => iced::window::run(id, move |window| {
                    if let Some(ns_window) = native_window(window) {
                        unsafe { glass::set_appearance(ns_window, dark) };
                    }
                })
                .discard(),
                None => Task::none(),
            })
        }
        #[cfg(not(target_os = "macos"))]
        Task::none()
    }
    pub(super) fn set_theme(&mut self, choice: ThemeChoice) -> Task<Message> {
        let before = self.dark();
        self.theme_choice = choice;
        save_theme(choice);
        self.appearance_changed(before)
    }
    pub(super) fn system_theme(&mut self, mode: iced::theme::Mode) -> Task<Message> {
        let before = self.dark();
        match mode {
            iced::theme::Mode::Dark => self.system_dark = true,
            iced::theme::Mode::Light => self.system_dark = false,
            iced::theme::Mode::None => {}
        }
        self.appearance_changed(before)
    }
    fn columns(&self) -> Columns {
        // Sidebar (232) plus content padding; two columns need ~760 px of content.
        if self.window_width - 232.0 - 80.0 >= 760.0 {
            Columns::Two
        } else {
            Columns::One
        }
    }
    /// Current level and the snapshot it was derived from.
    pub(super) fn level(&self) -> (Level, Option<Snapshot>) {
        if self.disconnecting {
            return (Level::Disconnecting, None);
        }
        if self.connecting {
            return (Level::Connecting, None);
        }
        let now = rtrust_control::observations::now_ms();
        if let Some(session) = &self.session {
            let mut snapshot = session.observations();
            if let Some((epoch, report)) = &self.diagnostic_report
                && *epoch == self.connection_epoch
            {
                apply_probe(&mut snapshot, report, now);
            }
            return (tunnel_level(&snapshot, now), Some(snapshot));
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if self.always_on.enabled {
            if self.always_on.contact_lost {
                return (Level::Unknown, None);
            }
            return match &self.always_on.service {
                Some((rtrust_control::State::Connected, snapshot)) => {
                    (tunnel_level(snapshot, now), Some(snapshot.clone()))
                }
                Some((rtrust_control::State::Blocked, snapshot)) => {
                    (Level::Warning, Some(snapshot.clone()))
                }
                Some((rtrust_control::State::Error, snapshot)) => {
                    (Level::Error, Some(snapshot.clone()))
                }
                // The service runs but holds no tunnel: not progress, so not "connecting".
                Some((rtrust_control::State::Idle, _)) => (Level::Off, None),
                // No reply yet since always-on was enabled.
                None => (Level::Connecting, None),
            };
        }
        if self.last_error.is_some() {
            return (Level::Error, None);
        }
        (Level::Off, None)
    }
    fn always_on_active(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            self.always_on.enabled
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        false
    }
    /// The profile carrying (or attempting) the connection, and whether it is a backup.
    pub(super) fn live_profile(&self) -> Option<(String, bool)> {
        if self.connecting && self.session.is_none() {
            return Some((self.connection_name.clone(), false));
        }
        let session = self.session.as_ref()?;
        Some(live_name(
            session.active_profile(),
            &self.connection_candidates,
            &self.connection_name,
        ))
    }
    /// Whether the endpoint relays IPv6 (otherwise full mode blocks IPv6 locally).
    fn full_ipv6(&self) -> bool {
        if self.connecting || self.session.is_some() {
            self.connection_ipv6
        } else {
            self.current().is_some_and(|p| p.endpoint.has_ipv6)
        }
    }
    /// Whether the connect/disconnect pill is shown: always on Home, and during a
    /// store conflict so a live session can still be stopped.
    pub(super) fn shows_connect_control(&self) -> bool {
        self.page == Page::Home || self.store_conflict.is_some()
    }
    /// The profile the big control acts on: the live one, else the selected one.
    fn subject(&self) -> Option<(String, String)> {
        if let Some((name, _)) = self.live_profile() {
            let host = self
                .profiles
                .iter()
                .find(|p| p.name == name)
                .map(|p| p.endpoint.hostname.clone())
                .unwrap_or_default();
            return Some((name, host));
        }
        if self.always_on_active() {
            return self
                .profiles
                .first()
                .map(|p| (p.name.clone(), p.endpoint.hostname.clone()));
        }
        self.current()
            .map(|p| (p.name.clone(), p.endpoint.hostname.clone()))
    }
    /// One row per check; "no data" when a check never produced a result.
    fn check_rows(
        &self,
        level: Level,
        snapshot: Option<&Snapshot>,
    ) -> Vec<(Check, &'static str, Option<Hue>, String)> {
        let now = rtrust_control::observations::now_ms();
        CHECKS
            .iter()
            .map(|&check| {
                let none = (t("нет данных", "no data"), None);
                let (value, hue) = match (snapshot, check, level) {
                    (Some(s), _, _) => {
                        check_value(check, s.transport.mode, normalized(check.of(s), now))
                    }
                    (None, Check::Transport, Level::Off) => (t("выключен", "off"), None),
                    (None, Check::Transport, Level::Connecting) => {
                        (t("подключение…", "connecting…"), Some(Hue::Blue))
                    }
                    (None, Check::Transport, Level::Disconnecting) => {
                        (t("отключение…", "disconnecting…"), Some(Hue::Blue))
                    }
                    (None, Check::Transport, Level::Error) => (t("сбой", "failed"), Some(Hue::Red)),
                    _ => none,
                };
                let detail = match snapshot {
                    Some(s) => {
                        let o = check.of(s);
                        let age = o
                            .observed_at_ms
                            .filter(|_| o.outcome != Outcome::Unknown)
                            .map(|at| {
                                let secs = now.saturating_sub(at) / 1000;
                                if ru() {
                                    format!(" Наблюдение {secs} с назад.")
                                } else {
                                    format!(" Observed {secs} s ago.")
                                }
                            })
                            .unwrap_or_default();
                        let probe = t(
                            "Системная проверка одного адреса.",
                            "System check of one address.",
                        );
                        let service = t("Проверка службы.", "Service check.");
                        match normalized(o, now) {
                            Outcome::Unsupported
                                if s.transport.mode == ObservationMode::Split
                                    && matches!(check, Check::Dns | Check::Guard) =>
                            {
                                check.meaning(s.transport.mode).to_owned()
                            }
                            Outcome::Unknown if o.source == Source::SystemProbe => format!(
                                "{}{age}",
                                t(
                                    "Проверка службы не дала результата.",
                                    "The service check was inconclusive.",
                                )
                            ),
                            Outcome::Unknown => reason_text(o.reason).to_owned(),
                            Outcome::Failed if o.source == Source::SystemProbe => format!(
                                "{}{age}",
                                match check {
                                    Check::Dns => t(
                                        "Проверка службы: DNS может идти мимо VPN.",
                                        "Service check: DNS may bypass the VPN.",
                                    ),
                                    Check::Guard => t(
                                        "Проверка службы: блокировка без VPN не подтверждена или нарушена.",
                                        "Service check: blocking without the VPN is missing or broken.",
                                    ),
                                    _ => t("Проверка службы не прошла.", "The service check failed."),
                                }
                            ),
                            _ if o.source == Source::SystemProbe => format!(
                                "{} {service}{age}",
                                check.meaning(s.transport.mode)
                            ),
                            Outcome::Failed if o.source == Source::AppProbe => format!(
                                "{}{age}",
                                t(
                                    "Системная проверка одного адреса не прошла; подробности — в последней проверке пути.",
                                    "The system check of one address failed; see the last path check.",
                                )
                            ),
                            _ if o.source == Source::AppProbe => format!(
                                "{} {probe}{age}",
                                check.meaning(s.transport.mode)
                            ),
                            _ => format!(
                                "{} {}{age}",
                                check.meaning(s.transport.mode),
                                reason_text(o.reason)
                            ),
                        }
                    }
                    None => check.meaning(ObservationMode::Full).to_owned(),
                };
                (check, value, hue, detail)
            })
            .collect()
    }
    fn checks_card(
        &self,
        tk: Tokens,
        level: Level,
        snapshot: Option<&Snapshot>,
        detailed: bool,
    ) -> Element<'_, Message> {
        let mut rows = column![].spacing(0);
        for (check, value, hue, detail) in self.check_rows(level, snapshot) {
            let fill = hue.map(|h| h.fill(tk.dark));
            let ring = match (hue, level) {
                (None, _) => tk.empty,
                (Some(h), _) => h.fill(tk.dark),
            };
            let outline = hue.is_some()
                && snapshot.is_none()
                && matches!(level, Level::Connecting | Level::Disconnecting);
            let value_color = hue.map(|h| h.text(tk.dark)).unwrap_or(tk.muted);
            let marker = dot(if outline { None } else { fill }, ring, 10.0);
            let line: Element<'_, Message> = if detailed {
                row![
                    container(marker).padding([5, 0]),
                    column![
                        row![
                            text(check.name()).size(15).font(BOLD).width(Length::Fill),
                            text(value).size(13).font(SEMIBOLD).color(value_color)
                        ]
                        .spacing(8),
                        muted(tk, detail)
                    ]
                    .spacing(3)
                    .width(Length::Fill)
                ]
                .spacing(14)
                .into()
            } else {
                row![
                    marker,
                    text(check.name()).font(BOLD).width(120),
                    muted(tk, check.note()).width(Length::Fill),
                    text(value).size(13).font(SEMIBOLD).color(value_color)
                ]
                .spacing(14)
                .align_y(iced::Alignment::Center)
                .into()
            };
            rows = rows
                .push(divider(tk))
                .push(container(line).padding([11, 0]));
        }
        rows.into()
    }

    // ------------------------------------------------------------ shell

    pub(super) fn shell(&self) -> Element<'_, Message> {
        let tk = self.tokens();
        let (level, _) = self.level();
        let active_page = match self.page {
            Page::Import => Page::Profiles,
            page => page,
        };
        let mut nav = column![
            container(text("R-TrustTunnel").size(17).font(BOLD)).padding([4, 14]),
            Space::new().height(12)
        ]
        .spacing(4)
        .width(232)
        .padding([20, 14]);
        let mut items = vec![
            (t("Главная", "Home"), Page::Home),
            (t("Профили", "Profiles"), Page::Profiles),
            (t("Проверки", "Checks"), Page::Diagnostics),
            (t("Сеть", "Network"), Page::Network),
            (t("Синхронизация", "Sync"), Page::Portal),
            (t("Настройки", "Settings"), Page::Settings),
        ];
        #[cfg(target_os = "windows")]
        items.push((t("Обновления", "Updates"), Page::Updates));
        #[cfg(not(target_os = "windows"))]
        let _ = &mut items;
        for (label, page) in items {
            let selected = active_page == page;
            nav = nav.push(
                buttons::Button::new(text(label).size(14).font(BOLD))
                    .width(Length::Fill)
                    .padding([12, 14])
                    .style(move |_, status| buttons::Style {
                        background: (selected
                            || matches!(
                                status,
                                buttons::Status::Hovered | buttons::Status::Pressed
                            ))
                        .then_some(if selected { tk.nav_active } else { tk.chip }.into()),
                        text_color: if selected { tk.text } else { tk.muted },
                        border: iced::Border {
                            radius: 14.0.into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    })
                    .on_press(Message::Navigate(page)),
            );
        }
        let hue = level.hue();
        let state_card = buttons::Button::new(
            row![
                dot(
                    (!level.outlined()).then_some(hue.fill(tk.dark)),
                    hue.fill(tk.dark),
                    8.0
                ),
                text(level.short()).size(13).font(BOLD)
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
        )
        .width(Length::Fill)
        .padding(14)
        .style(move |_, _| buttons::Style {
            background: Some(tk.card.into()),
            text_color: tk.text,
            border: iced::Border {
                color: tk.stroke,
                width: 1.0,
                radius: 16.0.into(),
            },
            ..Default::default()
        })
        .on_press(Message::Navigate(Page::Home));
        let nav = nav
            .push(Space::new().height(Length::Fill))
            .push(state_card)
            .push(
                pill(
                    tk,
                    Kind::Ghost,
                    text(t("Свернуть в трей", "Hide to tray")).size(13),
                )
                .width(Length::Fill)
                .on_press(Message::CloseRequested),
            )
            .push(
                pill(tk, Kind::Ghost, text(t("Выход", "Quit")).size(13))
                    .width(Length::Fill)
                    .on_press(Message::ExitRequested),
            );
        let sidebar = container(nav)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(tk.side.into()),
                text_color: Some(tk.text),
                ..Default::default()
            });
        let edge = container(Space::new())
            .width(1)
            .height(Length::Fill)
            .style(move |_| container::Style {
                background: Some(tk.stroke.into()),
                ..Default::default()
            });

        let header: Element<'_, Message> = match self.page {
            Page::Home => self.status_chip(tk, level),
            Page::Profiles => title(t("Профили", "Profiles")).into(),
            Page::Import => title(t("Новый профиль", "New profile")).into(),
            Page::Diagnostics => title(t("Проверки", "Checks")).into(),
            Page::Network => title(t("Сеть", "Network")).into(),
            Page::Portal => title(t("Синхронизация", "Sync")).into(),
            Page::Settings => title(t("Настройки", "Settings")).into(),
            #[cfg(target_os = "windows")]
            Page::Updates => title(t("Обновления", "Updates")).into(),
        };
        let body: Element<'_, Message> = if self.store_conflict.is_some() {
            card(tk, self.store_conflict_view()).into()
        } else {
            match self.page {
                Page::Home => self.home_view(tk, level),
                Page::Profiles => self.profiles_view(tk),
                Page::Import => self.add_view(tk),
                Page::Diagnostics => self.checks_view(tk, level),
                Page::Network => self.network_view(tk),
                Page::Portal => card(tk, self.portal_view()).into(),
                Page::Settings => self.settings_view(tk),
                #[cfg(target_os = "windows")]
                Page::Updates => card(tk, self.updates_view()).into(),
            }
        };
        let mut main = column![
            container(header)
                .height(44)
                .align_y(iced::Alignment::Center),
            scrollable(container(body).padding(iced::Padding {
                right: 14.0,
                ..Default::default()
            }))
            .height(Length::Fill)
        ]
        .spacing(20)
        .padding([24, 36]);
        if self.shows_connect_control() {
            main = main.push(self.connect_pill(tk, level));
        }
        main = main.push(
            container(muted(tk, &self.status))
                .padding([10, 16])
                .width(Length::Fill)
                .style(move |_| container::Style {
                    background: Some(tk.chip.into()),
                    border: iced::Border {
                        color: tk.stroke,
                        width: 1.0,
                        radius: 16.0.into(),
                    },
                    ..Default::default()
                }),
        );
        let window = container(row![sidebar, edge, main.width(Length::Fill)])
            .width(Length::Fill)
            .height(Length::Fill);
        if tk.dark {
            return window.into();
        }
        // As in the mockups, the main field shows the state only where the state is the subject.
        let field = match self.page {
            Page::Home | Page::Diagnostics => hue.fill(false),
            _ => Hue::Blue.fill(false),
        };
        iced::widget::stack![backdrop(field), window]
            .width(Length::Fill)
            .height(Length::Fill)
            .into()
    }
    fn status_chip(&self, tk: Tokens, level: Level) -> Element<'_, Message> {
        let hue = level.hue();
        let name = self
            .subject()
            .map(|(name, _)| name.to_uppercase())
            .unwrap_or_default();
        let tag = match level {
            Level::Off => level.short().to_uppercase(),
            Level::Connecting => format!("{name} · {}", t("ПОДКЛЮЧЕНИЕ", "CONNECTING")),
            Level::Disconnecting => format!("{name} · {}", t("ОТКЛЮЧЕНИЕ", "DISCONNECTING")),
            Level::Error => format!("{name} · {}", t("ОШИБКА", "ERROR")),
            Level::Unknown => level.short().to_uppercase(),
            _ => {
                let live = self.live_profile();
                let transport = match &live {
                    Some((live, _)) => self.profiles.iter().find(|p| &p.name == live),
                    None if self.always_on_active() => self.profiles.first(),
                    None => None,
                }
                .map(|p| protocol_label(p).to_uppercase())
                .unwrap_or_default();
                let backup = if live.is_some_and(|(_, backup)| backup) {
                    format!(" · {}", t("РЕЗЕРВ", "BACKUP"))
                } else {
                    String::new()
                };
                if self.session.as_ref().is_some_and(|s| !s.is_tun()) {
                    format!("{name} · SOCKS5")
                } else if transport.is_empty() {
                    format!("{name}{backup}")
                } else {
                    format!("{name} · {transport}{backup}")
                }
            }
        };
        soft(
            tk.chip,
            16.0,
            row![
                dot(
                    (!level.outlined()).then_some(hue.fill(tk.dark)),
                    hue.fill(tk.dark),
                    8.0
                ),
                text(tag).size(12).font(BOLD).color(tk.muted)
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
        )
        .padding([8, 12])
        .into()
    }

    // ------------------------------------------------------------ home

    fn description(&self, level: Level, snapshot: Option<&Snapshot>) -> String {
        let text = self.state_description(level, snapshot);
        match self.live_profile() {
            Some((name, true))
                if matches!(level, Level::Running | Level::Verified | Level::Warning) =>
            {
                if ru() {
                    format!("{text} Сейчас используется резервный профиль «{name}».")
                } else {
                    format!("{text} The backup profile “{name}” is in use.")
                }
            }
            _ => text,
        }
    }
    fn state_description(&self, level: Level, snapshot: Option<&Snapshot>) -> String {
        let ru = ru();
        let subject = self.subject();
        match level {
            Level::Off if self.always_on_active() => t(
                "Постоянный VPN включён, но служба не держит туннель — трафик не защищён VPN.",
                "Always-on is enabled, but the service holds no tunnel — traffic is not protected by the VPN.",
            )
            .into(),
            Level::Off => match &subject {
                Some((name, _)) if ru => format!(
                    "Туннель не подключён — трафик не защищён VPN. Подключите профиль «{name}»."
                ),
                Some((name, _)) => format!(
                    "The tunnel is not connected — traffic is not protected by the VPN. Connect profile “{name}”."
                ),
                None => t(
                    "Добавьте профиль, чтобы подключиться.",
                    "Add a profile to connect.",
                )
                .into(),
            },
            Level::Connecting if self.always_on_active() => t(
                "Постоянный VPN включён в системной службе; ожидаем её состояние.",
                "Always-on is enabled in the system service; waiting for its state.",
            )
            .into(),
            Level::Connecting => {
                let host = subject.map(|(_, host)| host).unwrap_or_default();
                if ru {
                    format!("Устанавливаем соединение с {host}.")
                } else {
                    format!("Connecting to {host}.")
                }
            }
            Level::Disconnecting => t(
                "Останавливаем туннель и восстанавливаем маршруты.",
                "Stopping the tunnel and restoring routes.",
            )
            .into(),
            Level::Running => match snapshot {
                Some(snapshot) => running_text(
                    snapshot,
                    rtrust_control::observations::now_ms(),
                    &self.proxy_port,
                ),
                None => t("Транспорт запущен.", "The transport is up.").into(),
            },
            Level::Unknown => t(
                "Постоянный VPN включён, но связь со службой потеряна; состояние туннеля и защиты не подтверждено.",
                "Always-on is enabled, but contact with the service was lost; tunnel and protection state are not confirmed.",
            )
            .into(),
            Level::Verified => t(
                "Все пять проверок пройдены в последние секунды. Результаты устаревают — статус вернётся к синему, если их не повторить.",
                "All five checks passed in the last few seconds. Results expire — the status returns to blue unless they are repeated.",
            )
            .into(),
            Level::Warning => {
                let now = rtrust_control::observations::now_ms();
                let failed: Vec<&str> = snapshot
                    .map(|s| {
                        CHECKS
                            .iter()
                            .filter(|c| normalized(c.of(s), now) == Outcome::Failed)
                            .map(|c| c.name())
                            .collect()
                    })
                    .unwrap_or_default();
                if failed.is_empty() {
                    t(
                        "Служба сообщает о блокировке: VPN не подключён, трафик без VPN заблокирован службой. Подробности — в разделе «Сеть».",
                        "The service reports a block: the VPN is not connected and the service blocks traffic outside it. See Network.",
                    )
                    .into()
                } else if ru {
                    format!(
                        "Туннель работает, но проверка не пройдена: {}. Откройте «Проверки», чтобы увидеть причину.",
                        failed.join(", ")
                    )
                } else {
                    format!(
                        "The tunnel is up, but a check failed: {}. Open Checks to see why.",
                        failed.join(", ")
                    )
                }
            }
            Level::Error => t(
                "Подключение не установлено. Проверьте профиль и сеть, затем повторите.",
                "The connection was not established. Check the profile and network, then retry.",
            )
            .into(),
        }
    }
    fn home_view(&self, tk: Tokens, level: Level) -> Element<'_, Message> {
        let (_, snapshot) = self.level();
        let hue = level.hue();
        let (line1, line2) = level.headline();
        let headline = column![
            text(line1).size(56).font(BOLD).line_height(1.02),
            text(line2)
                .size(56)
                .font(BOLD)
                .line_height(1.02)
                .color(hue.text(tk.dark))
        ];
        let mut left = column![
            headline,
            text(self.description(level, snapshot.as_ref()))
                .size(15)
                .color(tk.muted)
        ]
        .spacing(18)
        .width(Length::Fill);
        if level == Level::Error
            && let Some(error) = &self.last_error
        {
            left = left.push(muted(tk, error.as_str()));
        }
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if self.always_on.enabled {
            left = left.push(muted(tk, self.always_on.status.as_str()));
        }
        let checks = card(
            tk,
            column![
                row![
                    caps(tk, t("Проверки", "Checks")).width(Length::Fill),
                    pill(
                        tk,
                        Kind::Chip,
                        text(t("Открыть проверки", "Open checks"))
                            .size(13)
                            .font(BOLD)
                            .color(tk.link)
                    )
                    .padding([7, 12])
                    .on_press(Message::Navigate(Page::Diagnostics))
                ]
                .align_y(iced::Alignment::Center)
                .padding([4, 0]),
                self.checks_card(tk, level, snapshot.as_ref(), false)
            ],
        )
        .padding([8, 20]);
        left = left.push(checks);

        let mut right = column![].spacing(12);
        if let Some(profile) = self.current() {
            let label = if self.selected == 0 {
                t("Профиль по умолчанию", "Default profile")
            } else {
                t("Выбранный профиль", "Selected profile")
            };
            right = right.push(profile_card(
                tk,
                label,
                profile,
                true,
                Message::Navigate(Page::Profiles),
            ));
        }
        if let Some(backup) = self
            .saved_connection
            .fallbacks_for(&self.profiles, self.current())
            .first()
        {
            right = right.push(profile_card(
                tk,
                t("Резерв", "Backup"),
                backup,
                false,
                Message::Navigate(Page::Network),
            ));
        }
        let mode = match self.mode {
            Mode::Socks => (
                t("SOCKS5-прокси", "SOCKS5 proxy").to_owned(),
                format!("127.0.0.1:{}", self.proxy_port),
            ),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Mode::Tun => (
                "TUN".to_owned(),
                if self.saved_connection.managed_routes.is_some() {
                    t("маршруты от сервера", "routes from the server")
                } else {
                    t("выбранные IPv4-сети", "selected IPv4 networks")
                }
                .to_owned(),
            ),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Mode::Full => (
                t("Весь компьютер", "Whole computer").to_owned(),
                if self.full_ipv6() {
                    "IPv4/IPv6 + DNS"
                } else {
                    t("IPv4 + DNS, IPv6 заблокирован", "IPv4 + DNS, IPv6 blocked")
                }
                .to_owned(),
            ),
        };
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        let dns = if self.mode == Mode::Full {
            (
                self.dns.clone(),
                t("через туннель", "through the tunnel").to_owned(),
            )
        } else {
            (
                t("Системный", "System").to_owned(),
                t("не через VPN", "not through the VPN").to_owned(),
            )
        };
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        let dns = (
            t("Системный", "System").to_owned(),
            t("не через VPN", "not through the VPN").to_owned(),
        );
        let sync = (
            if self.saved_connection.sync.enabled {
                t("Включена", "On")
            } else {
                t("Выключена", "Off")
            }
            .to_owned(),
            t("панель сервера", "server panel").to_owned(),
        );
        let auto = (
            if self.saved_connection.auto_connect {
                t("При запуске", "On launch")
            } else {
                t("Выключено", "Off")
            }
            .to_owned(),
            if self.autostart {
                t("автозапуск включён", "starts at login")
            } else {
                t("без автозапуска", "no login start")
            }
            .to_owned(),
        );
        let tile = |label: &'static str, (value, sub): (String, String), page: Page| {
            buttons::Button::new(
                column![
                    caps(tk, label),
                    text(value).size(15).font(BOLD),
                    text(sub).size(12).color(tk.muted)
                ]
                .spacing(4),
            )
            .width(Length::Fill)
            .padding(16)
            .style(move |_, status| buttons::Style {
                background: Some(
                    if matches!(status, buttons::Status::Hovered) {
                        tk.chip
                    } else {
                        tk.card
                    }
                    .into(),
                ),
                text_color: tk.text,
                border: iced::Border {
                    color: tk.stroke,
                    width: 1.0,
                    radius: 22.0.into(),
                },
                ..Default::default()
            })
            .on_press(Message::Navigate(page))
        };
        right = right
            .push(
                row![
                    tile(t("Режим", "Mode"), mode, Page::Network),
                    tile("DNS", dns, Page::Network)
                ]
                .spacing(12),
            )
            .push(
                row![
                    tile(t("Синхронизация", "Sync"), sync, Page::Portal),
                    tile(t("Автоподключение", "Auto-connect"), auto, Page::Settings)
                ]
                .spacing(12),
            );
        match self.columns() {
            Columns::Two => row![left, right.width(340)].spacing(28).into(),
            Columns::One => column![left, right].spacing(18).into(),
        }
    }
    fn connect_pill(&self, tk: Tokens, level: Level) -> Element<'_, Message> {
        let hue = level.hue();
        let always_on = self.always_on_active();
        let has_profile = self.current().is_some();
        let (label, message): (String, Option<Message>) = match level {
            _ if always_on => (
                t("Выключить always-on", "Turn off always-on").into(),
                Some(Message::ToggleConnection),
            ),
            Level::Off if !has_profile => (
                t("Добавить профиль", "Add a profile").into(),
                Some(Message::Navigate(Page::Import)),
            ),
            Level::Off | Level::Error => {
                let name = self.current().map(|p| p.name.clone()).unwrap_or_default();
                let supported = self
                    .current()
                    .is_some_and(|p| rtrust_engine::check_capabilities(p).is_ok());
                (
                    match (level, ru()) {
                        (Level::Error, _) => t("Повторить подключение", "Retry connection").into(),
                        (_, true) => format!("Подключить «{name}»"),
                        (_, false) => format!("Connect “{name}”"),
                    },
                    (supported && !self.busy).then_some(Message::ToggleConnection),
                )
            }
            Level::Connecting => (
                t("Отменить подключение", "Cancel connection").into(),
                Some(Message::ToggleConnection),
            ),
            Level::Disconnecting => (t("Отключение…", "Disconnecting…").into(), None),
            Level::Running | Level::Verified | Level::Warning | Level::Unknown => (
                t("Отключить", "Disconnect").into(),
                Some(Message::ToggleConnection),
            ),
        };
        let enabled = message.is_some();
        let outlined = level.outlined();
        let knob_fill = hue.fill(tk.dark);
        let icon = if outlined {
            hue.text(tk.dark)
        } else if !tk.dark && !matches!(hue, Hue::Yellow | Hue::Green) {
            Color::WHITE
        } else {
            rgb(0x08090B)
        };
        let knob = container(
            container(Space::new())
                .width(14)
                .height(14)
                .style(move |_| container::Style {
                    background: (!outlined).then_some(icon.into()),
                    border: iced::Border {
                        radius: 7.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
        )
        .width(52)
        .height(52)
        .align_x(iced::Alignment::Center)
        .align_y(iced::Alignment::Center)
        .style(move |_| container::Style {
            background: (!outlined).then_some(knob_fill.into()),
            border: iced::Border {
                color: knob_fill,
                width: if outlined { 2.5 } else { 0.0 },
                radius: 26.0.into(),
            },
            ..Default::default()
        });
        buttons::Button::new(
            row![knob, text(label).size(16).font(BOLD)]
                .spacing(14)
                .align_y(iced::Alignment::Center),
        )
        .width(Length::Fill)
        .height(64)
        .padding(6)
        .style(move |_, status| buttons::Style {
            background: Some(
                if matches!(status, buttons::Status::Hovered | buttons::Status::Pressed) {
                    tk.chip
                } else {
                    tk.card
                }
                .into(),
            ),
            text_color: if enabled {
                tk.text
            } else {
                Color { a: 0.55, ..tk.text }
            },
            border: iced::Border {
                color: tk.stroke,
                width: 1.0,
                radius: 32.0.into(),
            },
            ..Default::default()
        })
        .on_press_maybe(message)
        .into()
    }

    // ------------------------------------------------------------ profiles

    fn profiles_view(&self, tk: Tokens) -> Element<'_, Message> {
        let query = self.profile_query.trim().to_lowercase();
        let (level, _) = self.level();
        let fallbacks = &self.saved_connection.fallback_profiles;
        let live_name = self.live_profile().map(|(name, _)| name);
        let mut list = column![].spacing(2);
        let mut shown = 0;
        for (i, p) in self.profiles.iter().enumerate() {
            let protocol = protocol_label(p);
            if !query.is_empty()
                && ![&p.name, &p.endpoint.hostname, &protocol]
                    .iter()
                    .any(|field| field.to_lowercase().contains(&query))
            {
                continue;
            }
            shown += 1;
            let (code, fg, bg) = badge(p, tk);
            let live = live_name.as_deref() == Some(p.name.as_str());
            let (status, status_color, status_dot) = if live {
                (
                    level.short().to_lowercase(),
                    level.hue().text(tk.dark),
                    level.hue().fill(tk.dark),
                )
            } else {
                (
                    t("выключен", "off").to_owned(),
                    tk.muted,
                    Hue::Grey.fill(tk.dark),
                )
            };
            let mut tags = Vec::new();
            if i == 0 {
                tags.push(t("по умолчанию", "default").to_owned());
            }
            if let Some(order) = fallbacks.iter().position(|n| *n == p.name) {
                tags.push(if ru() {
                    format!("резерв {}", order + 1)
                } else {
                    format!("backup {}", order + 1)
                });
            }
            let name_line = if tags.is_empty() {
                row![text(&p.name).size(15).font(BOLD)]
            } else {
                row![
                    text(&p.name).size(15).font(BOLD),
                    text(tags.join(" · ")).size(12).color(tk.link)
                ]
                .spacing(8)
                .align_y(iced::Alignment::Center)
            };
            let selected = i == self.selected;
            list = list.push(
                buttons::Button::new(
                    row![
                        soft(bg, 15.0, text(code).size(13).font(BOLD).color(fg))
                            .width(44)
                            .height(44)
                            .align_x(iced::Alignment::Center)
                            .align_y(iced::Alignment::Center),
                        column![name_line, text(protocol.clone()).size(12).color(tk.muted)]
                            .spacing(2)
                            .width(Length::Fill),
                        row![
                            dot(Some(status_dot), status_dot, 7.0),
                            text(status).size(12).font(BOLD).color(status_color)
                        ]
                        .spacing(6)
                        .align_y(iced::Alignment::Center)
                    ]
                    .spacing(14)
                    .align_y(iced::Alignment::Center),
                )
                .width(Length::Fill)
                .padding([10, 12])
                .style(move |_, status| buttons::Style {
                    background: (selected
                        || matches!(status, buttons::Status::Hovered | buttons::Status::Pressed))
                    .then_some(if selected { tk.nav_active } else { tk.chip }.into()),
                    text_color: tk.text,
                    border: iced::Border {
                        radius: 16.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                })
                .on_press(Message::Select(i)),
            );
        }
        if self.profiles.is_empty() {
            list = list.push(container(muted(tk, t(
                "Пока нет профилей. Нажмите «Добавить профиль», чтобы открыть файл или вставить ссылку.",
                "No profiles yet. Choose Add profile to open a file or paste a link.",
            ))).padding(12));
        } else if shown == 0 {
            list = list
                .push(container(muted(tk, t("Ничего не найдено.", "Nothing found."))).padding(12));
        }
        let mut left = column![
            row![
                text_input(
                    t("Имя, сервер или протокол", "Name, server or protocol"),
                    &self.profile_query
                )
                .on_input(Message::ProfileQuery)
                .style(field_style(tk))
                .padding([12, 16])
                .width(Length::Fill),
                pill(
                    tk,
                    Kind::Primary,
                    text(t("+ Добавить профиль", "+ Add profile"))
                        .size(14)
                        .font(BOLD)
                )
                .padding([12, 18])
                .on_press(Message::Navigate(Page::Import))
            ]
            .spacing(10)
            .align_y(iced::Alignment::Center),
            card(tk, list).padding([6, 8]),
            row![
                pill(
                    tk,
                    Kind::Chip,
                    text(t("Открыть хранилище", "Open storage")).size(13)
                )
                .on_press_maybe(
                    (!self.busy && !self.dirty && self.profiles.is_empty())
                        .then_some(Message::Load)
                ),
                pill(
                    tk,
                    Kind::Chip,
                    text(t("Сохранить шифрованно", "Save encrypted")).size(13)
                )
                .on_press_maybe(
                    (!self.busy
                        && (!self.profiles.is_empty() || self.revision.is_some() || self.dirty))
                        .then_some(Message::Save)
                )
            ]
            .spacing(8)
        ]
        .spacing(14)
        .width(Length::Fill);
        if self.dirty {
            left = left.push(muted(
                tk,
                t(
                    "Есть несохранённые изменения.",
                    "There are unsaved changes.",
                ),
            ));
        }
        left = left.push(muted(
            tk,
            t(
                "Щелчок выбирает профиль для подключения; профиль по умолчанию меняется только явно. Подключение — на главной.",
                "Click selects the profile to connect; the default changes only explicitly. Connect from Home.",
            ),
        ));
        let Some(p) = self.current() else {
            return left.into();
        };
        let detail = card(tk, self.profile_detail(tk, p)).padding(20);
        match self.columns() {
            Columns::Two => row![left, detail.width(360)].spacing(24).into(),
            Columns::One => column![left, detail].spacing(18).into(),
        }
    }
    fn profile_detail<'a>(&'a self, tk: Tokens, p: &'a Profile) -> Element<'a, Message> {
        let (code, fg, bg) = badge(p, tk);
        let backups = self.saved_connection.fallbacks_for(&self.profiles, Some(p));
        let capability = match rtrust_engine::check_capabilities(p) {
            Ok(()) => t("поддерживается", "supported").to_owned(),
            Err(e) => e.to_string(),
        };
        let mut panel = column![
            row![
                soft(bg, 17.0, text(code).size(15).font(BOLD).color(fg))
                    .width(52)
                    .height(52)
                    .align_x(iced::Alignment::Center)
                    .align_y(iced::Alignment::Center),
                column![
                    text(&p.name).size(20).font(BOLD),
                    muted(
                        tk,
                        if self.selected == 0 {
                            t("профиль по умолчанию", "default profile")
                        } else {
                            t("выбранный профиль", "selected profile")
                        }
                    )
                ]
                .spacing(2)
            ]
            .spacing(12)
            .align_y(iced::Alignment::Center),
            column![
                kv(tk, t("Сервер", "Server"), p.endpoint.addresses.join(", ")),
                kv(tk, t("TLS-имя", "TLS name"), p.endpoint.hostname.clone()),
                kv(tk, t("Протокол", "Protocol"), protocol_label(p)),
                kv(
                    tk,
                    t("Сертификат", "Certificate"),
                    if p.endpoint.certificate.is_empty() {
                        t("системные CA", "system CAs")
                    } else {
                        t("из профиля", "from the profile")
                    }
                    .to_owned()
                ),
                kv(
                    tk,
                    t("Логин и пароль", "Login and password"),
                    t("скрыты", "hidden").to_owned()
                ),
                kv(
                    tk,
                    t("Резерв", "Backup"),
                    if backups.is_empty() {
                        t("нет", "none").to_owned()
                    } else {
                        backups
                            .iter()
                            .map(|b| b.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
                kv(tk, t("Транспорт", "Transport"), capability),
            ],
            row![
                text_input(t("Название профиля", "Profile name"), &self.draft_name)
                    .on_input(Message::DraftName)
                    .style(field_style(tk))
                    .padding([10, 12])
                    .width(Length::Fill),
                pill(
                    tk,
                    Kind::Chip,
                    text(t("Переименовать", "Rename")).size(13).font(BOLD)
                )
                .on_press_maybe(self.can_change_profiles().then_some(Message::Rename))
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            pill(
                tk,
                Kind::Chip,
                text(if self.selected == 0 {
                    t("Профиль по умолчанию", "Default profile")
                } else {
                    t("Использовать по умолчанию", "Make default")
                })
                .size(14)
                .font(BOLD)
                .width(Length::Fill)
                .align_x(iced::Alignment::Center)
            )
            .width(Length::Fill)
            .on_press_maybe(
                (self.selected != 0 && !self.busy && !self.connecting && self.session.is_none())
                    .then_some(Message::MakeDefault)
            ),
            pill(
                tk,
                Kind::Danger,
                text(if self.confirm_delete {
                    t("Удалить — нажмите ещё раз", "Delete — click again")
                } else {
                    t("Удалить…", "Delete…")
                })
                .size(14)
                .font(BOLD)
                .width(Length::Fill)
                .align_x(iced::Alignment::Center)
            )
            .width(Length::Fill)
            .on_press_maybe(self.can_change_profiles().then_some(Message::Delete)),
            divider(tk),
            caps(tk, t("Экспорт", "Export")),
            pick_list(
                p.formats(),
                p.formats().contains(&self.format).then_some(self.format),
                Message::Format,
            )
            .width(Length::Fill)
        ]
        .spacing(14);
        if let Ok(export) = p.export(self.format) {
            for loss in &export.losses {
                panel = panel.push(
                    soft(
                        tk.warn_soft,
                        14.0,
                        text(format!("⚠ {loss}")).size(13).color(tk.warn),
                    )
                    .padding([10, 12])
                    .width(Length::Fill),
                );
            }
        }
        panel
            .push(
                checkbox(self.consent)
                    .label(t(
                        "Понимаю: экспорт содержит пароль; указанные настройки могут не войти в формат",
                        "I understand: the export contains the password; listed settings may be lost",
                    ))
                    .on_toggle(Message::Consent),
            )
            .push(
                pill(tk, Kind::Chip, text(t("Экспортировать…", "Export…")).size(14).font(BOLD).width(Length::Fill).align_x(iced::Alignment::Center))
                    .width(Length::Fill)
                    .on_press_maybe((self.consent && !self.busy).then_some(Message::Export)),
            )
            .into()
    }

    // ------------------------------------------------------------ add profile

    fn add_view(&self, tk: Tokens) -> Element<'_, Message> {
        let file = card(
            tk,
            column![
                text(t("Файл профиля", "Profile file")).size(17).font(BOLD),
                muted(tk, "TOML, YAML, JSON, .conf"),
                pill(
                    tk,
                    Kind::Primary,
                    text(t("Выбрать файл…", "Choose file…")).size(13).font(BOLD)
                )
                .on_press_maybe((!self.busy).then_some(Message::PickFile))
            ]
            .spacing(10),
        );
        let paste = card(
            tk,
            column![
                text(t("Ссылка или текст конфигурации", "Link or configuration text")).font(BOLD),
                text_editor(&self.input)
                    .placeholder(t("tt://, hy2:// или текст конфигурации", "tt://, hy2:// or configuration text"))
                    .height(110)
                    .padding(12)
                    .on_action(Message::Edit),
                muted(
                    tk,
                    t(
                        "Сначала покажем, что будет импортировано. Импорт и ссылка никогда не подключают VPN автоматически.",
                        "First we show what will be imported. Import and links never connect the VPN automatically.",
                    )
                ),
                pill(tk, Kind::Chip, text(t("Проверить", "Check")).size(13).font(BOLD))
                    .on_press_maybe((!self.busy).then_some(Message::Parse))
            ]
            .spacing(10),
        );
        let portal = card(
            tk,
            column![
                text(t("Подключить к серверу", "Connect to a server")).font(BOLD),
                muted(
                    tk,
                    t(
                        "Одноразовый код из панели — профили приходят синхронизацией.",
                        "One-time code from the panel; profiles arrive by sync.",
                    )
                ),
                pill(
                    tk,
                    Kind::Chip,
                    text(t("Открыть синхронизацию", "Open sync"))
                        .size(13)
                        .font(BOLD)
                )
                .on_press(Message::Navigate(Page::Portal))
            ]
            .spacing(10),
        );
        let left = column![file, paste, portal].spacing(14).width(Length::Fill);
        let mut preview = column![caps(tk, t("Предпросмотр импорта", "Import preview"))].spacing(4);
        match &self.preview {
            None => {
                preview = preview.push(muted(
                    tk,
                    t(
                        "Здесь появится профиль после проверки файла или текста.",
                        "The profile appears here after a file or text is checked.",
                    ),
                ));
            }
            Some(p) => {
                preview = preview
                    .push(kv(tk, t("Имя", "Name"), p.name.clone()))
                    .push(kv(
                        tk,
                        t("Сервер", "Server"),
                        p.endpoint.addresses.join(", "),
                    ))
                    .push(kv(
                        tk,
                        t("TLS-имя", "TLS name"),
                        p.endpoint.hostname.clone(),
                    ))
                    .push(kv(tk, t("Протокол", "Protocol"), protocol_label(p)))
                    .push(kv(
                        tk,
                        t("Сертификат", "Certificate"),
                        if p.endpoint.certificate.is_empty() {
                            t("системные CA", "system CAs")
                        } else {
                            t("из профиля", "from the profile")
                        }
                        .to_owned(),
                    ))
                    .push(kv(
                        tk,
                        t("Логин и пароль", "Login and password"),
                        t("скрыты", "hidden").to_owned(),
                    ));
                if let Err(e) = rtrust_engine::check_capabilities(p) {
                    preview = preview.push(
                        soft(
                            tk.warn_soft,
                            14.0,
                            text(e.to_string()).size(13).color(tk.warn),
                        )
                        .padding([10, 12])
                        .width(Length::Fill),
                    );
                }
                preview = preview.push(
                    row![
                        pill(
                            tk,
                            Kind::Chip,
                            text(t("Отмена", "Cancel"))
                                .size(14)
                                .font(BOLD)
                                .width(Length::Fill)
                                .align_x(iced::Alignment::Center)
                        )
                        .width(Length::Fill)
                        .on_press(Message::DiscardPreview),
                        pill(
                            tk,
                            Kind::Primary,
                            text(t("Импортировать", "Import"))
                                .size(14)
                                .font(BOLD)
                                .width(Length::Fill)
                                .align_x(iced::Alignment::Center)
                        )
                        .width(Length::Fill)
                        .on_press(Message::Accept)
                    ]
                    .spacing(8)
                    .padding(iced::Padding {
                        top: 12.0,
                        ..Default::default()
                    }),
                );
                if let Some(current) = self.current() {
                    preview = preview
                        .push(muted(
                            tk,
                            if ru() {
                                format!("Заменить выбранный профиль: {}", current.name)
                            } else {
                                format!("Replace the selected profile: {}", current.name)
                            },
                        ))
                        .push(
                            pill(
                                tk,
                                Kind::Chip,
                                text(if self.confirm_replace {
                                    t("Подтвердить замену", "Confirm replacement")
                                } else {
                                    t("Заменить выбранный…", "Replace selected…")
                                })
                                .size(13),
                            )
                            .on_press_maybe(self.can_change_profiles().then_some(Message::Replace)),
                        );
                }
            }
        }
        let right = column![
            card(tk, preview).padding(20),
            muted(
                tk,
                t(
                    "Учётные данные хранятся в зашифрованном хранилище; ключ — в системном хранилище ключей.",
                    "Credentials are kept in encrypted storage; the key is in the system keyring.",
                )
            )
        ]
        .spacing(14)
        .width(Length::Fill);
        match self.columns() {
            Columns::Two => row![left, right].spacing(24).into(),
            Columns::One => column![left, right].spacing(18).into(),
        }
    }

    // ------------------------------------------------------------ checks

    fn checks_view(&self, tk: Tokens, level: Level) -> Element<'_, Message> {
        let (_, snapshot) = self.level();
        let hue = level.hue();
        let tun = self.session.as_ref().is_some_and(Session::is_tun);
        let can_diagnose =
            !self.busy && self.diagnostic_start_allowed(std::time::Instant::now()) && tun;
        let subject = self
            .subject()
            .filter(|_| level != Level::Off)
            .map(|(name, host)| format!("{name} · {host}"))
            .unwrap_or_default();
        let header = row![
            soft(
                Color {
                    a: 0.15,
                    ..hue.fill(tk.dark)
                },
                14.0,
                row![
                    dot(
                        (!level.outlined()).then_some(hue.fill(tk.dark)),
                        hue.fill(tk.dark),
                        8.0
                    ),
                    text(level.short())
                        .size(13)
                        .font(BOLD)
                        .color(hue.text(tk.dark))
                ]
                .spacing(6)
                .align_y(iced::Alignment::Center)
            )
            .padding([8, 12]),
            muted(tk, subject).width(Length::Fill)
        ]
        .spacing(10)
        .align_y(iced::Alignment::Center);
        let mut left = column![
            header,
            card(tk, self.checks_card(tk, level, snapshot.as_ref(), true)).padding([4, 20]),
            muted(
                tk,
                t(
                    "Состояние строится только по наблюдениям службы. Результаты быстро устаревают; «нет данных» значит, что проверка не выполнялась, а не что она пройдена.",
                    "State comes only from service observations. Results expire quickly; “no data” means the check did not run, not that it passed.",
                )
            )
        ]
        .spacing(14)
        .width(Length::Fill);
        if let Some((epoch, report)) = &self.diagnostic_report {
            let stale = *epoch != self.connection_epoch
                || self.session.as_ref().is_none_or(|session| {
                    session.observations().generation != report.lifecycle.generation
                })
                || rtrust_control::observations::now_ms().saturating_sub(report.finished_at_ms)
                    > 6000;
            left = left.push(card(
                tk,
                column![
                    text(t("Последняя проверка пути", "Last path check")).font(BOLD),
                    muted(tk, if stale {
                        t("Исторический результат; повторите проверку для текущего состояния.", "Historical result; check again for the current state.")
                    } else {
                        t("Результат для одного адреса; защита и общий доступ в интернет не подтверждены.", "Result for one address; the guard and general Internet access are not confirmed.")
                    }),
                    text(report.verdict_text()).size(14),
                    muted(tk, report.summary()),
                    report.verdict().actions.into_iter().fold(row![].spacing(8), |actions, action| {
                        use rtrust_desktop::diagnostics::Action;
                        // Old results may still be repeated, never acted upon.
                        let allowed = !self.busy
                            && self.diagnostic_task.is_none()
                            && (action == Action::Recheck || !stale)
                            && (action != Action::Recheck
                                || self.diagnostic_start_allowed(std::time::Instant::now()));
                        actions.push(
                            pill(tk, Kind::Chip, text(action.label()).size(13))
                                .on_press_maybe(allowed.then_some(Message::DiagnosticAction(action))),
                        )
                    })
                ]
                .spacing(8),
            ));
        }
        if self.diagnostic_export_report.is_some() {
            left = left.push(card(
                tk,
                column![
                    text(t("Отчёт для экспорта", "Report for export")).font(BOLD),
                    muted(tk, if self.diagnostic_preview_dirty {
                        t("Редактируемая копия отчёта для экспорта. Ручные правки сохраняются; результаты автоматических проверок обновляются отдельно.", "Editable copy of the report for export. Manual edits are kept; automatic check results update separately.")
                    } else {
                        t("Копия последнего отчёта для экспорта. Адреса, имя сайта, URL, credentials и сырые ошибки исключены.", "Copy of the last report for export. Addresses, site name, URL, credentials and raw errors are excluded.")
                    }),
                    text_editor(&self.diagnostic_preview)
                        .on_action(Message::DiagnosticEdit)
                        .height(160),
                    row![
                        pill(tk, Kind::Chip, text(t("Заменить копию последним результатом", "Replace the copy with the latest result")).size(13))
                            .on_press_maybe((!self.busy && self.diagnostic_report.is_some()).then_some(Message::ResetDiagnosticPreview)),
                        pill(tk, Kind::Chip, text(t("Сохранить отчёт…", "Save report…")).size(13))
                            .on_press_maybe((!self.busy).then_some(Message::ExportDiagnostic))
                    ]
                    .spacing(8)
                ]
                .spacing(10),
            ));
        }
        let path = card(
            tk,
            column![
                text(t("Проверить путь до адреса", "Check the path to an address")).font(BOLD),
                row![
                    text_input("hostname / IP", &self.system_target)
                        .on_input(Message::SystemTarget)
                        .style(field_style(tk))
                        .padding([10, 12])
                        .width(Length::Fill),
                    pill(tk, Kind::Primary, text(t("Проверить", "Check")).size(13).font(BOLD))
                        .on_press_maybe(can_diagnose.then_some(Message::Diagnose))
                ]
                .spacing(8)
                .align_y(iced::Alignment::Center),
                muted(tk, t("Системное разрешение имени и один HEAD-запрос HTTPS:443, только если маршрут идёт на интерфейс RTrustTunnel. Без proxy среды, перенаправлений и прямого сравнения. Запускается при подключении TUN и повторяется каждые 30 секунд.", "System name resolution and one HTTPS:443 HEAD request, sent only if the route goes to the RTrustTunnel interface. No environment proxy, redirects or direct comparison. Runs when TUN connects and repeats every 30 seconds.")),
            ]
            .spacing(10),
        );
        let mut tunnel = column![
            text(t("Маршрут и TCP-туннель", "Route and TCP tunnel")).font(BOLD),
            text_input("example.com:80", &self.target)
                .on_input(Message::Target)
                .style(field_style(tk))
                .padding([10, 12]),
            muted(tk, t("«Объяснить маршрут» — прогноз без сетевого запроса. «Проверить TCP-туннель» — настоящий HTTP-запрос через TLS/HTTP2 или QUIC/HTTP3 CONNECT; не включает TUN, маршруты, DNS или kill switch.", "Explain route is a prediction without a network request. Probe TCP tunnel sends a real HTTP request through TLS/HTTP2 or QUIC/HTTP3 CONNECT; it does not enable TUN, routes, DNS or the kill switch.")),
            row![
                pill(tk, Kind::Chip, text(t("Объяснить маршрут", "Explain route")).size(13).font(BOLD).color(tk.link))
                    .on_press_maybe((!self.busy).then_some(Message::ExplainRoute)),
                pill(tk, Kind::Chip, text(t("Проверить TCP-туннель", "Probe TCP tunnel")).size(13).font(BOLD))
                    .on_press_maybe(
                        (self.current().is_some_and(|p| rtrust_engine::check_capabilities(p).is_ok())
                            && !self.busy)
                            .then_some(Message::Probe)
                    )
            ]
            .spacing(8)
        ]
        .spacing(10);
        if self.current().is_none() {
            tunnel = tunnel.push(muted(
                tk,
                t("Сначала выберите профиль.", "Choose a profile first."),
            ));
        }
        let mut right = column![path, card(tk, tunnel)]
            .spacing(14)
            .width(Length::Fill);
        if self.probe.is_some() || self.diagnostic_task.is_some() {
            right = right.push(
                pill(
                    tk,
                    Kind::Danger,
                    text(t("Отменить проверку", "Cancel check"))
                        .size(13)
                        .font(BOLD),
                )
                .on_press(Message::Cancel),
            );
        }
        match self.columns() {
            Columns::Two => row![left, right.width(380)].spacing(24).into(),
            Columns::One => column![left, right].spacing(18).into(),
        }
    }

    // ------------------------------------------------------------ network & settings

    fn network_view(&self, tk: Tokens) -> Element<'_, Message> {
        let mut content = column![
            card(
                tk,
                column![
                    text(t("Режим подключения", "Connection mode"))
                        .size(17)
                        .font(BOLD),
                    self.proxy_settings()
                ]
                .spacing(10)
            ),
            card(tk, self.fallback_settings())
        ]
        .spacing(14);
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            content = content.push(card(tk, self.always_view()));
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        let _ = &mut content;
        content.into()
    }
    fn settings_view(&self, tk: Tokens) -> Element<'_, Message> {
        let segment = |label: &'static str, choice: ThemeChoice| {
            let on = self.theme_choice == choice;
            pill(
                tk,
                if on { Kind::Primary } else { Kind::Chip },
                text(label).size(13).font(BOLD),
            )
            .on_press(Message::Theme(choice))
        };
        let appearance = column![
            text(t("Оформление", "Appearance")).size(17).font(BOLD),
            row![
                segment(t("Как в системе", "System"), ThemeChoice::System),
                segment(t("Тёмная", "Dark"), ThemeChoice::Dark),
                segment(t("Светлая", "Light"), ThemeChoice::Light)
            ]
            .spacing(8),
            muted(
                tk,
                t(
                    "Светлая тема — матовое стекло; настоящее размытие фона есть только там, где его даёт система (macOS).",
                    "Light theme is frosted glass; real background blur only where the system provides it (macOS).",
                )
            )
        ]
        .spacing(10);
        #[cfg(target_os = "macos")]
        let appearance = {
            let mut appearance = appearance.push(
                checkbox(self.glass_enabled)
                    .label(t(
                        "Стекло — прозрачный фон окна",
                        "Glass — translucent window background",
                    ))
                    .on_toggle(Message::Glass),
            );
            if !glass::transparency_allowed() {
                appearance = appearance.push(muted(
                    tk,
                    t(
                        "Прозрачность отключена в системных настройках универсального доступа.",
                        "Transparency is turned off in the system accessibility settings.",
                    ),
                ));
            }
            appearance
        };
        let mut toggle = checkbox(self.autostart).label(t(
            "Запускать приложение при входе в систему",
            "Start the app at login",
        ));
        if !self.busy && !self.startup_busy {
            toggle = toggle.on_toggle(Message::StartupSet);
        }
        let mut connect = checkbox(self.saved_connection.auto_connect).label(t(
            "Подключать профиль по умолчанию при запуске",
            "Connect the default profile at launch",
        ));
        if self.can_change_profiles() {
            connect = connect.on_toggle(Message::AutoConnect);
        }
        let mut startup = column![
            text(t("Запуск", "Startup")).size(17).font(BOLD),
            toggle,
            muted(tk, t("Приложение откроется в трее. При отсутствии трея окно будет свёрнуто.", "The app opens in the tray. Without a tray the window is minimized.")),
            pill(tk, Kind::Chip, text(t("Проверить настройку ОС", "Check the OS setting")).size(13))
                .on_press_maybe((!self.startup_busy).then_some(Message::StartupRefresh)),
            connect,
            muted(tk, t("Одна попытка после загрузки хранилища. При открытии файла или tt-ссылки автоподключение не выполняется. До подключения трафик не защищён VPN.", "One attempt after the storage loads. Opening a file or tt link does not auto-connect. Until connected, traffic is not protected by the VPN."))
        ]
        .spacing(10);
        if self.startup_busy {
            startup = startup.push(muted(
                tk,
                t(
                    "Проверка настройки автозапуска…",
                    "Checking the login start setting…",
                ),
            ));
        }
        if let Some(error) = &self.startup_error {
            startup = startup.push(text(error).color(tk.danger));
        }
        let recovery = column![
            text(t("Восстановление", "Recovery")).size(17).font(BOLD),
            muted(tk, t("Предыдущая зашифрованная копия хранилища показывается перед заменой; VPN при этом не подключается.", "The previous encrypted storage copy is shown before it replaces anything; the VPN does not connect.")),
            pill(tk, Kind::Chip, text(t("Восстановить предыдущую копию хранилища", "Restore the previous storage copy")).size(13)).on_press_maybe(
                (self.can_change_profiles() && !self.dirty).then_some(Message::ReadBackup),
            )
        ]
        .spacing(10);
        column![card(tk, appearance), card(tk, startup), card(tk, recovery)]
            .spacing(14)
            .into()
    }
}
fn profile_card<'a>(
    tk: Tokens,
    label: &'static str,
    p: &Profile,
    show_host: bool,
    message: Message,
) -> Element<'a, Message> {
    let detail = if show_host {
        format!("{} · {}", protocol_label(p), p.endpoint.hostname)
    } else {
        protocol_label(p)
    };
    let (code, fg, bg) = badge(p, tk);
    buttons::Button::new(
        row![
            soft(bg, 15.0, text(code).size(13).font(BOLD).color(fg))
                .width(44)
                .height(44)
                .align_x(iced::Alignment::Center)
                .align_y(iced::Alignment::Center),
            column![
                caps(tk, label),
                text(p.name.clone()).size(16).font(BOLD),
                text(detail).size(12).color(tk.muted)
            ]
            .spacing(2)
            .width(Length::Fill)
        ]
        .spacing(12)
        .align_y(iced::Alignment::Center),
    )
    .width(Length::Fill)
    .padding(16)
    .style(move |_, status| buttons::Style {
        background: Some(
            if matches!(status, buttons::Status::Hovered) {
                tk.chip
            } else {
                tk.card
            }
            .into(),
        ),
        text_color: tk.text,
        border: iced::Border {
            color: tk.stroke,
            width: 1.0,
            radius: 22.0.into(),
        },
        ..Default::default()
    })
    .on_press(message)
    .into()
}
#[cfg(target_os = "macos")]
pub(super) fn native_window(
    window: &dyn iced::window::Window,
) -> Option<*mut objc2::runtime::AnyObject> {
    use iced::window::raw_window_handle::RawWindowHandle;
    let handle = window.window_handle().ok()?;
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return None;
    };
    unsafe {
        let view = handle.ns_view.as_ptr() as *mut objc2::runtime::AnyObject;
        let ns_window: *mut objc2::runtime::AnyObject = objc2::msg_send![view, window];
        (!ns_window.is_null()).then_some(ns_window)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_control::observations::{FRESH_MS, Mode as ObsMode, Monitor, Source, now_ms};
    use rtrust_profile::routing::Action;
    fn passed(now: u64) -> Observation {
        Observation {
            outcome: Outcome::Passed,
            source: Source::ServiceLifecycle,
            observed_at_ms: Some(now),
            valid_for_ms: FRESH_MS,
            mode: ObsMode::Full,
            reason: ObservationReason::SessionRunning,
        }
    }
    fn all_passed(now: u64) -> Snapshot {
        let mut s = Snapshot::unknown(ObsMode::Full);
        for check in CHECKS {
            let o = match check {
                Check::Transport => &mut s.transport,
                Check::Route => &mut s.route,
                Check::Dns => &mut s.dns,
                Check::Guard => &mut s.guard,
                Check::Connectivity => &mut s.connectivity,
            };
            *o = passed(now);
        }
        s
    }
    #[test]
    fn path_check_fills_route_and_connectivity_only_for_its_session() {
        use rtrust_desktop::diagnostics::{Fact, Report};
        let mut service = Snapshot::unknown(ObsMode::Split);
        service.transport = Observation {
            mode: ObsMode::Split,
            ..passed(now_ms())
        };
        let mut report = Report::new(service.clone());
        report.route = Fact::Passed;
        report.https = Fact::Passed;
        report.dns = Fact::Passed;
        // Not finished yet: nothing to show.
        let mut shown = service.clone();
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown, service);
        report.finished_at_ms = now_ms();
        apply_probe(&mut shown, &report, now_ms());
        let now = now_ms();
        assert_eq!(normalized(&shown.route, now), Outcome::Passed);
        assert_eq!(normalized(&shown.connectivity, now), Outcome::Passed);
        // A system lookup is not DNS-path evidence, and the guard is never probed.
        assert_eq!(shown.dns.outcome, Outcome::Unknown);
        assert_eq!(shown.guard.outcome, Outcome::Unknown);
        // Probe results outlive the 6 s service TTL until the next 30 s run is overdue.
        assert_eq!(normalized(&shown.route, now + 20_000), Outcome::Passed);
        assert_eq!(
            normalized(&shown.route, now + PROBE_FRESH_MS + 1),
            Outcome::Stale
        );
        // A report from an earlier generation is ignored.
        let mut later = service.clone();
        later.generation += 1;
        let before = later.clone();
        apply_probe(&mut later, &report, now_ms());
        assert_eq!(later, before);
        // One site failing over the tunnel says nothing about the tunnel.
        report.https = Fact::Timeout;
        let mut shown = service.clone();
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown.connectivity, service.connectivity);
        // In split mode an unexplained bypass may be a rule doing its job.
        report.route = Fact::RouteMismatch;
        report.https = Fact::NotChecked;
        let mut shown = service.clone();
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown, service);
        report.policy = Some(policy(Action::Direct));
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown, service);
        // A bypass of a destination the policy tunnels is a failure; service
        // evidence is never overwritten.
        report.policy = Some(policy(Action::Tunnel));
        shown.connectivity = Observation {
            outcome: Outcome::Failed,
            source: Source::ServiceLifecycle,
            ..shown.connectivity
        };
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown.route.outcome, Outcome::Failed);
        assert_eq!(shown.connectivity.source, Source::ServiceLifecycle);
        assert_eq!(tunnel_level(&shown, now), Level::Warning);
        // The probe failure expires like its passes do.
        assert_eq!(
            normalized(&shown.route, now + PROBE_FRESH_MS + 1),
            Outcome::Stale
        );
    }
    #[test]
    fn full_mode_route_bypass_fails_unless_policy_excludes_it() {
        use rtrust_desktop::diagnostics::{Fact, Report};
        let mut service = Snapshot::unknown(ObsMode::Full);
        service.transport = passed(now_ms());
        let mut report = Report::new(service.clone());
        report.route = Fact::RouteMismatch;
        report.finished_at_ms = now_ms();
        let mut shown = service.clone();
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown.route.outcome, Outcome::Failed);
        // Endpoint and local-network bypasses are direct by design.
        report.policy = Some(policy(Action::Direct));
        let mut shown = service.clone();
        apply_probe(&mut shown, &report, now_ms());
        assert_eq!(shown, service);
    }
    #[test]
    fn backdrop_fields_are_blurred_disks() {
        let size = iced::Size::new(80.0, 40.0);
        let white = Color::WHITE;
        let pixels = backdrop_pixels(10, 5, size, &[(20.0, 20.0, 260.0, white, 0.35)]);
        assert_eq!(pixels.len(), 10 * 5 * 4);
        // Well inside the disk the field reaches its full opacity.
        let alpha = |i: usize| pixels[i * 4 + 3];
        assert!(
            (alpha(0) as f32 / 255.0 - 0.35).abs() < 0.01,
            "{}",
            alpha(0)
        );
        // A far field fades out; two fields compose over each other.
        let far = backdrop_pixels(1, 1, size, &[(1000.0, 0.0, 10.0, white, 0.4)]);
        assert_eq!(far[3], 0);
        let red = Color::from_rgb(1.0, 0.0, 0.0);
        let both = backdrop_pixels(
            1,
            1,
            size,
            &[
                (40.0, 20.0, 500.0, white, 0.4),
                (40.0, 20.0, 500.0, red, 0.4),
            ],
        );
        assert_eq!(both[0], 255);
        assert!(both[1] > 60 && both[1] < 120, "{both:?}");
        assert!((both[3] as f32 / 255.0 - 0.64).abs() < 0.01, "{both:?}");
        assert!((normal_cdf(0.0) - 0.5).abs() < 1e-6 && normal_cdf(3.0) > 0.998);
    }
    #[test]
    fn backdrop_raster_is_reused_until_its_grid_or_state_changes() {
        let blue = Hue::Blue.fill(false);
        let (first, snapped) = backdrop_image(iced::Size::new(1001.0, 701.0), blue);
        // Whole texels, covering the window by less than one texel.
        assert_eq!(snapped, iced::Size::new(1004.0, 704.0));
        let (same, _) = backdrop_image(iced::Size::new(1003.0, 703.5), blue);
        assert_eq!(first.id(), same.id());
        let (wider, _) = backdrop_image(iced::Size::new(1005.0, 701.0), blue);
        assert_ne!(first.id(), wider.id());
        let (recoloured, _) = backdrop_image(iced::Size::new(1005.0, 701.0), Hue::Red.fill(false));
        assert_ne!(wider.id(), recoloured.id());
    }
    #[test]
    fn disabled_pills_halve_their_own_alpha() {
        for tk in [LIGHT_TOKENS, DARK_TOKENS] {
            let enabled = pill_style(tk, Kind::Danger, buttons::Status::Active);
            let disabled = pill_style(tk, Kind::Danger, buttons::Status::Disabled);
            let alpha = |s: &buttons::Style| match s.background {
                Some(iced::Background::Color(c)) => c.a,
                _ => panic!("pill without a colour"),
            };
            assert!((alpha(&disabled) - alpha(&enabled) / 2.0).abs() < 1e-6);
        }
    }
    #[test]
    fn probe_stays_fresh_until_the_next_run_is_overdue() {
        let slowest_gap = PROBE_INTERVAL + rtrust_desktop::diagnostics::TOTAL;
        assert!(u128::from(PROBE_FRESH_MS) > slowest_gap.as_millis());
    }
    #[test]
    fn path_check_replaces_expired_service_evidence() {
        use rtrust_desktop::diagnostics::{Fact, Report};
        let now = now_ms();
        let mut service = Snapshot::unknown(ObsMode::Full);
        service.transport = passed(now);
        // The service proved the route once; that proof has since expired.
        service.route = passed(now - FRESH_MS - 1_000);
        let mut report = Report::new(service.clone());
        report.route = Fact::Passed;
        report.finished_at_ms = now;
        let mut shown = service.clone();
        apply_probe(&mut shown, &report, now);
        assert_eq!(shown.route.source, Source::AppProbe);
        assert_eq!(normalized(&shown.route, now), Outcome::Passed);
        // Fresh service evidence is kept.
        let mut fresh = service.clone();
        fresh.route = passed(now);
        let before = fresh.clone();
        apply_probe(&mut fresh, &report, now);
        assert_eq!(fresh, before);
    }
    fn policy(action: Action) -> rtrust_profile::routing::Decision {
        use rtrust_profile::routing::{Context, Decision, Reason};
        Decision {
            action,
            ..Decision::unknown(Context::default(), Reason::MatchedRule)
        }
    }
    #[test]
    fn green_only_when_every_check_passed_and_is_fresh() {
        let now = 1_000_000;
        let s = all_passed(now);
        assert_eq!(tunnel_level(&s, now), Level::Verified);
        // An expired pass is stale: back to blue, never green.
        assert_eq!(tunnel_level(&s, now + FRESH_MS + 1), Level::Running);
        // A future timestamp is not trusted either.
        assert_eq!(tunnel_level(&s, now - 1), Level::Running);
        // A longer service TTL is capped at FRESH_MS like Android.
        let mut long = all_passed(now);
        long.dns.valid_for_ms = FRESH_MS * 10;
        assert_eq!(tunnel_level(&long, now + FRESH_MS + 1), Level::Running);
        // One check without a result keeps the tunnel blue.
        let mut missing = all_passed(now);
        missing.guard = Observation::unknown(ObsMode::Full);
        assert_eq!(tunnel_level(&missing, now), Level::Running);
        let mut unsupported = all_passed(now);
        unsupported.route.outcome = Outcome::Unsupported;
        assert_eq!(tunnel_level(&unsupported, now), Level::Running);
    }
    #[test]
    fn any_failed_check_is_a_warning_even_if_others_passed() {
        let now = 1_000_000;
        let mut s = all_passed(now);
        s.dns.outcome = Outcome::Failed;
        assert_eq!(tunnel_level(&s, now), Level::Warning);
        // A failure does not expire into green or blue.
        assert_eq!(tunnel_level(&s, now + 60_000), Level::Warning);
    }
    #[test]
    fn a_running_transport_without_checks_is_blue_and_rows_say_no_data() {
        let now = rtrust_control::observations::now_ms();
        let running = Monitor::new(ObsMode::Full, Source::ServiceLifecycle, now).sample(now);
        assert_eq!(tunnel_level(&running, now), Level::Running);
        for check in [Check::Route, Check::Dns, Check::Guard, Check::Connectivity] {
            let (_, hue) = row_value(normalized(check.of(&running), now));
            assert!(hue.is_none(), "{check:?} must not look like a result");
        }
        let proxy = Monitor::new(ObsMode::Proxy, Source::ProxyLifecycle, now).sample(now);
        assert_eq!(tunnel_level(&proxy, now), Level::Running);
        assert_ne!(row_value(Outcome::Unknown).1, Some(Hue::Green));
    }
    #[test]
    fn app_level_follows_connection_lifecycle_and_errors() {
        let mut app = crate::tests::app();
        assert_eq!(app.level().0, Level::Off);
        let task = app.update(Message::ToggleConnection);
        assert_eq!(app.level().0, Level::Connecting);
        let _ = app.update(Message::Connected(
            app.connection_epoch,
            Err("offline".into()),
        ));
        assert_eq!(app.level().0, Level::Error);
        assert_eq!(app.last_error.as_deref(), Some("offline"));
        // Retrying clears the error until the new attempt resolves.
        let retry = app.update(Message::ToggleConnection);
        assert_eq!(app.level().0, Level::Connecting);
        assert!(app.last_error.is_none());
        let _ = app.update(Message::ToggleConnection); // cancel
        assert_eq!(app.level().0, Level::Off);
        app.disconnecting = true;
        assert_eq!(app.level().0, Level::Disconnecting);
        drop((task, retry));
    }
    fn system(outcome: Outcome, at: u64) -> Observation {
        Observation::system(outcome, ObsMode::Full, at)
    }
    #[test]
    fn service_probes_turn_green_and_return_to_blue_after_their_ttl() {
        use rtrust_desktop::diagnostics::{Fact, Report};
        let now = 1_000_000;
        let mut s = all_passed(now);
        for o in [&mut s.transport, &mut s.dns, &mut s.guard] {
            *o = system(Outcome::Passed, now);
        }
        s.route.source = Source::AppProbe;
        s.route.valid_for_ms = PROBE_FRESH_MS;
        s.connectivity = s.route.clone();
        // Service probe TTL outlives the 6 s lifecycle cap, not more.
        assert_eq!(tunnel_level(&s, now + FRESH_MS + 1), Level::Verified);
        assert_eq!(tunnel_level(&s, now + PROBE_TTL_MS + 1), Level::Running);
        let mut long = s.clone();
        long.guard.valid_for_ms = PROBE_TTL_MS * 10;
        assert_eq!(
            normalized(&long.guard, now + PROBE_TTL_MS + 1),
            Outcome::Stale
        );
        // A failed service check is yellow, named, and does not outlive its TTL.
        let mut failed = s.clone();
        failed.guard = system(Outcome::Failed, now);
        assert_eq!(tunnel_level(&failed, now), Level::Warning);
        assert_eq!(
            normalized(&failed.guard, now + PROBE_TTL_MS + 1),
            Outcome::Stale
        );
        // The app's path check never replaces a current service probe row.
        let mut shown = Snapshot::unknown(ObsMode::Full);
        shown.route = system(Outcome::Unknown, now);
        let mut report = Report::new(shown.clone());
        report.route = Fact::Passed;
        report.finished_at_ms = now;
        let before = shown.clone();
        apply_probe(&mut shown, &report, now);
        assert_eq!(shown.route, before.route);
        apply_probe(&mut shown, &report, now + PROBE_TTL_MS + 1);
        assert_eq!(shown.route.source, Source::AppProbe);
    }
    // ---- tester (issue #81): green needs five fresh passes; probe rows win ----
    fn tester_full_green(now: u64) -> Snapshot {
        let mut s = all_passed(now);
        for o in [&mut s.transport, &mut s.dns, &mut s.guard] {
            *o = system(Outcome::Passed, now);
        }
        for o in [&mut s.route, &mut s.connectivity] {
            o.source = Source::AppProbe;
            o.valid_for_ms = PROBE_FRESH_MS;
        }
        s
    }
    #[test]
    fn tester_green_only_with_five_fresh_passes() {
        let now = 1_000_000;
        assert_eq!(tunnel_level(&tester_full_green(now), now), Level::Verified);
        for check in CHECKS {
            for (outcome, level) in [
                (Outcome::Unknown, Level::Running),
                (Outcome::Configured, Level::Running),
                (Outcome::Stale, Level::Running),
                (Outcome::Unsupported, Level::Running),
                (Outcome::Failed, Level::Warning),
            ] {
                let mut s = tester_full_green(now);
                let o = match check {
                    Check::Transport => &mut s.transport,
                    Check::Route => &mut s.route,
                    Check::Dns => &mut s.dns,
                    Check::Guard => &mut s.guard,
                    Check::Connectivity => &mut s.connectivity,
                };
                o.outcome = outcome;
                assert_eq!(tunnel_level(&s, now), level, "{check:?} {outcome:?}");
            }
            // An untimed or future pass is not fresh.
            for at in [None, Some(now + 1)] {
                let mut s = tester_full_green(now);
                let o = match check {
                    Check::Transport => &mut s.transport,
                    Check::Route => &mut s.route,
                    Check::Dns => &mut s.dns,
                    Check::Guard => &mut s.guard,
                    Check::Connectivity => &mut s.connectivity,
                };
                o.observed_at_ms = at;
                assert_eq!(tunnel_level(&s, now), Level::Running, "{check:?} {at:?}");
            }
        }
        // Split never turns green, even with five passes.
        let mut split = tester_full_green(now);
        for o in [
            &mut split.transport,
            &mut split.route,
            &mut split.dns,
            &mut split.guard,
            &mut split.connectivity,
        ] {
            o.mode = ObsMode::Split;
        }
        assert_eq!(tunnel_level(&split, now), Level::Running);
        // Green holds up to the probe TTL and is blue one millisecond later.
        let s = tester_full_green(now);
        assert_eq!(tunnel_level(&s, now + PROBE_TTL_MS), Level::Verified);
        assert_eq!(tunnel_level(&s, now + PROBE_TTL_MS + 1), Level::Running);
        // A lifecycle row claiming the probe TTL keeps the 6 s cap.
        let mut lifecycle = s.clone();
        lifecycle.dns = passed(now);
        lifecycle.dns.valid_for_ms = PROBE_TTL_MS;
        assert_eq!(tunnel_level(&lifecycle, now + FRESH_MS + 1), Level::Running);
    }
    #[test]
    fn tester_apply_probe_never_overrides_a_current_service_probe_row() {
        use rtrust_desktop::diagnostics::{Fact, Report};
        let now = 1_000_000;
        for outcome in [Outcome::Failed, Outcome::Passed, Outcome::Unknown] {
            let mut shown = Snapshot::unknown(ObsMode::Full);
            shown.route = system(outcome, now);
            shown.connectivity = system(outcome, now);
            let mut report = Report::new(shown.clone());
            report.route = if outcome == Outcome::Passed {
                Fact::RouteMismatch
            } else {
                Fact::Passed
            };
            report.https = Fact::Passed;
            report.finished_at_ms = now;
            let before = shown.clone();
            apply_probe(&mut shown, &report, now + PROBE_TTL_MS);
            assert_eq!(shown.route, before.route, "{outcome:?}");
            assert_eq!(shown.connectivity, before.connectivity, "{outcome:?}");
            // Once expired, the app's own check may fill the row again.
            apply_probe(&mut shown, &report, now + PROBE_TTL_MS + 1);
            assert_eq!(shown.connectivity.source, Source::AppProbe, "{outcome:?}");
        }
    }
    #[test]
    fn split_dns_and_guard_read_not_applicable_and_off_and_stay_blue() {
        let now = rtrust_control::observations::now_ms();
        let split = Monitor::new(ObsMode::Split, Source::ServiceLifecycle, now).sample(now);
        assert_eq!(tunnel_level(&split, now), Level::Running);
        let dns = check_value(Check::Dns, ObsMode::Split, normalized(&split.dns, now));
        let guard = check_value(Check::Guard, ObsMode::Split, normalized(&split.guard, now));
        assert_eq!(dns, (t("не проверяется", "not checked"), None));
        assert_eq!(guard, (t("не включена", "off"), None));
        assert_eq!(
            check_value(Check::Guard, ObsMode::Full, Outcome::Unsupported),
            row_value(Outcome::Unsupported)
        );
    }
    #[test]
    fn split_tunnel_and_proxy_never_turn_green() {
        let now = 1_000_000;
        let mut split = all_passed(now);
        split.transport.mode = ObsMode::Split;
        assert_eq!(tunnel_level(&split, now), Level::Running);
        assert_ne!(
            Check::Guard.meaning(ObsMode::Split),
            Check::Guard.meaning(ObsMode::Full)
        );
        assert_ne!(
            Check::Dns.meaning(ObsMode::Split),
            Check::Dns.meaning(ObsMode::Full)
        );
        let mut proxy = all_passed(now);
        proxy.transport.mode = ObsMode::Proxy;
        assert_eq!(tunnel_level(&proxy, now), Level::Running);
    }
    #[test]
    fn running_text_follows_outcomes_and_explains_socks_scope() {
        let now = rtrust_control::observations::now_ms();
        let proxy = Monitor::new(ObsMode::Proxy, Source::ProxyLifecycle, now).sample(now);
        let socks = running_text(&proxy, now, "1080");
        assert!(socks.contains("SOCKS5") && socks.contains("127.0.0.1:1080"));
        // Proxy mode lists no route/guard results and claims nothing about them.
        assert!(!socks.contains(t("Пока без результата", "No result yet")));
        for check in [Check::Route, Check::Guard, Check::Connectivity] {
            assert!(!socks.contains(check.name()), "{check:?} in {socks}");
        }
        let full = Monitor::new(ObsMode::Full, Source::ServiceLifecycle, now).sample(now);
        let text = running_text(&full, now, "1080");
        assert!(!text.contains("SOCKS5"));
        for check in [Check::Route, Check::Dns, Check::Guard, Check::Connectivity] {
            assert!(text.contains(check.name()), "{check:?} missing in {text}");
        }
        let mut partial = full.clone();
        partial.dns = passed(now);
        partial.guard.outcome = Outcome::Unsupported;
        let text = running_text(&partial, now, "1080");
        let pending = text
            .split(&format!("{}:", t("Пока без результата", "No result yet")))
            .nth(1)
            .unwrap();
        assert!(!pending.contains(Check::Dns.name()) && !pending.contains(Check::Guard.name()));
    }
    #[test]
    fn failover_shows_the_backup_that_carries_traffic() {
        let candidates = vec!["office".to_owned(), "reserve".to_owned()];
        assert_eq!(
            live_name(Some(1), &candidates, "office"),
            ("reserve".to_owned(), true)
        );
        assert_eq!(
            live_name(Some(0), &candidates, "office"),
            ("office".to_owned(), false)
        );
        // Unknown or out-of-range indices keep the requested profile.
        assert_eq!(
            live_name(None, &candidates, "office"),
            ("office".to_owned(), false)
        );
        assert_eq!(
            live_name(Some(7), &candidates, "office"),
            ("office".to_owned(), false)
        );
    }
    #[test]
    fn connect_control_stays_available_during_a_store_conflict() {
        let mut app = crate::tests::app();
        app.page = Page::Profiles;
        assert!(!app.shows_connect_control());
        app.store_conflict = Some((
            rtrust_store::Vault {
                profiles: app.profiles.clone(),
                connection: Default::default(),
            },
            None,
        ));
        assert!(app.shows_connect_control());
        // A live attempt can still be cancelled from the conflict view.
        let task = app.update(Message::ToggleConnection);
        assert!(app.connecting);
        let _ = app.view();
        let _ = app.update(Message::ToggleConnection);
        assert!(!app.connecting);
        drop(task);
    }
    #[test]
    fn recovery_or_a_new_selection_clears_the_red_state() {
        let mut app = crate::tests::app();
        app.last_error = Some("cleanup failed".into());
        let _ = app.update(Message::Recovered(Ok("done".into())));
        assert!(app.last_error.is_none());
        app.last_error = Some("offline".into());
        let _ = app.update(Message::Recovered(Err("refused".into())));
        assert!(app.last_error.is_some());
        let _ = app.update(Message::Select(1));
        assert_eq!(app.level().0, Level::Off);
    }
    #[test]
    fn network_and_settings_stay_reachable_while_busy() {
        let mut app = crate::tests::app();
        app.busy = true;
        let _ = app.update(Message::Navigate(Page::Network));
        assert!(app.page == Page::Network);
        let _ = app.update(Message::Navigate(Page::Profiles));
        assert!(app.page == Page::Network);
    }
    #[test]
    fn language_detection_defaults_to_russian() {
        assert!(is_russian(None));
        assert!(is_russian(Some("")));
        assert!(is_russian(Some("ru-RU")));
        assert!(is_russian(Some("ru_RU.UTF-8")));
        assert!(is_russian(Some("C")));
        assert!(!is_russian(Some("en-US")));
        assert!(!is_russian(Some("de_DE.UTF-8")));
    }
    #[test]
    fn theme_choice_round_trips_and_follows_the_system_by_default() {
        for choice in [ThemeChoice::System, ThemeChoice::Dark, ThemeChoice::Light] {
            assert_eq!(ThemeChoice::parse(choice.key()), choice);
        }
        assert_eq!(ThemeChoice::parse("garbage"), ThemeChoice::System);
        let mut app = crate::tests::app();
        assert_eq!(app.theme_choice, ThemeChoice::System);
        let _ = app.update(Message::SystemTheme(iced::theme::Mode::Light));
        assert!(!app.dark());
        let _ = app.update(Message::Theme(ThemeChoice::Dark));
        assert!(app.dark());
        let _ = app.update(Message::SystemTheme(iced::theme::Mode::Light));
        assert!(app.dark(), "an explicit choice wins over the system");
    }
    #[test]
    fn every_page_renders_in_both_themes_and_widths() {
        let mut app = crate::tests::app();
        app.preview = Some(app.profiles[1].clone());
        app.saved_connection.fallback_profiles = vec![app.profiles[1].name.clone()];
        let mut pages = vec![
            Page::Home,
            Page::Profiles,
            Page::Import,
            Page::Diagnostics,
            Page::Network,
            Page::Portal,
            Page::Settings,
        ];
        #[cfg(target_os = "windows")]
        pages.push(Page::Updates);
        #[cfg(not(target_os = "windows"))]
        let _ = &mut pages;
        for theme in [ThemeChoice::Dark, ThemeChoice::Light] {
            app.theme_choice = theme;
            for width in [900.0, 1180.0, 1600.0] {
                app.window_width = width;
                for page in &pages {
                    app.page = *page;
                    let _ = app.view();
                }
            }
        }
        app.profile_query = "second".into();
        app.page = Page::Profiles;
        let _ = app.view();
    }
}
