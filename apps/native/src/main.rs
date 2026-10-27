#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod always_on;
mod autostart;
mod conflicts;
use rtrust_desktop::connection;
#[cfg(target_os = "linux")]
mod flatpak_startup;
#[cfg(target_os = "macos")]
#[path = "../../macos/glass.rs"]
mod glass;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod intent;
#[cfg(target_os = "macos")]
mod open_url;
mod portal;
#[cfg(test)]
mod socks_e2e_tests;
mod socks_recovery;
mod sync;
#[cfg(test)]
mod tester_socks_tests;
mod tray;
mod ui;
#[cfg(target_os = "windows")]
mod updates;
use connection::{Mode, Session};
use iced::{
    Color, Element, Length, Task, Theme,
    widget::{
        button as buttons, checkbox, column, container, pick_list, row, scrollable, text,
        text_editor, text_input,
    },
};
use rtrust_profile::{Format, Profile};
use zeroize::Zeroizing;

fn window_settings() -> iced::window::Settings {
    let window = iced::window::Settings {
        size: iced::Size::new(1180.0, 780.0),
        min_size: Some(iced::Size::new(760.0, 560.0)),
        exit_on_close_request: false,
        transparent: cfg!(target_os = "macos"),
        icon: iced::window::icon::from_rgba(
            include_bytes!("../../../packaging/branding/icon-128.rgba").to_vec(),
            128,
            128,
        )
        .ok(),
        ..Default::default()
    };
    #[cfg(target_os = "linux")]
    let window = iced::window::Settings {
        platform_specific: iced::window::settings::PlatformSpecific {
            application_id: "org.rtrusttunnel.Native".into(),
            ..Default::default()
        },
        ..window
    };
    window
}
fn open_window() -> Task<Message> {
    iced::window::open(window_settings()).1.then(|id| {
        iced::window::run(id, |window| {
            #[cfg(target_os = "macos")]
            {
                use iced::window::raw_window_handle::RawWindowHandle;
                if let Ok(handle) = window.window_handle()
                    && let RawWindowHandle::AppKit(handle) = handle.as_raw()
                {
                    unsafe {
                        let view = handle.ns_view.as_ptr() as *mut objc2::runtime::AnyObject;
                        let window = objc2::msg_send![view, window];
                        let installed = glass::install(window);
                        glass::set_appearance(window, ui::dark_now());
                        if std::env::args().any(|arg| arg == "--ci-glass-smoke") {
                            assert!(installed, "AppKit material was not installed");
                        }
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            let _ = window;
            Message::Tick
        })
    })
}
fn main() -> iced::Result {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args == ["--ci-storage-smoke"] || args == ["--ci-storage-read"] {
        let result = if args == ["--ci-storage-smoke"] {
            rtrust_store::platform_probe::run()
        } else {
            rtrust_store::platform_probe::child()
        };
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        println!("PASS isolated encrypted storage and OS keyring across processes");
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    if args == ["--ci-autostart-enable"] || args == ["--ci-autostart-disable"] {
        if let Err(error) = flatpak_startup::request(args == ["--ci-autostart-enable"]) {
            eprintln!("{error}");
            std::process::exit(1);
        }
        println!("PASS Background portal autostart response");
        return Ok(());
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if std::env::args_os()
        .skip(1)
        .eq([std::ffi::OsString::from("--ci-service-smoke")])
    {
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(async { rtrust_control::Client::prepare_update().await.map(drop) });
        if let Err(error) = result {
            eprintln!("{error}");
            std::process::exit(1);
        }
        println!("PASS authenticated service channel and maintenance lease");
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    open_url::install();
    iced::daemon(
        || {
            let (app, task) = App::boot();
            (
                app,
                Task::batch([
                    task,
                    iced::system::theme().map(Message::SystemTheme),
                    open_window(),
                ]),
            )
        },
        App::update,
        App::view_window,
    )
    .title("R-TrustTunnel")
    .subscription(App::subscription)
    .theme(|app: &App, _| ui::theme(&app.tokens()))
    .style(|_app: &App, theme: &Theme| {
        let background = theme.palette().background;
        #[cfg(target_os = "macos")]
        let background = {
            let mut background = background;
            if _app.glass_enabled && glass::transparency_allowed() {
                // iced blends quads premultiplied but clears with this colour
                // as given; a straight colour here washes every translucent
                // card and colour field above it out to white.
                let a = 0.68;
                background =
                    iced::Color::from_rgba(background.r * a, background.g * a, background.b * a, a);
            }
            background
        };
        iced::theme::Style {
            background_color: background,
            text_color: theme.palette().text,
        }
    })
    .settings(iced::Settings {
        id: Some("org.rtrusttunnel.Native".into()),
        default_text_size: 14.0.into(),
        default_font: ui::REGULAR,
        ..Default::default()
    })
    .run()
}
/// Shared by offline explain and the diagnostic verdict; prediction, not proof.
fn describe_decision(d: &rtrust_profile::routing::Decision) -> String {
    use rtrust_profile::routing::{Action, Reason, Source};
    let path = match d.action {
        Action::Tunnel => "через VPN",
        Action::Direct => "напрямую",
        Action::Block => "заблокировано",
        Action::Unknown => "неизвестно",
    };
    let reason = match d.reason {
        Reason::SelectedPrefix => "адрес входит в выбранные сети",
        Reason::ExcludedPrefix => "явное исключение имеет приоритет",
        Reason::ReservedAddress => "зарезервированный системный адрес",
        Reason::OutsideSelection => "адрес вне выбранных сетей",
        Reason::EndpointBypass => "адрес самого VPN endpoint",
        Reason::LocalNetworkBypass => "локальная сеть исключена",
        Reason::EndpointUnresolved => "адреса endpoint не подтверждены",
        Reason::LocalNetworksUnobserved => "текущие LAN-маршруты не наблюдались",
        Reason::UnsupportedFamily => "выбранный режим поддерживает только IPv4",
        Reason::ProxyScope => "SOCKS не задаёт системный маршрут",
        _ => "системный путь или DNS-происхождение имени не наблюдались",
    };
    let source = if d.context.source == Source::ManagedUnknown {
        "серверная политика; роль admin/user не указана"
    } else {
        "локальные настройки"
    };
    format!(
        "Прогноз: {path}. Причина: {reason}. Источник: {source}. Ревизия: {}. Правила: {:?}. Защита и фактический трафик не проверялись.",
        d.context.revision.as_deref().unwrap_or("неизвестна"),
        d.rules
    )
}
#[derive(Clone, Copy, PartialEq, Debug)]
enum Page {
    Home,
    Profiles,
    /// Add profile.
    Import,
    /// Checks.
    Diagnostics,
    Network,
    /// Sync and portal enrollment.
    Portal,
    Settings,
    #[cfg(target_os = "windows")]
    Updates,
}
impl Page {
    /// Sections whose controls must stay usable during a long operation:
    /// always-on disable/recovery, backups and updates live outside Settings.
    fn reachable_while_busy(self) -> bool {
        #[cfg(target_os = "windows")]
        if self == Page::Updates {
            return true;
        }
        matches!(self, Page::Settings | Page::Network)
    }
}
struct App {
    #[cfg(target_os = "macos")]
    glass_enabled: bool,
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    always_on: always_on::State,
    #[cfg(target_os = "windows")]
    updates: updates::State,
    portal: portal::State,
    store_recovery: bool,
    // Owner of a session this GUI started whose Stop was not confirmed; kept
    // in memory (never shown) until Recover succeeds or a new session starts.
    pending_owner: Option<rtrust_control::owner::Owner>,
    sync_state: sync::State,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    intent: intent::State,
    store_conflict: Option<(rtrust_store::Vault, Option<Vec<u8>>)>,
    autostart: bool,
    startup_busy: bool,
    startup_error: Option<String>,
    login_start: bool,
    boot_connect_pending: bool,
    tray_ready: bool,
    /// The window is shown (not hidden to the tray or minimized by the app).
    /// Only then does Tick tell the service a user is viewing the session.
    /// An OS-level minimize is not tracked: it stays "visible" (more probes,
    /// never a false result).
    window_visible: bool,
    tray_smoke: bool,
    pending_close: Option<bool>,
    autosave_due: Option<std::time::Instant>,
    profiles: Vec<Profile>,
    selected: usize,
    page: Page,
    input: text_editor::Content,
    preview: Option<Profile>,
    status: String,
    busy: bool,
    format: Format,
    consent: bool,
    revision: Option<Vec<u8>>,
    target: String,
    system_target: String,
    diagnostic_report: Option<(u64, rtrust_desktop::diagnostics::Report)>,
    diagnostic_preview: text_editor::Content,
    diagnostic_preview_dirty: bool,
    diagnostic_export_report: Option<rtrust_desktop::diagnostics::Report>,
    system_target_edited_at: Option<std::time::Instant>,
    last_diagnostic: Option<std::time::Instant>,
    diagnostic_task: Option<iced::task::Handle>,
    diagnostic_generation: u64,
    /// Set by a proposed action; attached to the next completed report.
    follow_up: Option<rtrust_desktop::diagnostics::FollowUp>,
    /// Reconnect action in progress: Stop, then Start, then repeat the check.
    reconnect_then_check: bool,
    /// Names sent with the last Start: the requested profile, then backups.
    connection_candidates: Vec<String>,
    probe: Option<iced::task::Handle>,
    generation: u64,
    connection_epoch: u64,
    connection_task: Option<iced::task::Handle>,
    session: Option<Session>,
    /// SOCKS reconnect policy for the connection the user started (#99).
    socks_recovery: Option<socks_recovery::Recovery>,
    connecting: bool,
    connection_name: String,
    /// Whether the connected endpoint relays IPv6; otherwise IPv6 is refused locally.
    connection_ipv6: bool,
    proxy_port: String,
    mode: Mode,
    networks: String,
    exclude: String,
    exclude_lan: bool,
    dns: String,
    saved_connection: rtrust_store::ConnectionSettings,
    disconnecting: bool,
    exit_after_stop: bool,
    draft_name: String,
    confirm_delete: bool,
    confirm_replace: bool,
    dirty: bool,
    theme_choice: ui::ThemeChoice,
    system_dark: bool,
    window_width: f32,
    profile_query: String,
    /// Last failed connect/disconnect, shown as the red state until the next attempt.
    last_error: Option<String>,
}
#[derive(Clone)]
enum Message {
    SystemTheme(iced::theme::Mode),
    Theme(ui::ThemeChoice),
    Resized(f32),
    ProfileQuery(String),
    DiscardPreview,
    #[cfg(target_os = "macos")]
    Glass(bool),
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    AlwaysOn(always_on::Action),
    Portal(portal::Action),
    StartupRefresh,
    AutoConnect(bool),
    StartupSet(bool),
    StartupLoaded(Result<bool, String>),
    StartupChanged(Result<bool, String>),
    TrayInit(iced::window::Id),
    TrayReady(bool),
    TraySmokeStep(u8),
    TraySmokeMode(iced::window::Mode),
    TraySmokeRestored(iced::window::Mode),
    TrayEvents(Vec<tray::Action>),
    ExitRequested,
    Navigate(Page),
    Edit(text_editor::Action),
    PickFile,
    Imported(Box<std::result::Result<Option<Profile>, String>>),
    Parse,
    Accept,
    Select(usize),
    Format(Format),
    Consent(bool),
    Export,
    Done(std::result::Result<String, String>),
    Load,
    Loaded(std::result::Result<(rtrust_store::Vault, Option<Vec<u8>>), String>),
    Sync(sync::Action),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Intent(intent::Action),
    #[cfg(target_os = "windows")]
    Update(updates::Action),
    Save,
    ReadBackup,
    BackupLoaded(Result<(rtrust_store::Vault, Option<Vec<u8>>), String>),
    StoreConflict(Result<(rtrust_store::Vault, Option<Vec<u8>>), String>),
    ResolveStore(conflicts::Choice),
    Saved(std::result::Result<Vec<u8>, String>),
    Target(String),
    Probe,
    SystemTarget(String),
    Diagnose,
    Diagnosed(u64, u64, rtrust_desktop::diagnostics::Report),
    DiagnosticAction(rtrust_desktop::diagnostics::Action),
    /// Allow or disallow a profile as an automatic backup.
    Fallback(String, bool),
    EndpointChecked(u64, u64, rtrust_desktop::diagnostics::EndpointCheck),
    DiagnosticEdit(text_editor::Action),
    ResetDiagnosticPreview,
    ExportDiagnostic,
    ExplainRoute,
    Probed(u64, std::result::Result<String, String>),
    Cancel,
    MakeDefault,
    ProxyPort(String),
    Mode(Mode),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Networks(String),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Exclude(String),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    ExcludeLan(bool),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    WholeIpv4,
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    Dns(String),
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    RecoverService,
    Recovered(Result<String, String>),
    Stopped(u64, Result<(), String>),
    CopyProxy,
    Tick,
    SmokeExit,
    CloseRequested,
    WindowFocused,
    DraftName(String),
    Rename,
    Delete,
    Replace,
    ToggleConnection,
    ToggleDefaultConnection,
    Connected(u64, Result<Session, String>),
    /// An automatic SOCKS reconnect attempt (#99); see `socks_recovery`.
    SocksAttempt(u64, Result<Session, socks_recovery::Failure>),
    Health(u64, Result<(), connection::HealthError>),
}
// Never derive Debug on UI messages carrying pasted profiles or file contents.
impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UiAction([REDACTED])")
    }
}
impl App {
    fn view_window(&self, _: iced::window::Id) -> Element<'_, Message> {
        self.view()
    }
    fn boot() -> (Self, Task<Message>) {
        let mut app = Self {
            #[cfg(target_os = "macos")]
            glass_enabled: glass::preference(),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            always_on: always_on::State::default(),
            #[cfg(target_os = "windows")]
            updates: updates::State::default(),
            portal: portal::State::default(),
            store_recovery: false,
            pending_owner: None,
            sync_state: sync::State::default(),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            intent: intent::State::default(),
            store_conflict: None,
            autostart: false,
            startup_busy: false,
            startup_error: None,
            login_start: false,
            boot_connect_pending: false,
            tray_ready: false,
            window_visible: true,
            tray_smoke: false,
            pending_close: None,
            autosave_due: None,
            profiles: vec![],
            selected: 0,
            page: Page::Home,
            input: text_editor::Content::new(),
            preview: None,
            status: "Загрузка защищённого хранилища…".into(),
            busy: false,
            format: Format::Json,
            consent: false,
            revision: None,
            target: "example.com:80".into(),
            system_target: "example.com".into(),
            diagnostic_report: None,
            diagnostic_preview: text_editor::Content::new(),
            diagnostic_preview_dirty: false,
            diagnostic_export_report: None,
            system_target_edited_at: None,
            last_diagnostic: None,
            diagnostic_task: None,
            diagnostic_generation: 0,
            follow_up: None,
            reconnect_then_check: false,
            connection_candidates: vec![],
            probe: None,
            generation: 0,
            connection_epoch: 0,
            connection_task: None,
            session: None,
            socks_recovery: None,
            connecting: false,
            connection_name: String::new(),
            connection_ipv6: true,
            proxy_port: "1080".into(),
            mode: Mode::Socks,
            networks: String::new(),
            exclude: String::new(),
            exclude_lan: false,
            dns: "1.1.1.1".into(),
            saved_connection: rtrust_store::ConnectionSettings::default(),
            disconnecting: false,
            exit_after_stop: false,
            draft_name: String::new(),
            confirm_delete: false,
            confirm_replace: false,
            dirty: false,
            theme_choice: ui::load_theme(),
            system_dark: true,
            window_width: 1180.0,
            profile_query: String::new(),
            last_error: None,
        };
        ui::remember_dark(app.dark());
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args
            .first()
            .is_some_and(|arg| arg == "--appearance-preview")
        {
            app.page = Page::Settings;
            app.status = "Предпросмотр оформления — VPN не подключён".into();
            return (app, Task::none());
        }
        if args.first().is_some_and(|arg| {
            arg == "--ci-smoke"
                || arg == "--ci-glass-smoke"
                || arg == "--ci-portal-smoke"
                || arg == "--ci-tray-smoke"
                || arg == "--ci-settings-smoke"
        }) {
            if args.first().is_some_and(|arg| arg == "--ci-portal-smoke") {
                app.page = Page::Portal;
            }
            if args.first().is_some_and(|arg| arg == "--ci-settings-smoke") {
                app.page = Page::Settings;
            }
            if args.first().is_some_and(|arg| arg == "--ci-tray-smoke") {
                app.tray_smoke = true;
                return (
                    app,
                    Task::perform(
                        async { tokio::time::sleep(std::time::Duration::from_secs(15)).await },
                        |_| Message::TraySmokeStep(99),
                    ),
                );
            }
            app.status = "CI: запуск интерфейса без хранилища и подключения".into();
            return (
                app,
                Task::perform(
                    async {
                        tokio::time::sleep(std::time::Duration::from_secs(
                            if std::env::args().any(|arg| arg == "--ci-glass-smoke") {
                                45
                            } else {
                                3
                            },
                        ))
                        .await
                    },
                    |_| Message::SmokeExit,
                ),
            );
        }
        app.boot_connect_pending = args.iter().all(|arg| arg == "--autostart");
        app.login_start = args.iter().any(|arg| arg == "--autostart");
        // A login start hides the window as soon as the tray is ready.
        app.window_visible = !app.login_start;
        if let Some(arg) = args
            .iter()
            .find(|arg| *arg != "--autostart" && *arg != "--no-auto-connect")
        {
            let input = if ["tt://", "hy2://", "hysteria2://"]
                .iter()
                .any(|scheme| arg.to_string_lossy().starts_with(scheme))
            {
                Ok(arg.to_string_lossy().into_owned())
            } else {
                startup_file(arg)
                    .and_then(|path| {
                        rtrust_store::read_bounded(&path, rtrust_profile::MAX_INPUT)
                            .map_err(|e| e.to_string())
                    })
                    .and_then(|b| String::from_utf8(b).map_err(|_| "Ожидается UTF-8".into()))
            };
            app.apply_import(
                input.and_then(|s| Profile::import(&s).map(Some).map_err(|e| e.to_string())),
            );
        }
        let task = app.update(Message::Load);
        let startup = app.update(Message::StartupRefresh);
        (app, Task::batch([task, startup]))
    }
    fn connect_on_boot(&mut self) -> Task<Message> {
        let unsupported = !cfg!(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos"
        )) && self.saved_connection.mode != rtrust_store::Mode::Socks;
        if unsupported || self.profiles.is_empty() {
            self.status = if unsupported {
                "Автоподключение отменено: сохранённый режим VPN не поддерживается на этой ОС."
            } else {
                "Автоподключение отменено: добавьте профиль по умолчанию."
            }
            .into();
            self.pending_close = None;
            self.login_start = false;
            return self.show_window();
        }
        // Never toggle an already active connection or restart a cancelled attempt.
        if self.connecting || self.session.is_some() || self.disconnecting {
            return Task::none();
        }
        self.update(Message::ToggleDefaultConnection)
    }
    fn connection_settings(&self) -> Result<rtrust_store::ConnectionSettings, String> {
        let socks_port = self
            .proxy_port
            .parse::<u16>()
            .ok()
            .filter(|p| *p > 0)
            .ok_or("Порт SOCKS5 должен быть числом от 1 до 65535.")?;
        let local_needed = self.saved_connection.mode == rtrust_store::Mode::Tun
            && self.saved_connection.managed_routes.is_none();
        // Leftover exclusions alone do not block saving outside TUN mode.
        let (networks, exclude) = if !local_needed && self.networks.trim().is_empty() {
            (vec![], vec![])
        } else {
            let selection =
                rtrust_control::Selection::parse(&self.networks, &self.exclude, self.exclude_lan)?;
            (selection.include, selection.exclude)
        };
        let settings = rtrust_store::ConnectionSettings {
            sync: self.saved_connection.sync.clone(),
            auto_connect: self.saved_connection.auto_connect,
            mode: self.saved_connection.mode,
            socks_port,
            networks,
            dns: self.dns.parse().map_err(|_| "Некорректный IPv4 DNS")?,
            exclude,
            exclude_lan: self.exclude_lan,
            managed_routes: self.saved_connection.managed_routes.clone(),
            // Deleted profiles drop out; the order is the user's preference.
            fallback_profiles: self
                .saved_connection
                .fallback_profiles
                .iter()
                .filter(|name| self.profiles.iter().any(|p| &p.name == *name))
                .cloned()
                .collect(),
        };
        settings
            .validate()
            .map_err(|_| "Для TUN укажите допустимые IPv4-сети.".to_owned())?;
        Ok(settings)
    }
    /// The TUN selection for the next connection: the server group policy
    /// when assigned, otherwise the local fields.
    fn tun_selection(&self) -> Result<rtrust_control::Selection, String> {
        match &self.saved_connection.managed_routes {
            Some(managed) => Ok(managed.selection.clone()),
            None => {
                rtrust_control::Selection::parse(&self.networks, &self.exclude, self.exclude_lan)
            }
        }
    }
    fn current(&self) -> Option<&Profile> {
        self.profiles.get(self.selected)
    }
    fn apply_import(&mut self, result: std::result::Result<Option<Profile>, String>) {
        self.busy = false;
        self.confirm_replace = false;
        match result {
            Ok(Some(p)) => {
                self.preview = Some(p);
                self.page = Page::Import;
                self.status="Профиль прочитан. Проверьте адрес, сертификат и возможности перед добавлением.".into();
            }
            Ok(None) => {}
            Err(e) => self.status = e,
        }
    }
    fn update(&mut self, m: Message) -> Task<Message> {
        let edited = matches!(
            &m,
            Message::AutoConnect(_)
                | Message::Fallback(..)
                | Message::Accept
                | Message::Rename
                | Message::Delete
                | Message::Replace
                | Message::MakeDefault
                | Message::ProxyPort(_)
                | Message::Mode(_)
        );
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        let edited = edited
            || matches!(
                &m,
                Message::Networks(_)
                    | Message::Exclude(_)
                    | Message::ExcludeLan(_)
                    | Message::WholeIpv4
                    | Message::Dns(_)
            );
        match m {
            #[cfg(target_os = "windows")]
            Message::Update(action) => return self.updates_update(action),
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            Message::AlwaysOn(action) => return self.always_update(action),
            Message::Sync(action) => return self.sync_update(action),
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::Intent(action) => return self.intent_update(action),
            Message::ReadBackup if self.can_change_profiles() && !self.dirty => {
                self.busy = true;
                return Task::perform(
                    async {
                        tokio::task::spawn_blocking(rtrust_store::recovery_snapshot)
                            .await
                            .map_err(|_| "Ошибка хранилища".to_string())
                            .and_then(|r| r.map_err(|e| e.to_string()))
                    },
                    Message::BackupLoaded,
                );
            }
            Message::BackupLoaded(result) => {
                let task = self.store_conflict_loaded(result);
                self.store_recovery = self.store_conflict.is_some();
                return task;
            }
            Message::StoreConflict(result) => return self.store_conflict_loaded(result),
            Message::ResolveStore(choice) => return self.resolve_store_conflict(choice),
            Message::AutoConnect(enabled) if self.can_change_profiles() => {
                self.saved_connection.auto_connect = enabled;
                self.dirty = true;
            }
            Message::Fallback(name, allowed) if self.can_change_profiles() => {
                let list = &mut self.saved_connection.fallback_profiles;
                list.retain(|n| *n != name);
                if allowed && list.len() < rtrust_control::MAX_FALLBACKS {
                    list.push(name);
                }
                self.dirty = true;
            }
            Message::StartupRefresh if !self.startup_busy => {
                self.startup_busy = true;
                return Task::perform(
                    async {
                        tokio::task::spawn_blocking(autostart::enabled)
                            .await
                            .map_err(|_| "Ошибка проверки автозапуска".to_string())
                            .and_then(|r| r)
                    },
                    Message::StartupLoaded,
                );
            }
            Message::StartupSet(enabled) if !self.busy && !self.startup_busy => {
                self.busy = true;
                self.startup_busy = true;
                return Task::perform(
                    async move {
                        tokio::task::spawn_blocking(move || autostart::set(enabled))
                            .await
                            .map_err(|_| "Ошибка настройки автозапуска".to_string())
                            .and_then(|r| r)
                    },
                    Message::StartupChanged,
                );
            }
            Message::StartupLoaded(result) => {
                self.startup_busy = false;
                match result {
                    Ok(enabled) => {
                        self.autostart = enabled;
                        self.startup_error = None;
                    }
                    Err(error) => self.startup_error = Some(error),
                }
            }
            Message::StartupChanged(result) => {
                self.busy = false;
                self.startup_busy = false;
                match result {
                    Ok(enabled) => {
                        self.autostart = enabled;
                        self.startup_error = None;
                        self.status = if enabled {
                            "Автозапуск приложения включён."
                        } else {
                            "Автозапуск приложения отключён."
                        }
                        .into();
                    }
                    Err(error) => {
                        self.startup_error = Some(error);
                        self.pending_close = None;
                        return self.show_window();
                    }
                }
            }

            Message::TrayInit(id) => {
                if !self.tray_ready
                    && (self.tray_smoke || !std::env::args().any(|arg| arg.starts_with("--ci-")))
                {
                    return iced::window::run(id, |_| tray::initialize()).map(Message::TrayReady);
                }
            }
            Message::TrayReady(ready) => {
                self.tray_ready = ready;
                if self.tray_smoke {
                    if cfg!(not(target_os = "linux"))
                        || std::env::var_os("RTRUST_CI_EXPECT_TRAY").is_some()
                    {
                        assert!(ready, "native tray could not be initialized");
                    }
                    return Task::batch([
                        self.update(Message::CloseRequested),
                        Task::perform(
                            async {
                                tokio::time::sleep(std::time::Duration::from_millis(400)).await
                            },
                            |_| Message::TraySmokeStep(1),
                        ),
                    ]);
                }
                if std::mem::take(&mut self.login_start) {
                    return self.update(Message::CloseRequested);
                }
            }
            Message::TraySmokeStep(1) => {
                return iced::window::oldest().then(|id| match id {
                    Some(id) => iced::window::mode(id).map(Message::TraySmokeMode),
                    None => Task::done(Message::TraySmokeMode(iced::window::Mode::Hidden)),
                });
            }
            Message::TraySmokeMode(mode) => {
                if self.tray_ready {
                    assert_eq!(mode, iced::window::Mode::Hidden);
                }
                if std::env::var_os("RTRUST_CI_EXPECT_TRAY").is_some() {
                    return Task::none();
                }
                return Task::batch([
                    self.show_window(),
                    Task::perform(
                        async { tokio::time::sleep(std::time::Duration::from_millis(400)).await },
                        |_| Message::TraySmokeStep(2),
                    ),
                ]);
            }
            Message::TraySmokeStep(2) => {
                return iced::window::oldest().then(|id| {
                    iced::window::mode(id.expect("smoke window")).map(Message::TraySmokeRestored)
                });
            }
            Message::TraySmokeRestored(mode) => {
                assert_eq!(mode, iced::window::Mode::Windowed);
                return iced::exit();
            }
            Message::TraySmokeStep(_) => panic!("tray lifecycle smoke timed out"),
            Message::TrayEvents(events) => {
                return Task::batch(events.into_iter().map(|event| match event {
                    tray::Action::Show => {
                        if self.tray_smoke {
                            Task::batch([
                                self.show_window(),
                                Task::perform(
                                    async {
                                        tokio::time::sleep(std::time::Duration::from_millis(400))
                                            .await
                                    },
                                    |_| Message::TraySmokeStep(2),
                                ),
                            ])
                        } else {
                            self.show_window()
                        }
                    }
                    #[cfg(target_os = "linux")]
                    tray::Action::Unavailable => {
                        self.tray_ready = false;
                        self.show_window()
                    }
                    tray::Action::Toggle => self.update(Message::ToggleDefaultConnection),
                    tray::Action::Exit => self.update(Message::ExitRequested),
                }));
            }
            Message::Portal(action) => return self.portal_update(action),
            Message::SystemTheme(mode) => return self.system_theme(mode),
            Message::Theme(choice) => return self.set_theme(choice),
            Message::Resized(width) => self.window_width = width,
            Message::ProfileQuery(query) => self.profile_query = query,
            Message::DiscardPreview if !self.busy => {
                self.preview = None;
                self.confirm_replace = false;
            }
            Message::SmokeExit => return iced::exit(),
            Message::CloseRequested => return self.request_close(false),
            Message::WindowFocused => self.window_visible = true,
            Message::ExitRequested => return self.request_close(true),
            Message::DraftName(name) if !self.busy => self.draft_name = name,
            Message::Rename if self.can_change_profiles() => {
                let name = self.draft_name.trim();
                if name.is_empty() || name.len() > 1024 || name.chars().any(char::is_control) {
                    self.status =
                        "Название должно быть непустым, без управляющих символов, до 1024 байт."
                            .into();
                } else if let Some(profile) = self.profiles.get_mut(self.selected) {
                    // An allowed backup stays allowed under its new name.
                    for allowed in &mut self.saved_connection.fallback_profiles {
                        if *allowed == profile.name {
                            *allowed = name.to_owned();
                        }
                    }
                    profile.name = name.to_owned();
                    self.dirty = true;
                    self.status = "Профиль переименован. Автоматическое сохранение…".into();
                }
            }
            Message::Delete if self.can_change_profiles() && self.current().is_some() => {
                if self.confirm_delete {
                    self.profiles.remove(self.selected);
                    self.selected = self.selected.min(self.profiles.len().saturating_sub(1));
                    self.reset_editor();
                    self.dirty = true;
                    self.status = "Профиль удалён из памяти. Автоматическое сохранение…".into();
                } else {
                    self.confirm_delete = true;
                }
            }
            Message::Replace
                if self.can_change_profiles()
                    && self.current().is_some()
                    && self.preview.is_some() =>
            {
                if self.confirm_replace {
                    let p = self.preview.as_ref().unwrap();
                    if self.profiles.iter().enumerate().any(|(i, other)| {
                        i != self.selected
                            && other.endpoint.addresses == p.endpoint.addresses
                            && other.endpoint.username == p.endpoint.username
                    }) {
                        self.status = "Этот endpoint и пользователь уже есть в другом профиле. Выберите его для замены.".into();
                    } else {
                        self.profiles[self.selected] = self.preview.take().unwrap();
                        self.reset_editor();
                        self.input = text_editor::Content::new();
                        self.page = Page::Profiles;
                        self.dirty = true;
                        self.status = "Профиль заменён. Автоматическое сохранение…".into();
                    }
                } else {
                    self.confirm_replace = true;
                }
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::Dns(value) if self.can_change_profiles() => {
                self.dns = value;
                self.dirty = true;
            }
            Message::Mode(mode) if self.can_change_profiles() => {
                self.mode = mode;
                self.saved_connection.mode = match mode {
                    Mode::Socks => rtrust_store::Mode::Socks,
                    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                    Mode::Tun => rtrust_store::Mode::Tun,
                    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                    Mode::Full => rtrust_store::Mode::Full,
                };
                self.dirty = true;
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::Networks(value) if self.can_change_profiles() => {
                self.networks = value;
                self.dirty = true;
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::Exclude(value) if self.can_change_profiles() => {
                self.exclude = value;
                self.dirty = true;
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::ExcludeLan(value) if self.can_change_profiles() => {
                self.exclude_lan = value;
                self.dirty = true;
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::WholeIpv4 if self.can_change_profiles() => {
                self.networks = "0.0.0.0/0".into();
                self.exclude_lan = true;
                self.dirty = true;
            }
            #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
            Message::RecoverService if self.can_change_profiles() => {
                self.busy = true;
                let current = self.recover_owner();
                return Task::perform(
                    async move {
                        rtrust_desktop::connection::recover_service(current, true)
                            .await
                            .map(|()| {
                                if cfg!(target_os = "windows") {
                                    "Windows-служба доступна.".into()
                                } else {
                                    "Блокировка выбранных сетей снята.".into()
                                }
                            })
                    },
                    Message::Recovered,
                );
            }
            Message::Recovered(result) => {
                if result.is_ok() {
                    self.pending_owner = None;
                    self.last_error = None;
                }
                return self.update(Message::Done(result));
            }
            Message::Stopped(epoch, result) if epoch == self.connection_epoch => {
                let failed = result.is_err();
                if !failed {
                    // The service confirmed Idle; the owner is spent.
                    self.pending_owner = None;
                }
                let exit = std::mem::take(&mut self.exit_after_stop) && result.is_ok();
                self.disconnect();
                if exit {
                    return iced::exit();
                }
                self.status = result
                    .map(|()| "Отключено; маршруты восстановлены.".into())
                    .unwrap_or_else(|e| e);
                if failed {
                    self.last_error = Some(self.status.clone());
                    self.reconnect_then_check = false;
                    self.follow_up = None;
                    return self.show_window();
                }
                if std::mem::take(&mut self.reconnect_then_check) {
                    // Start through the ordinary path; the check follows Connected.
                    let start = self.update(Message::ToggleConnection);
                    self.reconnect_then_check = self.connecting;
                    if !self.connecting {
                        self.follow_up = None;
                    }
                    return start;
                }
            }
            Message::ProxyPort(value) if self.can_change_profiles() => {
                self.dirty = true;
                self.proxy_port = value
            }
            Message::CopyProxy => {
                if let Some(proxy) = &self.session {
                    return iced::clipboard::write(proxy.address().to_string());
                }
            }
            #[cfg(target_os = "macos")]
            Message::Glass(enabled) => {
                self.glass_enabled = enabled;
                glass::save_preference(enabled);
            }
            Message::Tick => {
                self.mark_viewed();
                if !self.busy {
                    if let Some(exit) = self.pending_close.take() {
                        return self.request_close(exit);
                    }
                    if self
                        .autosave_due
                        .is_some_and(|due| std::time::Instant::now() >= due)
                    {
                        self.autosave_due = None;
                        if self.dirty {
                            return self.update(Message::Save);
                        }
                    }
                }
                #[cfg(target_os = "macos")]
                if !self.busy
                    && let Some(link) = open_url::take()
                {
                    self.apply_import(Profile::import(&link).map(Some).map_err(|e| e.to_string()));
                    return self.show_window();
                }
                if self.tray_ready {
                    let events = tray::poll();
                    if !events.is_empty() {
                        return self.update(Message::TrayEvents(events));
                    }
                }
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                if let Some(task) = self.always_poll() {
                    return task;
                }
                return self.sync_tick();
            }
            Message::MakeDefault if !self.busy && !self.connecting && self.session.is_none() => {
                if self.selected < self.profiles.len() {
                    let profile = self.profiles.remove(self.selected);
                    self.profiles.insert(0, profile);
                    self.selected = 0;
                    self.reset_editor();
                    self.dirty = true;
                    self.status = "Профиль по умолчанию выбран. Автоматическое сохранение…".into();
                }
            }
            Message::ToggleDefaultConnection => {
                let selected = self.selected;
                self.selected = 0;
                let task = self.update(Message::ToggleConnection);
                self.selected = selected;
                return task;
            }
            Message::ToggleConnection => {
                self.cancel_diagnostic();
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                if self.always_on.enabled {
                    return self.always_update(always_on::Action::Disable);
                }
                if self.disconnecting {
                    return Task::none();
                }
                self.last_error = None;
                if self.session.as_ref().is_some_and(Session::is_tun) {
                    self.connection_epoch += 1;
                    let epoch = self.connection_epoch;
                    if let Some(handle) = self.connection_task.take() {
                        handle.abort();
                    }
                    let session = self.take_session().unwrap();
                    self.connecting = true;
                    self.disconnecting = true;
                    self.status = "Отключение службы и восстановление маршрутов…".into();
                    let (task, handle) =
                        Task::perform(session.stop(), move |r| Message::Stopped(epoch, r))
                            .abortable();
                    self.connection_task = Some(handle);
                    return task;
                }
                if self.connecting || self.session.is_some() {
                    // disconnect() also ends any SOCKS reconnect wait.
                    self.reconnect_then_check = false;
                    self.follow_up = None;
                    self.disconnect();
                    self.status = if self.saved_connection.mode == rtrust_store::Mode::Full {
                        "Подключение отменено. Если сеть заблокирована, используйте сброс блокировки.".into()
                    } else {
                        "Отключено.".into()
                    };
                } else if !self.busy
                    && let Some(profile) = self.current().cloned()
                {
                    let port = if self.mode == Mode::Socks {
                        match self.proxy_port.parse::<u16>() {
                            Ok(port) if port > 0 => port,
                            _ => {
                                self.status =
                                    "Порт SOCKS5 должен быть числом от 1 до 65535.".into();
                                return Task::none();
                            }
                        }
                    } else {
                        0
                    };
                    let selection = if self.saved_connection.mode == rtrust_store::Mode::Tun {
                        match self.tun_selection() {
                            Ok(selection) => selection,
                            Err(error) => {
                                self.status = error;
                                return Task::none();
                            }
                        }
                    } else {
                        Default::default()
                    };
                    let mode = self.mode;
                    let dns = self.dns.clone();
                    let fallbacks = self
                        .saved_connection
                        .fallbacks_for(&self.profiles, Some(&profile));
                    let authorized = std::iter::once(profile.clone())
                        .chain(fallbacks.iter().cloned())
                        .collect::<Vec<_>>();
                    let lease = match self
                        .saved_connection
                        .sync
                        .lease_for(self.saved_connection.managed_routes.is_some(), &authorized)
                    {
                        Ok(lease) => lease,
                        Err(error) => {
                            self.status = error;
                            return Task::none();
                        }
                    };
                    self.socks_recovery = (mode == Mode::Socks)
                        .then(|| socks_recovery::Recovery::new(profile.clone(), port));
                    self.connection_candidates = std::iter::once(profile.name.clone())
                        .chain(fallbacks.iter().map(|p| p.name.clone()))
                        .collect();
                    self.connection_epoch += 1;
                    let epoch = self.connection_epoch;
                    self.connecting = true;
                    self.connection_name = profile.name.clone();
                    self.connection_ipv6 = profile.endpoint.has_ipv6;
                    self.status = if mode == Mode::Socks {
                        "Подключение к серверу…"
                    } else {
                        "Системный VPN: подключение…"
                    }
                    .into();
                    let (task, handle) = Task::perform(
                        async move {
                            Session::start_authorized(
                                profile, fallbacks, mode, port, selection, dns, lease,
                            )
                            .await
                            .map_err(|e| e.to_string())
                        },
                        move |r| Message::Connected(epoch, r),
                    )
                    .abortable();
                    self.connection_task = Some(handle);
                    return task;
                }
            }
            Message::Connected(epoch, result)
                if epoch == self.connection_epoch && self.connecting =>
            {
                self.connection_task = None;
                self.connecting = false;
                match result {
                    Ok(session) => {
                        if let Some(recovery) = &mut self.socks_recovery {
                            recovery.connected(std::time::Instant::now());
                        }
                        // A successful automatic attempt clears its wait notice.
                        self.last_error = None;
                        self.session = Some(session);
                        // A new admitted session supersedes any lost one.
                        self.pending_owner = None;
                        if let Some(index) = self.session.as_ref().and_then(Session::active_profile)
                            && let Some(name) = self.connection_candidates.get(index as usize)
                        {
                            self.connection_name = name.clone();
                        }
                        if std::mem::take(&mut self.reconnect_then_check) {
                            self.last_diagnostic = None;
                            let monitor = self.monitor_connection();
                            return Task::batch([monitor, self.update(Message::Diagnose)]);
                        }
                        self.last_diagnostic = None;
                        self.diagnostic_report = None;
                        self.status = if self.mode == Mode::Socks { "Прокси SOCKS5/HTTP включён. Его можно указать и как системный прокси Windows. Для DNS выберите разрешение имён через прокси." } else if self.saved_connection.mode == rtrust_store::Mode::Full && self.connection_ipv6 { "IPv4, IPv6 и DNS всего компьютера через VPN. Пересылка между интерфейсами заблокирована." } else if self.saved_connection.mode == rtrust_store::Mode::Full { "IPv4 и DNS всего компьютера через VPN. Сервер без IPv6: IPv6 заблокирован, приложения переходят на IPv4. Пересылка между интерфейсами заблокирована." } else { "Выбранные IPv4-сети подключены через службу. Исключения, остальной трафик и системный DNS идут напрямую." }.into();
                        if let Some(warning) =
                            self.session.as_ref().and_then(|s| s.owner_warning(true))
                        {
                            self.status = format!("{} {warning}", self.status);
                        }
                        return Task::batch([self.monitor_connection(), self.start_diagnostic()]);
                    }
                    Err(error) => {
                        self.socks_recovery = None;
                        self.reconnect_then_check = false;
                        self.follow_up = None;
                        self.connection_name.clear();
                        self.last_error = Some(error.clone());
                        self.status = error;
                        self.pending_close = None;
                        self.login_start = false;
                        return self.show_window();
                    }
                }
            }
            Message::SocksAttempt(epoch, result)
                if epoch == self.connection_epoch && self.connecting =>
            {
                if let Err(failure) = &result {
                    socks_recovery::record_failure(failure);
                }
                match result {
                    Ok(session) => return self.update(Message::Connected(epoch, Ok(session))),
                    // Retrying cannot fix it: end recovery, as a user start would.
                    Err(failure) if failure.permanent => {
                        self.disconnect();
                        self.status = format!("Соединение потеряно: {}", failure.message);
                        self.last_error = Some(self.status.clone());
                    }
                    Err(failure) => {
                        self.connection_task = None;
                        if let Some(recovery) = &mut self.socks_recovery {
                            let retry = recovery.attempt_failed(socks_recovery::entropy());
                            return self.retry_socks(retry, &failure.message);
                        }
                    }
                }
            }
            Message::Health(epoch, result)
                if epoch == self.connection_epoch && self.session.is_some() =>
            {
                self.connection_task = None;
                match result {
                    Ok(()) => {
                        if self.session.as_ref().is_some_and(Session::is_tun) {
                            let session = self.session.as_ref().unwrap();
                            if !self.busy && self.probe.is_none() {
                                self.status = self.connection_check_summary();
                                if let Some(name) = session
                                    .active_profile()
                                    .filter(|&index| index > 0)
                                    .and_then(|index| {
                                        self.connection_candidates.get(index as usize)
                                    })
                                {
                                    self.status += &format!(" · через резервный профиль «{name}»");
                                }
                            }
                            if self.diagnostic_due() {
                                return Task::batch([
                                    self.monitor_connection(),
                                    self.start_diagnostic(),
                                ]);
                            }
                        }
                        return self.monitor_connection();
                    }
                    Err(error) => {
                        if self.session.as_ref().is_some_and(Session::is_tun) {
                            self.cancel_diagnostic();
                            self.last_diagnostic = None;
                            self.diagnostic_report = None;
                            self.status = error.message;
                            return self.monitor_connection();
                        }
                        return self.socks_lost(error);
                    }
                }
            }
            Message::Navigate(page) if !self.busy || page.reachable_while_busy() => {
                self.page = page;
                self.confirm_delete = false;
                self.confirm_replace = false;
                self.consent = false;
            }
            Message::Edit(action) if !self.busy => {
                self.input.perform(action);
                self.preview = None;
                self.confirm_replace = false;
            }
            Message::PickFile if !self.busy => {
                self.busy = true;
                return Task::perform(
                    async {
                        let Some(file) = rfd::AsyncFileDialog::new()
                            .add_filter(
                                "TrustTunnel profile",
                                &["toml", "json", "txt", "conf", "yaml", "yml"],
                            )
                            .pick_file()
                            .await
                        else {
                            return Ok(None);
                        };
                        let path = file.path().to_path_buf();
                        tokio::task::spawn_blocking(move || {
                            let raw = Zeroizing::new(
                                rtrust_store::read_bounded(&path, rtrust_profile::MAX_INPUT)
                                    .map_err(|e| e.to_string())?,
                            );
                            Profile::import(
                                std::str::from_utf8(&raw)
                                    .map_err(|_| "Файл должен быть UTF-8".to_owned())?,
                            )
                            .map(Some)
                            .map_err(|e| e.to_string())
                        })
                        .await
                        .map_err(|_| "Не удалось прочитать файл".to_owned())?
                    },
                    |r| Message::Imported(Box::new(r)),
                );
            }
            Message::Imported(result) => self.apply_import(*result),
            Message::Parse if !self.busy => {
                let raw = Zeroizing::new(self.input.text());
                self.apply_import(Profile::import(&raw).map(Some).map_err(|e| e.to_string()));
            }
            Message::Accept if !self.busy => {
                if let Some(p) = self.preview.take() {
                    if self.profiles.iter().any(|x| {
                        x.endpoint.addresses == p.endpoint.addresses
                            && x.endpoint.username == p.endpoint.username
                    }) {
                        self.status="Такой endpoint/пользователь уже добавлен. Выберите существующий профиль и подтвердите замену в импорте.".into();
                        self.preview = Some(p);
                    } else {
                        self.profiles.push(p);
                        self.selected = self.profiles.len() - 1;
                        self.reset_editor();
                        self.dirty = true;
                        self.input = text_editor::Content::new();
                        self.page = Page::Profiles;
                        self.status =
                            "Профиль добавлен. Автоматическое шифрованное сохранение…".into();
                    }
                }
            }
            Message::Select(i) if !self.busy => {
                if i < self.profiles.len() {
                    self.selected = i;
                    self.reset_editor();
                    // The red state belongs to the previous attempt, not the new choice.
                    if !self.connecting && self.session.is_none() {
                        self.last_error = None;
                    }
                }
            }
            Message::Format(format) => {
                self.format = format;
                self.consent = false;
            }
            Message::Consent(v) => self.consent = v,
            Message::Export if !self.busy && self.consent => {
                if let Some(p) = self.current() {
                    match p.export(self.format) {
                        Ok(export) => {
                            self.busy = true;
                            let extension = self.format.extension();
                            return Task::perform(
                                async move {
                                    let Some(file) = rfd::AsyncFileDialog::new()
                                        .set_file_name(format!("trusttunnel-profile.{extension}"))
                                        .save_file()
                                        .await
                                    else {
                                        return Ok("Экспорт отменён".into());
                                    };
                                    let path = file.path().to_path_buf();
                                    tokio::task::spawn_blocking(move || {
                                        rtrust_store::write_private(
                                            &path,
                                            export.content.as_bytes(),
                                        )
                                        .map(|_| {
                                            "Профиль экспортирован. Файл содержит VPN-пароль."
                                                .into()
                                        })
                                        .map_err(|e| e.to_string())
                                    })
                                    .await
                                    .map_err(|_| "Ошибка записи".to_owned())?
                                },
                                Message::Done,
                            );
                        }
                        Err(e) => self.status = e.to_string(),
                    }
                }
            }
            Message::Done(result) => {
                self.busy = false;
                self.consent = false;
                self.status = result.unwrap_or_else(|e| e);
            }
            Message::Load if !self.busy && !self.dirty && self.profiles.is_empty() => {
                self.busy = true;
                return Task::perform(
                    async {
                        tokio::task::spawn_blocking(rtrust_store::snapshot)
                            .await
                            .map_err(|_| "Ошибка хранилища".to_owned())?
                            .map_err(|e| e.to_string())
                    },
                    Message::Loaded,
                );
            }
            Message::Loaded(result) => {
                let initial_load = std::mem::take(&mut self.boot_connect_pending);
                self.busy = false;
                match result {
                    Ok((vault, r)) => {
                        self.sync_state = sync::State::default();
                        self.proxy_port = vault.connection.socks_port.to_string();
                        self.dns = vault.connection.dns.to_string();
                        self.networks = vault
                            .connection
                            .networks
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ");
                        self.exclude = vault
                            .connection
                            .exclude
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ");
                        self.exclude_lan = vault.connection.exclude_lan;
                        self.saved_connection = vault.connection;
                        #[cfg(any(
                            target_os = "linux",
                            target_os = "windows",
                            target_os = "macos"
                        ))]
                        {
                            self.mode = match self.saved_connection.mode {
                                rtrust_store::Mode::Socks => Mode::Socks,
                                rtrust_store::Mode::Tun => Mode::Tun,
                                #[cfg(any(
                                    target_os = "linux",
                                    target_os = "windows",
                                    target_os = "macos"
                                ))]
                                rtrust_store::Mode::Full => Mode::Full,
                            };
                        }
                        self.profiles = vault.profiles;
                        self.revision = r;
                        self.selected = 0;
                        self.reset_editor();
                        self.dirty = false;
                        self.status =
                            "Профили и настройки загружены. Подключение — по кнопке.".into();
                        #[cfg(not(any(
                            target_os = "linux",
                            target_os = "windows",
                            target_os = "macos"
                        )))]
                        if self.saved_connection.mode == rtrust_store::Mode::Full
                            || (!cfg!(target_os = "windows")
                                && self.saved_connection.mode == rtrust_store::Mode::Tun)
                        {
                            self.status =
                                "Настройки TUN сохранены; на этой ОС доступен SOCKS5.".into();
                        }
                        if initial_load && self.saved_connection.auto_connect {
                            return self.connect_on_boot();
                        }
                    }
                    Err(e) => {
                        self.status = e;
                        self.pending_close = None;
                        self.login_start = false;
                        return self.show_window();
                    }
                }
            }
            Message::Save
                if self.store_conflict.is_none()
                    && !self.busy
                    && (!self.profiles.is_empty() || self.revision.is_some() || self.dirty) =>
            {
                self.autosave_due = None;
                let connection = match self.connection_settings() {
                    Ok(settings) => settings,
                    Err(error) => {
                        self.pending_close = None;
                        self.status = format!("Не сохранено: {error}");
                        return self.show_window();
                    }
                };
                let vault = rtrust_store::Vault {
                    profiles: self.profiles.clone(),
                    connection,
                };
                let revision = self.revision.clone();
                self.busy = true;
                return Task::perform(
                    async move {
                        match tokio::task::spawn_blocking(move || {
                            rtrust_store::save(&vault, revision)
                        })
                        .await
                        {
                            Ok(Err(rtrust_store::Error::Conflict)) => Message::StoreConflict(
                                tokio::task::spawn_blocking(rtrust_store::snapshot)
                                    .await
                                    .map_err(|_| "Ошибка хранилища".to_owned())
                                    .and_then(|r| r.map_err(|e| e.to_string())),
                            ),
                            other => Message::Saved(
                                other
                                    .map_err(|_| "Ошибка хранилища".to_owned())
                                    .and_then(|r| r.map_err(|e| e.to_string())),
                            ),
                        }
                    },
                    |message| message,
                );
            }
            Message::Saved(result) => {
                self.busy = false;
                match result {
                    Ok(r) => {
                        self.revision = Some(r);
                        self.dirty = false;
                        self.status =
                            "Профили и настройки автоматически сохранены шифрованно.".into();
                        if let Some(exit) = self.pending_close.take() {
                            return self.request_close(exit);
                        }
                    }
                    Err(e) => {
                        self.pending_close = None;
                        self.status = format!(
                            "Не удалось сохранить конфигурацию: {e}. Окно оставлено открытым."
                        );
                        return self.show_window();
                    }
                }
            }
            Message::Target(s) if !self.busy => self.target = s,
            Message::ExplainRoute if !self.busy => {
                use rtrust_profile::routing::{Context, Decision, Reason, Source};
                let context = match &self.saved_connection.managed_routes {
                    Some(managed) => Context {
                        source: Source::ManagedUnknown,
                        revision: Some(managed.revision.clone()),
                    },
                    None => Context {
                        source: Source::Local,
                        revision: None,
                    },
                };
                let address = self
                    .target
                    .parse::<std::net::SocketAddr>()
                    .map(|s| s.ip())
                    .or_else(|_| self.target.parse::<std::net::IpAddr>());
                let decision: Result<Decision, String> = match address {
                    Err(_) => Ok(Decision::unknown(context, Reason::SystemPathUnobserved)),
                    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
                    Ok(ip) if self.mode == Mode::Tun => {
                        let endpoints = self.offline_route_endpoints();
                        self.tun_selection().and_then(|selection| {
                            selection.explain(ip, endpoints.as_deref(), None, context)
                        })
                    }
                    Ok(_) => Ok(Decision::unknown(
                        context,
                        if self.mode == Mode::Socks {
                            Reason::ProxyScope
                        } else {
                            Reason::SystemPathUnobserved
                        },
                    )),
                };
                self.status = match decision {
                    Ok(d) => describe_decision(&d),
                    Err(e) => format!("Предпросмотр отклонён: {e}"),
                };
            }
            Message::SystemTarget(s) if !self.busy => {
                self.cancel_diagnostic();
                self.system_target = s;
                self.diagnostic_report = None;
                self.follow_up = None;
                self.system_target_edited_at = Some(std::time::Instant::now());
            }
            Message::DiagnosticEdit(action) if !self.busy => {
                self.diagnostic_preview_dirty |= action.is_edit();
                self.diagnostic_preview.perform(action)
            }
            Message::ResetDiagnosticPreview if !self.busy => {
                if let Some((_, report)) = self.diagnostic_report.clone() {
                    self.diagnostic_preview_dirty = false;
                    self.refresh_diagnostic_preview(&report);
                }
            }
            Message::Diagnose if !self.busy => {
                return self.start_diagnostic();
            }
            Message::Diagnosed(g, epoch, report)
                if g == self.diagnostic_generation
                    && epoch == self.connection_epoch
                    && self.session.as_ref().is_some_and(Session::is_tun) =>
            {
                self.diagnostic_task = None;
                // A service reconnect can keep the same UI epoch. Reject its old evidence too.
                if self.session.as_ref().unwrap().observations().generation
                    != report.lifecycle.generation
                {
                    self.last_diagnostic = None;
                    self.diagnostic_report = None;
                    return self.start_diagnostic();
                }
                let mut report = report;
                report.follows = self.follow_up.take();
                self.refresh_diagnostic_preview(&report);
                self.diagnostic_report = Some((epoch, report));
                if !self.busy && self.probe.is_none() {
                    self.status = self.connection_check_summary();
                }
            }
            Message::DiagnosticAction(action) if !self.busy && self.diagnostic_task.is_none() => {
                use rtrust_desktop::diagnostics::{Action, FollowUp};
                let Some((epoch, report)) = &self.diagnostic_report else {
                    return Task::none();
                };
                let follow_up = FollowUp {
                    action,
                    previous_cause: report.verdict().cause,
                    previous_finished_at_ms: report.finished_at_ms,
                };
                let current = *epoch == self.connection_epoch;
                match action {
                    Action::Recheck => {
                        self.follow_up = Some(follow_up);
                        return self.update(Message::Diagnose);
                    }
                    Action::ReviewRules => {
                        self.status = match &report.policy {
                            Some(decision) => format!(
                                "{} Измените выбор сетей или исключения в настройках подключения, затем повторите проверку.",
                                describe_decision(decision)
                            ),
                            None => "Прогноз политики для этого адреса не получен.".into(),
                        };
                    }
                    Action::CheckEndpoint if current => {
                        self.cancel_diagnostic();
                        let Some(session) = self.session.clone() else {
                            return Task::none();
                        };
                        self.busy = true;
                        self.generation += 1;
                        let generation = self.generation;
                        let epoch = self.connection_epoch;
                        self.status = "Служба проверяет текущий VPN endpoint: TLS → аутентификация → проверка связи. До 15 секунд; неподтверждённый независимый путь отмечается явно.".into();
                        let (task, handle) = Task::perform(
                            rtrust_desktop::diagnostics::check_endpoint(session),
                            move |check| Message::EndpointChecked(generation, epoch, check),
                        )
                        .abortable();
                        self.probe = Some(handle);
                        return task;
                    }
                    Action::Reconnect
                        if current && self.session.as_ref().is_some_and(Session::is_tun) =>
                    {
                        #[cfg(any(target_os = "linux", target_os = "windows"))]
                        if self.always_on.enabled {
                            self.status = "Always-on управляет подключением; переподключение из диагностики недоступно.".into();
                            return Task::none();
                        }
                        self.follow_up = Some(follow_up);
                        self.reconnect_then_check = true;
                        return self.update(Message::ToggleConnection);
                    }
                    _ => {
                        self.status =
                            "Результат относится к прошлому подключению; повторите проверку."
                                .into();
                    }
                }
            }
            Message::EndpointChecked(g, epoch, check)
                if g == self.generation && epoch == self.connection_epoch =>
            {
                self.probe = None;
                self.busy = false;
                let updated = if let Some((report_epoch, report)) = &mut self.diagnostic_report
                    && *report_epoch == epoch
                    && report.attach_endpoint(check)
                {
                    self.status = format!("{} {}", report.verdict_text(), report.summary());
                    Some(report.clone())
                } else {
                    None
                };
                if let Some(report) = updated {
                    self.refresh_diagnostic_preview(&report);
                }
            }
            Message::ExportDiagnostic if !self.busy && self.diagnostic_export_report.is_some() => {
                let preview = self.diagnostic_preview.text();
                self.busy = true;
                return Task::perform(
                    async move {
                        let Some(file) = rfd::AsyncFileDialog::new()
                            .set_file_name("vpn-diagnostics.json")
                            .save_file()
                            .await
                        else {
                            return Ok("Экспорт отменён".into());
                        };
                        file.write(preview.as_bytes())
                            .await
                            .map_err(|_| "Не удалось сохранить отчёт".to_string())?;
                        Ok("Отредактированный отчёт сохранён; никуда не отправлен".into())
                    },
                    Message::Done,
                );
            }
            Message::Probe if !self.busy => {
                if let Some(p) = self.current().cloned() {
                    self.busy = true;
                    self.generation += 1;
                    let generation = self.generation;
                    let target = self.target.clone();
                    self.status =
                        "TLS → аутентификация → CONNECT → HTTP-ответ. Системный VPN не включается."
                            .into();
                    let (task, handle) = Task::perform(
                        async move {
                            rtrust_engine::probe_http(&p, &target)
                                .await
                                .map_err(|e| e.to_string())
                        },
                        move |r| Message::Probed(generation, r),
                    )
                    .abortable();
                    self.probe = Some(handle);
                    return task;
                }
            }
            Message::Probed(g, r) if g == self.generation => {
                self.probe = None;
                self.busy = false;
                self.status = r.unwrap_or_else(|e| e);
            }
            Message::Cancel => {
                self.cancel_diagnostic();
                self.follow_up = None;
                self.status = "Проверка отменена.".into();
            }
            _ => {}
        }
        if edited && self.dirty && !self.busy {
            self.autosave_due =
                Some(std::time::Instant::now() + std::time::Duration::from_millis(600));
        }
        Task::none()
    }
    /// Report a view to the service only while the window is shown.
    fn mark_viewed(&self) {
        if self.window_visible
            && let Some(session) = &self.session
        {
            session.mark_viewed();
        }
    }
    fn show_window(&mut self) -> Task<Message> {
        self.window_visible = true;
        Self::show_window_task()
    }
    fn show_window_task() -> Task<Message> {
        iced::window::oldest().then(|id| match id {
            Some(id) => Task::batch([
                iced::window::set_mode(id, iced::window::Mode::Windowed),
                iced::window::minimize(id, false),
                iced::window::gain_focus(id),
            ]),
            None => open_window(),
        })
    }
    fn request_close(&mut self, exit: bool) -> Task<Message> {
        self.cancel_diagnostic();
        if self.busy {
            self.pending_close = Some(exit);
            return Task::none();
        }
        if self.dirty {
            self.pending_close = Some(exit);
            return self.update(Message::Save);
        }
        if !exit {
            self.window_visible = false;
            if self.tray_ready {
                return iced::window::oldest().then(|id| match id {
                    Some(id) => {
                        #[cfg(target_os = "linux")]
                        {
                            iced::window::close(id)
                        }
                        #[cfg(not(target_os = "linux"))]
                        {
                            iced::window::set_mode(id, iced::window::Mode::Hidden)
                        }
                    }
                    None => Task::none(),
                });
            }
            self.status = "Трей недоступен. Окно свёрнуто; для завершения нажмите «Выход».".into();
            return iced::window::oldest().then(|id| match id {
                Some(id) => iced::window::minimize(id, true),
                None => Task::none(),
            });
        }
        if self.disconnecting {
            self.exit_after_stop = true;
            return Task::none();
        }
        if self.session.as_ref().is_some_and(Session::is_tun) {
            self.exit_after_stop = true;
            return self.update(Message::ToggleConnection);
        }
        // A SOCKS reconnect wait has nothing to finish: its listener is down.
        if self.connecting
            && !self
                .socks_recovery
                .as_ref()
                .is_some_and(socks_recovery::Recovery::retrying)
        {
            self.status = "Дождитесь подключения или отмените его перед выходом.".into();
            return self.show_window();
        }
        self.disconnect();
        iced::exit()
    }
    fn can_change_profiles(&self) -> bool {
        !self.busy && !self.connecting && self.session.is_none()
    }
    fn reset_editor(&mut self) {
        self.draft_name = self.current().map(|p| p.name.clone()).unwrap_or_default();
        self.confirm_delete = false;
        self.confirm_replace = false;
        self.consent = false;
    }
    fn refresh_diagnostic_preview(&mut self, report: &rtrust_desktop::diagnostics::Report) {
        // The editable export is a separate snapshot once the user changes it.
        if !self.diagnostic_preview_dirty {
            self.diagnostic_preview = text_editor::Content::with_text(&report.redacted_json());
            self.diagnostic_export_report = Some(report.clone());
        }
    }
    fn diagnostic_start_allowed(&self, now: std::time::Instant) -> bool {
        self.diagnostic_task.is_none()
            && self.last_diagnostic.is_none_or(|started| {
                now.saturating_duration_since(started) >= std::time::Duration::from_secs(5)
            })
            && self.system_target_edited_at.is_none_or(|edited| {
                now.saturating_duration_since(edited) >= std::time::Duration::from_secs(1)
            })
    }
    fn diagnostic_due(&self) -> bool {
        self.diagnostic_start_allowed(std::time::Instant::now())
            && !self.busy
            && self.probe.is_none()
            && self.session.as_ref().is_some_and(Session::is_tun)
            && (self.system_target_edited_at.is_some()
                || self
                    .last_diagnostic
                    .is_none_or(|t| t.elapsed() >= ui::PROBE_INTERVAL)
                || self.diagnostic_report.as_ref().is_some_and(|(_, report)| {
                    self.session.as_ref().unwrap().observations().generation
                        != report.lifecycle.generation
                }))
    }
    fn connection_check_summary(&self) -> String {
        let summary = self.connection_check_text();
        // Repeated while connected: a crash would otherwise need a restart.
        match self.session.as_ref().and_then(|s| s.owner_warning(true)) {
            Some(warning) => format!("{summary} {warning}"),
            None => summary,
        }
    }
    fn connection_check_text(&self) -> String {
        if self.diagnostic_task.is_some() {
            return format!(
                "Проверяем {}: DNS → маршрут VPN → HTTPS…",
                self.system_target
            );
        }
        if let Some((epoch, report)) = &self.diagnostic_report
            && *epoch == self.connection_epoch
            && self
                .session
                .as_ref()
                .is_some_and(|s| s.observations().generation == report.lifecycle.generation)
        {
            let age =
                rtrust_control::observations::now_ms().saturating_sub(report.finished_at_ms) / 1000;
            // The full DNS/route/HTTPS breakdown lives on the checks page; a
            // multi-line status here squeezed the scrolling content away.
            return format!(
                "Последняя проверка ({} с назад): {} Подробности — в разделе «Проверки».",
                age,
                report.verdict_text()
            );
        }
        "Транспорт запущен. Проверка системного пути ожидается.".into()
    }
    fn start_diagnostic(&mut self) -> Task<Message> {
        let follow_up = self.follow_up.take();
        let Some(session) = self.session.clone().filter(Session::is_tun) else {
            // SOCKS health is already checked using the active transport, never another profile.
            if self.session.is_none() {
                self.status = "Для системной проверки подключите TUN.".into();
            }
            return Task::none();
        };
        if !self.diagnostic_start_allowed(std::time::Instant::now()) {
            return Task::none();
        }
        let target = match rtrust_desktop::diagnostics::Target::parse(&self.system_target) {
            Ok(t) => t,
            Err(e) => {
                self.status = e.into();
                return Task::none();
            }
        };
        self.follow_up = follow_up;
        self.system_target_edited_at = None;
        self.last_diagnostic = Some(std::time::Instant::now());
        self.diagnostic_generation += 1;
        let generation = self.diagnostic_generation;
        let epoch = self.connection_epoch;
        let selection = if self.mode == Mode::Tun {
            self.tun_selection().ok()
        } else {
            None
        };
        let context = match &self.saved_connection.managed_routes {
            Some(m) => rtrust_profile::routing::Context {
                source: rtrust_profile::routing::Source::ManagedUnknown,
                revision: Some(m.revision.clone()),
            },
            None => rtrust_profile::routing::Context {
                source: rtrust_profile::routing::Source::Local,
                revision: None,
            },
        };
        let (task, handle) = Task::perform(
            rtrust_desktop::diagnostics::run(target, session, selection, context),
            move |r| Message::Diagnosed(generation, epoch, r),
        )
        .abortable();
        self.diagnostic_task = Some(handle);
        if !self.busy && self.probe.is_none() {
            self.status = self.connection_check_summary();
        }
        task
    }
    fn cancel_diagnostic(&mut self) {
        if let Some(handle) = self.diagnostic_task.take() {
            handle.abort();
            self.diagnostic_generation += 1;
        }
        if let Some(handle) = self.probe.take() {
            handle.abort();
            self.generation += 1;
            self.busy = false;
        }
    }
    // Every exit of a session from the App keeps its owner until the service
    // confirms Stop or Recover: a failed Stop must not strand the guard.
    fn take_session(&mut self) -> Option<Session> {
        let session = self.session.take()?;
        if let Some(owner) = session.owner() {
            self.pending_owner = Some(owner);
        }
        Some(session)
    }
    fn recover_owner(&self) -> Option<rtrust_control::owner::Owner> {
        self.session
            .as_ref()
            .and_then(Session::owner)
            .or_else(|| self.pending_owner.clone())
    }
    fn disconnect(&mut self) {
        self.cancel_diagnostic();
        self.connection_epoch += 1;
        if let Some(handle) = self.connection_task.take() {
            handle.abort();
        }
        if let Some(proxy) = self.take_session() {
            proxy.cancel();
        }
        self.connecting = false;
        self.disconnecting = false;
        self.connection_name.clear();
        self.socks_recovery = None;
    }
    /// A failed SOCKS health check. A tunnel that carries no traffic is
    /// retried under the recovery budget; any other failure ends the session.
    /// Either way the proxy stops first: no request is ever sent directly.
    fn socks_lost(&mut self, error: connection::HealthError) -> Task<Message> {
        let recovery = self.socks_recovery.take();
        self.disconnect();
        if let (Some(proven), Some(mut recovery)) = (error.degraded, recovery) {
            let retry =
                recovery.degraded(proven, std::time::Instant::now(), socks_recovery::entropy());
            self.socks_recovery = Some(recovery);
            return self.retry_socks(retry, &error.message);
        }
        self.status = format!("Соединение потеряно: {}", error.message);
        self.last_error = Some(self.status.clone());
        Task::none()
    }
    /// Waits, then starts the proxy again for the same profile and port. The
    /// attempt is the connection task: Cancel and a stale epoch drop it.
    fn retry_socks(&mut self, retry: socks_recovery::Retry, reason: &str) -> Task<Message> {
        let Some(recovery) = &self.socks_recovery else {
            return Task::none();
        };
        let (profile, port) = recovery.target();
        self.cancel_diagnostic();
        if let Some(handle) = self.connection_task.take() {
            handle.abort();
        }
        self.connection_epoch += 1;
        let epoch = self.connection_epoch;
        self.connecting = true;
        self.connection_name = profile.name.clone();
        let seconds = retry.delay.as_secs().max(1);
        self.status = if retry.cooling {
            format!(
                "Прокси остановлен: {reason}. Несколько попыток подряд не удались, следующая через {seconds} с. Прямых соединений нет."
            )
        } else {
            format!(
                "Прокси остановлен: {reason}. Переподключение через {seconds} с. Прямых соединений нет."
            )
        };
        self.last_error = Some(self.status.clone());
        let (task, handle) = Task::perform(
            async move {
                tokio::time::sleep(retry.delay).await;
                socks_recovery::attempt_with_metadata(profile, port, retry).await
            },
            move |r| Message::SocksAttempt(epoch, r),
        )
        .abortable();
        self.connection_task = Some(handle);
        task
    }
    fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch([
            iced::window::open_events().map(Message::TrayInit),
            iced::window::close_requests().map(|_| Message::CloseRequested),
            // A window restored by the OS (not through the tray) counts again.
            iced::event::listen_with(|event, _, _| {
                matches!(event, iced::Event::Window(iced::window::Event::Focused))
                    .then_some(Message::WindowFocused)
            }),
            iced::window::resize_events().map(|(_, size)| Message::Resized(size.width)),
            iced::system::theme_changes().map(Message::SystemTheme),
            iced::time::every(std::time::Duration::from_millis(250)).map(|_| Message::Tick),
        ])
    }

    fn fallback_settings(&self) -> Element<'_, Message> {
        let allowed = &self.saved_connection.fallback_profiles;
        let mut list = column![
            text("Автоматическое восстановление").size(18),
            text(format!(
                "Служба может переключиться на отмеченные профили, если endpoint профиля по умолчанию не отвечает: после двух неудачных попыток подряд и не чаще раза в {} с. Защита при переключении не снимается: адреса endpoint всех отмеченных профилей разрешены с начала подключения. Открытые соединения при переключении обрываются. Только TUN и «весь компьютер», не Always-on. Без отмеченных профилей используется только профиль по умолчанию.",
                20
            ))
            .size(13)
        ]
        .spacing(8);
        for profile in self.profiles.iter().skip(1) {
            let checked = allowed.contains(&profile.name);
            let mut entry =
                checkbox(checked).label(match allowed.iter().position(|n| *n == profile.name) {
                    Some(order) => format!("{} · резерв {}", profile.name, order + 1),
                    None => profile.name.clone(),
                });
            if self.can_change_profiles()
                && (checked || allowed.len() < rtrust_control::MAX_FALLBACKS)
            {
                let name = profile.name.clone();
                entry = entry.on_toggle(move |on| Message::Fallback(name.clone(), on));
            }
            list = list.push(entry);
        }
        if self.profiles.len() < 2 {
            list = list.push(
                text("Добавьте второй профиль, чтобы разрешить резервное подключение.").size(13),
            );
        }
        list.into()
    }
    fn proxy_settings(&self) -> Element<'_, Message> {
        let mut port = text_input("1080", &self.proxy_port).width(80);
        if self.can_change_profiles() {
            port = port.on_input(Message::ProxyPort);
        }
        let mut mode = pick_list(Mode::ALL, Some(self.mode), Message::Mode);
        if !self.can_change_profiles() {
            mode = pick_list(Mode::ALL, Some(self.mode), |_| Message::Tick);
        }
        let mut panel = column![
            mode,
            row![text("SOCKS5 · 127.0.0.1:"), port]
                .spacing(6)
                .align_y(iced::Alignment::Center),
            text("SOCKS5 и системный VPN используют транспорт профиля (HTTP/2 или HTTP/3) без автоматической смены.")
                .size(12)
        ]
        .spacing(6);
        if let Some(proxy) = self.session.as_ref().and_then(Session::proxy) {
            let stats = proxy.stats();
            panel = panel.push(
                row![
                    text(format!(
                        "↑ {} КБ  ↓ {} КБ  ·  соединений: {}  ·  ошибок: {}",
                        stats.uploaded / 1024,
                        stats.downloaded / 1024,
                        stats.active,
                        stats.errors
                    ))
                    .size(12),
                    button("Копировать адрес").on_press(Message::CopyProxy)
                ]
                .spacing(10)
                .align_y(iced::Alignment::Center),
            );
        }
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        if self.mode == Mode::Tun {
            let editable = self.can_change_profiles();
            let mut mode = pick_list(Mode::ALL, Some(self.mode), Message::Mode);
            if !editable {
                mode = pick_list(Mode::ALL, Some(self.mode), |_| Message::Tick);
            }
            let list = |nets: &[rtrust_control::Ipv4Net]| {
                if nets.is_empty() {
                    "нет".to_owned()
                } else {
                    nets.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                }
            };
            let routes: Element<'_, Message> = match &self.saved_connection.managed_routes {
                Some(managed) => text(format!(
                    "Маршруты задаёт сервер, группа «{}».\nЧерез VPN: {}\nИсключения: {}\nЛокальные сети: {}",
                    managed.group,
                    list(&managed.selection.include),
                    list(&managed.selection.exclude),
                    if managed.selection.exclude_lan { "напрямую" } else { "не исключаются" },
                ))
                .size(13)
                .into(),
                None => {
                    let mut networks =
                        text_input("Через VPN: 0.0.0.0/0 или 198.18.0.0/24, 10.20.0.0/16", &self.networks);
                    let mut exclude =
                        text_input("Исключения: например 192.168.0.0/16, 203.0.113.0/24", &self.exclude);
                    let mut lan = checkbox(self.exclude_lan)
                        .label("Не направлять локальные сети (LAN) в VPN");
                    if editable {
                        networks = networks.on_input(Message::Networks);
                        exclude = exclude.on_input(Message::Exclude);
                        lan = lan.on_toggle(Message::ExcludeLan);
                    }
                    column![
                        row![
                            networks,
                            button("Весь IPv4").on_press_maybe(editable.then_some(Message::WholeIpv4))
                        ]
                        .spacing(6),
                        exclude,
                        lan
                    ]
                    .spacing(6)
                    .into()
                }
            };
            panel = column![
                mode,
                routes,
                self.intent_view(),
                text(
                    if cfg!(target_os = "macos") { "IPv4-сети всего компьютера, кроме исключений. DNS/IPv6 остаются системными. После аварии используйте сброс блокировки." } else if cfg!(target_os = "windows") { "IPv4-сети всего компьютера, кроме исключений. DNS/IPv6 системные. При аварии службы блокировка не гарантируется." } else { "IPv4-сети этого пользователя, кроме исключений. IPv6 и DNS остаются системными." }
                )
                .size(12),
                button(if cfg!(target_os = "windows") { "Проверить службу" } else { "Сбросить блокировку после аварии" }).on_press_maybe(
                    editable.then_some(Message::RecoverService)
                )
            ]
            .spacing(6);
        }
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        if self.mode == Mode::Full {
            let mut dns = text_input("DNS через VPN, например 1.1.1.1", &self.dns);
            if self.can_change_profiles() {
                dns = dns.on_input(Message::Dns);
            }
            let mode = if self.can_change_profiles() {
                pick_list(Mode::ALL, Some(self.mode), Message::Mode)
            } else {
                pick_list(Mode::ALL, Some(self.mode), |_| Message::Tick)
            };
            panel = column![mode, dns].spacing(6).push(text(if cfg!(target_os = "macos") { "IPv4, IPv6 и DNS через VPN. Требуется системная служба macOS. После аварии защита остаётся до явного сброса." } else if cfg!(target_os = "windows") { "IPv4, IPv6 и DNS через VPN. Прямая LAN и пересылка заблокированы. После аварии защита остаётся до явного сброса." } else { "IPv4, IPv6 и DNS всего компьютера через VPN. Пересылка между интерфейсами заблокирована. Требуется systemd-resolved." }).size(12))
                .push(button("Сбросить блокировку после аварии").on_press_maybe(self.can_change_profiles().then_some(Message::RecoverService)));
        }
        panel.into()
    }
    fn monitor_connection(&mut self) -> Task<Message> {
        let Some(session) = self.session.clone() else {
            return Task::none();
        };
        let epoch = self.connection_epoch;
        let (task, handle) = Task::perform(
            async move {
                tokio::time::sleep(std::time::Duration::from_secs(if session.is_tun() {
                    2
                } else {
                    15
                }))
                .await;
                session.health().await
            },
            move |r| Message::Health(epoch, r),
        )
        .abortable();
        self.connection_task = Some(handle);
        task
    }
    fn view(&self) -> Element<'_, Message> {
        self.shell()
    }
}
/// Secondary action used by the section views; styled from the theme being drawn.
fn button<'a>(content: impl Into<Element<'a, Message>>) -> buttons::Button<'a, Message> {
    buttons::Button::new(content)
        .padding([8, 14])
        .style(|theme, status| ui::pill_style(ui::tokens_of(theme), ui::Kind::Chip, status))
}

// Flatpak file forwarding supplies file: URIs (including escaped spaces), while
// native file associations may still supply ordinary OS paths.
fn startup_file(arg: &std::ffi::OsStr) -> Result<std::path::PathBuf, String> {
    if let Some(value) = arg.to_str().filter(|v| v.starts_with("file:")) {
        return url::Url::parse(value)
            .map_err(|_| "Некорректная ссылка на файл")?
            .to_file_path()
            .map_err(|_| "Ожидается локальный файл".into());
    }
    Ok(arg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn app() -> App {
        let (mut app, _) = App::boot();
        app.busy = false;
        app.startup_busy = false;
        app.profiles = ["first.example", "second.example"].into_iter().map(|host| {
            Profile::import(&format!("hostname='{host}'\naddresses=['192.0.2.1:443']\nusername='demo'\npassword='synthetic'\n")).unwrap()
        }).collect();
        app
    }
    #[test]
    fn autoconnect_requires_opt_in_and_initial_load_and_runs_once() {
        let mut app = app();
        let mut vault = rtrust_store::Vault {
            profiles: app.profiles.clone(),
            connection: Default::default(),
        };
        app.boot_connect_pending = true;
        let _ = app.update(Message::Loaded(Ok((vault.clone(), None))));
        assert!(!app.connecting);
        vault.connection.auto_connect = true;
        // A manual reload must not start a connection.
        let _ = app.update(Message::Loaded(Ok((vault.clone(), None))));
        assert!(!app.connecting);
        app.boot_connect_pending = true;
        let _ = app.update(Message::Loaded(Ok((vault.clone(), None))));
        assert!(app.connecting);
        assert_eq!(app.connection_name, app.profiles[0].name);
        assert!(!app.boot_connect_pending && !app.dirty);
        let _ = app.update(Message::ToggleConnection); // cancel
        let _ = app.update(Message::Loaded(Ok((vault, None))));
        assert!(!app.connecting);
    }
    #[test]
    fn autoconnect_setting_saves_without_connecting_immediately() {
        let mut app = app();
        let _ = app.update(Message::AutoConnect(true));
        assert!(app.dirty && app.autosave_due.is_some());
        assert!(app.connection_settings().unwrap().auto_connect);
        assert!(!app.connecting);
    }
    #[test]
    fn autoconnect_missing_profile_or_locked_vault_stays_visible() {
        let mut app = app();
        app.boot_connect_pending = true;
        app.login_start = true;
        app.pending_close = Some(false);
        let vault = rtrust_store::Vault {
            profiles: vec![],
            connection: rtrust_store::ConnectionSettings {
                auto_connect: true,
                ..Default::default()
            },
        };
        let _ = app.update(Message::Loaded(Ok((vault, None))));
        assert!(!app.connecting && !app.login_start && app.pending_close.is_none());
        app.boot_connect_pending = true;
        let _ = app.update(Message::Loaded(Err("locked".into())));
        assert!(!app.boot_connect_pending && !app.connecting);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn autoconnect_never_downgrades_system_vpn_to_socks() {
        let mut app = app();
        app.boot_connect_pending = true;
        let vault = rtrust_store::Vault {
            profiles: app.profiles.clone(),
            connection: rtrust_store::ConnectionSettings {
                auto_connect: true,
                mode: rtrust_store::Mode::Full,
                ..Default::default()
            },
        };
        let _ = app.update(Message::Loaded(Ok((vault, None))));
        assert!(app.connecting);
        assert_eq!(app.mode, Mode::Full);
        assert!(app.saved_connection.mode == rtrust_store::Mode::Full);
    }
    #[test]
    fn connection_failure_restores_hidden_login_window() {
        let mut app = app();
        let _ = app.update(Message::ToggleConnection);
        app.login_start = true;
        app.pending_close = Some(false);
        let _ = app.update(Message::Connected(
            app.connection_epoch,
            Err("offline".into()),
        ));
        assert!(!app.login_start && app.pending_close.is_none() && !app.connecting);
        assert_eq!(app.status, "offline");
    }
    #[test]
    fn locked_vault_at_login_keeps_error_window_visible() {
        let mut app = app();
        app.login_start = true;
        app.busy = true;
        let _ = app.update(Message::TrayReady(true));
        assert_eq!(app.pending_close, Some(false));
        let _ = app.update(Message::Loaded(Err("keyring locked".into())));
        assert!(app.pending_close.is_none());
        assert!(!app.login_start);
        assert!(app.status.contains("keyring locked"));
        assert!(!app.connecting && app.session.is_none());
    }
    #[test]
    fn background_check_cancellation_preserves_unrelated_busy_operation() {
        let mut app = app();
        let (_task, handle) =
            Task::perform(std::future::pending::<()>(), |_| Message::Tick).abortable();
        app.diagnostic_task = Some(handle);
        app.busy = true; // e.g. saving a profile, independent of the background check
        let before = app.diagnostic_generation;
        app.cancel_diagnostic();
        assert!(app.busy);
        assert!(app.diagnostic_task.is_none());
        assert_eq!(app.diagnostic_generation, before + 1);
    }
    #[test]
    fn changing_destination_discards_previous_check_and_does_not_lock_ui() {
        let mut app = app();
        let (_task, handle) =
            Task::perform(std::future::pending::<()>(), |_| Message::Tick).abortable();
        app.diagnostic_task = Some(handle);
        app.last_diagnostic = Some(std::time::Instant::now());
        let _ = app.update(Message::SystemTarget("other.example".into()));
        assert_eq!(app.system_target, "other.example");
        assert!(app.diagnostic_task.is_none() && app.last_diagnostic.is_some());
        assert!(app.system_target_edited_at.is_some());
        assert!(!app.busy);
    }
    #[test]
    fn edited_export_survives_background_and_endpoint_updates_until_explicit_reset() {
        use rtrust_desktop::diagnostics::Report;
        let mut app = app();
        let mut first = Report::new(rtrust_control::observations::Snapshot::unknown(
            rtrust_control::observations::Mode::Full,
        ));
        first.started_at_ms = 100;
        app.refresh_diagnostic_preview(&first);
        // Selecting text alone must not freeze automatic updates.
        let _ = app.update(Message::DiagnosticEdit(text_editor::Action::SelectAll));
        assert!(!app.diagnostic_preview_dirty);
        let _ = app.update(Message::DiagnosticEdit(text_editor::Action::Edit(
            text_editor::Edit::Paste(std::sync::Arc::new("user-redacted report".into())),
        )));
        assert!(app.diagnostic_preview_dirty);
        let edited = app.diagnostic_preview.text();
        let mut newer = first.clone();
        newer.started_at_ms = 200;
        app.refresh_diagnostic_preview(&newer);
        assert_eq!(app.diagnostic_preview.text(), edited);
        assert_eq!(
            app.diagnostic_export_report.as_ref().unwrap().started_at_ms,
            100
        );
        // Endpoint refinement and a destination edit must also preserve the copy.
        newer.endpoint = rtrust_desktop::diagnostics::Fact::Passed;
        app.refresh_diagnostic_preview(&newer);
        let _ = app.update(Message::SystemTarget("other.example".into()));
        assert_eq!(app.diagnostic_preview.text(), edited);
        app.diagnostic_report = Some((app.connection_epoch, newer.clone()));
        let _ = app.update(Message::ResetDiagnosticPreview);
        assert!(!app.diagnostic_preview_dirty);
        assert_eq!(app.diagnostic_preview.text(), newer.redacted_json());
        assert_eq!(
            app.diagnostic_export_report.as_ref().unwrap().started_at_ms,
            200
        );
    }
    #[test]
    fn destination_edits_debounce_without_resetting_the_request_cooldown() {
        let mut app = app();
        let started = std::time::Instant::now();
        app.last_diagnostic = Some(started);
        let _ = app.update(Message::SystemTarget("other.example".into()));
        assert_eq!(app.last_diagnostic, Some(started));
        assert!(!app.diagnostic_start_allowed(started + std::time::Duration::from_secs(2)));
        // A later keystroke restarts the debounce, but keeps the original cooldown.
        app.system_target_edited_at = Some(started + std::time::Duration::from_millis(4900));
        assert!(!app.diagnostic_start_allowed(started + std::time::Duration::from_secs(5)));
        assert!(app.diagnostic_start_allowed(started + std::time::Duration::from_secs(6)));
        // Cancellation does not reopen the cooldown either.
        let _ = app.update(Message::Cancel);
        assert_eq!(app.last_diagnostic, Some(started));
    }
    #[test]
    fn system_diagnostic_requires_active_tun_and_report_export_requires_completion() {
        let mut app = app();
        let _ = app.update(Message::Diagnose);
        assert!(app.status.contains("подключите TUN"));
        assert!(!app.busy && app.probe.is_none() && app.session.is_none());
        let _ = app.update(Message::ExportDiagnostic);
        assert!(!app.busy && app.diagnostic_report.is_none());
    }
    #[test]
    fn diagnostic_actions_need_a_current_report_and_follow_ups_attach_once() {
        use rtrust_desktop::diagnostics::{Action, Cause, FollowUp, Report};
        let mut app = app();
        let snapshot = rtrust_control::observations::Snapshot::unknown(
            rtrust_control::observations::Mode::Full,
        );
        // A report from an earlier connection cannot drive an action.
        app.diagnostic_report = Some((app.connection_epoch + 1, Report::new(snapshot.clone())));
        let _ = app.update(Message::DiagnosticAction(Action::CheckEndpoint));
        assert!(!app.busy && app.probe.is_none());
        let _ = app.update(Message::DiagnosticAction(Action::Reconnect));
        assert!(!app.reconnect_then_check && app.follow_up.is_none());
        // A repeat that cannot start leaves no dangling follow-up.
        let _ = app.update(Message::DiagnosticAction(Action::Recheck));
        assert!(app.status.contains("подключите TUN") && app.follow_up.is_none());
        // A delayed completion after disconnect cannot replace the displayed report.
        app.busy = true;
        let _ = app.update(Message::Diagnosed(
            app.diagnostic_generation,
            app.connection_epoch,
            Report::new(snapshot.clone()),
        ));
        assert_eq!(
            app.diagnostic_report.as_ref().unwrap().0,
            app.connection_epoch + 1
        );
        assert!(app.busy);
        // Follow-up provenance is retained on the report, not inferred from success.
        let mut report = Report::new(snapshot);
        report.follows = Some(FollowUp {
            action: Action::Reconnect,
            previous_cause: Cause::Undetermined,
            previous_finished_at_ms: 7,
        });
        assert!(report.verdict_text().contains("Повторная проверка"));
        app.diagnostic_report = Some((app.connection_epoch, report));
        let (_, report) = app.diagnostic_report.as_ref().unwrap();
        // An endpoint result for this connection refines the shown report.
        app.busy = true;
        let started = report.started_at_ms;
        let _ = app.update(Message::EndpointChecked(
            app.generation,
            app.connection_epoch,
            rtrust_desktop::diagnostics::EndpointCheck {
                fact: rtrust_desktop::diagnostics::Fact::Passed,
                started_at_ms: started,
                finished_at_ms: started + 1,
                independent: true,
            },
        ));
        let (_, report) = app.diagnostic_report.as_ref().unwrap();
        assert_eq!(report.endpoint, rtrust_desktop::diagnostics::Fact::Passed);
        assert!(!app.busy);
    }
    #[test]
    fn backup_profiles_are_opt_in_saved_in_order_and_follow_a_rename() {
        let mut app = app();
        let backup = app.profiles[1].name.clone();
        assert!(app.saved_connection.fallbacks(&app.profiles).is_empty());
        let _ = app.update(Message::Fallback(backup.clone(), true));
        assert!(app.dirty);
        assert_eq!(
            app.connection_settings().unwrap().fallback_profiles,
            std::slice::from_ref(&backup)
        );
        // Renaming the backup keeps it allowed.
        app.selected = 1;
        app.draft_name = "renamed backup".into();
        let _ = app.update(Message::Rename);
        assert_eq!(app.saved_connection.fallback_profiles, ["renamed backup"]);
        assert_eq!(
            app.saved_connection.fallbacks(&app.profiles)[0].name,
            "renamed backup"
        );
        let _ = app.update(Message::Fallback("renamed backup".into(), false));
        assert!(
            app.connection_settings()
                .unwrap()
                .fallback_profiles
                .is_empty()
        );
    }
    #[test]
    fn a_failed_reconnect_action_drops_its_planned_repeat_check() {
        let mut app = app();
        app.reconnect_then_check = true;
        app.follow_up = Some(rtrust_desktop::diagnostics::FollowUp {
            action: rtrust_desktop::diagnostics::Action::Reconnect,
            previous_cause: rtrust_desktop::diagnostics::Cause::Undetermined,
            previous_finished_at_ms: 1,
        });
        app.connecting = true;
        let epoch = app.connection_epoch;
        let _ = app.update(Message::Connected(epoch, Err("endpoint refused".into())));
        assert!(!app.reconnect_then_check && app.follow_up.is_none());
    }
    #[test]
    fn startup_settings_do_not_connect_or_dirty_profiles() {
        let mut app = app();
        let _ = app.update(Message::StartupSet(true));
        assert!(app.busy && app.startup_busy);
        let _ = app.update(Message::StartupChanged(Ok(true)));
        assert!(app.autostart);
        assert!(!app.dirty && !app.connecting && app.session.is_none());
        let _ = app.update(Message::StartupSet(false));
        let _ = app.update(Message::StartupChanged(Err("denied".into())));
        assert!(app.autostart);
        assert!(app.startup_error.is_some());
        assert!(!app.busy && !app.startup_busy);
    }
    #[test]
    fn login_launch_closes_to_tray_without_connecting() {
        let mut app = app();
        app.login_start = true;
        let _ = app.update(Message::TrayReady(true));
        assert!(!app.login_start && !app.connecting && app.session.is_none());
        assert!(!app.exit_after_stop);
    }
    #[test]
    fn close_flushes_dirty_configuration_before_hiding() {
        let mut app = app();
        app.tray_ready = true;
        let _ = app.update(Message::DraftName("Persist me".into()));
        let _ = app.update(Message::Rename);
        assert!(app.autosave_due.is_some());
        let _ = app.update(Message::CloseRequested);
        assert!(app.busy && app.dirty);
        assert_eq!(app.pending_close, Some(false));
        let _ = app.update(Message::Saved(Err("keyring locked".into())));
        assert!(app.dirty);
        assert!(app.pending_close.is_none());
        assert!(app.status.contains("keyring locked"));
        let _ = app.update(Message::ExitRequested);
        assert_eq!(app.pending_close, Some(true));
        let _ = app.update(Message::Saved(Ok(vec![1, 2, 3])));
        assert!(!app.dirty);
        assert!(app.pending_close.is_none());
    }
    #[test]
    fn autosave_debounces_and_does_not_retry_failed_save_forever() {
        let mut app = app();
        let _ = app.update(Message::MakeDefault);
        app.autosave_due = Some(std::time::Instant::now());
        let _ = app.update(Message::Tick);
        assert!(app.busy);
        assert!(app.autosave_due.is_none());
        let _ = app.update(Message::Saved(Err("locked".into())));
        let _ = app.update(Message::Tick);
        assert!(!app.busy && app.dirty);
    }
    #[test]
    fn ticks_report_a_view_only_while_the_window_is_shown() {
        let mut app = app();
        assert!(app.window_visible, "an interactive start shows the window");
        // Hidden to the tray: ticks keep running but report no view.
        app.tray_ready = true;
        let _ = app.update(Message::CloseRequested);
        assert!(!app.window_visible);
        for _ in 0..4 {
            let _ = app.update(Message::Tick);
            assert!(!app.window_visible);
        }
        let _ = app.update(Message::TrayEvents(vec![tray::Action::Show]));
        assert!(app.window_visible);
        let _ = app.update(Message::Tick);
        assert!(app.window_visible);
        // Without a tray the app minimizes itself: also not viewed, until
        // the OS restores and focuses the window.
        app.tray_ready = false;
        let _ = app.update(Message::CloseRequested);
        assert!(!app.window_visible);
        let _ = app.update(Message::WindowFocused);
        assert!(app.window_visible);
        // A login start hides the window once the tray is ready.
        let mut app = super::tests::app();
        app.login_start = true;
        app.window_visible = false;
        let _ = app.update(Message::TrayReady(true));
        assert!(!app.window_visible);
    }
    #[test]
    fn closing_to_tray_keeps_connection_attempt_alive() {
        let mut app = app();
        app.tray_ready = true;
        app.connecting = true;
        let _ = app.update(Message::CloseRequested);
        assert!(app.connecting);
        assert!(!app.exit_after_stop);
    }
    #[test]
    fn portal_download_requires_local_accept_and_never_connects() {
        let mut app = app();
        let profile = app.profiles[1].clone();
        let before = app.profiles.len();
        let _ = app.update(Message::Portal(portal::Action::Downloaded(Box::new(Ok(
            profile,
        )))));
        assert!(app.preview.is_some());
        assert!(app.page == Page::Import);
        assert_eq!(app.profiles.len(), before);
        assert!(app.session.is_none());
        assert!(!app.connecting);
    }
    #[test]
    fn portal_upload_requires_explicit_secret_consent() {
        let mut app = app();
        let _ = app.update(Message::Portal(portal::Action::Upload));
        assert!(!app.busy);
        assert!(app.session.is_none());
    }
    #[test]
    fn selected_profile_does_not_change_default_until_explicit_action() {
        let mut app = app();
        let _ = app.update(Message::Select(1));
        assert_eq!(app.profiles[0].endpoint.hostname, "first.example");
        let _ = app.update(Message::MakeDefault);
        assert_eq!(app.profiles[0].endpoint.hostname, "second.example");
        assert_eq!(app.selected, 0);
        let _ = app.update(Message::Select(1));
        let task = app.update(Message::ToggleConnection);
        assert_eq!(app.connection_name, "first.example");
        assert!(app.connecting);
        drop(task);
    }
    #[test]
    fn selected_fallback_is_not_sent_twice_as_a_connection_candidate() {
        let mut app = app();
        let _ = app.update(Message::Select(1));
        app.saved_connection.fallback_profiles = vec!["second.example".into()];
        let task = app.update(Message::ToggleConnection);
        assert_eq!(app.connection_candidates, vec!["second.example"]);
        drop(task);
    }
    #[test]
    fn selected_connection_retains_a_permitted_default_backup() {
        let mut app = app();
        let _ = app.update(Message::Select(1));
        app.saved_connection.fallback_profiles =
            vec!["first.example".into(), "second.example".into()];
        let task = app.update(Message::ToggleConnection);
        assert_eq!(
            app.connection_candidates,
            vec!["second.example", "first.example"]
        );
        drop(task);
    }
    #[test]
    fn background_connect_uses_default_without_changing_selection() {
        let mut app = app();
        let _ = app.update(Message::Select(1));
        let task = app.update(Message::ToggleDefaultConnection);
        assert_eq!(app.connection_name, "first.example");
        assert_eq!(app.selected, 1);
        assert!(app.connecting);
        drop(task);
    }
    #[test]
    fn cancel_invalidates_late_connection_results_and_allows_retry() {
        let mut app = app();
        let task = app.update(Message::ToggleConnection);
        let old = app.connection_epoch;
        let _ = app.update(Message::ToggleConnection);
        assert!(!app.connecting);
        assert!(app.connection_task.is_none());
        let _ = app.update(Message::Connected(old, Err("stale error".into())));
        assert_eq!(app.status, "Отключено.");
        let retry = app.update(Message::ToggleConnection);
        let _ = app.update(Message::Connected(
            app.connection_epoch,
            Err("authentication failed".into()),
        ));
        assert!(!app.connecting);
        assert!(app.session.is_none());
        assert_eq!(app.status, "authentication failed");
        drop((task, retry));
    }
    #[test]
    fn profile_edits_are_explicit_and_preserve_default_order() {
        let mut app = app();
        let _ = app.update(Message::Select(0));
        let _ = app.update(Message::DraftName("Мой сервер".into()));
        let _ = app.update(Message::Rename);
        assert_eq!(app.profiles[0].name, "Мой сервер");
        assert!(app.dirty);
        let _ = app.update(Message::Delete);
        assert_eq!(app.profiles.len(), 2);
        let _ = app.update(Message::Delete);
        assert_eq!(app.profiles.len(), 1);
        assert_eq!(app.profiles[0].endpoint.hostname, "second.example");
        app.preview = Some(Profile::import("hostname='new.example'\naddresses=['192.0.2.3:443']\nusername='new'\npassword='rotated'\n").unwrap());
        let _ = app.update(Message::Replace);
        assert_eq!(app.profiles[0].endpoint.hostname, "second.example");
        let _ = app.update(Message::Replace);
        assert_eq!(app.profiles[0].endpoint.hostname, "new.example");
        assert!(app.preview.is_none());
        app.connecting = true;
        let _ = app.update(Message::Delete);
        let _ = app.update(Message::Delete);
        assert_eq!(app.profiles.len(), 1);
    }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    fn tun_rejects_invalid_routes_and_locks_mode_during_connect() {
        let mut app = app();
        let _ = app.update(Message::Mode(Mode::Tun));
        for network in ["", "0.0.0.0/8", "127.0.0.1/32", "bad"] {
            let _ = app.update(Message::Networks(network.into()));
            let _ = app.update(Message::ToggleConnection);
            assert!(!app.connecting);
            assert!(app.connection_task.is_none());
        }
        let _ = app.update(Message::Networks("198.18.0.1/32".into()));
        app.proxy_port = "not used by TUN".into();
        let task = app.update(Message::ToggleConnection);
        assert!(app.connecting);
        let _ = app.update(Message::Mode(Mode::Socks));
        let _ = app.update(Message::Networks("203.0.113.1/32".into()));
        assert_eq!(app.mode, Mode::Tun);
        assert_eq!(app.networks, "198.18.0.1/32");
        let _ = app.update(Message::ToggleConnection);
        drop(task);
    }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    fn offline_preview_keeps_managed_policy_precedence_and_does_not_start_a_session() {
        let mut app = app();
        app.mode = Mode::Tun;
        app.networks = "0.0.0.0/0".into();
        app.exclude_lan = false;
        app.saved_connection.managed_routes = Some(rtrust_store::ManagedRoutes {
            group: "office".into(),
            revision: "3:4".into(),
            selection: rtrust_control::Selection::parse("10.0.0.0/8", "", false).unwrap(),
        });
        app.target = "198.51.100.1:443".into();
        let _ = app.update(Message::ExplainRoute);
        assert!(app.status.contains("напрямую") && app.status.contains("3:4"));
        assert!(app.status.contains("серверная политика"));
        assert!(app.session.is_none() && !app.connecting && !app.busy);
        app.target = "https://sensitive.test/?token=canary".into();
        let _ = app.update(Message::ExplainRoute);
        assert!(app.status.contains("неизвестно") && !app.status.contains("canary"));
    }
    #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
    #[test]
    fn whole_ipv4_with_exclusions_and_server_policy_override() {
        let mut app = app();
        let _ = app.update(Message::Mode(Mode::Tun));
        let _ = app.update(Message::WholeIpv4);
        let _ = app.update(Message::Exclude("10.0.0.0/8; 203.0.113.0/24".into()));
        let local = app.tun_selection().unwrap();
        assert_eq!(
            local.include,
            rtrust_control::networks("0.0.0.0/0").unwrap()
        );
        assert_eq!(local.exclude.len(), 2);
        assert!(local.exclude_lan);
        let settings = app.connection_settings().unwrap();
        assert_eq!(settings.selection(), local);
        let _ = app.update(Message::Exclude("0.0.0.0/0".into()));
        assert!(app.tun_selection().is_err());
        assert!(app.connection_settings().is_err());
        let managed = rtrust_store::ManagedRoutes {
            group: "office".into(),
            revision: "1:1".into(),
            selection: rtrust_control::Selection::parse("10.0.0.0/8", "", false).unwrap(),
        };
        app.saved_connection.managed_routes = Some(managed.clone());
        assert_eq!(app.tun_selection().unwrap(), managed.selection);
        let _ = app.update(Message::Networks(String::new()));
        let _ = app.update(Message::Exclude(String::new()));
        assert!(app.connection_settings().unwrap().managed_routes == Some(managed));
    }
    #[test]
    fn failed_stop_keeps_the_owner_for_recover_until_it_succeeds() {
        use rtrust_control::owner::{LEN, Owner};
        let owner = Owner::from_bytes([9; LEN]);
        let mut app = app();
        // As captured by take_session when Disconnect removed the session.
        app.pending_owner = Some(owner.clone());
        app.connecting = true;
        app.disconnecting = true;
        app.connection_epoch = 4;
        let _ = app.update(Message::Stopped(4, Err("IPC lost".into())));
        assert!(app.session.is_none());
        assert!(app.can_change_profiles());
        assert!(app.recover_owner().unwrap().matches(&owner));
        let _ = app.update(Message::Recovered(Err("refused".into())));
        assert!(app.recover_owner().unwrap().matches(&owner));
        assert_eq!(app.status, "refused");
        let _ = app.update(Message::Recovered(Ok("done".into())));
        assert!(app.pending_owner.is_none());
        assert!(app.recover_owner().is_none());
        // A confirmed Stop also spends the owner.
        app.pending_owner = Some(owner);
        app.connection_epoch = 5;
        let _ = app.update(Message::Stopped(5, Ok(())));
        assert!(app.pending_owner.is_none());
        assert!(!format!("{:?}", app.recover_owner()).contains("0909"));
    }
    #[test]
    fn disconnect_waits_for_current_ack_and_preserves_failure() {
        let mut app = app();
        app.connecting = true;
        app.disconnecting = true;
        app.connection_epoch = 7;
        let _ = app.update(Message::ToggleConnection);
        assert!(app.disconnecting);
        let _ = app.update(Message::Stopped(6, Ok(())));
        assert!(app.disconnecting);
        let _ = app.update(Message::Stopped(7, Err("cleanup failed".into())));
        assert!(!app.disconnecting);
        assert!(!app.connecting);
        assert_eq!(app.status, "cleanup failed");
    }
    #[test]
    fn close_waits_for_disconnect_and_cleanup_errors_keep_window_open() {
        let mut app = app();
        app.connection_epoch = 9;
        app.connecting = true;
        let _ = app.update(Message::ExitRequested);
        assert!(!app.exit_after_stop);
        assert!(app.status.contains("Дождитесь"));
        app.disconnecting = true;
        let _ = app.update(Message::ExitRequested);
        assert!(app.exit_after_stop);
        let _ = app.update(Message::Stopped(9, Err("guard retained".into())));
        assert!(!app.exit_after_stop);
        assert_eq!(app.status, "guard retained");
        assert!(!app.disconnecting);
    }
    #[test]
    fn loading_full_mode_preserves_dns_without_autoconnect() {
        let mut app = app();
        let settings = rtrust_store::ConnectionSettings {
            mode: rtrust_store::Mode::Full,
            dns: "10.0.0.53".parse().unwrap(),
            ..Default::default()
        };
        let vault = rtrust_store::Vault {
            profiles: app.profiles.clone(),
            connection: settings.clone(),
        };
        let _ = app.update(Message::Loaded(Ok((vault, None))));
        assert!(app.connection_settings().unwrap() == settings);
        assert!(app.session.is_none() && !app.connecting);
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        {
            assert_eq!(app.mode, Mode::Full);
            app.connecting = true;
            let _ = app.update(Message::Dns("127.0.0.53".into()));
            assert_eq!(app.dns, "10.0.0.53");
        }
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        assert_eq!(app.mode, Mode::Socks);
    }
    #[test]
    fn loading_restores_settings_without_connecting_or_losing_linux_mode() {
        let mut app = app();
        let settings = rtrust_store::ConnectionSettings {
            mode: rtrust_store::Mode::Tun,
            socks_port: 2080,
            networks: rtrust_control::networks("198.18.0.0/24").unwrap(),
            dns: "9.9.9.9".parse().unwrap(),
            auto_connect: false,
            sync: Default::default(),
            exclude: rtrust_control::networks("198.18.0.128/25").unwrap(),
            exclude_lan: true,
            managed_routes: None,
            fallback_profiles: vec![],
        };
        let vault = rtrust_store::Vault {
            profiles: app.profiles.clone(),
            connection: settings.clone(),
        };
        let _ = app.update(Message::Loaded(Ok((vault, Some(vec![42])))));
        assert_eq!(app.proxy_port, "2080");
        assert_eq!(app.networks, "198.18.0.0/24");
        assert_eq!(app.exclude, "198.18.0.128/25");
        assert!(app.exclude_lan);
        assert!(app.connection_settings().unwrap() == settings);
        assert!(!app.connecting && !app.dirty);
        assert!(app.session.is_none() && app.connection_task.is_none());
        #[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
        assert_eq!(app.mode, Mode::Tun);
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        assert_eq!(app.mode, Mode::Socks);
    }
    #[test]
    fn settings_are_dirty_and_frozen_while_saving() {
        let mut app = app();
        let _ = app.update(Message::ProxyPort("2080".into()));
        assert!(app.dirty);
        let task = app.update(Message::Save);
        assert!(app.busy);
        let _ = app.update(Message::ProxyPort("3080".into()));
        assert_eq!(app.proxy_port, "2080");
        let _ = app.update(Message::Saved(Err("locked keyring".into())));
        assert!(app.dirty && !app.busy);
        assert!(app.status.contains("locked keyring"));
        drop(task);
    }
    #[test]
    fn invalid_port_does_not_start_connection() {
        let mut app = app();
        for port in ["0", "65536", "bad"] {
            let _ = app.update(Message::ProxyPort(port.into()));
            let _ = app.update(Message::ToggleConnection);
            assert!(!app.connecting);
            assert!(app.connection_task.is_none());
        }
    }
    /// A SOCKS session the user started and the proxy admitted. The proxy
    /// itself is not needed: the health verdict arrives without it.
    fn socks_admitted(app: &mut App) {
        app.mode = Mode::Socks;
        let mut recovery = socks_recovery::Recovery::new(app.profiles[0].clone(), 1080);
        recovery.connected(std::time::Instant::now());
        app.socks_recovery = Some(recovery);
        app.connection_name = app.profiles[0].name.clone();
    }
    /// Seconds shown in a wait notice: the delay carries bounded jitter.
    fn shown_wait(status: &str) -> u64 {
        let tail = status.rsplit("через ").next().unwrap();
        tail.split(' ').next().unwrap().parse().unwrap()
    }
    fn degraded(proven: bool) -> connection::HealthError {
        connection::HealthError {
            message: "Tunnel carries no traffic".into(),
            degraded: Some(proven),
        }
    }
    #[test]
    fn socks_degraded_health_waits_and_retries_without_a_proxy() {
        for proven in [false, true] {
            let mut app = app();
            socks_admitted(&mut app);
            let epoch = app.connection_epoch;
            let task = app.socks_lost(degraded(proven));
            drop(task);
            // Fail-closed: no proxy runs during the wait; the attempt is the
            // current connection task under a new epoch.
            assert!(app.session.is_none() && app.connecting);
            assert!(app.connection_epoch > epoch && app.connection_task.is_some());
            assert!(app.socks_recovery.as_ref().unwrap().retrying());
            assert_eq!(app.connection_name, app.profiles[0].name);
            assert!(app.status.contains("Переподключение через 2"));
            assert!(app.status.contains("Прямых соединений нет"));
            assert_eq!(app.last_error.as_deref(), Some(app.status.as_str()));
        }
    }
    #[test]
    fn socks_failures_other_than_degraded_still_disconnect() {
        let mut app = app();
        socks_admitted(&mut app);
        let _ = app.socks_lost(connection::HealthError {
            message: "Tunnel I/O failed".into(),
            degraded: None,
        });
        assert!(!app.connecting && app.session.is_none() && app.socks_recovery.is_none());
        assert_eq!(app.status, "Соединение потеряно: Tunnel I/O failed");
    }
    #[test]
    fn socks_retry_failures_reach_the_cooldown_and_stay_cancellable() {
        let mut app = app();
        socks_admitted(&mut app);
        let _ = app.socks_lost(degraded(false));
        // The first wait was 2 s; seven more failed attempts spend the burst.
        for seconds in [4, 8, 16, 30, 30, 30, 30] {
            let _ = app.update(Message::SocksAttempt(
                app.connection_epoch,
                Err(rtrust_engine::Error::Connect.into()),
            ));
            assert!(app.connecting && app.session.is_none());
            assert!(app.status.contains("Переподключение через"));
            assert!((seconds..=seconds * 5 / 4).contains(&shown_wait(&app.status)));
        }
        let _ = app.update(Message::SocksAttempt(
            app.connection_epoch,
            Err(rtrust_engine::Error::Timeout.into()),
        ));
        assert!(app.status.contains("Несколько попыток подряд не удались"));
        let cooldown = rtrust_control::recovery::COOLDOWN.as_secs();
        assert!((cooldown..=cooldown + 30).contains(&shown_wait(&app.status)));
        // A late result of the cancelled attempt cannot revive it.
        let stale = app.connection_epoch;
        let _ = app.update(Message::ToggleConnection);
        assert!(!app.connecting && app.socks_recovery.is_none() && app.connection_task.is_none());
        let _ = app.update(Message::SocksAttempt(
            stale,
            Err(rtrust_engine::Error::Connect.into()),
        ));
        assert!(!app.connecting && app.socks_recovery.is_none());
    }
    #[test]
    fn a_failed_user_socks_start_is_shown_not_retried() {
        let mut app = app();
        app.mode = Mode::Socks;
        let _ = app.update(Message::ToggleConnection);
        assert!(app.connecting);
        assert!(!app.socks_recovery.as_ref().unwrap().retrying());
        let _ = app.update(Message::Connected(
            app.connection_epoch,
            Err("TLS failed".into()),
        ));
        assert!(!app.connecting && app.socks_recovery.is_none());
        assert_eq!(app.status, "TLS failed");
    }
    #[test]
    fn a_permanent_attempt_failure_ends_socks_recovery() {
        for error in [
            rtrust_engine::Error::LocalBind,
            rtrust_engine::Error::Authentication,
        ] {
            let mut app = app();
            socks_admitted(&mut app);
            let _ = app.socks_lost(degraded(true));
            let epoch = app.connection_epoch;
            let message = error.to_string();
            let _ = app.update(Message::SocksAttempt(epoch, Err(error.into())));
            assert!(!app.connecting && app.session.is_none() && app.socks_recovery.is_none());
            assert!(app.connection_task.is_none() && app.connection_epoch > epoch);
            assert_eq!(app.status, format!("Соединение потеряно: {message}"));
            assert!(!app.status.contains("Прямых соединений нет"));
        }
    }
    #[test]
    fn exit_is_not_blocked_by_a_socks_reconnect_wait() {
        let mut app = app();
        socks_admitted(&mut app);
        let _ = app.socks_lost(degraded(true));
        let _ = app.update(Message::ExitRequested);
        assert!(!app.status.contains("Дождитесь"));
        assert!(!app.connecting && app.socks_recovery.is_none());
    }
}

#[cfg(all(test, unix))]
mod file_uri_tests {
    #[test]
    fn decodes_local_file_uri_and_rejects_remote_file_host() {
        assert_eq!(
            super::startup_file(std::ffi::OsStr::new("file:///tmp/test%20profile.toml")).unwrap(),
            std::path::PathBuf::from("/tmp/test profile.toml")
        );
        assert!(
            super::startup_file(std::ffi::OsStr::new("file://remote.example/profile.toml"))
                .is_err()
        );
    }
}
