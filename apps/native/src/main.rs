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
#[cfg(target_os = "macos")]
mod open_url;
mod portal;
mod sync;
mod tray;
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
        size: iced::Size::new(860.0, 620.0),
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
            (app, Task::batch([task, open_window()]))
        },
        App::update,
        App::view_window,
    )
    .title("R-TrustTunnel · Native Preview")
    .subscription(App::subscription)
    .theme(Theme::custom(
        "R-TrustTunnel",
        iced::theme::Palette {
            background: Color::from_rgb8(48, 57, 72),
            text: Color::from_rgb8(227, 231, 241),
            primary: Color::from_rgb8(133, 184, 247),
            success: Color::from_rgb8(114, 194, 166),
            warning: Color::from_rgb8(230, 191, 114),
            danger: Color::from_rgb8(226, 130, 143),
        },
    ))
    .style(|_app: &App, theme: &Theme| {
        let background = theme.palette().background;
        #[cfg(target_os = "macos")]
        let background = {
            let mut background = background;
            if _app.glass_enabled && glass::transparency_allowed() {
                background.a = 0.68;
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
        ..Default::default()
    })
    .run()
}
#[derive(Clone, Copy, PartialEq)]
enum Page {
    Profiles,
    Import,
    Diagnostics,
    Portal,
    Settings,
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
    sync_state: sync::State,
    store_conflict: Option<(rtrust_store::Vault, Option<Vec<u8>>)>,
    autostart: bool,
    startup_busy: bool,
    startup_error: Option<String>,
    login_start: bool,
    boot_connect_pending: bool,
    tray_ready: bool,
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
    probe: Option<iced::task::Handle>,
    generation: u64,
    connection_epoch: u64,
    connection_task: Option<iced::task::Handle>,
    session: Option<Session>,
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
}
#[derive(Clone)]
enum Message {
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
    Stopped(u64, Result<(), String>),
    CopyProxy,
    Tick,
    SmokeExit,
    CloseRequested,
    DraftName(String),
    Rename,
    Delete,
    Replace,
    ToggleConnection,
    Connected(u64, Result<Session, String>),
    Health(u64, Result<(), String>),
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
            sync_state: sync::State::default(),
            store_conflict: None,
            autostart: false,
            startup_busy: false,
            startup_error: None,
            login_start: false,
            boot_connect_pending: false,
            tray_ready: false,
            tray_smoke: false,
            pending_close: None,
            autosave_due: None,
            profiles: vec![],
            selected: 0,
            page: Page::Profiles,
            input: text_editor::Content::new(),
            preview: None,
            status: "Загрузка защищённого хранилища…".into(),
            busy: false,
            format: Format::Json,
            consent: false,
            revision: None,
            target: "example.com:80".into(),
            probe: None,
            generation: 0,
            connection_epoch: 0,
            connection_task: None,
            session: None,
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
        };
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
            return Self::show_window();
        }
        // Never toggle an already active connection or restart a cancelled attempt.
        if self.connecting || self.session.is_some() || self.disconnecting {
            return Task::none();
        }
        self.update(Message::ToggleConnection)
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
                        return Self::show_window();
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
                    Self::show_window(),
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
                                Self::show_window(),
                                Task::perform(
                                    async {
                                        tokio::time::sleep(std::time::Duration::from_millis(400))
                                            .await
                                    },
                                    |_| Message::TraySmokeStep(2),
                                ),
                            ])
                        } else {
                            Self::show_window()
                        }
                    }
                    #[cfg(target_os = "linux")]
                    tray::Action::Unavailable => {
                        self.tray_ready = false;
                        Self::show_window()
                    }
                    tray::Action::Toggle => self.update(Message::ToggleConnection),
                    tray::Action::Exit => self.update(Message::ExitRequested),
                }));
            }
            Message::Portal(action) => return self.portal_update(action),
            Message::SmokeExit => return iced::exit(),
            Message::CloseRequested => return self.request_close(false),
            Message::ExitRequested => return self.request_close(true),
            Message::DraftName(name) if !self.busy => self.draft_name = name,
            Message::Rename if self.can_change_profiles() => {
                let name = self.draft_name.trim();
                if name.is_empty() || name.len() > 1024 || name.chars().any(char::is_control) {
                    self.status =
                        "Название должно быть непустым, без управляющих символов, до 1024 байт."
                            .into();
                } else if let Some(profile) = self.profiles.get_mut(self.selected) {
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
                return Task::perform(
                    async {
                        rtrust_control::Client::recover().await.map(|()| {
                            if cfg!(target_os = "windows") {
                                "Windows-служба доступна.".into()
                            } else {
                                "Блокировка выбранных сетей снята.".into()
                            }
                        })
                    },
                    Message::Done,
                );
            }
            Message::Stopped(epoch, result) if epoch == self.connection_epoch => {
                let failed = result.is_err();
                let exit = std::mem::take(&mut self.exit_after_stop) && result.is_ok();
                self.disconnect();
                if exit {
                    return iced::exit();
                }
                self.status = result
                    .map(|()| "Отключено; маршруты восстановлены.".into())
                    .unwrap_or_else(|e| e);
                if failed {
                    return Self::show_window();
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
                    return Self::show_window();
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
            Message::ToggleConnection => {
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                if self.always_on.enabled {
                    return self.always_update(always_on::Action::Disable);
                }
                if self.disconnecting {
                    return Task::none();
                }
                if self.session.as_ref().is_some_and(Session::is_tun) {
                    self.connection_epoch += 1;
                    let epoch = self.connection_epoch;
                    if let Some(handle) = self.connection_task.take() {
                        handle.abort();
                    }
                    let session = self.session.take().unwrap();
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
                    self.disconnect();
                    self.status = if self.saved_connection.mode == rtrust_store::Mode::Full {
                        "Подключение отменено. Если сеть заблокирована, используйте сброс блокировки.".into()
                    } else {
                        "Отключено.".into()
                    };
                } else if !self.busy
                    && let Some(profile) = self.profiles.first().cloned()
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
                            Session::start(profile, mode, port, selection, dns)
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
                        self.session = Some(session);
                        self.status = if self.mode == Mode::Socks { "Прокси SOCKS5/HTTP включён. Его можно указать и как системный прокси Windows. Для DNS выберите разрешение имён через прокси." } else if self.saved_connection.mode == rtrust_store::Mode::Full && self.connection_ipv6 { "IPv4, IPv6 и DNS всего компьютера через VPN. Пересылка между интерфейсами заблокирована." } else if self.saved_connection.mode == rtrust_store::Mode::Full { "IPv4 и DNS всего компьютера через VPN. Сервер без IPv6: IPv6 заблокирован, приложения переходят на IPv4. Пересылка между интерфейсами заблокирована." } else { "Выбранные IPv4-сети подключены через службу. Исключения, остальной трафик и системный DNS идут напрямую." }.into();
                        return self.monitor_connection();
                    }
                    Err(error) => {
                        self.connection_name.clear();
                        self.status = error;
                        self.pending_close = None;
                        self.login_start = false;
                        return Self::show_window();
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
                            self.status = self.session.as_ref().unwrap().address();
                        }
                        return self.monitor_connection();
                    }
                    Err(error) => {
                        if self.session.as_ref().is_some_and(Session::is_tun) {
                            self.status = error;
                            return self.monitor_connection();
                        }
                        self.disconnect();
                        self.status = format!("Соединение потеряно: {error}");
                    }
                }
            }
            Message::Navigate(page) if !self.busy || page == Page::Settings => {
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
                        return Self::show_window();
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
                        return Self::show_window();
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
                        return Self::show_window();
                    }
                }
            }
            Message::Target(s) if !self.busy => self.target = s,
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
                if let Some(handle) = self.probe.take() {
                    handle.abort();
                    self.generation += 1;
                    self.busy = false;
                    self.status = "Проверка отменена; сеть не изменялась.".into();
                }
            }
            _ => {}
        }
        if edited && self.dirty && !self.busy {
            self.autosave_due =
                Some(std::time::Instant::now() + std::time::Duration::from_millis(600));
        }
        Task::none()
    }
    fn show_window() -> Task<Message> {
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
        if self.busy {
            self.pending_close = Some(exit);
            return Task::none();
        }
        if self.dirty {
            self.pending_close = Some(exit);
            return self.update(Message::Save);
        }
        if !exit {
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
        if self.connecting {
            self.status = "Дождитесь подключения или отмените его перед выходом.".into();
            return Self::show_window();
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
    fn disconnect(&mut self) {
        self.connection_epoch += 1;
        if let Some(handle) = self.connection_task.take() {
            handle.abort();
        }
        if let Some(proxy) = self.session.take() {
            proxy.cancel();
        }
        self.connecting = false;
        self.disconnecting = false;
        self.connection_name.clear();
    }
    fn subscription(&self) -> iced::Subscription<Message> {
        iced::Subscription::batch([
            iced::window::open_events().map(Message::TrayInit),
            iced::window::close_requests().map(|_| Message::CloseRequested),
            iced::time::every(std::time::Duration::from_millis(250)).map(|_| Message::Tick),
        ])
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
                session.health().await.map_err(|e| e.to_string())
            },
            move |r| Message::Health(epoch, r),
        )
        .abortable();
        self.connection_task = Some(handle);
        task
    }
    fn connection_bar(&self, window_width: f32) -> Element<'_, Message> {
        let active = self.connecting || self.session.is_some();
        let name = if active {
            self.connection_name.as_str()
        } else {
            self.profiles
                .first()
                .map(|p| p.name.as_str())
                .unwrap_or("Добавьте профиль")
        };
        let state = if self.disconnecting {
            "Отключение…".into()
        } else if self.connecting {
            "Подключение…".into()
        } else if let Some(proxy) = &self.session {
            if proxy.is_tun() {
                proxy.address()
            } else {
                format!("SOCKS5 {}", proxy.address())
            }
        } else {
            "Не подключено".into()
        };
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        let (active, state) = if self.always_on.enabled {
            (true, self.always_on.status.clone())
        } else {
            (active, state)
        };
        let enabled = !self.disconnecting
            && (active
                || (!self.busy
                    && self
                        .profiles
                        .first()
                        .is_some_and(|p| rtrust_engine::check_capabilities(p).is_ok())));
        container(
            row![
                column![
                    text("ПРОФИЛЬ ПО УМОЛЧАНИЮ").size(10),
                    text(name).size(17),
                    text(state).size(12)
                ]
                .spacing(3)
                .width(Length::Fill),
                button(
                    text(if self.disconnecting {
                        "Отключение…"
                    } else if self.connecting {
                        "Отменить"
                    } else if active {
                        "Отключить"
                    } else {
                        "Подключить"
                    })
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .align_x(iced::Alignment::Center)
                    .align_y(iced::Alignment::Center)
                    .font(iced::Font {
                        weight: iced::font::Weight::Semibold,
                        ..iced::Font::DEFAULT
                    })
                )
                .width(window_width * 0.4)
                .height(39)
                .style(move |theme, status| {
                    let mut style = if active {
                        buttons::danger(theme, status)
                    } else {
                        buttons::primary(theme, status)
                    };
                    style.border.radius = 7.0.into();
                    style
                })
                .on_press_maybe(enabled.then_some(Message::ToggleConnection))
            ]
            .spacing(12)
            .align_y(iced::Alignment::Center),
        )
        .padding(12)
        .style(container::rounded_box)
        .into()
    }
    fn view(&self) -> Element<'_, Message> {
        let mut nav = column![
            text("R-TrustTunnel").size(19),
            text("Ваше подключение").size(12)
        ]
        .spacing(8)
        .width(160);
        for (label, page) in [
            ("Профили", Page::Profiles),
            ("Добавить профиль", Page::Import),
            ("Синхронизация", Page::Portal),
            ("Настройки", Page::Settings),
            ("Диагностика", Page::Diagnostics),
        ] {
            let selected = self.page == page;
            nav = nav.push(
                button(label)
                    .width(Length::Fill)
                    .padding([11, 12])
                    .style(move |theme, status| {
                        let mut style = if selected {
                            buttons::primary(theme, status)
                        } else {
                            buttons::text(theme, status)
                        };
                        style.border.radius = 8.0.into();
                        style
                    })
                    .on_press(Message::Navigate(page)),
            );
        }
        let nav = nav
            .push(iced::widget::Space::new().height(Length::Fill))
            .push(
                button("Свернуть в трей")
                    .on_press(Message::CloseRequested)
                    .width(Length::Fill),
            )
            .push(
                button("Выход")
                    .on_press(Message::ExitRequested)
                    .width(Length::Fill),
            );
        let body: Element<'_, Message> = match self.page {
            Page::Import => {
                let mut content = column![
                    text("Добавить профиль").size(22),
                    text("TrustTunnel TOML/tt://, Hysteria 2 YAML/hy2://, AmneziaWG .conf, JSON. Импорт не подключает VPN."),
                    button("Выбрать файл…")
                        .on_press_maybe((!self.busy).then_some(Message::PickFile)),
                    text_editor(&self.input)
                        .placeholder("Вставьте tt://, hy2:// или конфигурацию")
                        .height(120)
                        .on_action(Message::Edit),
                    button("Проверить").on_press_maybe((!self.busy).then_some(Message::Parse))
                ]
                .spacing(10);
                if let Some(p) = &self.preview {
                    content = content
                        .push(summary(p))
                        .push(button("Добавить в профили").on_press(Message::Accept));
                    if let Some(current) = self.current() {
                        content = content
                            .push(
                                text(format!("Заменить выбранный профиль: {}", current.name))
                                    .size(12),
                            )
                            .push(
                                button(if self.confirm_replace {
                                    "Подтвердить замену"
                                } else {
                                    "Заменить выбранный…"
                                })
                                .on_press_maybe(
                                    self.can_change_profiles().then_some(Message::Replace),
                                ),
                            );
                    }
                }
                content.into()
            }
            Page::Portal => self.portal_view(),
            Page::Settings => {
                let mut toggle =
                    checkbox(self.autostart).label("Запускать приложение при входе в систему");
                if !self.busy && !self.startup_busy {
                    toggle = toggle.on_toggle(Message::StartupSet);
                }
                let mut connect = checkbox(self.saved_connection.auto_connect)
                    .label("Подключать профиль по умолчанию при запуске");
                if self.can_change_profiles() {
                    connect = connect.on_toggle(Message::AutoConnect);
                }
                let appearance = column![text("Настройки").size(22)].spacing(12);
                #[cfg(target_os = "macos")]
                let appearance = {
                    let mut appearance = appearance.push(
                        checkbox(self.glass_enabled)
                            .label("Стекло — прозрачный фон окна")
                            .on_toggle(Message::Glass),
                    );
                    if !glass::transparency_allowed() {
                        appearance = appearance.push(text("Прозрачность отключена в системных настройках универсального доступа.").size(13));
                    }
                    appearance
                };
                let mut panel = column![
                    appearance,
                    self.proxy_settings(),
                    toggle,
                    text("Приложение откроется в трее. При отсутствии трея окно будет свёрнуто.")
                        .size(13),
                    button("Проверить настройку ОС")
                        .on_press_maybe((!self.startup_busy).then_some(Message::StartupRefresh))
                ]
                .spacing(12);
                panel = panel.push(connect).push(text("Одна попытка после загрузки хранилища. При открытии файла или tt-ссылки автоподключение не выполняется. До подключения трафик не защищён VPN.").size(13));
                if self.startup_busy {
                    panel = panel.push(text("Проверка настройки автозапуска…"));
                }
                if let Some(error) = &self.startup_error {
                    panel = panel.push(text(error));
                }
                panel = panel.push(
                    button("Восстановить предыдущую копию хранилища").on_press_maybe(
                        (self.can_change_profiles() && !self.dirty).then_some(Message::ReadBackup),
                    ),
                );
                #[cfg(target_os = "windows")]
                {
                    panel = panel.push(self.updates_view());
                }
                #[cfg(any(target_os = "linux", target_os = "windows"))]
                {
                    panel = panel.push(self.always_view());
                }
                panel.into()
            }
            Page::Profiles => {
                let mut list = column![
                    text("Профили").size(22),
                    text("Выберите профиль для подключения или добавьте новый.").size(13),
                    button("+ Добавить профиль").on_press(Message::Navigate(Page::Import)),
                    row![
                        button("Открыть хранилище").on_press_maybe(
                            (!self.busy && !self.dirty && self.profiles.is_empty())
                                .then_some(Message::Load)
                        ),
                        button("Сохранить шифрованно").on_press_maybe(
                            (!self.busy
                                && (!self.profiles.is_empty()
                                    || self.revision.is_some()
                                    || self.dirty))
                                .then_some(Message::Save)
                        )
                    ]
                    .spacing(10)
                ]
                .spacing(10);
                if self.dirty {
                    list = list.push(text("Есть несохранённые изменения").size(12));
                }
                if self.profiles.is_empty() {
                    list=list.push(text("Пока нет профилей. Нажмите «Добавить профиль», чтобы открыть файл или вставить ссылку."));
                }
                for (i, p) in self.profiles.iter().enumerate() {
                    list = list.push(
                        button(text(format!(
                            "{}  {}{}",
                            if i == self.selected { "●" } else { "○" },
                            p.name,
                            if i == 0 {
                                " · по умолчанию"
                            } else {
                                ""
                            }
                        )))
                        .on_press(Message::Select(i))
                        .width(Length::Fill),
                    );
                }
                if let Some(p) = self.current() {
                    list = list
                        .push(
                            row![
                                text_input("Название профиля", &self.draft_name)
                                    .on_input(Message::DraftName),
                                button("Переименовать").on_press_maybe(
                                    self.can_change_profiles().then_some(Message::Rename)
                                ),
                                button(if self.confirm_delete {
                                    "Подтвердить удаление"
                                } else {
                                    "Удалить…"
                                })
                                .on_press_maybe(
                                    self.can_change_profiles().then_some(Message::Delete)
                                )
                            ]
                            .spacing(6),
                        )
                        .push(
                            button(if self.selected == 0 {
                                "Профиль по умолчанию"
                            } else {
                                "Использовать по умолчанию"
                            })
                            .on_press_maybe(
                                (self.selected != 0
                                    && !self.busy
                                    && !self.connecting
                                    && self.session.is_none())
                                .then_some(Message::MakeDefault),
                            ),
                        )
                        .push(summary(p))
                        .push(text("Экспорт").size(18))
                        .push(pick_list(
                            p.formats(),
                            p.formats().contains(&self.format).then_some(self.format),
                            Message::Format,
                        ));
                    if let Ok(export) = p.export(self.format) {
                        for loss in &export.losses {
                            list = list.push(text(format!("⚠ {loss}")).size(14));
                        }
                    }
                    list=list.push(checkbox(self.consent).label("Понимаю: экспорт содержит пароль; указанные настройки могут не войти в формат").on_toggle(Message::Consent)).push(button("Сохранить файл…").on_press_maybe((self.consent&&!self.busy).then_some(Message::Export)));
                }
                list.into()
            }
            Page::Diagnostics => {
                let mut content=column![text("Проверка транспорта").size(22),text("Настоящий HTTP-запрос через TLS/HTTP2 или QUIC/HTTP3 CONNECT. Проверяет обмен данными, но не включает TUN, маршруты, DNS или kill switch."),
                    text("Назначение внутри туннеля (HOST:PORT, обычный HTTP)"),text_input("example.com:80",&self.target).on_input(Message::Target)].spacing(10);
                if let Some(p) = self.current() {
                    content = content.push(summary(p));
                    let supported = rtrust_engine::check_capabilities(p).is_ok();
                    content = content.push(
                        button("Проверить TCP-туннель")
                            .on_press_maybe((supported && !self.busy).then_some(Message::Probe)),
                    );
                } else {
                    content = content.push(text("Сначала выберите профиль."));
                }
                if self.probe.is_some() {
                    content = content.push(button("Отмена").on_press(Message::Cancel));
                }
                content.into()
            }
        };
        container(
            column![
                iced::widget::responsive(|size| self.connection_bar(size.width + 24.0)).height(81),
                row![
                    nav,
                    scrollable(
                        container(if self.store_conflict.is_some() {
                            self.store_conflict_view()
                        } else {
                            body
                        })
                        .padding(8)
                    )
                    .width(Length::Fill)
                ]
                .spacing(18)
                .height(Length::Fill),
                container(text(&self.status).size(14))
                    .padding(10)
                    .width(Length::Fill)
                    .style(container::rounded_box)
            ]
            .spacing(12),
        )
        .padding(12)
        .into()
    }
}
fn summary(p: &Profile) -> Element<'_, Message> {
    let capability = match rtrust_engine::check_capabilities(p) {
        Ok(()) => format!("Транспорт {} поддерживается", p.transport_name()),
        Err(e) => e.to_string(),
    };
    container(
        column![
            text(&p.name).size(17),
            text(format!("Сервер: {}", p.endpoint.addresses.join(", "))),
            text(format!(
                "TLS hostname: {} · {}",
                p.endpoint.hostname,
                p.transport_name()
            )),
            text(if p.endpoint.certificate.is_empty() {
                "Системные CA · логин и пароль скрыты"
            } else {
                "Сертификат из профиля · логин и пароль скрыты"
            }),
            text(capability).size(12)
        ]
        .spacing(4),
    )
    .padding(12)
    .width(Length::Fill)
    .style(container::rounded_box)
    .into()
}

fn button<'a>(content: impl Into<Element<'a, Message>>) -> buttons::Button<'a, Message> {
    buttons::Button::new(content)
        .padding([7, 11])
        .style(|theme, status| {
            let mut style = buttons::secondary(theme, status);
            style.border.radius = 7.0.into();
            style
        })
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
        assert_eq!(app.connection_name, "second.example");
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
