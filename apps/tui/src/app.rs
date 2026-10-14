//! Terminal state, key handling and rendering. No I/O happens here: actions
//! leave as [`Command`]s and come back as [`Outcome`]s, so it is testable.
use ratatui::{
    Frame,
    crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, List, ListItem, ListState, Paragraph, Wrap},
};
use rtrust_desktop::Controller;
use rtrust_store::{ConnectionSettings, Mode};
use zeroize::Zeroizing;

pub const LINK_SCHEMES: [&str; 3] = ["tt://", "hy2://", "hysteria2://"];

pub fn tr(ru: bool, russian: &'static str, english: &'static str) -> &'static str {
    if ru { russian } else { english }
}

/// Inline profile text (a link or a pasted config) rather than a file path.
pub fn is_inline(input: &str) -> bool {
    LINK_SCHEMES.iter().any(|s| input.starts_with(s)) || input.contains('\n')
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub hostname: String,
    pub protocol: String,
}
impl Row {
    fn of(name: &str, hostname: &str, protocol: &str) -> Self {
        Self {
            name: name.into(),
            hostname: hostname.into(),
            protocol: protocol.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub address: Option<std::net::SocketAddr>,
    pub uploaded: u64,
    pub downloaded: u64,
    pub active: usize,
}

/// What the screen shows; never holds credentials or sync baselines.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub revision: u64,
    pub profiles: Vec<Row>,
    pub mode: Mode,
    pub socks_port: u16,
    pub dns: Option<std::net::Ipv4Addr>,
    pub networks: Vec<rtrust_control::Ipv4Net>,
    pub exclude: Vec<rtrust_control::Ipv4Net>,
    pub exclude_lan: bool,
    pub auto_connect: bool,
    pub fallback_profiles: Vec<String>,
    pub managed_group: Option<String>,
    pub connected: Option<usize>,
    pub session: bool,
    pub verified: bool,
    pub note: String,
    pub summary: Option<String>,
    /// Lifecycle failure measured for the current session epoch only.
    pub health: Option<String>,
    pub traffic: Option<Traffic>,
    pub backup: Option<u8>,
    pub owner_warning: Option<&'static str>,
}
impl Snapshot {
    pub fn capture(c: &Controller, ru: bool, health: Option<String>) -> Self {
        let session = c.session.as_ref();
        let s = &c.vault.connection;
        Self {
            revision: c.revision,
            profiles: c
                .vault
                .profiles
                .iter()
                .map(|p| Row::of(&p.name, &p.endpoint.hostname, p.transport_name()))
                .collect(),
            mode: s.mode,
            socks_port: s.socks_port,
            dns: Some(s.dns),
            networks: s.networks.clone(),
            exclude: s.exclude.clone(),
            exclude_lan: s.exclude_lan,
            auto_connect: s.auto_connect,
            fallback_profiles: s.fallback_profiles.clone(),
            managed_group: s.managed_routes.as_ref().map(|m| m.group.clone()),
            connected: session.and(c.connected_profile),
            session: session.is_some(),
            verified: session.is_some_and(|s| s.observations().verified()),
            note: c.connected_note().into(),
            summary: session.map(|s| s.status_summary(ru)),
            health: session.and(health),
            traffic: session.and_then(|s| s.proxy()).map(|p| {
                let stats = p.stats();
                Traffic {
                    address: Some(p.address()),
                    uploaded: stats.uploaded,
                    downloaded: stats.downloaded,
                    active: stats.active,
                }
            }),
            backup: session.and_then(|s| s.active_profile()).filter(|i| *i > 0),
            owner_warning: session.and_then(|s| s.owner_warning(ru)),
        }
    }
    /// Settings to submit: the controller keeps sync state and server policy.
    fn settings(&self) -> ConnectionSettings {
        ConnectionSettings {
            mode: self.mode,
            socks_port: self.socks_port,
            dns: self.dns.unwrap_or(ConnectionSettings::default().dns),
            networks: self.networks.clone(),
            exclude: self.exclude.clone(),
            exclude_lan: self.exclude_lan,
            auto_connect: self.auto_connect,
            fallback_profiles: self.fallback_profiles.clone(),
            ..ConnectionSettings::default()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Import,
    Networks,
    Exclude,
    Port,
    Dns,
}

pub enum Modal {
    None,
    Input {
        field: Field,
        text: Zeroizing<String>,
        /// Switch to TUN once the networks are accepted.
        then_tun: bool,
    },
    ConfirmImport {
        revision: u64,
        row: Row,
    },
    ConfirmDelete {
        revision: u64,
        index: usize,
        name: String,
    },
    ConfirmQuit,
}

pub enum Command {
    Connect {
        revision: u64,
        index: usize,
    },
    Disconnect,
    Preview(Zeroizing<String>),
    Import {
        revision: u64,
    },
    Discard,
    Edit {
        revision: u64,
        action: &'static str,
        index: usize,
    },
    Settings {
        revision: u64,
        settings: Box<ConnectionSettings>,
    },
    Recover,
    /// `force` exits even when disconnecting fails (signals, lost terminal).
    Quit {
        force: bool,
    },
}

pub enum Outcome {
    Done(String),
    Failed(String),
    Previewed { revision: u64, row: Row },
    Exit(Option<String>),
}

pub struct App {
    pub ru: bool,
    pub snap: Snapshot,
    pub list: ListState,
    pub modal: Modal,
    pub busy: Option<&'static str>,
    /// (is error, text)
    pub message: Option<(bool, String)>,
    /// Quit requested while busy; `Some(force)`.
    quit_after: Option<bool>,
    pub exit: bool,
    frame: usize,
}

impl App {
    pub fn new(ru: bool) -> Self {
        Self {
            ru,
            snap: Snapshot::default(),
            list: ListState::default().with_selected(Some(0)),
            modal: Modal::None,
            busy: None,
            message: None,
            quit_after: None,
            exit: false,
            frame: 0,
        }
    }
    fn t(&self, russian: &'static str, english: &'static str) -> &'static str {
        tr(self.ru, russian, english)
    }
    pub fn update(&mut self, snap: Snapshot) {
        let len = snap.profiles.len();
        self.snap = snap;
        let selected = self.list.selected().unwrap_or(0).min(len.saturating_sub(1));
        self.list.select((len > 0).then_some(selected));
    }
    pub fn tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
    }
    fn selected(&self) -> Option<usize> {
        self.list
            .selected()
            .filter(|i| *i < self.snap.profiles.len())
    }
    fn info(&mut self, text: impl Into<String>) {
        self.message = Some((false, text.into()));
    }
    fn error(&mut self, text: impl Into<String>) {
        self.message = Some((true, text.into()));
    }
    pub fn start(&mut self, command: Command) -> Option<Command> {
        if self.busy.is_some() {
            self.info(self.t(
                "Подождите завершения текущего действия",
                "Wait for the current action to finish",
            ));
            return None;
        }
        self.busy = Some(match &command {
            Command::Connect { .. } => self.t("Подключение…", "Connecting…"),
            Command::Disconnect => self.t("Отключение…", "Disconnecting…"),
            Command::Preview(_) => self.t("Чтение профиля…", "Reading profile…"),
            Command::Import { .. } => self.t("Сохранение профиля…", "Saving profile…"),
            Command::Discard => self.t("Отмена импорта…", "Discarding import…"),
            Command::Edit { .. } | Command::Settings { .. } => self.t("Сохранение…", "Saving…"),
            Command::Recover => self.t("Снятие блокировки…", "Releasing the block…"),
            Command::Quit { .. } => self.t("Отключение и выход…", "Disconnecting and quitting…"),
        });
        self.message = None;
        Some(command)
    }
    pub fn finish(&mut self, outcome: Outcome) -> Option<Command> {
        self.busy = None;
        match outcome {
            Outcome::Done(text) if text.is_empty() => self.message = None,
            Outcome::Done(text) => self.info(text),
            Outcome::Failed(error) => self.error(error),
            Outcome::Previewed { revision, row } => {
                self.modal = Modal::ConfirmImport { revision, row }
            }
            Outcome::Exit(_) => self.exit = true,
        }
        if self.exit {
            return None;
        }
        let force = self.quit_after.take()?;
        self.modal = Modal::None;
        self.start(Command::Quit { force })
    }
    /// SIGTERM/SIGHUP or a closed terminal: disconnect and leave regardless.
    pub fn signal(&mut self) -> Option<Command> {
        if self.busy.is_some() {
            self.quit_after = Some(true);
            return None;
        }
        self.start(Command::Quit { force: true })
    }
    fn request_quit(&mut self) -> Option<Command> {
        if self.busy.is_some() {
            self.quit_after = Some(self.quit_after.unwrap_or(false));
            self.info(self.t(
                "Выход после завершения текущего действия",
                "Quitting after the current action",
            ));
            return None;
        }
        if self.snap.session {
            self.modal = Modal::ConfirmQuit;
            return None;
        }
        self.start(Command::Quit { force: false })
    }
    pub fn paste(&mut self, pasted: &str) {
        if let Modal::Input { text, .. } = &mut self.modal {
            let pasted = pasted.replace('\r', "\n");
            if text.len() + pasted.len() > rtrust_profile::MAX_INPUT {
                self.message = Some((
                    true,
                    tr(self.ru, "Слишком большой ввод", "Input is too large").into(),
                ));
                return;
            }
            text.push_str(&pasted);
        }
    }
    pub fn key(&mut self, key: KeyEvent) -> Option<Command> {
        if key.kind == KeyEventKind::Release {
            return None;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && key.code == KeyCode::Char('c') {
            return if matches!(self.modal, Modal::ConfirmQuit) {
                self.modal = Modal::None;
                self.start(Command::Quit { force: false })
            } else {
                self.request_quit()
            };
        }
        match std::mem::replace(&mut self.modal, Modal::None) {
            Modal::Input {
                field,
                mut text,
                then_tun,
            } => {
                match key.code {
                    KeyCode::Esc => return None,
                    KeyCode::Enter => return self.submit(field, &text, then_tun),
                    KeyCode::Backspace => {
                        text.pop();
                    }
                    KeyCode::Char('u') if ctrl => text.clear(),
                    KeyCode::Char(ch)
                        if !ctrl && text.len() + ch.len_utf8() <= rtrust_profile::MAX_INPUT =>
                    {
                        text.push(ch)
                    }
                    _ => {}
                }
                self.modal = Modal::Input {
                    field,
                    text,
                    then_tun,
                };
                None
            }
            Modal::ConfirmImport { revision, row } => match key.code {
                KeyCode::Char('y' | 'Y' | 'д' | 'Д') | KeyCode::Enter => {
                    self.start(Command::Import { revision })
                }
                KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc => {
                    self.start(Command::Discard)
                }
                _ => {
                    self.modal = Modal::ConfirmImport { revision, row };
                    None
                }
            },
            Modal::ConfirmDelete {
                revision,
                index,
                name,
            } => match key.code {
                KeyCode::Char('y' | 'Y' | 'д' | 'Д') => self.start(Command::Edit {
                    revision,
                    action: "delete",
                    index,
                }),
                KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc | KeyCode::Enter => None,
                _ => {
                    self.modal = Modal::ConfirmDelete {
                        revision,
                        index,
                        name,
                    };
                    None
                }
            },
            Modal::ConfirmQuit => match key.code {
                KeyCode::Char('y' | 'Y' | 'д' | 'Д') => {
                    self.start(Command::Quit { force: false })
                }
                KeyCode::Char('n' | 'N' | 'н' | 'Н') | KeyCode::Esc | KeyCode::Enter => None,
                _ => {
                    self.modal = Modal::ConfirmQuit;
                    None
                }
            },
            Modal::None => self.normal(key),
        }
    }
    fn input(&mut self, field: Field, text: String, then_tun: bool) {
        let mut buffer = Zeroizing::new(String::with_capacity(text.len().max(64)));
        buffer.push_str(&text);
        self.modal = Modal::Input {
            field,
            text: buffer,
            then_tun,
        };
    }
    fn save(&mut self, settings: ConnectionSettings) -> Option<Command> {
        let revision = self.snap.revision;
        self.start(Command::Settings {
            revision,
            settings: Box::new(settings),
        })
    }
    fn normal(&mut self, key: KeyEvent) -> Option<Command> {
        let len = self.snap.profiles.len();
        let revision = self.snap.revision;
        let selected = self.selected();
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.list.select(selected.map(|i| i.saturating_sub(1)));
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.list
                    .select(selected.map(|i| (i + 1).min(len.saturating_sub(1))));
                None
            }
            KeyCode::Home => {
                self.list.select((len > 0).then_some(0));
                None
            }
            KeyCode::End => {
                self.list.select(len.checked_sub(1));
                None
            }
            KeyCode::Char('q') | KeyCode::Esc => self.request_quit(),
            KeyCode::Enter | KeyCode::Char('c') => {
                if self.snap.session {
                    self.info(self.t("Сначала отключитесь (d)", "Disconnect first (d)"));
                    return None;
                }
                let Some(index) = selected else {
                    self.info(self.t("Импортируйте профиль (i)", "Import a profile first (i)"));
                    return None;
                };
                self.start(Command::Connect { revision, index })
            }
            KeyCode::Char('d') if self.snap.session => self.start(Command::Disconnect),
            KeyCode::Char('i') => {
                self.input(Field::Import, String::new(), false);
                None
            }
            KeyCode::Char('s') => match selected {
                Some(index) if index > 0 => {
                    let command = self.start(Command::Edit {
                        revision,
                        action: "default",
                        index,
                    });
                    if command.is_some() {
                        self.list.select(Some(0));
                    }
                    command
                }
                _ => None,
            },
            KeyCode::Char('x') | KeyCode::Delete => {
                if let Some(index) = selected {
                    self.modal = Modal::ConfirmDelete {
                        revision,
                        index,
                        name: self.snap.profiles[index].name.clone(),
                    };
                }
                None
            }
            KeyCode::Char('m') => {
                let mut next = self.snap.settings();
                next.mode = match next.mode {
                    Mode::Socks => Mode::Tun,
                    Mode::Tun => Mode::Full,
                    Mode::Full => Mode::Socks,
                };
                if next.mode == Mode::Tun
                    && next.networks.is_empty()
                    && self.snap.managed_group.is_none()
                {
                    self.input(Field::Networks, String::new(), true);
                    return None;
                }
                self.save(next)
            }
            KeyCode::Char('n') => {
                let text = join(&self.snap.networks);
                self.input(Field::Networks, text, false);
                None
            }
            KeyCode::Char('e') => {
                let text = join(&self.snap.exclude);
                self.input(Field::Exclude, text, false);
                None
            }
            KeyCode::Char('p') => {
                self.input(Field::Port, self.snap.socks_port.to_string(), false);
                None
            }
            KeyCode::Char('o') => {
                let text = self.snap.dns.map(|d| d.to_string()).unwrap_or_default();
                self.input(Field::Dns, text, false);
                None
            }
            KeyCode::Char('l') => {
                let mut next = self.snap.settings();
                next.exclude_lan = !next.exclude_lan;
                self.save(next)
            }
            KeyCode::Char('a') => {
                let mut next = self.snap.settings();
                next.auto_connect = !next.auto_connect;
                self.save(next)
            }
            KeyCode::Char('R') => {
                if self.snap.session {
                    self.info(self.t(
                        "Это приложение держит подключение: отключите его (d)",
                        "This app holds the connection: disconnect it (d)",
                    ));
                    return None;
                }
                self.start(Command::Recover)
            }
            _ => None,
        }
    }
    fn submit(&mut self, field: Field, text: &str, then_tun: bool) -> Option<Command> {
        let text = text.trim();
        let mut next = self.snap.settings();
        let result = match field {
            Field::Import => {
                if text.is_empty() {
                    return None;
                }
                return self.start(Command::Preview(Zeroizing::new(text.to_owned())));
            }
            Field::Networks => parse_networks(text).map(|n| next.networks = n),
            Field::Exclude => parse_networks(text).map(|n| next.exclude = n),
            Field::Port => match text.parse::<u16>() {
                Ok(port) if port > 0 => {
                    next.socks_port = port;
                    Ok(())
                }
                _ => Err(self
                    .t("Порт: число 1–65535", "Port: a number 1–65535")
                    .into()),
            },
            Field::Dns => text
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| {
                    self.t("DNS: IPv4-адрес", "DNS: an IPv4 address")
                        .to_string()
                })
                .and_then(|dns| rtrust_control::validate_dns(dns).map(|()| next.dns = dns)),
        };
        if then_tun {
            next.mode = Mode::Tun;
        }
        // Explain a rejected selection here; the store only reports "invalid".
        let result = result.and_then(|()| {
            if (next.mode == Mode::Tun && self.snap.managed_group.is_none())
                || !next.networks.is_empty()
                || !next.exclude.is_empty()
            {
                next.selection().validate()
            } else {
                Ok(())
            }
        });
        match result {
            Ok(()) => self.save(next),
            Err(error) => {
                self.error(error);
                let mut buffer = Zeroizing::new(String::new());
                buffer.push_str(text);
                self.modal = Modal::Input {
                    field,
                    text: buffer,
                    then_tun,
                };
                None
            }
        }
    }

    pub fn draw(&mut self, frame: &mut Frame) {
        let [header, body, footer, help] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(4),
            Constraint::Length(1),
        ])
        .areas(frame.area());
        frame.render_widget(self.header(), header);
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(body);
        let items = self
            .snap
            .profiles
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let marker = if self.snap.connected == Some(i) {
                    Span::styled("● ", Style::new().fg(Color::Green))
                } else if i == 0 {
                    Span::styled("★ ", Style::new().fg(Color::Yellow))
                } else {
                    Span::raw("  ")
                };
                ListItem::new(Line::from(vec![
                    marker,
                    Span::styled(p.name.clone(), Modifier::BOLD),
                    Span::raw("  "),
                    Span::styled(p.hostname.clone(), Style::new().fg(Color::Gray)),
                    Span::styled(
                        format!("  [{}]", p.protocol),
                        Style::new().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect::<Vec<_>>();
        let list = if items.is_empty() {
            List::new([ListItem::new(self.t(
                "Профилей нет — нажмите i, чтобы импортировать",
                "No profiles — press i to import",
            ))])
        } else {
            List::new(items)
                .highlight_style(Style::new().add_modifier(Modifier::REVERSED))
                .highlight_symbol("› ")
        }
        .block(Block::bordered().title(self.t(" Профили ", " Profiles ")));
        frame.render_stateful_widget(list, left, &mut self.list);
        frame.render_widget(
            Paragraph::new(self.details())
                .wrap(Wrap { trim: true })
                .block(Block::bordered().title(self.t(" Подключение ", " Connection "))),
            right,
        );
        frame.render_widget(
            Paragraph::new(self.footer())
                .wrap(Wrap { trim: false })
                .block(Block::bordered()),
            footer,
        );
        frame.render_widget(
            Paragraph::new(self.help()).style(Style::new().fg(Color::DarkGray)),
            help,
        );
    }
    fn header(&self) -> Paragraph<'static> {
        let line = if let Some(busy) = self.busy {
            const SPIN: [&str; 4] = ["◐", "◓", "◑", "◒"];
            Line::from(format!("{} {busy}", SPIN[self.frame % SPIN.len()])).fg(Color::Cyan)
        } else if self.snap.session {
            let name = self
                .snap
                .connected
                .and_then(|i| self.snap.profiles.get(i))
                .map_or(String::new(), |p| format!(" · {}", p.name));
            let (text, color) = if self.snap.health.is_some() {
                (
                    self.t("● Подключение нарушено", "● Connection failing"),
                    Color::Red,
                )
            } else if self.snap.verified {
                (
                    self.t("● Подключено, проверено", "● Connected, verified"),
                    Color::Green,
                )
            } else {
                (self.t("● Подключено", "● Connected"), Color::Green)
            };
            Line::from(format!("{text}{name}")).fg(color).bold()
        } else {
            Line::from(self.t("○ Отключено", "○ Disconnected")).fg(Color::Gray)
        };
        Paragraph::new(line).block(Block::bordered().title(" R-TrustTunnel "))
    }
    fn details(&self) -> Vec<Line<'static>> {
        let s = &self.snap;
        let (yes, no) = (self.t("да", "yes"), self.t("нет", "no"));
        let none = "—".to_string();
        let field = |label: &'static str, value: String| {
            Line::from(vec![
                Span::styled(format!("{label}: "), Style::new().fg(Color::DarkGray)),
                Span::raw(value),
            ])
        };
        let mut lines = vec![field(
            self.t("Режим", "Mode"),
            mode_label(s.mode, self.ru).into(),
        )];
        match s.mode {
            Mode::Socks => lines.push(field("SOCKS5/HTTP", format!("127.0.0.1:{}", s.socks_port))),
            Mode::Tun => {
                if let Some(group) = &s.managed_group {
                    lines.push(field(
                        self.t("Правила сервера", "Server policy"),
                        group.clone(),
                    ));
                } else {
                    let nets = join(&s.networks);
                    lines.push(field(
                        self.t("Сети", "Networks"),
                        if nets.is_empty() { none.clone() } else { nets },
                    ));
                }
                let excl = join(&s.exclude);
                lines.push(field(
                    self.t("Исключения", "Excluded"),
                    if excl.is_empty() { none.clone() } else { excl },
                ));
                lines.push(field(
                    self.t("Без локальной сети", "Exclude LAN"),
                    (if s.exclude_lan { yes } else { no }).into(),
                ));
            }
            Mode::Full => {}
        }
        if s.mode != Mode::Socks {
            lines.push(field("DNS", s.dns.map_or(none.clone(), |d| d.to_string())));
        }
        lines.push(field(
            self.t("Автоподключение", "Auto-connect"),
            (if s.auto_connect { yes } else { no }).into(),
        ));
        if !s.session {
            return lines;
        }
        lines.push(Line::default());
        if let Some(t) = s.traffic {
            if let Some(address) = t.address {
                lines.push(field(self.t("Прокси", "Proxy"), address.to_string()));
            }
            lines.push(field(
                self.t("Трафик", "Traffic"),
                format!(
                    "↑ {} ↓ {} · {} {}",
                    bytes(t.uploaded),
                    bytes(t.downloaded),
                    t.active,
                    self.t("соед.", "conn.")
                ),
            ));
        }
        if let Some(summary) = &s.summary {
            lines.push(Line::from(summary.clone()).fg(Color::Gray));
        }
        if s.backup.is_some() {
            lines.push(
                Line::from(self.t("Используется резервный профиль", "Using a backup profile"))
                    .fg(Color::Yellow),
            );
        }
        if !s.note.is_empty() {
            lines.push(Line::from(s.note.clone()).fg(Color::Gray));
        }
        if let Some(health) = &s.health {
            lines.push(Line::from(health.clone()).fg(Color::Red));
        }
        if let Some(warning) = s.owner_warning {
            lines.push(Line::from(warning).fg(Color::Yellow));
        }
        lines
    }
    fn footer(&self) -> Vec<Line<'static>> {
        let message = self.message.as_ref().map(|(error, text)| {
            Line::from(text.clone()).fg(if *error { Color::Red } else { Color::Green })
        });
        let prompt = match &self.modal {
            Modal::None => None,
            Modal::Input { field, text, .. } => {
                let label = match field {
                    Field::Import => self.t(
                        "Ссылка tt:// / hy2:// или путь к файлу",
                        "tt:// / hy2:// link or file path",
                    ),
                    Field::Networks => self.t(
                        "IPv4-сети через туннель (CIDR, через запятую)",
                        "IPv4 networks via the tunnel (CIDR, comma-separated)",
                    ),
                    Field::Exclude => self.t(
                        "Сети-исключения (CIDR, через запятую)",
                        "Excluded networks (CIDR, comma-separated)",
                    ),
                    Field::Port => self.t("Порт SOCKS5/HTTP", "SOCKS5/HTTP port"),
                    Field::Dns => self.t("IPv4 DNS через туннель", "IPv4 DNS via the tunnel"),
                };
                let shown = if *field == Field::Import {
                    masked(text)
                } else {
                    text.to_string()
                };
                Some(Line::from(vec![
                    Span::styled(format!("{label}: "), Style::new().fg(Color::Cyan)),
                    Span::raw(shown),
                    Span::styled("█", Style::new().fg(Color::Cyan)),
                ]))
            }
            Modal::ConfirmImport { row, .. } => Some(
                Line::from(format!(
                    "{} {} · {} [{}]? (y/n)",
                    self.t("Добавить профиль", "Add profile"),
                    row.name,
                    row.hostname,
                    row.protocol
                ))
                .fg(Color::Yellow),
            ),
            Modal::ConfirmDelete { name, .. } => Some(
                Line::from(format!(
                    "{} {name}? (y/n)",
                    self.t("Удалить профиль", "Delete profile")
                ))
                .fg(Color::Yellow),
            ),
            Modal::ConfirmQuit => Some(
                Line::from(self.t(
                    "Отключить VPN и выйти? (y/n)",
                    "Disconnect the VPN and quit? (y/n)",
                ))
                .fg(Color::Yellow),
            ),
        };
        prompt.into_iter().chain(message).collect()
    }
    fn help(&self) -> &'static str {
        match self.modal {
            Modal::Input { .. } => self.t(
                "Enter — принять · Esc — отмена · Ctrl+U — очистить · вставка поддерживается",
                "Enter accept · Esc cancel · Ctrl+U clear · paste supported",
            ),
            Modal::None if self.snap.session => self.t(
                "↑↓ выбор · d отключить · q выход",
                "↑↓ select · d disconnect · q quit",
            ),
            Modal::None => self.t(
                "↑↓ выбор · Enter подключить · i импорт · s по умолч. · x удалить · m режим · n/e сети · l LAN · p порт · o DNS · a авто · R сброс · q выход",
                "↑↓ select · Enter connect · i import · s default · x delete · m mode · n/e networks · l LAN · p port · o DNS · a auto · R recover · q quit",
            ),
            _ => self.t("y — да · n — нет", "y yes · n no"),
        }
    }
}

pub fn mode_label(mode: Mode, ru: bool) -> &'static str {
    match mode {
        Mode::Socks => tr(
            ru,
            "SOCKS5/HTTP-прокси для приложений",
            "SOCKS5/HTTP proxy for apps",
        ),
        Mode::Tun => tr(
            ru,
            "TUN · выбранные IPv4-сети",
            "TUN · selected IPv4 networks",
        ),
        Mode::Full => tr(
            ru,
            "Весь компьютер · IPv4/IPv6 + DNS",
            "Whole device · IPv4/IPv6 + DNS",
        ),
    }
}
fn join(nets: &[rtrust_control::Ipv4Net]) -> String {
    nets.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
fn parse_networks(text: &str) -> Result<Vec<rtrust_control::Ipv4Net>, String> {
    text.split([',', ' ', ';', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| format!("{s}: IPv4 CIDR, 198.18.0.0/24"))
        })
        .collect()
}
/// Links and pasted configs carry credentials; only a file path is shown.
fn masked(text: &str) -> String {
    if !is_inline(text) {
        return text.to_owned();
    }
    let scheme = LINK_SCHEMES
        .iter()
        .find(|s| text.starts_with(*s))
        .copied()
        .unwrap_or("");
    let rest = text.chars().count() - scheme.chars().count();
    format!(
        "{scheme}{} ({} chars)",
        "•".repeat(rest.min(24)),
        text.chars().count()
    )
}
fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{Terminal, backend::TestBackend};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 24)).unwrap();
        terminal.draw(|f| app.draw(f)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect()
    }
    fn app_with_profiles() -> App {
        let mut app = App::new(false);
        app.update(Snapshot {
            revision: 3,
            profiles: vec![
                Row::of("home", "vpn.example", "h2"),
                Row::of("work", "edge.example", "h3"),
            ],
            socks_port: 1080,
            ..Default::default()
        });
        app
    }

    #[test]
    fn a_pasted_link_is_masked_and_previewed_with_the_current_revision() {
        let mut app = app_with_profiles();
        assert!(app.key(key(KeyCode::Char('i'))).is_none());
        app.paste("tt://regression-secret-value@vpn.example");
        let shown = screen(&mut app);
        assert!(!shown.contains("regression-secret-value"));
        assert!(shown.contains("tt://"));
        let Some(Command::Preview(input)) = app.key(key(KeyCode::Enter)) else {
            panic!("expected preview")
        };
        assert!(input.starts_with("tt://regression"));
        assert!(app.busy.is_some());
        assert!(
            app.finish(Outcome::Previewed {
                revision: 3,
                row: Row::of("n", "h", "h2")
            })
            .is_none()
        );
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Some(Command::Import { revision: 3 })
        ));
    }

    #[test]
    fn pasted_config_text_is_masked_but_a_file_path_is_shown() {
        assert!(!masked("[endpoint]\npassword = \"p\"").contains("password"));
        assert_eq!(masked("~/profiles/home.toml"), "~/profiles/home.toml");
    }

    #[test]
    fn declining_an_import_discards_the_pending_profile() {
        let mut app = app_with_profiles();
        app.finish(Outcome::Previewed {
            revision: 3,
            row: Row::of("n", "h", "h2"),
        });
        assert!(matches!(
            app.key(key(KeyCode::Char('n'))),
            Some(Command::Discard)
        ));
    }

    #[test]
    fn connect_targets_the_selected_profile_and_busy_blocks_a_second_action() {
        let mut app = app_with_profiles();
        app.key(key(KeyCode::Down));
        assert!(matches!(
            app.key(key(KeyCode::Enter)),
            Some(Command::Connect {
                revision: 3,
                index: 1
            })
        ));
        assert!(app.key(key(KeyCode::Char('i'))).is_none());
        assert!(
            app.key(key(KeyCode::Enter)).is_none(),
            "input is open, empty submit is ignored"
        );
        app.modal = Modal::None;
        assert!(app.key(key(KeyCode::Char('l'))).is_none(), "busy");
    }

    #[test]
    fn quitting_while_connected_asks_and_a_signal_waits_for_the_running_action() {
        let mut app = app_with_profiles();
        app.snap.session = true;
        assert!(app.key(key(KeyCode::Char('q'))).is_none());
        assert!(matches!(app.modal, Modal::ConfirmQuit));
        assert!(matches!(
            app.key(key(KeyCode::Char('y'))),
            Some(Command::Quit { force: false })
        ));
        assert!(app.signal().is_none(), "disconnect still running");
        assert!(matches!(
            app.finish(Outcome::Failed("service unreachable".into())),
            Some(Command::Quit { force: true })
        ));
        assert!(app.finish(Outcome::Exit(None)).is_none());
        assert!(app.exit);
    }

    #[test]
    fn switching_to_tun_without_networks_asks_for_them_and_rejects_bad_input_in_place() {
        let mut app = app_with_profiles();
        assert!(app.key(key(KeyCode::Char('m'))).is_none());
        assert!(matches!(
            app.modal,
            Modal::Input {
                field: Field::Networks,
                then_tun: true,
                ..
            }
        ));
        app.paste("10.0.0.1/8");
        assert!(app.key(key(KeyCode::Enter)).is_none());
        assert!(matches!(app.message, Some((true, _))));
        assert!(matches!(
            app.modal,
            Modal::Input {
                field: Field::Networks,
                ..
            }
        ));
        app.key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        app.paste("10.0.0.0/8");
        let Some(Command::Settings {
            revision: 3,
            settings,
        }) = app.key(key(KeyCode::Enter))
        else {
            panic!("expected settings")
        };
        assert!(settings.mode == Mode::Tun);
        assert_eq!(settings.networks, vec!["10.0.0.0/8".parse().unwrap()]);
    }

    #[test]
    fn recover_is_refused_while_this_app_holds_the_session() {
        let mut app = app_with_profiles();
        app.snap.session = true;
        assert!(app.key(key(KeyCode::Char('R'))).is_none());
        app.snap.session = false;
        assert!(matches!(
            app.key(key(KeyCode::Char('R'))),
            Some(Command::Recover)
        ));
    }

    #[test]
    fn the_screen_never_shows_profile_credentials() {
        let mut controller = Controller::smoke();
        let mut profile =
            rtrust_profile::Profile::import(include_str!("../../../examples/demo.endpoint.toml"))
                .unwrap();
        profile.endpoint.password = rtrust_profile::Secret::new("regression-profile-password");
        controller.vault.profiles.push(profile);
        let mut app = App::new(true);
        app.update(Snapshot::capture(&controller, true, Some("stale".into())));
        assert!(
            app.snap.health.is_none(),
            "health without a session is dropped"
        );
        let shown = screen(&mut app);
        assert!(!shown.contains("regression-profile-password"));
        assert!(shown.contains("Профили"));
    }
}
