//! Draft-only desktop CIDR intent editor. It never installs OS routes.
use super::*;
use iced::widget::column;
use rtrust_control::Selection;
use rtrust_profile::routing::{Context, Source};

#[derive(Default)]
pub(super) struct State {
    draft: Option<Draft>,
    preview: Option<Selection>,
    report: String,
}
#[derive(Clone, PartialEq)]
struct Base {
    include: String,
    exclude: String,
    lan: bool,
    managed: Option<rtrust_store::ManagedRoutes>,
    endpoints: Option<Vec<String>>,
    mode: Mode,
}
struct Draft {
    work: String,
    direct: String,
    lan: bool,
    target: String,
    base: Base,
}
#[derive(Clone)]
pub(super) enum Action {
    Open,
    Work(String),
    Direct(String),
    Lan(bool),
    Target(String),
    Preview,
    Apply,
    Close,
}
fn conflicts(selection: &Selection) -> String {
    let mut overlaps = Vec::new();
    for (include_index, include) in selection.include.iter().enumerate() {
        for (exclude_index, exclude) in selection.exclude.iter().enumerate() {
            if include.contains(&exclude.network()) || exclude.contains(&include.network()) {
                overlaps.push(format!("VPN #{} ({include}) пересекается с исключением #{} ({exclude}): исключение побеждает", include_index, exclude_index));
            }
        }
    }
    if overlaps.is_empty() {
        "Пересечений VPN-сетей и исключений нет.".into()
    } else {
        overlaps.join("\n")
    }
}
impl App {
    fn intent_base(&self) -> Base {
        Base {
            include: self.networks.clone(),
            exclude: self.exclude.clone(),
            lan: self.exclude_lan,
            managed: self.saved_connection.managed_routes.clone(),
            endpoints: self
                .current()
                .map(|profile| profile.endpoint.addresses.clone()),
            mode: self.mode,
        }
    }
    fn intent_can_apply(&self) -> bool {
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        if self.always_on.enabled {
            return false;
        }
        self.can_change_profiles()
            && self.mode == Mode::Tun
            && self.store_conflict.is_none()
            && self.saved_connection.managed_routes.is_none()
    }
    pub(super) fn intent_update(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::Open if !self.busy => {
                let (work, direct, lan) =
                    self.saved_connection.managed_routes.as_ref().map_or_else(
                        || {
                            (
                                self.networks.clone(),
                                self.exclude.clone(),
                                self.exclude_lan,
                            )
                        },
                        |managed| {
                            (
                                join(&managed.selection.include),
                                join(&managed.selection.exclude),
                                managed.selection.exclude_lan,
                            )
                        },
                    );
                self.intent.draft = Some(Draft {
                    work,
                    direct,
                    lan,
                    target: "198.18.0.1".into(),
                    base: self.intent_base(),
                });
                self.intent.preview = None;
                self.intent.report.clear();
            }
            Action::Close => self.intent = State::default(),
            Action::Work(_) | Action::Direct(_) | Action::Target(_) if !self.busy => {
                if let Some(draft) = &mut self.intent.draft {
                    match action {
                        Action::Work(value) if self.saved_connection.managed_routes.is_none() => {
                            draft.work = value
                        }
                        Action::Direct(value) if self.saved_connection.managed_routes.is_none() => {
                            draft.direct = value
                        }
                        Action::Target(value) => draft.target = value,
                        _ => return Task::none(),
                    }
                    self.intent.preview = None;
                    self.intent.report.clear();
                }
            }
            Action::Lan(value) if !self.busy && self.saved_connection.managed_routes.is_none() => {
                if let Some(draft) = &mut self.intent.draft {
                    draft.lan = value;
                    self.intent.preview = None;
                    self.intent.report.clear();
                }
            }
            Action::Preview if !self.busy => {
                let Some(draft) = &self.intent.draft else {
                    return Task::none();
                };
                self.intent.preview = None;
                if draft.base != self.intent_base() {
                    self.intent.report =
                        "Настройки или источник политики изменились. Откройте редактор заново."
                            .into();
                    return Task::none();
                }
                let preview = (|| {
                    let selection = Selection::parse(&draft.work, &draft.direct, draft.lan)?;
                    // Do not silently ignore a domain, port or unsupported family.
                    let address = draft.target.parse::<std::net::Ipv4Addr>()
                        .map_err(|_| "Для этого редактора нужен IPv4 без порта. Домены, IPv6 и per-app правила здесь не поддерживаются.".to_owned())?;
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
                    let endpoints = self.offline_route_endpoints();
                    let decision =
                        selection.explain(address.into(), endpoints.as_deref(), None, context)?;
                    let report = format!(
                        "{}\n{}\nПриоритет: системные адреса и адрес VPN-сервера; сети напрямую; LAN при включении; VPN-сети; остальные IPv4 напрямую. Порядок строк приоритет не меняет.\nLAN и системный маршрут не наблюдались; это прогноз для следующего подключения, не проверка трафика.",
                        describe_decision(&decision),
                        conflicts(&selection)
                    );
                    Ok::<_, String>((selection, report))
                })();
                match preview {
                    Ok((selection, report)) => {
                        self.intent.preview = Some(selection);
                        self.intent.report = report;
                    }
                    Err(error) => self.intent.report = format!("Предпросмотр отклонён: {error}"),
                }
            }
            Action::Apply if self.intent_can_apply() => {
                let (Some(draft), Some(selection)) = (&self.intent.draft, &self.intent.preview)
                else {
                    return Task::none();
                };
                if draft.base != self.intent_base() {
                    self.intent.preview = None;
                    self.intent.report =
                        "Настройки изменились после предпросмотра. Откройте редактор заново."
                            .into();
                    return Task::none();
                }
                if selection.validate().is_err() {
                    return Task::none();
                }
                self.networks = join(&selection.include);
                self.exclude = join(&selection.exclude);
                self.exclude_lan = selection.exclude_lan;
                self.intent = State::default();
                self.dirty = true;
                self.status =
                    "Локальные намерения приняты для следующего подключения. Сохранение…".into();
                return self.update(Message::Save);
            }
            _ => {}
        }
        Task::none()
    }
    /// Inputs are shared with Diagnostics offline explain; no resolver is called.
    pub(super) fn offline_route_endpoints(&self) -> Option<Vec<std::net::Ipv4Addr>> {
        if cfg!(target_os = "linux") {
            return Some(vec![]);
        }
        self.current()
            .and_then(|profile| {
                profile
                    .endpoint
                    .addresses
                    .iter()
                    .map(|address| {
                        address
                            .parse::<std::net::SocketAddr>()
                            .ok()
                            .map(|socket| socket.ip())
                    })
                    .collect::<Option<Vec<_>>>()
            })
            .map(|addresses| {
                addresses
                    .into_iter()
                    .filter_map(|ip| match ip {
                        std::net::IpAddr::V4(ip) => Some(ip),
                        _ => None,
                    })
                    .collect()
            })
    }
    pub(super) fn intent_view(&self) -> Element<'_, Message> {
        let Some(draft) = &self.intent.draft else {
            return button("Намерения и предпросмотр правил")
                .on_press_maybe((!self.busy).then_some(Message::Intent(Action::Open)))
                .into();
        };
        let local = self.saved_connection.managed_routes.is_none();
        let edit = !self.busy && local;
        let mut work = text_input("Работа через VPN: IPv4 CIDR", &draft.work);
        let mut direct = text_input("Сети напрямую: IPv4 CIDR", &draft.direct);
        let mut lan =
            checkbox(draft.lan).label("LAN напрямую — сети, обнаруженные при подключении");
        let mut target = text_input("Проверить IPv4 без порта", &draft.target);
        if edit {
            work = work.on_input(|value| Message::Intent(Action::Work(value)));
            direct = direct.on_input(|value| Message::Intent(Action::Direct(value)));
            lan = lan.on_toggle(|value| Message::Intent(Action::Lan(value)));
        }
        if !self.busy {
            target = target.on_input(|value| Message::Intent(Action::Target(value)));
        }
        let source = match &self.saved_connection.managed_routes {
            Some(managed) => format!("Источник: серверная группа «{}», роль admin/user не подтверждена; ревизия {}. Локальные намерения не меняют эту политику.", managed.group, managed.revision),
            None => "Источник: локальные настройки этого устройства. Встроенные поля профиля не изменяются. Правила доменов, портов, приложений и блокировки не поддерживаются этим IPv4-редактором.".into(),
        };
        column![text(source).size(12), text("Работа через VPN · сети IPv4").size(13), work, text("Сети напрямую · исключения").size(13), direct, lan, target,
            row![button("Предпросмотр без сети").on_press_maybe((!self.busy).then_some(Message::Intent(Action::Preview))),
                button("Принять для следующего подключения").on_press_maybe((self.intent_can_apply() && self.intent.preview.is_some()).then_some(Message::Intent(Action::Apply))),
                button("Закрыть").on_press(Message::Intent(Action::Close))].spacing(6),
            text(&self.intent.report).size(12),
            text("Во время подключения применение недоступно. Сначала отключите VPN; сохранение черновика не заменяет активную политику.").size(12)
        ].spacing(6).into()
    }
}
fn join(networks: &[rtrust_control::Ipv4Net]) -> String {
    networks
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}
#[cfg(test)]
mod tests {
    use super::*;
    fn configured() -> App {
        let mut app = crate::tests::app();
        app.mode = Mode::Tun;
        app.saved_connection.mode = rtrust_store::Mode::Tun;
        app.networks = "198.18.0.0/16".into();
        app.exclude = String::new();
        app.exclude_lan = false;
        app
    }
    fn open(app: &mut App) {
        let _ = app.intent_update(Action::Open);
    }
    fn preview(app: &mut App) {
        let _ = app.intent_update(Action::Preview);
    }
    #[test]
    fn overlapping_intents_show_fixed_direct_priority_without_mutating_any_policy() {
        let mut app = configured();
        let profiles = app.profiles.clone();
        let connection = app.saved_connection.clone();
        open(&mut app);
        let _ = app.intent_update(Action::Direct("198.18.0.0/24".into()));
        preview(&mut app);
        assert!(app.intent.report.contains("Прогноз: напрямую"));
        assert!(app.intent.report.contains("исключение побеждает"));
        assert!(app.intent.report.contains("Источник: локальные настройки"));
        assert!(app.intent.report.contains("Ревизия:"));
        assert!(app.intent.preview.is_some());
        assert!(app.exclude.is_empty());
        assert!(app.saved_connection == connection);
        assert_eq!(app.profiles, profiles);
        assert!(!app.dirty && !app.busy && !app.connecting);
    }
    #[test]
    fn managed_provenance_is_unknown_and_local_apply_cannot_override_it() {
        let mut app = configured();
        app.saved_connection.managed_routes = Some(rtrust_store::ManagedRoutes {
            group: "Team".into(),
            revision: "server:7".into(),
            selection: Selection::parse("0.0.0.0/0", "198.18.0.0/24", false).unwrap(),
        });
        let local = app.networks.clone();
        open(&mut app);
        let _ = app.intent_update(Action::Work("203.0.113.0/24".into()));
        preview(&mut app);
        assert_eq!(app.intent.draft.as_ref().unwrap().work, "0.0.0.0/0");
        assert!(app.intent.report.contains("роль admin/user не указана"));
        assert!(app.intent.report.contains("server:7"));
        let _ = app.intent_update(Action::Apply);
        assert_eq!(app.networks, local);
        assert!(app.saved_connection.managed_routes.is_some());
        assert!(!app.dirty && !app.busy);
    }
    #[test]
    fn unsupported_domain_port_ipv6_and_fully_excluded_selection_cannot_be_applied() {
        for input in ["work.example", "198.18.0.0/16:443", "fd00::/8"] {
            let mut app = configured();
            open(&mut app);
            let _ = app.intent_update(Action::Work(input.into()));
            preview(&mut app);
            assert!(app.intent.preview.is_none());
            let _ = app.intent_update(Action::Apply);
            assert_eq!(app.networks, "198.18.0.0/16");
            assert!(!app.dirty);
        }
        let mut app = configured();
        open(&mut app);
        let _ = app.intent_update(Action::Direct("198.18.0.0/16".into()));
        preview(&mut app);
        assert!(app.intent.preview.is_none());
        let _ = app.intent_update(Action::Apply);
        assert!(!app.dirty);
    }
    #[test]
    fn changing_the_draft_or_source_invalidates_reviewed_application() {
        let mut app = configured();
        open(&mut app);
        preview(&mut app);
        assert!(app.intent.preview.is_some());
        let _ = app.intent_update(Action::Lan(true));
        assert!(app.intent.preview.is_none());
        preview(&mut app);
        assert!(app.intent.report.contains("LAN-маршруты не наблюдались"));
        app.networks = "203.0.113.0/24".into();
        let _ = app.intent_update(Action::Apply);
        assert_eq!(app.networks, "203.0.113.0/24");
        assert!(!app.dirty && app.intent.preview.is_none());
    }
    #[test]
    fn selecting_another_endpoint_invalidates_an_existing_prediction() {
        let mut app = configured();
        open(&mut app);
        preview(&mut app);
        assert!(app.intent.preview.is_some());
        app.profiles[1].endpoint.addresses = vec!["198.18.0.1:443".into()];
        app.selected = 1;
        let _ = app.intent_update(Action::Apply);
        assert!(app.intent.preview.is_none());
        assert!(app.intent.report.contains("после предпросмотра"));
        assert!(!app.dirty && !app.busy);
    }
    #[test]
    fn apply_preserves_embedded_profile_data_and_only_updates_next_connection_settings() {
        let mut app = configured();
        app.profiles[0]
            .extensions
            .insert("future-policy".into(), true.into());
        let profiles = app.profiles.clone();
        open(&mut app);
        let _ = app.intent_update(Action::Direct("198.18.0.0/24".into()));
        preview(&mut app);
        let _ = app.intent_update(Action::Apply);
        assert_eq!(app.exclude, "198.18.0.0/24");
        assert!(app.dirty && app.busy); // Save was scheduled, no network started.
        assert!(app.session.is_none() && !app.connecting);
        assert_eq!(app.profiles, profiles);
        assert!(app.intent.draft.is_none());
    }
    #[test]
    fn active_connection_or_always_on_blocks_apply_without_discarding_preview() {
        let mut app = configured();
        open(&mut app);
        preview(&mut app);
        app.connecting = true;
        let _ = app.intent_update(Action::Apply);
        assert!(!app.dirty && app.intent.preview.is_some());
        app.connecting = false;
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        {
            app.always_on.enabled = true;
            let _ = app.intent_update(Action::Apply);
            assert!(!app.dirty && app.intent.preview.is_some());
        }
    }
}
