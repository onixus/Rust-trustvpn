use super::*;
use iced::widget::column;
use rtrust_portal::{Client, RemoteProfile};
use rtrust_store::TrackedProfile;
#[derive(Default)]
pub(super) struct State {
    due: Option<std::time::Instant>,
    pending: Vec<(RemoteProfile, Profile)>,
    status: String,
}
#[derive(Clone)]
pub(super) enum Action {
    Enable(bool),
    Poll,
    Received(Result<Batch, String>),
    KeepLocal,
    KeepBoth,
}
#[derive(Clone)]
pub(super) struct Batch {
    origin: String,
    client: Client,
    changed: Vec<(RemoteProfile, Profile)>,
    available: Vec<String>,
    /// Err keeps the previous policy; profile updates still apply.
    routing: Result<Option<rtrust_store::ManagedRoutes>, String>,
}
/// The device group's TUN route policy, checked before it can replace the
/// local selection.
fn managed(policy: rtrust_portal::RoutingPolicy) -> Result<rtrust_store::ManagedRoutes, String> {
    let routes = rtrust_store::ManagedRoutes {
        group: policy.group,
        revision: policy.revision,
        selection: rtrust_control::Selection {
            include: policy.include,
            exclude: policy.exclude,
            exclude_lan: policy.exclude_lan,
        },
    };
    routes
        .selection
        .validate()
        .map_err(|e| format!("Сервер прислал недопустимые маршруты TUN: {e}"))?;
    routes
        .validate()
        .map_err(|_| "Сервер прислал недопустимую группу маршрутов".to_owned())?;
    Ok(routes)
}
fn track(tracked: &mut Vec<TrackedProfile>, meta: &RemoteProfile, profile: Profile) {
    let item = TrackedProfile {
        id: meta.id.clone(),
        revision: meta.revision.clone(),
        baseline: profile,
    };
    if let Some(old) = tracked.iter_mut().find(|v| v.id == meta.id) {
        *old = item;
    } else {
        tracked.push(item);
    }
}
impl App {
    pub(super) fn sync_tick(&mut self) -> Task<Message> {
        if self.saved_connection.sync.enabled
            && self
                .sync_state
                .due
                .is_none_or(|due| std::time::Instant::now() >= due)
        {
            return self.sync_update(Action::Poll);
        }
        Task::none()
    }
    pub(super) fn sync_update(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::Enable(enabled)
                if self.can_change_profiles() && self.store_conflict.is_none() =>
            {
                if enabled {
                    let Some(client) = &self.portal.client else {
                        return Task::none();
                    };
                    if self.saved_connection.sync.origin != client.address() {
                        self.saved_connection.sync.tracked.clear();
                        self.saved_connection.sync.origin = client.address().into();
                    }
                }
                self.saved_connection.sync.enabled = enabled;
                if !enabled {
                    // Without sync nothing would update or revoke a server policy.
                    self.saved_connection.managed_routes = None;
                }
                self.sync_state = State::default();
                self.dirty = true;
                return self.update(Message::Save);
            }
            Action::Poll
                if self.can_change_profiles()
                    && !self.dirty
                    && self.store_conflict.is_none()
                    && self.sync_state.pending.is_empty()
                    && self.saved_connection.sync.enabled =>
            {
                self.sync_state.due =
                    Some(std::time::Instant::now() + std::time::Duration::from_secs(60));
                self.busy = true;
                let existing = self.portal.client.clone();
                let settings = self.saved_connection.sync.clone();
                let fetch = async move {
                    let client = match existing {
                        Some(c) => c,
                        None => tokio::task::spawn_blocking(Client::restore)
                            .await
                            .map_err(|_| "Ошибка системного хранилища".to_string())??,
                    };
                    if client.address() != settings.origin {
                        return Err(
                            "Привязка панели изменилась. Включите синхронизацию заново.".into()
                        );
                    }
                    let listed = client.list().await?;
                    let available = listed.iter().map(|p| p.id.clone()).collect();
                    let mut changed = Vec::new();
                    let mut total = 0;
                    for remote in listed {
                        if !settings
                            .tracked
                            .iter()
                            .any(|p| p.id == remote.id && p.revision == remote.revision)
                        {
                            let profile = client.download(&remote).await?;
                            total += profile
                                .export(Format::Json)
                                .map_err(|_| "Некорректный профиль")?
                                .content
                                .len();
                            if total > 4 * rtrust_profile::MAX_INPUT {
                                return Err("Обновление профилей превышает лимит 4 MiB".into());
                            }
                            changed.push((remote, profile));
                        }
                    }
                    let routing = client
                        .routing()
                        .await
                        .and_then(|policy| policy.map(managed).transpose());
                    Ok(Batch {
                        origin: settings.origin,
                        client,
                        changed,
                        available,
                        routing,
                    })
                };
                return Task::perform(
                    async move {
                        tokio::time::timeout(std::time::Duration::from_secs(30), fetch)
                            .await
                            .map_err(|_| "Синхронизация превысила 30 секунд".to_string())?
                    },
                    |result| Message::Sync(Action::Received(result)),
                );
            }
            Action::Received(result) => {
                self.busy = false;
                match result {
                    Ok(batch)
                        if self.saved_connection.sync.enabled
                            && batch.origin == self.saved_connection.sync.origin =>
                    {
                        self.portal.url = batch.origin.clone();
                        self.portal.client = Some(batch.client);
                        let previous_profiles = self.profiles.clone();
                        let previous_sync = self.saved_connection.sync.clone();
                        let previous_routes = self.saved_connection.managed_routes.clone();
                        let routing_error = batch.routing.as_ref().err().cloned();
                        if let Ok(routing) = batch.routing {
                            self.saved_connection.managed_routes = routing;
                        }
                        let routes_changed =
                            self.saved_connection.managed_routes != previous_routes;
                        let mut updated = 0;
                        for (meta, incoming) in batch.changed {
                            let old = self
                                .saved_connection
                                .sync
                                .tracked
                                .iter()
                                .find(|p| p.id == meta.id);
                            let matches: Vec<usize> = old
                                .map(|old| {
                                    self.profiles
                                        .iter()
                                        .enumerate()
                                        .filter_map(|(i, p)| (p == &old.baseline).then_some(i))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if old.is_some() && matches.len() != 1 {
                                self.sync_state.pending.push((meta, incoming));
                                continue;
                            }
                            if let Some(&index) = matches.first() {
                                self.profiles[index] = incoming.clone();
                            } else if !self.profiles.contains(&incoming) {
                                self.profiles.push(incoming.clone());
                            }
                            track(&mut self.saved_connection.sync.tracked, &meta, incoming);
                            updated += 1;
                        }
                        let candidate = rtrust_store::Vault {
                            profiles: self.profiles.clone(),
                            connection: self.saved_connection.clone(),
                        };
                        if candidate.validate().is_err() {
                            self.profiles = previous_profiles;
                            self.saved_connection.sync = previous_sync;
                            self.saved_connection.managed_routes = previous_routes;
                            self.sync_state.pending.clear();
                            self.sync_state.status="Обновление превышает лимит хранилища. Локальные данные не изменены.".into();
                            return Task::none();
                        }
                        let missing = self
                            .saved_connection
                            .sync
                            .tracked
                            .iter()
                            .filter(|p| !batch.available.contains(&p.id))
                            .count();
                        let routes = match (&routing_error, &self.saved_connection.managed_routes) {
                            (Some(e), _) => format!("не обновлены ({e})"),
                            (None, Some(m)) => format!("группа «{}»", m.group),
                            (None, None) => "локальные настройки".into(),
                        };
                        self.sync_state.status = format!(
                            "Обновлено: {updated}. Конфликтов: {}. Недоступно на сервере: {missing} (локальные копии сохранены). Маршруты TUN: {routes}.",
                            self.sync_state.pending.len()
                        );
                        if updated > 0 {
                            self.reset_editor();
                        }
                        if updated > 0 || routes_changed {
                            self.dirty = true;
                            return self.update(Message::Save);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => self.sync_state.status = e,
                }
            }
            Action::KeepLocal | Action::KeepBoth
                if self.can_change_profiles()
                    && self.store_conflict.is_none()
                    && !self.sync_state.pending.is_empty() =>
            {
                let (meta, profile) = self.sync_state.pending.remove(0);
                if matches!(action, Action::KeepBoth) && !self.profiles.contains(&profile) {
                    self.profiles.push(profile.clone());
                }
                track(&mut self.saved_connection.sync.tracked, &meta, profile);
                self.dirty = true;
                return self.update(Message::Save);
            }
            _ => {}
        }
        Task::none()
    }
    pub(super) fn sync_view(&self) -> Element<'_, Message> {
        let ready = self.can_change_profiles() && self.store_conflict.is_none();
        let mut toggle = checkbox(self.saved_connection.sync.enabled)
            .label("Автоматически получать изменения профилей с этой панели");
        if ready && (self.portal.client.is_some() || self.saved_connection.sync.enabled) {
            toggle = toggle.on_toggle(|v| Message::Sync(Action::Enable(v)));
        }
        let mut panel=column![toggle,text("Все выданные устройству профили проверяются раз в минуту, пока VPN отключён. Локальные изменения требуют решения конфликта. Пароли на сервер автоматически не отправляются.").size(12),text(&self.sync_state.status),button("Синхронизировать сейчас").on_press_maybe((ready && !self.dirty && self.saved_connection.sync.enabled).then_some(Message::Sync(Action::Poll)))].spacing(8);
        if let Some((meta, _)) = self.sync_state.pending.first() {
            panel = panel
                .push(text(format!(
                    "Конфликт: {}. Локальный профиль изменён или удалён.",
                    meta.summary.name
                )))
                .push(
                    button("Оставить локальную версию")
                        .on_press_maybe(ready.then_some(Message::Sync(Action::KeepLocal))),
                )
                .push(
                    button("Добавить серверную версию отдельной копией")
                        .on_press_maybe(ready.then_some(Message::Sync(Action::KeepBoth))),
                );
        }
        panel.into()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn meta() -> RemoteProfile {
        RemoteProfile {
            id: "remote-1".into(),
            revision: "2".into(),
            summary: rtrust_portal::Summary {
                name: "example".into(),
                hostname: "example.test".into(),
            },
            origin: "external_stored".into(),
        }
    }
    fn configured() -> App {
        let mut app = crate::tests::app();
        app.saved_connection.sync = rtrust_store::SyncSettings {
            enabled: true,
            origin: "https://example.test/".into(),
            tracked: vec![TrackedProfile {
                id: "remote-1".into(),
                revision: "1".into(),
                baseline: app.profiles[0].clone(),
            }],
        };
        app
    }
    fn batch(profile: Profile) -> Batch {
        Batch {
            origin: "https://example.test/".into(),
            client: Client::new("https://example.test").unwrap(),
            changed: vec![(meta(), profile)],
            available: vec!["remote-1".into()],
            routing: Ok(None),
        }
    }
    #[test]
    fn clean_update_replaces_in_place_without_connecting() {
        let mut app = configured();
        let mut remote = app.profiles[0].clone();
        remote.name = "server revision two".into();
        let _ = app.sync_update(Action::Received(Ok(batch(remote.clone()))));
        assert_eq!(app.profiles[0], remote);
        assert_eq!(app.profiles.len(), 2);
        assert!(!app.connecting && app.dirty);
        assert_eq!(app.saved_connection.sync.tracked[0].revision, "2");
    }
    #[test]
    fn local_edit_conflicts_and_keep_both_preserves_default() {
        let mut app = configured();
        let remote = app.profiles[0].clone();
        app.profiles[0].name = "local edit".into();
        let local = app.profiles[0].clone();
        let _ = app.sync_update(Action::Received(Ok(batch(remote.clone()))));
        assert_eq!(app.profiles[0], local);
        assert_eq!(app.sync_state.pending.len(), 1);
        let _ = app.sync_update(Action::KeepBoth);
        assert_eq!(app.profiles[0], local);
        assert_eq!(app.profiles[2], remote);
    }
    #[test]
    fn revoked_profile_is_retained_and_wrong_origin_ignored() {
        let mut app = configured();
        let before = app.profiles.clone();
        let mut result = batch(before[0].clone());
        result.changed.clear();
        result.available.clear();
        let _ = app.sync_update(Action::Received(Ok(result)));
        assert_eq!(app.profiles, before);
        assert!(app.sync_state.status.contains("Недоступно на сервере: 1"));
        let mut result = batch(before[0].clone());
        result.origin = "https://different.test/".into();
        let _ = app.sync_update(Action::Received(Ok(result)));
        assert_eq!(app.profiles, before);
        assert!(!app.dirty);
    }
    #[test]
    fn group_route_policy_is_applied_replaced_and_cleared() {
        let mut app = configured();
        let policy = |include: &str, exclude: &str| rtrust_portal::RoutingPolicy {
            group: "office".into(),
            revision: format!("1:{include}"),
            include: rtrust_control::networks(include).unwrap(),
            exclude: if exclude.is_empty() {
                vec![]
            } else {
                rtrust_control::networks(exclude).unwrap()
            },
            exclude_lan: true,
        };
        let mut result = batch(app.profiles[0].clone());
        result.changed.clear();
        result.routing = Ok(Some(managed(policy("0.0.0.0/0", "10.0.0.0/8")).unwrap()));
        let _ = app.sync_update(Action::Received(Ok(result)));
        let applied = app.saved_connection.managed_routes.clone().unwrap();
        assert_eq!(applied.group, "office");
        assert!(applied.selection.exclude_lan && app.dirty);
        assert_eq!(app.tun_selection().unwrap(), applied.selection);
        assert!(app.sync_state.status.contains("группа «office»"));
        // A policy that leaves nothing to route is refused, keeps the previous
        // policy and does not stop profile updates.
        let refused = managed(policy("10.0.0.0/8", "10.0.0.0/8"));
        assert!(refused.is_err());
        let mut remote = app.profiles[0].clone();
        remote.name = "server revision two".into();
        let mut result = batch(remote.clone());
        result.routing = refused.map(Some);
        app.busy = false;
        let _ = app.sync_update(Action::Received(Ok(result)));
        assert_eq!(app.saved_connection.managed_routes.as_ref(), Some(&applied));
        assert_eq!(app.profiles[0], remote);
        assert!(app.sync_state.status.contains("не обновлены"));
        let mut result = batch(app.profiles[0].clone());
        result.changed.clear();
        let _ = app.sync_update(Action::Received(Ok(result)));
        assert!(app.saved_connection.managed_routes.is_none());
        app.saved_connection.managed_routes = Some(applied);
        app.dirty = false;
        app.busy = false; // the save started by the previous batch has finished
        let _ = app.sync_update(Action::Enable(false));
        assert!(app.saved_connection.managed_routes.is_none());
    }
    #[test]
    fn sync_does_not_start_during_connection_or_unsaved_edits() {
        let mut app = configured();
        app.connecting = true;
        let _ = app.sync_tick();
        assert!(!app.busy);
        app.connecting = false;
        app.dirty = true;
        let _ = app.sync_tick();
        assert!(!app.busy);
    }
}
