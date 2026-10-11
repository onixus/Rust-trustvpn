use super::*;
use iced::widget::column;
#[derive(Default)]
pub(super) struct State {
    pub(super) status: String,
    pub(super) enabled: bool,
    polling: bool,
    generation: u64,
    next_poll: Option<std::time::Instant>,
    confirm: bool,
    backups: Vec<Profile>,
    recovery_confirm: bool,
}
#[derive(Clone)]
pub(super) enum Action {
    Check,
    Enable,
    Disable,
    Backup(usize, bool),
    EnableRecovery,
    Done(Result<rtrust_control::Response, String>),
    Observed(u64, Result<rtrust_control::Response, String>),
}
impl App {
    pub(super) fn always_update(&mut self, action: Action) -> Task<Message> {
        let command = match action {
            Action::Backup(index, enabled)
                if self.can_change_profiles() && !self.always_on.enabled =>
            {
                self.always_on.recovery_confirm = false;
                if index == 0 || index >= self.profiles.len() {
                    return Task::none();
                }
                let profile = self.profiles[index].clone();
                self.always_on.backups.retain(|p| p != &profile);
                if enabled && self.always_on.backups.len() < rtrust_control::recovery::MAX_BACKUPS {
                    self.always_on.backups.push(profile);
                }
                return Task::none();
            }
            Action::EnableRecovery
                if self.can_change_profiles() && !self.dirty && !self.always_on.enabled =>
            {
                let Some(profile) = self.profiles.first().cloned() else {
                    return Task::none();
                };
                let backups = self.always_on.backups.clone();
                if backups.is_empty()
                    || backups
                        .iter()
                        .any(|p| !self.profiles.contains(p) || p == &profile)
                {
                    self.always_on.status =
                        "Выбранный резерв изменён или удалён. Выберите резервы заново.".into();
                    self.always_on.backups.clear();
                    self.always_on.recovery_confirm = false;
                    return Task::none();
                }
                let Ok(dns) = self.dns.parse() else {
                    self.always_on.status = "Укажите IPv4 DNS в настройках полного туннеля".into();
                    return Task::none();
                };
                if !self.always_on.recovery_confirm {
                    self.always_on.recovery_confirm = true;
                    self.always_on.status = "Подтвердите автоматическую смену только выбранных профилей. Текущие TCP/UDP-сессии могут прерваться. Сеть без VPN останется заблокированной.".into();
                    return Task::none();
                }
                rtrust_control::Command::EnableRecovery {
                    profile: Box::new(profile),
                    dns,
                    backups,
                }
            }
            Action::Observed(generation, result) => {
                self.always_on.polling = false;
                if generation == self.always_on.generation {
                    match result {
                        Ok(r) => self.always_observed(r),
                        Err(_) => {
                            self.always_on.status =
                                "Связь со службой потеряна; состояние защиты не подтверждено".into()
                        }
                    }
                }
                return Task::none();
            }
            Action::Done(result) => {
                self.busy = false;
                self.always_on.confirm = false;
                self.always_on.recovery_confirm = false;
                match result {
                    Ok(r) => self.always_observed(r),
                    Err(e) => self.always_on.status = e,
                }
                self.always_on.next_poll = None;
                return Task::none();
            }
            Action::Check if !self.busy => rtrust_control::Command::AlwaysOnStatus,
            Action::Disable if !self.busy => rtrust_control::Command::DisableAlwaysOn,
            Action::Enable if self.can_change_profiles() && !self.dirty => {
                if !self.always_on.confirm {
                    self.always_on.confirm = true;
                    return Task::none();
                }
                let Some(profile) = self.profiles.first().cloned() else {
                    return Task::none();
                };
                let Ok(dns) = self.dns.parse() else {
                    self.always_on.status = "Укажите IPv4 DNS в настройках полного туннеля".into();
                    return Task::none();
                };
                rtrust_control::Command::EnableAlwaysOn {
                    profile: Box::new(profile),
                    dns,
                }
            }
            _ => return Task::none(),
        };
        self.always_on.generation = self.always_on.generation.wrapping_add(1);
        self.busy = true;
        Task::perform(rtrust_control::Client::always_on(command), |r| {
            Message::AlwaysOn(Action::Done(r))
        })
    }
    fn always_observed(&mut self, response: rtrust_control::Response) {
        if let Some(enabled) = response.always_on {
            self.always_on.enabled = enabled;
        } else {
            match response.state {
                rtrust_control::State::Idle => self.always_on.enabled = false,
                rtrust_control::State::Connected | rtrust_control::State::Blocked => {
                    self.always_on.enabled = true
                }
                rtrust_control::State::Error => {}
            }
        }
        let recovery = response
            .recovery
            .as_ref()
            .map(|status| {
                format!(
                    "\nАвтовосстановление: профиль №{}; попыток {}/{}; {}",
                    status.selected_index + 1,
                    status.attempts,
                    rtrust_control::recovery::MAX_ATTEMPTS,
                    if status.exhausted {
                        "лимит исчерпан — проверьте состояние защиты"
                    } else {
                        "разрешённые резервы включены"
                    }
                )
            })
            .unwrap_or_default();
        self.always_on.status = format!(
            "{}\n{}{}",
            response.message,
            rtrust_desktop::observation_summary(&response.observations, true),
            recovery
        );
    }
    pub(super) fn always_poll(&mut self) -> Option<Task<Message>> {
        if self.always_on.polling
            || self.busy
            || self
                .always_on
                .next_poll
                .is_some_and(|t| t > std::time::Instant::now())
        {
            return None;
        }
        self.always_on.polling = true;
        self.always_on.next_poll =
            Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
        let generation = self.always_on.generation;
        Some(Task::perform(
            rtrust_control::Client::always_on(rtrust_control::Command::AlwaysOnStatus),
            move |r| Message::AlwaysOn(Action::Observed(generation, r)),
        ))
    }
    pub(super) fn always_view(&self) -> Element<'_, Message> {
        let mut panel = column![text("VPN системной службы").size(18),text(&self.always_on.status),
            text("Служба хранит отдельную зашифрованную копию профиля по умолчанию и подключается без открытого приложения. При недоступности VPN сеть остаётся заблокированной. Изменение профиля в приложении не меняет эту копию.").size(12),
            button("Проверить состояние службы").on_press_maybe((!self.busy).then_some(Message::AlwaysOn(Action::Check))),
            button(if self.always_on.confirm {"Подтвердить постоянный VPN"}else{"Включить always-on…"}).on_press_maybe((self.can_change_profiles() && !self.dirty && !self.profiles.is_empty()).then_some(Message::AlwaysOn(Action::Enable))),
            button("Выключить always-on и восстановить сеть").on_press_maybe((!self.busy).then_some(Message::AlwaysOn(Action::Disable)))
        ].spacing(8);
        if !self.always_on.enabled {
            panel = panel.push(text("Резервные подключения: отметьте в порядке предпочтения (до трёх). Основной — профиль по умолчанию. Автоматический режим применяет полный туннель и сохраняет защиту; это preview до проверки на вашем устройстве.").size(12));
            for (index, profile) in self.profiles.iter().enumerate().skip(1) {
                let selected = self.always_on.backups.iter().position(|p| p == profile);
                let mut toggle = checkbox(selected.is_some()).label(match selected {
                    Some(order) => format!("{}. {}", order + 1, profile.name),
                    None => profile.name.clone(),
                });
                if self.can_change_profiles()
                    && (selected.is_some()
                        || self.always_on.backups.len() < rtrust_control::recovery::MAX_BACKUPS)
                {
                    toggle = toggle
                        .on_toggle(move |value| Message::AlwaysOn(Action::Backup(index, value)));
                }
                panel = panel.push(toggle);
            }
            panel = panel.push(
                button(if self.always_on.recovery_confirm {
                    "Подтвердить автоматическое восстановление"
                } else {
                    "Включить с выбранными резервами…"
                })
                .on_press_maybe(
                    (self.can_change_profiles()
                        && !self.dirty
                        && !self.always_on.backups.is_empty())
                    .then_some(Message::AlwaysOn(Action::EnableRecovery)),
                ),
            );
        }
        panel.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_poll_cannot_hide_a_new_service_owned_connection() {
        let mut app = crate::tests::app();
        let old = app.always_on.generation;
        app.always_on.generation += 1;
        let mut enabled = rtrust_control::Response::new(
            rtrust_control::State::Error,
            "Guard setup needs recovery",
        );
        enabled.always_on = Some(true);
        let _ = app.always_update(Action::Done(Ok(enabled)));
        assert!(app.always_on.enabled);
        let _ = app.always_update(Action::Observed(
            old,
            Ok(rtrust_control::Response::new(
                rtrust_control::State::Idle,
                "off",
            )),
        ));
        assert!(app.always_on.enabled);
        let _ = app.update(Message::ToggleConnection);
        assert!(app.busy);
        assert!(!app.connecting);
        assert!(app.session.is_none());
    }
    fn profile(name: &str, address: &str) -> Profile {
        Profile::import(&format!("name='{name}'\nhostname='vpn.example'\naddresses=['{address}:443']\nusername='u'\npassword='p'\n")).unwrap()
    }
    #[test]
    fn recovery_requires_explicit_confirmation_with_ordered_snapshots() {
        let mut app = crate::tests::app();
        app.profiles = vec![
            profile("primary", "192.0.2.1"),
            profile("second", "192.0.2.2"),
            profile("third", "192.0.2.3"),
        ];
        app.dns = "1.1.1.1".into();
        let _ = app.always_update(Action::Backup(2, true));
        let _ = app.always_update(Action::Backup(1, true));
        assert_eq!(
            app.always_on.backups,
            vec![app.profiles[2].clone(), app.profiles[1].clone()]
        );
        let _ = app.always_update(Action::EnableRecovery);
        assert!(app.always_on.recovery_confirm);
        assert!(!app.busy);
        let _ = app.always_update(Action::EnableRecovery);
        assert!(app.busy);
    }
    #[test]
    fn edited_backup_invalidates_confirmation_without_sending_credentials() {
        let mut app = crate::tests::app();
        app.profiles = vec![
            profile("primary", "192.0.2.1"),
            profile("backup", "192.0.2.2"),
        ];
        app.dns = "1.1.1.1".into();
        let _ = app.always_update(Action::Backup(1, true));
        let _ = app.always_update(Action::EnableRecovery);
        app.profiles[1] = profile("backup", "192.0.2.4");
        let _ = app.always_update(Action::EnableRecovery);
        assert!(!app.busy);
        assert!(!app.always_on.recovery_confirm);
        assert!(app.always_on.backups.is_empty());
    }
}
