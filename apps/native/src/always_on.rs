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
}
#[derive(Clone)]
pub(super) enum Action {
    Check,
    Enable,
    Disable,
    Done(Result<rtrust_control::Response, String>),
    Observed(u64, Result<rtrust_control::Response, String>),
}
impl App {
    pub(super) fn always_update(&mut self, action: Action) -> Task<Message> {
        let command = match action {
            Action::Observed(generation, result) => {
                self.always_on.polling = false;
                if generation == self.always_on.generation
                    && let Ok(r) = result
                {
                    self.always_observed(r);
                }
                return Task::none();
            }
            Action::Done(result) => {
                self.busy = false;
                self.always_on.confirm = false;
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
                let Some(mut profile) = self.profiles.first().cloned() else {
                    return Task::none();
                };
                if profile.protocol == rtrust_profile::Protocol::TrustTunnel {
                    profile.endpoint.upstream_protocol = "http2".into();
                }
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
        self.always_on.status = response.message;
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
        column![text("VPN системной службы").size(18),text(&self.always_on.status),
            text("Служба хранит отдельную зашифрованную копию профиля по умолчанию и подключается без открытого приложения. При недоступности VPN сеть остаётся заблокированной. Изменение профиля в приложении не меняет эту копию.").size(12),
            button("Проверить состояние службы").on_press_maybe((!self.busy).then_some(Message::AlwaysOn(Action::Check))),
            button(if self.always_on.confirm {"Подтвердить постоянный VPN"}else{"Включить always-on…"}).on_press_maybe((self.can_change_profiles() && !self.dirty && !self.profiles.is_empty()).then_some(Message::AlwaysOn(Action::Enable))),
            button("Выключить always-on и восстановить сеть").on_press_maybe((!self.busy).then_some(Message::AlwaysOn(Action::Disable)))
        ].spacing(8).into()
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
}
