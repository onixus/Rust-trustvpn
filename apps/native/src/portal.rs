use super::*;
use iced::widget::column;
use rtrust_portal::{Client, Preview, RemoteProfile};
use zeroize::Zeroize;
#[derive(Default)]
pub(super) struct State {
    pub(super) url: String,
    code: String,
    name: String,
    pub(super) client: Option<Client>,
    profiles: Vec<RemoteProfile>,
    preview: Option<Preview>,
    consent: bool,
}
#[derive(Clone)]
pub(super) enum Action {
    Url(String),
    Code(String),
    Name(String),
    Consent(bool),
    Enroll,
    Restore,
    Forget,
    Ready(Result<Client, String>),
    Refresh,
    Listed(Result<Vec<RemoteProfile>, String>),
    Download(usize),
    Downloaded(Box<Result<Profile, String>>),
    Upload,
    Previewed(Result<Preview, String>),
    Commit,
    Replace(usize),
    Committed(Result<(), String>),
    Forgotten(Result<(), String>),
}
fn task<T: Send + 'static>(
    future: impl std::future::Future<Output = T> + Send + 'static,
    map: fn(T) -> Action,
) -> Task<Message> {
    Task::perform(future, move |value| Message::Portal(map(value)))
}
impl App {
    pub(super) fn portal_update(&mut self, action: Action) -> Task<Message> {
        use Action::*;
        match action {
            Url(v) if !self.busy && self.portal.client.is_none() => self.portal.url = v,
            Code(v) if !self.busy => self.portal.code = v,
            Name(v) if !self.busy => self.portal.name = v,
            Consent(v) if !self.busy => self.portal.consent = v,
            Enroll if self.can_change_profiles() && self.portal.client.is_none() => {
                match Client::new(&self.portal.url) {
                    Ok(client) => {
                        self.busy = true;
                        let code = Zeroizing::new(std::mem::take(&mut self.portal.code));
                        let name = self.portal.name.clone();
                        return task(
                            async move {
                                let client = client.enroll(&code, &name).await?;
                                let saved = client.clone();
                                tokio::task::spawn_blocking(move || saved.remember())
                                    .await
                                    .map_err(|_| "Ошибка системного хранилища")??;
                                Ok(client)
                            },
                            Ready,
                        );
                    }
                    Err(e) => self.status = e,
                }
            }
            Restore if self.can_change_profiles() && self.portal.client.is_none() => {
                self.busy = true;
                return task(
                    async {
                        tokio::task::spawn_blocking(Client::restore)
                            .await
                            .map_err(|_| "Ошибка системного хранилища".into())
                            .and_then(|v| v)
                    },
                    Ready,
                );
            }
            Ready(result) => {
                self.busy = false;
                match result {
                    Ok(client) => {
                        self.portal.url = client.address().into();
                        self.portal.client = Some(client);
                        self.portal.code.zeroize();
                        self.portal.profiles.clear();
                        self.portal.preview = None;
                        self.status =
                            "Устройство привязано. Выдайте ему доступ к нужным профилям в панели."
                                .into();
                        return self.portal_update(Refresh);
                    }
                    Err(e) => self.status = e,
                }
            }
            Forget if self.can_change_profiles() => {
                self.busy = true;
                return task(
                    async {
                        tokio::task::spawn_blocking(Client::forget)
                            .await
                            .map_err(|_| "Ошибка системного хранилища".into())
                            .and_then(|v| v)
                    },
                    Forgotten,
                );
            }
            Forgotten(result) => {
                self.busy = false;
                match result {
                    Ok(()) => {
                        self.portal = State::default();
                        self.saved_connection.sync.enabled = false;
                        self.dirty = true;
                        self.autosave_due = Some(std::time::Instant::now());
                        self.status="Локальная привязка удалена. Для отзыва доступа устройства удалите его в панели.".into();
                    }
                    Err(e) => self.status = e,
                }
            }
            Refresh if self.can_change_profiles() => {
                if let Some(client) = self.portal.client.clone() {
                    self.busy = true;
                    return task(async move { client.list().await }, Listed);
                }
            }
            Listed(result) => {
                self.busy = false;
                match result {
                    Ok(v) => {
                        self.portal.profiles = v;
                        self.status = "Список доступных профилей обновлён.".into();
                    }
                    Err(e) => {
                        self.portal.profiles.clear();
                        self.status = e;
                    }
                }
            }
            Download(i) if self.can_change_profiles() => {
                if let (Some(client), Some(profile)) = (
                    self.portal.client.clone(),
                    self.portal.profiles.get(i).cloned(),
                ) {
                    self.busy = true;
                    return task(async move { client.download(&profile).await }, |value| {
                        Downloaded(Box::new(value))
                    });
                }
            }
            Downloaded(result) => {
                self.apply_import((*result).map(Some));
                if self.preview.is_some() {
                    self.page = Page::Import;
                    self.status="Профиль получен с сервера. Проверьте и добавьте его — хранилище сохранится автоматически. VPN не подключён.".into();
                }
            }
            Upload if self.can_change_profiles() && self.portal.consent => {
                if let (Some(client), Some(profile)) =
                    (self.portal.client.clone(), self.current().cloned())
                {
                    self.busy = true;
                    self.portal.preview = None;
                    return task(
                        async move { client.preview_upload(&profile).await },
                        Previewed,
                    );
                }
            }
            Previewed(result) => {
                self.busy = false;
                match result {
                    Ok(v) => {
                        self.portal.preview = Some(v);
                        self.status =
                            "Профиль проверен сервером. Подтвердите создание серверной копии."
                                .into();
                    }
                    Err(e) => self.status = e,
                }
            }
            Commit if self.can_change_profiles() && self.portal.consent => {
                if let (Some(client), Some(preview)) =
                    (self.portal.client.clone(), self.portal.preview.clone())
                {
                    self.busy = true;
                    return task(async move { client.commit(&preview).await }, Committed);
                }
            }
            Replace(i) if self.can_change_profiles() && self.portal.consent => {
                if let (Some(client), Some(preview), Some(target)) = (
                    self.portal.client.clone(),
                    self.portal.preview.clone(),
                    self.portal.profiles.get(i).cloned(),
                ) {
                    self.busy = true;
                    return task(
                        async move { client.replace(&preview, &target).await },
                        Committed,
                    );
                }
            }
            Committed(result) => {
                self.busy = false;
                match result {
                    Ok(()) => {
                        self.portal.preview = None;
                        self.portal.consent = false;
                        self.status =
                            "Серверный профиль сохранён. Учётная запись VPN на endpoint не менялась."
                                .into();
                        return self.portal_update(Refresh);
                    }
                    Err(e) => self.status = e,
                }
            }
            _ => {}
        }
        Task::none()
    }
    pub(super) fn portal_view(&self) -> Element<'_, Message> {
        let enabled = self.can_change_profiles();
        let mut content = column![
            text("Обмен с серверной панелью").size(22),
            text("Получение и отправка конфигов не подключают VPN.").size(12)
        ]
        .spacing(10);
        if self.portal.client.is_none() {
            content = content
                .push(
                    text_input("https://адрес-панели", &self.portal.url)
                        .on_input(|v| Message::Portal(Action::Url(v))),
                )
                .push(
                    text_input("Имя этого устройства", &self.portal.name)
                        .on_input(|v| Message::Portal(Action::Name(v))),
                )
                .push(
                    text_input("Одноразовый код со страницы /profiles", &self.portal.code)
                        .secure(true)
                        .on_input(|v| Message::Portal(Action::Code(v))),
                )
                .push(
                    row![
                        button("Привязать устройство")
                            .on_press_maybe(enabled.then_some(Message::Portal(Action::Enroll))),
                        button("Открыть сохранённую привязку")
                            .on_press_maybe(enabled.then_some(Message::Portal(Action::Restore)))
                    ]
                    .spacing(8),
                );
        } else {
            content = content.push(text(&self.portal.url)).push(
                row![
                    button("Обновить список")
                        .on_press_maybe(enabled.then_some(Message::Portal(Action::Refresh))),
                    button("Забыть привязку")
                        .on_press_maybe(enabled.then_some(Message::Portal(Action::Forget)))
                ]
                .spacing(8),
            );
            if self.portal.profiles.is_empty() {
                content=content.push(text("Нет доступных профилей. Выдайте этому устройству права в панели и обновите список."));
            }
            for (i, p) in self.portal.profiles.iter().enumerate() {
                content = content.push(
                    row![
                        text(format!("{} · {}", p.summary.name, p.summary.hostname))
                            .width(Length::Fill),
                        button("Загрузить и проверить").on_press_maybe(
                            enabled.then_some(Message::Portal(Action::Download(i)))
                        )
                    ]
                    .spacing(8),
                );
            }
            if let Some(profile) = self.current() {
                content = content
                    .push(text(format!("На сервер: {}", profile.name)))
                    .push(
                        checkbox(self.portal.consent)
                            .label("Разрешаю передать VPN-пароль этой панели")
                            .on_toggle(|v| Message::Portal(Action::Consent(v))),
                    )
                    .push(button("Проверить отправку").on_press_maybe(
                        (enabled && self.portal.consent).then_some(Message::Portal(Action::Upload)),
                    ));
            }
            if let Some(preview) = &self.portal.preview {
                content = content
                    .push(text(format!(
                        "Серверная копия: {} · {}",
                        preview.summary.name, preview.summary.hostname
                    )))
                    .push(button("Подтвердить сохранение на сервере").on_press_maybe(
                        (enabled && self.portal.consent).then_some(Message::Portal(Action::Commit)),
                    ));
                for (i, remote) in self
                    .portal
                    .profiles
                    .iter()
                    .enumerate()
                    .filter(|(_, p)| p.origin == "external_stored")
                {
                    content = content.push(
                        button(text(format!(
                            "Заменить серверный профиль «{}»",
                            remote.summary.name
                        )))
                        .on_press_maybe(
                            (enabled && self.portal.consent)
                                .then_some(Message::Portal(Action::Replace(i))),
                        ),
                    );
                }
            }
        }
        content = content.push(self.sync_view());
        content.into()
    }
}
