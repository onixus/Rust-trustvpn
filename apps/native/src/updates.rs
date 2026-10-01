use super::*;
use iced::widget::column;
#[derive(Default)]
pub(super) struct State {
    release: Option<rtrust_update::Release>,
    staged: Option<std::path::PathBuf>,
    status: String,
}
#[derive(Clone)]
pub(super) enum Action {
    Check,
    Checked(Result<rtrust_update::Release, String>),
    Download,
    Downloaded(Result<std::path::PathBuf, String>),
    Install,
    Started(Result<(), String>),
}
impl App {
    pub(super) fn updates_update(&mut self, action: Action) -> Task<Message> {
        match action {
            Action::Check if !self.busy => {
                self.busy = true;
                self.updates.staged = None;
                self.updates.release = None;
                return Task::perform(rtrust_update::check(rtrust_update::CURRENT_SEQUENCE), |r| {
                    Message::Update(Action::Checked(r))
                });
            }
            Action::Checked(result) => {
                self.busy = false;
                match result {
                    Ok(release) => {
                        self.updates.status =
                            if release.manifest().sequence > rtrust_update::CURRENT_SEQUENCE {
                                format!(
                                    "Доступна версия {}. Подпись релиза проверена.",
                                    release.manifest().version
                                )
                            } else {
                                "Установлена актуальная версия.".into()
                            };
                        self.updates.release = Some(release);
                    }
                    Err(e) => self.updates.status = e,
                }
            }
            Action::Download if !self.busy => {
                if let Some(release) = self.updates.release.clone() {
                    self.busy = true;
                    self.updates.status =
                        "Загрузка и проверка обновления и пакета для отката…".into();
                    return Task::perform(
                        async move { rtrust_update::stage(&release).await },
                        |r| Message::Update(Action::Downloaded(r)),
                    );
                }
            }
            Action::Downloaded(result) => {
                self.busy = false;
                match result {
                    Ok(folder) => {
                        self.updates.staged = Some(folder);
                        self.updates.status="Оба пакета проверены. Установка завершит клиент и запросит разрешение Windows. При неуспешной проверке новой версии будет выполнен откат.".into();
                    }
                    Err(e) => self.updates.status = e,
                }
            }
            Action::Install
                if self.can_change_profiles() && !self.dirty && self.store_conflict.is_none() =>
            {
                if let Some(folder) = self.updates.staged.clone() {
                    self.busy = true;
                    return Task::perform(
                        async move {
                            tokio::task::spawn_blocking(move || {
                            let source=std::env::current_exe().map_err(|_|"Не найден клиент")?.with_file_name("rtrust-update.exe");
                            let helper=folder.join("updater.exe");
                            std::fs::copy(source,&helper).map_err(|_|"Не найден помощник обновления; используйте установленный клиент")?;
                            std::process::Command::new(helper).arg(folder).arg(std::process::id().to_string()).spawn().map_err(|_|"Не удалось запустить обновление")?;
                            Ok(())
                        }).await.map_err(|_|"Ошибка помощника обновления".to_string()).and_then(|r:Result<(),&str>|r.map_err(str::to_owned))
                        },
                        |r| Message::Update(Action::Started(r)),
                    );
                }
            }
            Action::Started(result) => {
                self.busy = false;
                match result {
                    Ok(()) => return iced::exit(),
                    Err(e) => self.updates.status = e,
                }
            }
            _ => {}
        }
        Task::none()
    }
    pub(super) fn updates_view(&self) -> Element<'_, Message> {
        let newer = self
            .updates
            .release
            .as_ref()
            .is_some_and(|r| r.manifest().sequence > rtrust_update::CURRENT_SEQUENCE);
        column![
            text("Обновление клиента и службы").size(18),
            text(&self.updates.status),
            button("Проверить обновления")
                .on_press_maybe((!self.busy).then_some(Message::Update(Action::Check))),
            button("Скачать проверенные пакеты")
                .on_press_maybe((!self.busy && newer).then_some(Message::Update(Action::Download))),
            button("Установить обновление").on_press_maybe(
                (self.can_change_profiles()
                    && !self.dirty
                    && self.store_conflict.is_none()
                    && self.updates.staged.is_some())
                .then_some(Message::Update(Action::Install))
            )
        ]
        .spacing(8)
        .into()
    }
}
