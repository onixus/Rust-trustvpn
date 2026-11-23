use super::*;
use iced::widget::column;
#[derive(Default)]
pub(super) struct State {
    release: Option<rtrust_update::Release>,
    staged: Option<std::path::PathBuf>,
    /// GitHub Release lookup. Independent of the signed update channel.
    github: Github,
    status: String,
}
#[derive(Default)]
struct Github {
    release: Option<rtrust_update::github::ReleaseInfo>,
    /// Checksum-verified package. Not executed.
    file: Option<std::path::PathBuf>,
    status: String,
}
#[derive(Clone)]
pub(super) enum Action {
    Check,
    Checked(Result<rtrust_update::Release, String>),
    Download,
    Downloaded(Result<std::path::PathBuf, String>),
    #[cfg(target_os = "windows")]
    Install,
    #[cfg(target_os = "windows")]
    Started(Result<(), String>),
    GithubCheck,
    GithubChecked(Result<rtrust_update::github::ReleaseInfo, String>),
    GithubDownload,
    GithubDownloaded(Result<std::path::PathBuf, String>),
    GithubOpen,
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
            #[cfg(target_os = "windows")]
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
            Action::GithubCheck if !self.busy => {
                self.busy = true;
                self.updates.github.file = None;
                self.updates.github.release = None;
                self.updates.github.status = "Проверка релизов GitHub…".into();
                return Task::perform(
                    async {
                        let kind = rtrust_update::github::kind_for_current_app()
                            .ok_or("Это приложение не публикует пакет на GitHub")?;
                        rtrust_update::github::check(kind).await
                    },
                    |r| Message::Update(Action::GithubChecked(r)),
                );
            }
            Action::GithubChecked(result) => {
                self.busy = false;
                match result {
                    Ok(release) => {
                        self.updates.github.status = github_status(&release);
                        self.updates.github.release = Some(release);
                    }
                    Err(e) => self.updates.github.status = e,
                }
            }
            Action::GithubDownload if !self.busy => {
                if let Some(asset) = self
                    .updates
                    .github
                    .release
                    .as_ref()
                    .filter(|r| r.newer)
                    .and_then(|r| r.asset.clone())
                {
                    let tag = self.updates.github.release.as_ref().unwrap().tag.clone();
                    self.busy = true;
                    self.updates.github.status = "Загрузка пакета и сверка с SHA256SUMS…".into();
                    return Task::perform(
                        async move {
                            let folder = rtrust_update::cache_dir()?.join("github").join(tag);
                            rtrust_update::github::download(&asset, &folder).await
                        },
                        |r| Message::Update(Action::GithubDownloaded(r)),
                    );
                }
            }
            Action::GithubDownloaded(result) => {
                self.busy = false;
                match result {
                    Ok(path) => {
                        self.updates.github.status = format!(
                            "Пакет сверен с SHA256SUMS и сохранён: {}. Установите его вручную: это не подписанный канал обновлений.",
                            path.display()
                        );
                        self.updates.github.file = Some(path);
                    }
                    Err(e) => self.updates.github.status = e,
                }
            }
            Action::GithubOpen => {
                if let Some(page) = self
                    .updates
                    .github
                    .release
                    .as_ref()
                    .map(|r| r.page.clone())
                    .filter(|p| !p.is_empty())
                {
                    open_page(&page);
                }
            }
            #[cfg(target_os = "windows")]
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
        let github_newer = self
            .updates
            .github
            .release
            .as_ref()
            .is_some_and(|r| r.newer && r.asset.is_some());
        let mut view = column![
            text("Обновление клиента и службы").size(18),
            text(&self.updates.status),
            button("Проверить обновления")
                .on_press_maybe((!self.busy).then_some(Message::Update(Action::Check))),
            button("Скачать проверенные пакеты")
                .on_press_maybe((!self.busy && newer).then_some(Message::Update(Action::Download))),
        ];
        #[cfg(target_os = "windows")]
        {
            view = view.push(
                button("Установить обновление").on_press_maybe(
                    (self.can_change_profiles()
                        && !self.dirty
                        && self.store_conflict.is_none()
                        && self.updates.staged.is_some())
                    .then_some(Message::Update(Action::Install)),
                ),
            );
        }
        #[cfg(not(target_os = "windows"))]
        let _ = newer;
        view = view.push(text("Релизы GitHub").size(16));
        view = view.push(text("SHA256SUMS не подписан. Совпадение хеша не заменяет канал обновлений и не устанавливает пакет."));
        view = view.push(text(&self.updates.github.status));
        view = view.push(
            button("Проверить GitHub")
                .on_press_maybe((!self.busy).then_some(Message::Update(Action::GithubCheck))),
        );
        view = view.push(button("Скачать проверенный пакет").on_press_maybe(
            (!self.busy && github_newer).then_some(Message::Update(Action::GithubDownload)),
        ));
        view = view.push(
            button("Открыть страницу релиза").on_press_maybe(
                self.updates
                    .github
                    .release
                    .as_ref()
                    .is_some_and(|r| !r.page.is_empty())
                    .then_some(Message::Update(Action::GithubOpen)),
            ),
        );
        view.spacing(8).into()
    }
}

fn github_status(release: &rtrust_update::github::ReleaseInfo) -> String {
    if !release.newer {
        return format!(
            "GitHub: {} — новее установленной {} нет.",
            release.version,
            env!("CARGO_PKG_VERSION")
        );
    }
    match &release.asset {
        Some(asset) => format!(
            "GitHub: {} новее установленной {}. Пакет {} есть в SHA256SUMS. Установка вручную.",
            release.version,
            env!("CARGO_PKG_VERSION"),
            asset.name
        ),
        None => format!(
            "GitHub: {} новее, но пакета для этой платформы в релизе нет.",
            release.version
        ),
    }
}

/// Show the release page. The page is a fixed GitHub tag URL, never a package.
fn open_page(page: &str) {
    let allowed = page.starts_with("https://github.com/onixus/Rust-trustvpn/releases/tag/");
    if !allowed {
        return;
    }
    let mut command = std::process::Command::new(if cfg!(windows) {
        "cmd"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    if cfg!(windows) {
        command.args(["/C", "start", "", page]);
    } else {
        command.arg(page);
    }
    let _ = command.spawn();
}
