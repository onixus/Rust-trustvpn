use super::*;
use iced::widget::column;
#[derive(Clone, Copy)]
pub(super) enum Choice {
    Local,
    Disk,
    Both,
    Cancel,
}
impl App {
    pub(super) fn store_conflict_loaded(
        &mut self,
        result: Result<(rtrust_store::Vault, Option<Vec<u8>>), String>,
    ) -> Task<Message> {
        self.store_recovery = false;
        self.busy = false;
        self.pending_close = None;
        self.autosave_due = None;
        match result {
            Ok(snapshot) => {
                self.store_conflict = Some(snapshot);
                self.status =
                    "Хранилище изменено другим окном. Выберите, какие данные сохранить.".into();
            }
            Err(e) => {
                self.status = format!(
                    "Не удалось прочитать конфликтующую версию: {e}. Локальные изменения сохранены в этом окне."
                )
            }
        }
        Self::show_window()
    }
    pub(super) fn resolve_store_conflict(&mut self, choice: Choice) -> Task<Message> {
        if !self.can_change_profiles() {
            return Task::none();
        }
        let Some((disk, revision)) = self.store_conflict.take() else {
            return Task::none();
        };
        let recovery = std::mem::take(&mut self.store_recovery);
        match choice {
            Choice::Cancel => Task::none(),
            Choice::Disk => {
                self.boot_connect_pending = false;
                self.autosave_due = None;
                let loaded = self.update(Message::Loaded(Ok((disk, revision))));
                if recovery {
                    self.dirty = true;
                    self.update(Message::Save)
                } else {
                    loaded
                }
            }
            Choice::Local | Choice::Both => {
                if matches!(choice, Choice::Both) {
                    for profile in disk.profiles {
                        if !self.profiles.contains(&profile) {
                            self.profiles.push(profile);
                        }
                    }
                }
                self.revision = revision;
                self.dirty = true;
                self.update(Message::Save)
            }
        }
    }
    pub(super) fn store_conflict_view(&self) -> Element<'_, Message> {
        let Some((disk, _)) = &self.store_conflict else {
            return column![].into();
        };
        let ready = self.can_change_profiles();
        if self.store_recovery {
            return column![text("Восстановление предыдущей копии").size(22),
                text(format!("В зашифрованной резервной копии {} профилей. Восстановление заменит текущее хранилище и настройки, включая синхронизацию и автоподключение. Сейчас VPN не подключится.",disk.profiles.len())),
                button("Подтвердить восстановление").on_press_maybe(ready.then_some(Message::ResolveStore(Choice::Disk))),
                button("Отмена").on_press(Message::ResolveStore(Choice::Cancel))].spacing(12).into();
        }
        column![
            text("Конфликт сохранения").size(22),
            text(format!("В этом окне: {} профилей. На диске: {}.", self.profiles.len(), disk.profiles.len())),
            text("Локальная версия заменит данные на диске. Версия с диска отбросит несохранённые изменения этого окна. «Оставить оба» добавит отличающиеся профили с диска и сохранит локальные настройки и профиль по умолчанию."),
            text(format!("Локальные: {}", self.profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "))),
            text(format!("На диске: {}", disk.profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>().join(", "))),
            button("Оставить оба набора").on_press_maybe(ready.then_some(Message::ResolveStore(Choice::Both))),
            button("Сохранить локальную версию").on_press_maybe(ready.then_some(Message::ResolveStore(Choice::Local))),
            button("Принять версию с диска").on_press_maybe(ready.then_some(Message::ResolveStore(Choice::Disk))),
        ].spacing(12).into()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keep_both_deduplicates_exact_profiles_and_preserves_default() {
        let mut app = crate::tests::app();
        let mut changed = app.profiles[0].clone();
        changed.name = "remote edit".into();
        let mut profiles = app.profiles.clone();
        profiles.push(changed);
        let _ = app.store_conflict_loaded(Ok((
            rtrust_store::Vault {
                profiles,
                connection: Default::default(),
            },
            Some(vec![7]),
        )));
        assert!(!app.busy && app.pending_close.is_none());
        let first = app.profiles[0].clone();
        let _ = app.resolve_store_conflict(Choice::Both);
        assert_eq!(app.profiles.len(), 3);
        assert_eq!(app.profiles[0], first);
        assert_eq!(app.revision, Some(vec![7]));
        assert!(app.dirty && app.busy);
    }
    #[test]
    fn accepting_disk_never_autoconnects_or_writes() {
        let mut app = crate::tests::app();
        app.boot_connect_pending = true;
        let vault = rtrust_store::Vault {
            profiles: app.profiles.clone(),
            connection: rtrust_store::ConnectionSettings {
                auto_connect: true,
                ..Default::default()
            },
        };
        let _ = app.store_conflict_loaded(Ok((vault, Some(vec![9]))));
        let _ = app.resolve_store_conflict(Choice::Disk);
        assert!(!app.connecting && !app.dirty && !app.busy);
        assert_eq!(app.revision, Some(vec![9]));
    }
}
