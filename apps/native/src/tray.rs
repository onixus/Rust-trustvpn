//! All native handles stay on the window event-loop thread, including on macOS.
use std::cell::RefCell;
#[derive(Clone, Copy, Debug)]
pub enum Action {
    Show,
    Toggle,
    Exit,
    #[cfg(target_os = "linux")]
    Unavailable,
}
#[cfg(not(target_os = "linux"))]
type Handle = tray_icon::TrayIcon;
#[cfg(target_os = "linux")]
type Handle = ksni::blocking::Handle<LinuxTray>;
thread_local! { static HANDLE: RefCell<Option<Handle>> = const { RefCell::new(None) }; }
fn pixels() -> Vec<u8> {
    include_bytes!("../../../packaging/branding/tray-32.rgba").to_vec()
}
#[cfg(not(target_os = "linux"))]
pub fn initialize() -> bool {
    use tray_icon::{
        Icon, TrayIconBuilder,
        menu::{Menu, MenuItem},
    };
    HANDLE.with(|slot| {
        if slot.borrow().is_some() {
            return true;
        }
        let make = || -> Result<Handle, Box<dyn std::error::Error>> {
            let menu = Menu::new();
            for (id, label) in [
                ("show", "Открыть"),
                ("toggle", "Подключить / отключить"),
                ("exit", "Выход"),
            ] {
                menu.append(&MenuItem::with_id(id, label, true, None))?;
            }
            Ok(TrayIconBuilder::new()
                .with_tooltip("R-TrustTunnel")
                .with_icon(Icon::from_rgba(pixels(), 32, 32).expect("fixed icon dimensions"))
                .with_icon_as_template(cfg!(target_os = "macos"))
                .with_menu(Box::new(menu))
                .build()?)
        };
        match make() {
            Ok(handle) => {
                *slot.borrow_mut() = Some(handle);
                true
            }
            Err(_) => false,
        }
    })
}
#[cfg(not(target_os = "linux"))]
pub fn poll() -> Vec<Action> {
    use tray_icon::{MouseButton, MouseButtonState, TrayIconEvent, menu::MenuEvent};
    let mut actions = Vec::new();
    while let Ok(event) = MenuEvent::receiver().try_recv() {
        match event.id.as_ref() {
            "show" => actions.push(Action::Show),
            "toggle" => actions.push(Action::Toggle),
            "exit" => actions.push(Action::Exit),
            _ => {}
        }
    }
    while let Ok(event) = TrayIconEvent::receiver().try_recv() {
        if matches!(
            event,
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
        ) {
            actions.push(Action::Show);
        }
    }
    actions
}
#[cfg(target_os = "linux")]
struct LinuxTray;
#[cfg(target_os = "linux")]
static EVENTS: std::sync::Mutex<Vec<Action>> = std::sync::Mutex::new(Vec::new());
#[cfg(target_os = "linux")]
fn send(action: Action) {
    EVENTS.lock().unwrap().push(action);
}
#[cfg(target_os = "linux")]
impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "org.rtrusttunnel.Native".into()
    }
    fn title(&self) -> String {
        "R-TrustTunnel".into()
    }
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        let mut bytes = pixels();
        for rgba in bytes.as_chunks_mut::<4>().0 {
            rgba.rotate_right(1);
        }
        vec![ksni::Icon {
            width: 32,
            height: 32,
            data: bytes,
        }]
    }
    fn activate(&mut self, _x: i32, _y: i32) {
        send(Action::Show);
    }
    fn watcher_offline(&self, _reason: ksni::OfflineReason) -> bool {
        send(Action::Unavailable);
        false
    }
    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        [
            ("Открыть", Action::Show),
            ("Подключить / отключить", Action::Toggle),
            ("Выход", Action::Exit),
        ]
        .into_iter()
        .map(|(label, action)| {
            ksni::menu::StandardItem {
                label: label.into(),
                activate: Box::new(move |_| send(action)),
                ..Default::default()
            }
            .into()
        })
        .collect()
    }
}
#[cfg(target_os = "linux")]
pub fn initialize() -> bool {
    use ksni::blocking::TrayMethods;
    HANDLE.with(|slot| {
        match LinuxTray
            .disable_dbus_name(std::env::var_os("FLATPAK_ID").is_some())
            .spawn()
        {
            Ok(handle) => {
                *slot.borrow_mut() = Some(handle);
                true
            }
            Err(_) => false,
        }
    })
}
#[cfg(target_os = "linux")]
pub fn poll() -> Vec<Action> {
    std::mem::take(&mut *EVENTS.lock().unwrap())
}
