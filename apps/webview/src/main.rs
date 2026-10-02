#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use rtrust_desktop::{Controller, Summary, View};
use tauri::{Manager, State};
use tokio::sync::Mutex;
type Shared = Mutex<Controller>;
fn note_pending(c: &mut Controller, result: Result<Summary, String>) {
    c.status = match result {
        Ok(p) => format!(
            "Pending import: {}. Confirm in the Profiles section.",
            p.name
        ),
        Err(e) => e,
    };
}
#[tauri::command]
async fn ui_ready(app: tauri::AppHandle) -> Result<(), String> {
    if !std::env::args().any(|s| s == "--ci-smoke") {
        return Ok(());
    }
    let window = app
        .get_webview_window("main")
        .ok_or("Main window missing")?;
    window.close().map_err(|e| e.to_string())?;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    if window.is_visible().map_err(|e| e.to_string())? {
        app.exit(1);
        return Err("Close did not hide the window".into());
    }
    window.show().map_err(|e| e.to_string())?;
    if !window.is_visible().map_err(|e| e.to_string())? {
        app.exit(1);
        return Err("Window restore failed".into());
    }
    println!("PASS WebView local assets, JavaScript IPC, close-to-hide and restore");
    app.exit(0);
    Ok(())
}
#[tauri::command]
async fn view(state: State<'_, Shared>) -> Result<View, String> {
    let mut c = state.lock().await;
    if let Some(session) = &c.session {
        c.status = session.health().await.err().unwrap_or_default();
    }
    Ok(c.view())
}
#[tauri::command]
async fn preview(input: String, state: State<'_, Shared>) -> Result<Summary, String> {
    let input = zeroize::Zeroizing::new(input);
    state.lock().await.preview(&input)
}
#[tauri::command]
async fn pick_import(state: State<'_, Shared>) -> Result<Option<Summary>, String> {
    let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Import VPN profile")
        .pick_file()
        .await
    else {
        return Ok(None);
    };
    let bytes = rtrust_store::read_bounded(file.path(), rtrust_profile::MAX_INPUT)
        .map_err(|e| e.to_string())?;
    let bytes = zeroize::Zeroizing::new(bytes);
    let input = std::str::from_utf8(&bytes).map_err(|_| "Profile must be UTF-8")?;
    state.lock().await.preview(input).map(Some)
}
#[tauri::command]
async fn commit_import(revision: u64, state: State<'_, Shared>) -> Result<(), String> {
    state.lock().await.import(revision)
}
#[tauri::command]
async fn edit_profile(
    revision: u64,
    action: String,
    index: usize,
    state: State<'_, Shared>,
) -> Result<(), String> {
    state.lock().await.edit(revision, &action, index)
}
#[tauri::command]
async fn save_settings(
    revision: u64,
    settings: rtrust_store::ConnectionSettings,
    state: State<'_, Shared>,
) -> Result<(), String> {
    state.lock().await.settings(revision, settings)
}
#[tauri::command]
async fn connect(revision: u64, state: State<'_, Shared>) -> Result<(), String> {
    state.lock().await.connect(revision).await
}
#[tauri::command]
async fn disconnect(state: State<'_, Shared>) -> Result<(), String> {
    state.lock().await.disconnect().await
}
#[tauri::command]
async fn export_profile(
    revision: u64,
    index: usize,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let profile = {
        let c = state.lock().await;
        if c.revision != revision {
            return Err("Profiles changed; refresh".into());
        }
        c.vault
            .profiles
            .get(index)
            .cloned()
            .ok_or("Profile unavailable")?
    };
    let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Export includes VPN credentials")
        .set_file_name("profile.json")
        .save_file()
        .await
    else {
        return Ok(());
    };
    let data = profile
        .export(rtrust_profile::Format::Json)
        .map_err(|e| e.to_string())?;
    rtrust_store::write_private(file.path(), data.content.as_bytes()).map_err(|e| e.to_string())
}
#[tauri::command]
async fn portal_enroll(
    revision: u64,
    address: String,
    code: String,
    name: String,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let mut c = state.lock().await;
    c.check(revision)?;
    let code = zeroize::Zeroizing::new(code);
    let client = rtrust_portal::Client::new(&address)?
        .enroll(&code, &name)
        .await?;
    client.remember()?;
    let mut next = c.vault.clone();
    next.connection.sync = rtrust_store::SyncSettings {
        origin: client.address().into(),
        ..Default::default()
    };
    c.save(next)
}
async fn sync_profiles(c: &mut Controller) -> Result<(), String> {
    let client = rtrust_portal::Client::restore()?;
    let mut next = c.vault.clone();
    if next.connection.sync.origin != client.address() {
        return Err("Portal registration changed; enroll again".into());
    }
    let mut total = 0;
    for remote in client.list().await? {
        let old = next
            .connection
            .sync
            .tracked
            .iter()
            .find(|p| p.id == remote.id)
            .cloned();
        if old.as_ref().is_some_and(|p| p.revision == remote.revision) {
            continue;
        }
        let profile = client.download(&remote).await?;
        total += profile
            .export(rtrust_profile::Format::Json)
            .map_err(|e| e.to_string())?
            .content
            .len();
        if total > 4 * rtrust_profile::MAX_INPUT {
            return Err("Profile sync exceeds 4 MiB".into());
        }
        if let Some(old) = old {
            if let Some(index) = next.profiles.iter().position(|p| p == &old.baseline) {
                next.profiles[index] = profile.clone()
            } else {
                return Err(
                    "Local profile changed; resolve the conflict in Native UI before syncing"
                        .into(),
                );
            }
        } else {
            next.profiles.push(profile.clone())
        }
        next.connection.sync.tracked.retain(|p| p.id != remote.id);
        next.connection
            .sync
            .tracked
            .push(rtrust_store::TrackedProfile {
                id: remote.id,
                revision: remote.revision,
                baseline: profile,
            });
    }
    c.save(next)
}
#[tauri::command]
async fn portal_sync(revision: u64, state: State<'_, Shared>) -> Result<(), String> {
    let mut c = state.lock().await;
    c.check(revision)?;
    sync_profiles(&mut c).await
}
#[tauri::command]
async fn portal_auto(revision: u64, enabled: bool, state: State<'_, Shared>) -> Result<(), String> {
    let mut c = state.lock().await;
    c.check(revision)?;
    if enabled {
        let client = rtrust_portal::Client::restore()?;
        if c.vault.connection.sync.origin != client.address() {
            return Err("Portal registration changed".into());
        }
    }
    let mut next = c.vault.clone();
    next.connection.sync.enabled = enabled;
    c.save(next)
}
#[tauri::command]
async fn portal_upload(
    revision: u64,
    index: usize,
    state: State<'_, Shared>,
) -> Result<(), String> {
    let c = state.lock().await;
    c.check(revision)?;
    let profile = c.vault.profiles.get(index).ok_or("Profile unavailable")?;
    let client = rtrust_portal::Client::restore()?;
    let confirmed = rfd::AsyncMessageDialog::new()
        .set_title("Upload VPN credentials")
        .set_description(format!(
            "Send profile {} and its credentials to {}?",
            profile.name,
            client.address()
        ))
        .set_buttons(rfd::MessageButtons::YesNo)
        .show()
        .await;
    if confirmed != rfd::MessageDialogResult::Yes {
        return Ok(());
    }
    let preview = client.preview_upload(profile).await?;
    client.commit(&preview).await
}
#[tauri::command]
async fn portal_forget(revision: u64, state: State<'_, Shared>) -> Result<(), String> {
    let mut c = state.lock().await;
    c.check(revision)?;
    rtrust_portal::Client::forget()?;
    let mut next = c.vault.clone();
    next.connection.sync = Default::default();
    c.save(next)
}
fn main() {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if std::env::args().nth(1).as_deref() == Some("--ci-service-smoke") {
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(rtrust_control::Client::prepare_update());
        match result {
            Ok(_) => println!("PASS authenticated service channel"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1)
            }
        }
        return;
    }
    #[cfg(target_os = "linux")]
    {
        // Before GTK/Tauri creates threads, restrict backend selection even
        // when a desktop session also advertises an XWayland DISPLAY.
        unsafe { std::env::set_var("GDK_BACKEND", "wayland") };
        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            eprintln!("A Wayland session is required");
            std::process::exit(1)
        }
    }
    let mut controller = match if std::env::args().any(|s| s == "--ci-smoke") {
        Ok(Controller::smoke())
    } else {
        Controller::load()
    } {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    if let Some(input) = std::env::args().nth(1).filter(|s| !s.starts_with("--")) {
        let result = if ["tt://", "hy2://", "hysteria2://"]
            .iter()
            .any(|scheme| input.starts_with(scheme))
        {
            controller.preview(&input)
        } else {
            rtrust_store::read_bounded(std::path::Path::new(&input), rtrust_profile::MAX_INPUT)
                .map_err(|e| e.to_string())
                .and_then(|data| {
                    let data = zeroize::Zeroizing::new(data);
                    let text = std::str::from_utf8(&data).map_err(|_| "Profile must be UTF-8")?;
                    controller.preview(text)
                })
        };
        note_pending(&mut controller, result);
    }
    tauri::Builder::default()
        .manage(Mutex::new(controller))
        .invoke_handler(tauri::generate_handler![
            ui_ready,
            view,
            preview,
            pick_import,
            commit_import,
            edit_profile,
            save_settings,
            connect,
            disconnect,
            export_profile,
            portal_enroll,
            portal_sync,
            portal_forget,
            portal_auto,
            portal_upload
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                {
                    let shared = handle.state::<Shared>();
                    let mut c = shared.lock().await;
                    if c.vault.connection.auto_connect
                        && !std::env::args().any(|s| s == "--no-auto-connect")
                    {
                        let revision = c.revision;
                        if let Err(e) = c.connect(revision).await {
                            c.status = e
                        }
                    }
                }
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    let shared = handle.state::<Shared>();
                    let mut c = shared.lock().await;
                    if c.session.is_none()
                        && c.vault.connection.sync.enabled
                        && let Err(e) = sync_profiles(&mut c).await
                    {
                        c.status = e;
                    }
                }
            });
            let open = tauri::menu::MenuItem::with_id(
                app,
                "open",
                "Open R-TrustTunnel",
                true,
                None::<&str>,
            )?;
            let quit = tauri::menu::MenuItem::with_id(
                app,
                "quit",
                "Disconnect and quit",
                true,
                None::<&str>,
            )?;
            let menu = tauri::menu::Menu::with_items(app, &[&open, &quit])?;
            let icon = tauri::image::Image::new_owned(
                include_bytes!("../../../packaging/branding/tray-32.rgba").to_vec(),
                32,
                32,
            );
            tauri::tray::TrayIconBuilder::new()
                .icon(icon)
                .icon_as_template(cfg!(target_os = "macos"))
                .menu(&menu)
                .tooltip("R-TrustTunnel")
                .on_menu_event(|app, event| {
                    if event.id.as_ref() == "open"
                        && let Some(w) = app.get_webview_window("main")
                    {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                    if event.id.as_ref() == "quit" {
                        let app = app.clone();
                        tauri::async_runtime::spawn(async move {
                            let result = app.state::<Shared>().lock().await.disconnect().await;
                            if result.is_ok() {
                                app.exit(0)
                            } else if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                            }
                        });
                    }
                })
                .build(app)?;
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .build(tauri::generate_context!())
        .expect("Desktop application runtime")
        .run(|app, event| {
            // macOS hands tt:// and hy2:// links to the running app as Apple
            // Events; Windows and Linux pass them as the first argument instead.
            #[cfg(target_os = "macos")]
            if let tauri::RunEvent::Opened { urls } = &event
                && let Some(link) = urls
                    .iter()
                    .rev()
                    .find(|url| ["tt", "hy2", "hysteria2"].contains(&url.scheme()))
            {
                let (app, link) = (app.clone(), zeroize::Zeroizing::new(link.to_string()));
                tauri::async_runtime::spawn(async move {
                    let shared = app.state::<Shared>();
                    let mut c = shared.lock().await;
                    let result = c.preview(&link);
                    note_pending(&mut c, result);
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                });
            }
            if let tauri::RunEvent::ExitRequested {
                api, code: None, ..
            } = event
            {
                api.prevent_exit();
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let shared = app.state::<Shared>();
                    let mut c = shared.lock().await;
                    match c.disconnect().await {
                        Ok(()) => {
                            drop(c);
                            app.exit(0)
                        }
                        Err(e) => {
                            c.status = e;
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                            }
                        }
                    }
                });
            }
        });
}
