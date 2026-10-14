#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
use rtrust_desktop::{Controller, Summary, View};
use tauri::{Manager, State};
use tokio::sync::Mutex;
type Shared = std::sync::Arc<Mutex<Controller>>;
fn note_pending(c: &mut Controller, result: Result<Summary, String>) {
    c.status = match result {
        Ok(p) => format!(
            "Pending import: {}. Confirm it under Profiles, Add profile.",
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
/// The shared credential-free view plus which saved profile the live session
/// was started from, so the profile list can mark it without guessing.
#[derive(serde::Serialize)]
struct WebView {
    #[serde(flatten)]
    view: View,
    connected_profile: Option<usize>,
}
fn web_view(c: &Controller) -> WebView {
    WebView {
        connected_profile: c.session.as_ref().and(c.connected_profile),
        view: c.view(),
    }
}
#[tauri::command]
async fn view(russian: Option<bool>, state: State<'_, Shared>) -> Result<WebView, String> {
    let mut c = state.lock().await;
    if let Some(session) = &c.session {
        let health = session.lifecycle_health().await;
        c.status = health
            .err()
            .unwrap_or_else(|| session.status_summary(russian.unwrap_or(false)));
    }
    Ok(web_view(&c))
}
#[tauri::command]
async fn diagnostic_cancel(state: State<'_, Shared>) -> Result<(), String> {
    state.lock().await.diagnostics.cancel();
    Ok(())
}
#[tauri::command]
async fn diagnostic_start(
    target: String,
    action: String,
    state: State<'_, Shared>,
) -> Result<(), String> {
    use rtrust_desktop::diagnostics::{self, Action, FollowUp};
    let target = diagnostics::Target::parse(&target)?;
    let shared = state.inner().clone();
    let mut c = shared.lock().await;
    let mut session = c.session.clone().ok_or("Connect the system VPN first")?;
    if !session.is_tun() {
        return Err("System diagnostics require TUN or whole-device mode".into());
    }
    let mut epoch = c.session_epoch;
    let mut generation = session.observations().generation;
    let previous =
        c.diagnostics
            .current_report(epoch, generation, rtrust_control::observations::now_ms());
    let follow_action = if action == "reconnect" {
        Action::Reconnect
    } else {
        Action::Recheck
    };
    c.diagnostics.ensure_ready()?;
    let endpoint = match action.as_str() {
        "recheck" => false,
        "reconnect"
            if previous
                .as_ref()
                .is_some_and(|r| r.verdict().actions.contains(&Action::Reconnect)) =>
        {
            if let rtrust_desktop::connection::Session::Tun(client, _) = &session
                && client.status().always_on == Some(true)
            {
                return Err("Disable Always-on explicitly before reconnecting".into());
            }
            let index = c
                .connected_profile
                .ok_or("Connected profile identity unavailable")?;
            let revision = c.revision;
            c.disconnect().await?;
            c.connect_profile(revision, index).await?;
            session = c.session.clone().ok_or("Reconnection failed")?;
            epoch = c.session_epoch;
            generation = session.observations().generation;
            false
        }
        "check_endpoint"
            if previous
                .as_ref()
                .is_some_and(|r| r.verdict().actions.contains(&Action::CheckEndpoint)) =>
        {
            true
        }
        _ => return Err("This diagnostic action is unavailable or historical".into()),
    };
    let selection = (c.vault.connection.mode == rtrust_store::Mode::Tun)
        .then(|| c.vault.connection.effective_selection());
    let context = c
        .vault
        .connection
        .managed_routes
        .as_ref()
        .map(|m| rtrust_profile::routing::Context {
            source: rtrust_profile::routing::Source::ManagedUnknown,
            revision: Some(m.revision.clone()),
        })
        .unwrap_or(rtrust_profile::routing::Context {
            source: rtrust_profile::routing::Source::Local,
            revision: None,
        });
    let ticket = c.diagnostics.begin(epoch, generation)?;
    let task_state = shared.clone();
    let task = tokio::spawn(async move {
        let mut report = if endpoint {
            let mut report = previous.expect("checked current report");
            let check = diagnostics::check_endpoint(session).await;
            if !report.attach_endpoint(check) {
                return;
            }
            report
        } else {
            let mut report = diagnostics::run(target, session, selection, context).await;
            if let Some(previous) = previous {
                report.follows = Some(FollowUp {
                    action: follow_action,
                    previous_cause: previous.verdict().cause,
                    previous_finished_at_ms: previous.finished_at_ms,
                });
            }
            report
        };
        // No controller lock is held while resolver/route/TLS work runs.
        let mut c = task_state.lock().await;
        let Some(current) = c.session.as_ref() else {
            return;
        };
        let current_generation = current.observations().generation;
        let current_epoch = c.session_epoch;
        if report.lifecycle.generation != current_generation {
            report.https = diagnostics::Fact::SessionChanged;
        }
        c.diagnostics
            .finish(ticket, current_epoch, current_generation, report);
    });
    c.diagnostics.own(task.abort_handle());
    Ok(())
}
#[tauri::command]
async fn diagnostic_edit(text: String, state: State<'_, Shared>) -> Result<(), String> {
    state
        .lock()
        .await
        .diagnostics
        .edit_export(text)
        .map_err(str::to_owned)
}
#[tauri::command]
async fn diagnostic_replace(state: State<'_, Shared>) -> Result<(), String> {
    state.lock().await.diagnostics.replace_export();
    Ok(())
}
#[tauri::command]
async fn diagnostic_export(state: State<'_, Shared>) -> Result<(), String> {
    let text = {
        let c = state.lock().await;
        c.view()
            .diagnostics
            .export
            .ok_or("Run a diagnostic first")?
    };
    if let Some(file) = rfd::AsyncFileDialog::new()
        .set_title("Save redacted local diagnostic")
        .set_file_name("vpn-diagnostic.json")
        .save_file()
        .await
    {
        rtrust_store::write_private(file.path(), text.as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(())
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
async fn connect(revision: u64, index: usize, state: State<'_, Shared>) -> Result<(), String> {
    state.lock().await.connect_profile(revision, index).await
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
    let snapshot = tokio::time::timeout(std::time::Duration::from_secs(30), client.snapshot())
        .await
        .map_err(|_| "Portal sync exceeded 30 seconds")??;
    next = rtrust_desktop::sync::prepare(&next, snapshot)?;
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
async fn portal_renew(revision: u64, state: State<'_, Shared>) -> Result<(), String> {
    let c = state.lock().await;
    c.check(revision)?;
    let client = rtrust_portal::Client::restore()?;
    if c.vault.connection.sync.origin != client.address() {
        return Err("Portal registration changed".into());
    }
    client.renew_access().await?.remember()
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
        .manage(std::sync::Arc::new(Mutex::new(controller)))
        .invoke_handler(tauri::generate_handler![
            ui_ready,
            diagnostic_cancel,
            diagnostic_start,
            diagnostic_edit,
            diagnostic_replace,
            diagnostic_export,
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
            portal_renew,
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

#[cfg(test)]
mod tests {
    #[test]
    fn view_model_has_no_session_profile_or_portal_baselines_when_idle() {
        let c = rtrust_desktop::Controller::smoke();
        let v = serde_json::to_value(super::web_view(&c)).expect("serializable view");
        assert!(v["connected_profile"].is_null());
        assert_eq!(v["connected"], false);
        assert!(v["observations"].is_null());
        let tracked = &v["connection"]["sync"]["tracked"];
        assert!(tracked.as_array().is_some_and(Vec::is_empty));
    }
}
