fn main() {
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "ui_ready",
            "view",
            "preview",
            "pick_import",
            "commit_import",
            "edit_profile",
            "save_settings",
            "connect",
            "disconnect",
            "export_profile",
            "portal_enroll",
            "portal_sync",
            "portal_forget",
            "portal_auto",
            "portal_upload",
        ]),
    ))
    .expect("Tauri assets and capabilities");
}
