fn main() {
    println!("cargo:rerun-if-changed=../../packaging/branding/icon.ico");
    #[cfg(target_os = "windows")]
    tauri_winres::WindowsResource::new()
        .set_icon("../../packaging/branding/icon.ico")
        .compile()
        .expect("Embed the client icon in the Windows executable");
}
