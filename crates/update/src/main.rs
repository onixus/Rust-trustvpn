#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
#[cfg(target_os = "windows")]
mod windows;
#[tokio::main]
async fn main() {
    #[cfg(target_os = "windows")]
    if let Err(error) = windows::run().await {
        windows::notify_error(&error);
        eprintln!("{error}");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("System update helper is currently available on Windows only");
        std::process::exit(1);
    }
}
