#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if let Err(error) = rtrust_tun::service::run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn main() {
    eprintln!("The service currently requires Linux");
    std::process::exit(1);
}

#[cfg(target_os = "windows")]
fn main() {
    if let Err(error) = rtrust_tun::windows::dispatch() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    if let Err(error) = rtrust_tun::macos::run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
