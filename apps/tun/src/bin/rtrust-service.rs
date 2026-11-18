#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if let Err(error) = rtrust_tun::service::run().await {
        let journal = rtrust_journal::service();
        journal.lifecycle_at(rtrust_journal::Level::Critical, "service_stopped");
        let _ = journal.flush(std::time::Duration::from_secs(2));
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
        let journal = rtrust_journal::service();
        journal.lifecycle_at(rtrust_journal::Level::Critical, "service_stopped");
        let _ = journal.flush(std::time::Duration::from_secs(2));
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    if let Err(error) = rtrust_tun::macos::run().await {
        let journal = rtrust_journal::service();
        journal.lifecycle_at(rtrust_journal::Level::Critical, "service_stopped");
        let _ = journal.flush(std::time::Duration::from_secs(2));
        eprintln!("{error}");
        std::process::exit(1);
    }
}
