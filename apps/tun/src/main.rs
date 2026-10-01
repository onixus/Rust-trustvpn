#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(target_os = "linux")]
async fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::io::Write;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 3 {
        return Err("Usage: rtrust-tun PROFILE INTERFACE IPV4_ADDRESS".into());
    }
    let name = args[1].to_str().ok_or("Invalid interface name")?;
    if name.is_empty()
        || name.len() > 15
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid interface name".into());
    }
    let address: std::net::Ipv4Addr = args[2].to_str().ok_or("Invalid address")?.parse()?;
    if address.is_unspecified()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_loopback()
    {
        return Err("Invalid IPv4 address".into());
    }
    let bytes =
        rtrust_store::read_bounded(std::path::Path::new(&args[0]), rtrust_profile::MAX_INPUT)?;
    let profile = rtrust_profile::Profile::import(std::str::from_utf8(&bytes)?)?;
    let prepared = rtrust_tun::linux::Prepared::connect(&profile, name, address).await?;
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    println!("TUN {name} {address} IPv4 TCP/UDP ready; no default route, DNS or firewall changes");
    std::io::stdout().flush()?;
    tokio::select! {
        result = prepared.run() => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("Experimental TUN requires Linux");
    std::process::exit(1);
}
