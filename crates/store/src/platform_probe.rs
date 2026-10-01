//! Explicit diagnostic using a synthetic credential and a temporary encrypted vault.
//! Never reads or changes the user's profile vault or its master key.
use super::*;

pub fn run() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let account = format!("probe-{}-{}", std::process::id(), rand_id());
    let entry = keyring::Entry::new("org.rtrusttunnel.storage-probe", &account)
        .map_err(|_| Error::Vault)?;
    let mut bytes = Zeroizing::new(vec![0; 32]);
    OsRng.fill_bytes(&mut bytes);
    entry.set_secret(&bytes).map_err(|_| Error::Vault)?;
    let result = (|| {
        let vault = Vault {
            profiles: vec![Profile::import("hostname='probe.example'\naddresses=['192.0.2.1:443']\nusername='probe'\npassword='RTRUST_STORAGE_PROBE_CANARY'\n").map_err(|_| Error::Invalid)?],
            connection: ConnectionSettings { socks_port: 2088, ..Default::default() },
        };
        save_in(dir.path(), &vault, None, |_| {
            entry
                .get_secret()
                .map(Zeroizing::new)
                .map_err(|_| Error::Vault)
        })?;
        let data = fs::read(dir.path().join("profiles.rtrust"))?;
        if data
            .windows(b"RTRUST_STORAGE_PROBE_CANARY".len())
            .any(|w| w == b"RTRUST_STORAGE_PROBE_CANARY")
        {
            return Err(Error::Invalid);
        }
        let status = std::process::Command::new(std::env::current_exe()?)
            .arg("--ci-storage-read")
            .env("RTRUST_PROBE_DIR", dir.path())
            .env("RTRUST_PROBE_ACCOUNT", &account)
            .status()?;
        if !status.success() {
            return Err(Error::Vault);
        }
        Ok(())
    })();
    let cleanup = entry.delete_credential().map_err(|_| Error::Vault);
    result.and(cleanup)
}
fn rand_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn child() -> Result<()> {
    let directory = std::env::var_os("RTRUST_PROBE_DIR").ok_or(Error::Invalid)?;
    let account = std::env::var("RTRUST_PROBE_ACCOUNT").map_err(|_| Error::Invalid)?;
    if !account.starts_with("probe-") || account.len() > 80 {
        return Err(Error::Invalid);
    }
    let entry = keyring::Entry::new("org.rtrusttunnel.storage-probe", &account)
        .map_err(|_| Error::Vault)?;
    let key = Zeroizing::new(entry.get_secret().map_err(|_| Error::Vault)?);
    let path = Path::new(&directory).join("profiles.rtrust");
    if fs::metadata(&path)?.len() > MAX_STORE as u64 {
        return Err(Error::Invalid);
    }
    let vault = decrypt(&fs::read(path)?, &key)?;
    if vault.profiles.len() != 1
        || vault.profiles[0].endpoint.password.expose() != "RTRUST_STORAGE_PROBE_CANARY"
        || vault.connection.socks_port != 2088
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
