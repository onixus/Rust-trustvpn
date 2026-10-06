//! Encrypted-at-rest profile store; the master key is only stored in the OS keyring.
pub mod platform_probe;
mod sync;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, OsRng, Payload, rand_core::RngCore},
};
use rtrust_profile::{MAX_INPUT, Profile};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
pub use sync::{SyncSettings, TrackedProfile};
use zeroize::Zeroizing;
const LEGACY_MAGIC: &[u8] = b"RTRUST1\0";
const MAGIC: &[u8] = b"RTRUST2\0";
const MAX_STORE: usize = 16 * MAX_INPUT;
#[derive(Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Mode {
    #[default]
    Socks,
    Tun,
    Full,
}
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSettings {
    #[serde(default)]
    pub sync: SyncSettings,
    #[serde(default)]
    pub auto_connect: bool,
    pub mode: Mode,
    pub socks_port: u16,
    pub networks: Vec<rtrust_control::Ipv4Net>,
    #[serde(default = "default_dns")]
    pub dns: std::net::Ipv4Addr,
    // Written only when used, so older releases can still read the vault.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<rtrust_control::Ipv4Net>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub exclude_lan: bool,
    /// Route policy of this device's group on the server; overrides the local
    /// TUN selection while present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_routes: Option<ManagedRoutes>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRoutes {
    pub group: String,
    pub revision: String,
    pub selection: rtrust_control::Selection,
}
impl ManagedRoutes {
    pub fn validate(&self) -> Result<()> {
        if !(1..=80).contains(&self.group.chars().count())
            || !(1..=64).contains(&self.revision.len())
        {
            return Err(Error::Invalid);
        }
        self.selection.validate().map_err(|_| Error::Invalid)
    }
}
fn default_dns() -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::new(1, 1, 1, 1)
}
impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            sync: SyncSettings::default(),
            auto_connect: false,
            mode: Mode::Socks,
            socks_port: 1080,
            networks: vec![],
            dns: default_dns(),
            exclude: vec![],
            exclude_lan: false,
            managed_routes: None,
        }
    }
}
impl ConnectionSettings {
    pub fn validate(&self) -> Result<()> {
        self.sync.validate()?;
        rtrust_control::validate_dns(self.dns).map_err(|_| Error::Invalid)?;
        if self.socks_port == 0 {
            return Err(Error::Invalid);
        }
        if (self.mode == Mode::Tun && self.managed_routes.is_none())
            || !self.networks.is_empty()
            || !self.exclude.is_empty()
        {
            self.selection().validate().map_err(|_| Error::Invalid)?;
        }
        if let Some(managed) = &self.managed_routes {
            managed.validate()?;
        }
        Ok(())
    }
    /// The local TUN selection, ignoring any server policy.
    pub fn selection(&self) -> rtrust_control::Selection {
        rtrust_control::Selection {
            include: self.networks.clone(),
            exclude: self.exclude.clone(),
            exclude_lan: self.exclude_lan,
        }
    }
    /// What TUN mode applies: the server policy when assigned, else local.
    pub fn effective_selection(&self) -> rtrust_control::Selection {
        self.managed_routes
            .as_ref()
            .map_or_else(|| self.selection(), |m| m.selection.clone())
    }
}
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vault {
    pub profiles: Vec<Profile>,
    pub connection: ConnectionSettings,
}
impl Vault {
    pub fn validate(&self) -> Result<()> {
        for profile in &self.profiles {
            profile.validate().map_err(|_| Error::Invalid)?;
        }
        self.connection.validate()?;
        if Zeroizing::new(serde_json::to_vec(self).map_err(|_| Error::Invalid)?).len() > MAX_STORE {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Secure storage is unavailable or locked; no plaintext fallback")]
    Vault,
    #[error("Cannot access profile storage")]
    Io,
    #[error("Profile storage is invalid, too large, or authentication failed")]
    Invalid,
    #[error("Another application is using the profile store")]
    Busy,
    #[error("Profile storage changed in another process")]
    Conflict,
}
type Result<T> = std::result::Result<T, Error>;
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::Io
    }
}

fn default_dir() -> Result<PathBuf> {
    Ok(
        directories::ProjectDirs::from("org", "RTrustTunnel", "RTrustTunnel")
            .ok_or(Error::Io)?
            .data_local_dir()
            .to_path_buf(),
    )
}
fn lock(dir: &Path) -> Result<File> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("profiles.lock"))?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|_| Error::Busy)?;
    Ok(file)
}
fn key(create: bool) -> Result<Zeroizing<Vec<u8>>> {
    let entry = keyring::Entry::new("org.rtrusttunnel.desktop", "profile-master-key-v1")
        .map_err(|_| Error::Vault)?;
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == 32 => Ok(Zeroizing::new(bytes)),
        Err(keyring::Error::NoEntry) if create => {
            let mut bytes = Zeroizing::new(vec![0; 32]);
            OsRng.fill_bytes(&mut bytes);
            entry.set_secret(&bytes).map_err(|_| Error::Vault)?;
            Ok(bytes)
        }
        _ => Err(Error::Vault),
    }
}
fn encrypt(vault: &Vault, key: &[u8]) -> Result<Vec<u8>> {
    vault.validate()?;
    let plain = Zeroizing::new(serde_json::to_vec(vault).map_err(|_| Error::Invalid)?);
    seal(&plain, key, MAGIC)
}
fn seal(plain: &[u8], key: &[u8], magic: &[u8]) -> Result<Vec<u8>> {
    if plain.len() > MAX_STORE {
        return Err(Error::Invalid);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid)?;
    let mut nonce = [0; 12];
    OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plain,
                aad: magic,
            },
        )
        .map_err(|_| Error::Invalid)?;
    let mut data = magic.to_vec();
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&encrypted);
    Ok(data)
}
fn decrypt(data: &[u8], key: &[u8]) -> Result<Vault> {
    if data.len() < 36
        || data.len() > MAX_STORE + 36
        || !(data.starts_with(MAGIC) || data.starts_with(LEGACY_MAGIC))
    {
        return Err(Error::Invalid);
    }
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| Error::Invalid)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                data[8..20].into(),
                Payload {
                    msg: &data[20..],
                    aad: &data[..8],
                },
            )
            .map_err(|_| Error::Invalid)?,
    );
    let vault = if data.starts_with(LEGACY_MAGIC) {
        Vault {
            profiles: serde_json::from_slice(&plain).map_err(|_| Error::Invalid)?,
            connection: ConnectionSettings::default(),
        }
    } else {
        serde_json::from_slice::<Vault>(&plain).map_err(|_| Error::Invalid)?
    };
    vault.validate()?;
    Ok(vault)
}
pub fn load() -> Result<Vault> {
    let dir = default_dir()?;
    let _lock = lock(&dir)?;
    let path = dir.join("profiles.rtrust");
    if !path.exists() {
        return Ok(Vault::default());
    }
    let bytes = read_bounded(&path, MAX_STORE + 36).map_err(|_| Error::Invalid)?;
    decrypt(&bytes, &key(false)?)
}
/// Compare the encrypted file revision before write: two instances cannot overwrite each other silently.
pub fn save(vault: &Vault, expected: Option<Vec<u8>>) -> Result<Vec<u8>> {
    save_in(&default_dir()?, vault, expected, key)
}
fn save_in(
    dir: &Path,
    vault: &Vault,
    expected: Option<Vec<u8>>,
    get_key: impl FnOnce(bool) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<Vec<u8>> {
    vault.validate()?;
    let _lock = lock(dir)?;
    let path = dir.join("profiles.rtrust");
    let current = if path.exists() {
        Some(read_bounded(&path, MAX_STORE + 36)?)
    } else {
        None
    };
    if current != expected {
        return Err(Error::Conflict);
    }
    let key = get_key(current.is_none())?;
    let encrypted = encrypt(vault, &key)?;
    if let Some(previous) = &current
        && decrypt(previous, &key).is_ok()
    {
        write_private(&dir.join("profiles.previous.rtrust"), previous)?;
    }
    write_private(&path, &encrypted)?;
    Ok(encrypted)
}
pub fn snapshot() -> Result<(Vault, Option<Vec<u8>>)> {
    let dir = default_dir()?;
    let _lock = lock(&dir)?;
    let path = dir.join("profiles.rtrust");
    if !path.exists() {
        return Ok((Vault::default(), None));
    }
    let data = read_bounded(&path, MAX_STORE + 36)?;
    let profiles = decrypt(&data, &key(false)?)?;
    Ok((profiles, Some(data)))
}
/// Explicit recovery preview. Returns the current revision for compare-and-swap;
/// never silently loads the backup on startup.
pub fn recovery_snapshot() -> Result<(Vault, Option<Vec<u8>>)> {
    recovery_in(&default_dir()?, key)
}
fn recovery_in(
    dir: &Path,
    get_key: impl FnOnce(bool) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<(Vault, Option<Vec<u8>>)> {
    let _lock = lock(dir)?;
    let path = dir.join("profiles.rtrust");
    let current = if path.exists() {
        Some(read_bounded(&path, MAX_STORE + 36)?)
    } else {
        None
    };
    let previous = read_bounded(&dir.join("profiles.previous.rtrust"), MAX_STORE + 36)?;
    Ok((decrypt(&previous, &get_key(false)?)?, current))
}
pub fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut out = vec![];
    File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut out)?;
    if out.len() > max {
        return Err(Error::Invalid);
    }
    Ok(out)
}
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|_| Error::Io)?;
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn explicit_recovery_preserves_authenticated_backup_after_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let key = vec![19u8; 32];
        let mut vault = Vault::default();
        let first = save_in(dir.path(), &vault, None, |_| {
            Ok(Zeroizing::new(key.clone()))
        })
        .unwrap();
        vault.connection.auto_connect = true;
        let _second = save_in(dir.path(), &vault, Some(first.clone()), |_| {
            Ok(Zeroizing::new(key.clone()))
        })
        .unwrap();
        assert_eq!(
            fs::read(dir.path().join("profiles.previous.rtrust")).unwrap(),
            first
        );
        fs::write(dir.path().join("profiles.rtrust"), b"corrupted").unwrap();
        let (recovered, revision) =
            recovery_in(dir.path(), |_| Ok(Zeroizing::new(key.clone()))).unwrap();
        assert!(!recovered.connection.auto_connect);
        save_in(dir.path(), &recovered, revision, |_| {
            Ok(Zeroizing::new(key.clone()))
        })
        .unwrap();
        assert_eq!(
            fs::read(dir.path().join("profiles.previous.rtrust")).unwrap(),
            first
        );
        let (_, revision) = recovery_in(dir.path(), |_| Ok(Zeroizing::new(key.clone()))).unwrap();
        vault.connection.auto_connect = false;
        save_in(dir.path(), &vault, revision.clone(), |_| {
            Ok(Zeroizing::new(key.clone()))
        })
        .unwrap();
        assert!(matches!(
            save_in(dir.path(), &recovered, revision, |_| Ok(Zeroizing::new(
                key.clone()
            ))),
            Err(Error::Conflict)
        ));
    }
    #[test]
    fn old_settings_migrate_dns_and_full_mode_roundtrips() {
        let old: super::ConnectionSettings =
            serde_json::from_str(r#"{"mode":"Socks","socks_port":1080,"networks":[]}"#).unwrap();
        assert_eq!(old.dns.to_string(), "1.1.1.1");
        assert!(!old.auto_connect);
        let full = super::ConnectionSettings {
            mode: super::Mode::Full,
            dns: "10.0.0.53".parse().unwrap(),
            ..old
        };
        full.validate().unwrap();
        let restored: super::ConnectionSettings =
            serde_json::from_slice(&serde_json::to_vec(&full).unwrap()).unwrap();
        assert!(full == restored);
    }

    use super::*;
    #[test]
    fn split_selection_and_server_policy_roundtrip_and_stay_optional() {
        let plain = ConnectionSettings::default();
        let json = serde_json::to_value(&plain).unwrap();
        for key in ["exclude", "exclude_lan", "managed_routes"] {
            assert!(json.get(key).is_none(), "{key}");
        }
        let managed = ManagedRoutes {
            group: "office".into(),
            revision: "3:7".into(),
            selection: rtrust_control::Selection::parse("10.0.0.0/8", "", false).unwrap(),
        };
        let split = ConnectionSettings {
            mode: Mode::Tun,
            networks: rtrust_control::networks("0.0.0.0/0").unwrap(),
            exclude: rtrust_control::networks("192.168.0.0/16").unwrap(),
            exclude_lan: true,
            managed_routes: Some(managed.clone()),
            ..plain
        };
        split.validate().unwrap();
        let restored: ConnectionSettings =
            serde_json::from_slice(&serde_json::to_vec(&split).unwrap()).unwrap();
        assert!(restored == split);
        assert_eq!(restored.effective_selection(), managed.selection);
        assert!(restored.selection().exclude_lan);
        let mut bad = split;
        bad.managed_routes.as_mut().unwrap().group.clear();
        assert!(bad.validate().is_err());
    }
    #[test]
    fn encrypted_roundtrip_and_tamper_detection() {
        let p=Profile::import("hostname='vpn.example'\naddresses=['127.0.0.1:443']\nusername='test'\npassword='CANARY_SECRET'\n").unwrap();
        let key = [7; 32];
        let mut data = encrypt(
            &Vault {
                profiles: vec![p],
                ..Vault::default()
            },
            &key,
        )
        .unwrap();
        assert!(!data.windows(13).any(|w| w == b"CANARY_SECRET"));
        assert_eq!(
            decrypt(&data, &key).unwrap().profiles[0]
                .endpoint
                .password
                .expose(),
            "CANARY_SECRET"
        );
        data[25] ^= 1;
        assert!(decrypt(&data, &key).is_err());
        assert!(decrypt(&data, &[8; 32]).is_err());
    }
    #[test]
    fn legacy_migration_keeps_profiles_and_rejects_stale_writer() {
        let dir = tempfile::tempdir().unwrap();
        let key = [9; 32];
        let profile = Profile::import("hostname='vpn.example'\naddresses=['127.0.0.1:443']\nusername='test'\npassword='legacy-secret'\n").unwrap();
        let old = seal(
            &serde_json::to_vec(&vec![profile.clone()]).unwrap(),
            &key,
            LEGACY_MAGIC,
        )
        .unwrap();
        let path = dir.path().join("profiles.rtrust");
        write_private(&path, &old).unwrap();
        let mut vault = decrypt(&fs::read(&path).unwrap(), &key).unwrap();
        assert!(
            serde_json::to_vec(&vault.profiles).unwrap()
                == serde_json::to_vec(&vec![profile]).unwrap()
        );
        assert!(vault.connection == ConnectionSettings::default());
        vault.connection = ConnectionSettings {
            mode: Mode::Tun,
            socks_port: 2080,
            networks: rtrust_control::networks("198.18.0.0/24,10.20.0.0/16").unwrap(),
            dns: default_dns(),
            auto_connect: true,
            sync: Default::default(),
            exclude: vec![],
            exclude_lan: false,
            managed_routes: None,
        };
        let new = save_in(dir.path(), &vault, Some(old.clone()), |create| {
            assert!(!create);
            Ok(Zeroizing::new(key.to_vec()))
        })
        .unwrap();
        assert!(new.starts_with(MAGIC));
        assert!(!new.windows(11).any(|w| w == b"198.18.0.0/"));
        let loaded = decrypt(&fs::read(&path).unwrap(), &key).unwrap();
        assert!(
            serde_json::to_vec(&loaded.profiles).unwrap()
                == serde_json::to_vec(&vault.profiles).unwrap()
        );
        assert!(loaded.connection == vault.connection);
        assert!(matches!(
            save_in(dir.path(), &vault, Some(old), |_| panic!(
                "stale write must not access keyring"
            )),
            Err(Error::Conflict)
        ));
        assert_eq!(fs::read(&path).unwrap(), new);
    }
    #[test]
    fn invalid_or_future_settings_never_replace_store() {
        let key = [3; 32];
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::default();
        let old = save_in(dir.path(), &vault, None, |_| {
            Ok(Zeroizing::new(key.to_vec()))
        })
        .unwrap();
        let mut invalid = vault.clone();
        invalid.connection.mode = Mode::Tun;
        assert!(
            save_in(dir.path(), &invalid, Some(old.clone()), |_| panic!(
                "invalid settings must not access keyring"
            ))
            .is_err()
        );
        assert_eq!(fs::read(dir.path().join("profiles.rtrust")).unwrap(), old);
        let mut renamed = old.clone();
        renamed[6] = b'1'; // Existing version label cannot be substituted: it is authenticated.
        assert!(decrypt(&renamed, &key).is_err());
        renamed[6] = b'9';
        assert!(decrypt(&renamed, &key).is_err());
        for json in [
            r#"{"profiles":[],"connection":{"mode":"Socks","socks_port":0,"networks":[]}}"#,
            r#"{"profiles":[],"connection":{"mode":"Tun","socks_port":1080,"networks":["127.0.0.0/8"]}}"#,
            r#"{"profiles":[],"connection":{"mode":"Tun","socks_port":1080,"networks":["0.0.0.0/0"],"exclude":["0.0.0.0/0"]}}"#,
            r#"{"profiles":[],"connection":{"mode":"Future","socks_port":1080,"networks":[]}}"#,
            r#"{"profiles":[],"connection":{"mode":"Socks","socks_port":1080,"networks":[],"autoconnect":true}}"#,
        ] {
            let data = seal(json.as_bytes(), &key, MAGIC).unwrap();
            assert!(decrypt(&data, &key).is_err());
        }
    }
    // Opt-in real platform vault test. It uses a unique credential and a private
    // temporary directory, never the user's application profile or master key.
    #[test]
    #[ignore = "requires an unlocked OS credential store"]
    fn os_keyring_restart_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let account = format!(
            "ci-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let entry = keyring::Entry::new("org.rtrusttunnel.ci", &account).unwrap();
        let key = [19; 32];
        entry.set_secret(&key).expect("OS credential store write");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let vault = Vault {profiles:vec![Profile::import("hostname='persist.example'\naddresses=['192.0.2.1:443']\nusername='ci'\npassword='CI_PERSIST_CANARY'\n").unwrap()],connection:ConnectionSettings {socks_port:2088,..Default::default()}};
            save_in(dir.path(), &vault, None, |_| {
                Ok(Zeroizing::new(entry.get_secret().unwrap()))
            })
            .unwrap();
            let bytes = fs::read(dir.path().join("profiles.rtrust")).unwrap();
            assert!(
                !bytes
                    .windows(b"CI_PERSIST_CANARY".len())
                    .any(|w| w == b"CI_PERSIST_CANARY")
            );
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "tests::os_keyring_read_child"])
                .env("RTRUST_CI_VAULT_DIR", dir.path())
                .env("RTRUST_CI_VAULT_ACCOUNT", &account)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "new process must decrypt saved profile via OS keyring"
            );
        }));
        entry
            .delete_credential()
            .expect("remove only the synthetic CI credential");
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }
    #[test]
    #[ignore = "helper only for isolated OS credential restart test"]
    fn os_keyring_read_child() {
        let Some(dir) = std::env::var_os("RTRUST_CI_VAULT_DIR") else {
            return;
        };
        let account = std::env::var("RTRUST_CI_VAULT_ACCOUNT").unwrap();
        assert!(account.starts_with("ci-"));
        let entry = keyring::Entry::new("org.rtrusttunnel.ci", &account).unwrap();
        let key = Zeroizing::new(entry.get_secret().unwrap());
        let data = fs::read(Path::new(&dir).join("profiles.rtrust")).unwrap();
        let vault = decrypt(&data, &key).unwrap();
        assert_eq!(
            vault.profiles[0].endpoint.password.expose(),
            "CI_PERSIST_CANARY"
        );
        assert_eq!(vault.connection.socks_port, 2088);
    }
    #[test]
    fn private_atomic_write() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("profile");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }
}
