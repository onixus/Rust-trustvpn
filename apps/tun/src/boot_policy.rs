//! Service-owned always-on policy. Never uses or exports the interactive user's vault key.
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use zeroize::Zeroizing;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub owner: String,
    pub profile: rtrust_profile::Profile,
    pub dns: Ipv4Addr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<rtrust_profile::Profile>,
}
impl Policy {
    pub fn validate(&self, owner: &str) -> Result<(), String> {
        if self.version != 1 || self.owner != owner || owner.is_empty() || owner.len() > 184 {
            return Err("Always-on policy owner/version mismatch".into());
        }
        self.profile
            .validate()
            .map_err(|_| "Invalid always-on profile")?;
        rtrust_control::validate_dns(self.dns)?;
        for endpoint in &self.profile.endpoint.addresses {
            let endpoint: SocketAddr = endpoint
                .parse()
                .map_err(|_| "Always-on requires pinned endpoint IP addresses")?;
            if endpoint.ip().is_unspecified()
                || endpoint.ip().is_loopback()
                || endpoint.ip().is_multicast()
            {
                return Err("Invalid always-on endpoint".into());
            }
        }
        if self.backups.len() > rtrust_control::recovery::MAX_BACKUPS {
            return Err("Too many backup profiles".into());
        }
        for profile in &self.backups {
            let candidate = Policy {
                version: self.version,
                owner: self.owner.clone(),
                profile: profile.clone(),
                dns: self.dns,
                backups: vec![],
            };
            candidate.validate(owner)?;
            if profile == &self.profile {
                return Err("Backup duplicates primary profile".into());
            }
        }
        for (i, profile) in self.backups.iter().enumerate() {
            if self.backups[..i].contains(profile) {
                return Err("Duplicate backup profile".into());
            }
        }
        Ok(())
    }
}
const POLICY_LIMIT: usize = rtrust_control::LIMIT;
const AAD: &[u8] = b"rtrust-service-always-on-v1";
fn seal(policy: &Policy, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    };
    let plain =
        Zeroizing::new(serde_json::to_vec(policy).map_err(|_| "Cannot encode boot policy")?);
    if plain.len() + 40 > POLICY_LIMIT {
        return Err("Combined recovery policy exceeds service frame limit".into());
    }
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut result = nonce.to_vec();
    result.extend(
        XChaCha20Poly1305::new(key.into())
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: AAD,
                },
            )
            .map_err(|_| "Cannot encrypt boot policy")?,
    );
    Ok(result)
}
fn unseal(data: &[u8], key: &[u8; 32], owner: &str) -> Result<Policy, String> {
    use chacha20poly1305::{
        XChaCha20Poly1305,
        aead::{Aead, KeyInit, Payload},
    };
    if data.len() < 40 || data.len() > POLICY_LIMIT {
        return Err("Invalid boot policy size".into());
    }
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(
                data[..24].into(),
                Payload {
                    msg: &data[24..],
                    aad: AAD,
                },
            )
            .map_err(|_| "Boot policy authentication failed")?,
    );
    let policy: Policy = serde_json::from_slice(&plain).map_err(|_| "Invalid boot policy")?;
    policy.validate(owner)?;
    Ok(policy)
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn directory() -> Result<std::path::PathBuf, String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt};
        let dir = std::path::PathBuf::from("/var/lib/rtrust");
        if !dir.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|_| "Cannot create service policy directory")?;
        }
        let meta = std::fs::symlink_metadata(&dir)
            .map_err(|_| "Cannot inspect service policy directory")?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
            return Err("Unsafe service policy directory".into());
        }
        Ok(dir)
    }
    #[cfg(target_os = "windows")]
    {
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(std::path::Path::to_path_buf))
            .ok_or("Cannot locate service policy directory".into())
    }
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn exists() -> Result<bool, String> {
    Ok(directory()?.join("always-on.rtrust").exists())
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn machine_key(create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    let path = directory()?.join("always-on.key");
    if !path.exists() && create {
        let key = Zeroizing::new(rand::random::<[u8; 32]>());
        #[cfg(target_os = "windows")]
        let encoded = dpapi(&key[..], true)?;
        #[cfg(target_os = "linux")]
        let encoded = Zeroizing::new(key.to_vec());
        rtrust_store::write_private(&path, &encoded).map_err(|_| "Cannot protect service key")?;
        sync_directory()?;
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "Missing service key")?;
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o077 != 0 {
            return Err("Unsafe service key".into());
        }
    }
    let encoded = Zeroizing::new(
        rtrust_store::read_bounded(&path, 4096).map_err(|_| "Cannot read service key")?,
    );
    #[cfg(target_os = "windows")]
    let encoded = dpapi(&encoded, false)?;
    let key: [u8; 32] = encoded
        .as_slice()
        .try_into()
        .map_err(|_| "Invalid service key")?;
    Ok(Zeroizing::new(key))
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn save(policy: &Policy) -> Result<(), String> {
    policy.validate(&policy.owner)?;
    let data = seal(policy, &*machine_key(true)?)?;
    rtrust_store::write_private(&directory()?.join("always-on.rtrust"), &data)
        .map_err(|_| "Cannot save protected boot policy")?;
    sync_directory()
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn sync_directory() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    std::fs::File::open(directory()?)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "Cannot persist boot policy directory")?;
    Ok(())
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn load(owner: &str) -> Result<Option<Policy>, String> {
    let path = directory()?.join("always-on.rtrust");
    if !path.exists() {
        return Ok(None);
    }
    let data =
        rtrust_store::read_bounded(&path, POLICY_LIMIT).map_err(|_| "Cannot read boot policy")?;
    unseal(&data, &*machine_key(false)?, owner).map(Some)
}
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub fn remove() -> Result<(), String> {
    let path = directory()?.join("always-on.rtrust");
    if path.exists() {
        std::fs::remove_file(&path).map_err(|_| "Cannot remove boot policy")?;
        #[cfg(target_os = "linux")]
        std::fs::File::open(path.parent().ok_or("Missing policy directory")?)
            .and_then(|dir| dir.sync_all())
            .map_err(|_| "Cannot persist boot policy removal")?;
    }
    Ok(())
}
#[cfg(target_os = "windows")]
fn dpapi(bytes: &[u8], protect: bool) -> Result<Zeroizing<Vec<u8>>, String> {
    use windows_sys::Win32::{Foundation::LocalFree, Security::Cryptography::*};
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        return Err("Service DPAPI key unavailable".into());
    }
    let result = unsafe {
        Zeroizing::new(std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec())
    };
    unsafe {
        std::ptr::write_bytes(output.pbData, 0, output.cbData as usize);
        LocalFree(output.pbData.cast());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_policy_is_authenticated_owner_bound_and_has_no_plaintext_credentials() {
        let policy=Policy{version:1,owner:"1000".into(),profile:rtrust_profile::Profile::import("hostname='boot.example'\naddresses=['192.0.2.1:443']\nusername='boot-user'\npassword='boot-secret-canary'\n").unwrap(),backups:vec![],dns:"1.1.1.1".parse().unwrap()};
        let key = [7; 32];
        let encrypted = seal(&policy, &key).unwrap();
        assert!(!encrypted.windows(18).any(|w| w == b"boot-secret-canary"));
        assert_eq!(
            unseal(&encrypted, &key, "1000").unwrap().profile,
            policy.profile
        );
        assert!(unseal(&encrypted, &key, "1001").is_err());
        assert!(unseal(&encrypted, &[8; 32], "1000").is_err());
        let mut corrupt = encrypted;
        corrupt[30] ^= 1;
        assert!(unseal(&corrupt, &key, "1000").is_err());
    }
    #[test]
    fn large_recovery_policy_round_trips_with_the_shared_persistence_bound() {
        let profiles: Vec<_> = (1..=3).map(|n| {
            let mut p = rtrust_profile::Profile::import(&format!(
                "hostname='boot{n}.example'\naddresses=['192.0.2.{n}:443']\nusername='u'\npassword='p'\n"
            )).unwrap();
            p.extensions.insert("padding".into(), serde_json::json!("x".repeat(750 * 1024)));
            let export = p.export(rtrust_profile::Format::Json).unwrap();
            assert!(export.content.len() < rtrust_profile::MAX_INPUT);
            rtrust_profile::Profile::import(&export.content).unwrap()
        }).collect();
        let policy = Policy {
            version: 1,
            owner: "1000".into(),
            profile: profiles[0].clone(),
            dns: "1.1.1.1".parse().unwrap(),
            backups: profiles[1..].to_vec(),
        };
        policy.validate("1000").unwrap();
        let data = seal(&policy, &[7; 32]).unwrap();
        assert!(data.len() > 2 * rtrust_profile::MAX_INPUT);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot-policy");
        std::fs::write(&path, &data).unwrap();
        let loaded = rtrust_store::read_bounded(&path, POLICY_LIMIT).unwrap();
        let restored = unseal(&loaded, &[7; 32], "1000").unwrap();
        assert_eq!(restored.profile, policy.profile);
        assert_eq!(restored.backups, policy.backups);
        assert!(unseal(&vec![0; POLICY_LIMIT + 1], &[7; 32], "1000").is_err());
    }
    #[test]
    fn backups_remain_authenticated_and_duplicate_or_oversized_policies_are_rejected() {
        let profile = |host: &str| {
            rtrust_profile::Profile::import(&format!(
                "hostname='{host}'\naddresses=['192.0.2.1:443']\nusername='u'\npassword='p'\n"
            ))
            .unwrap()
        };
        let mut policy = Policy {
            version: 1,
            owner: "1000".into(),
            profile: profile("primary.example"),
            dns: "1.1.1.1".parse().unwrap(),
            backups: vec![profile("backup.example")],
        };
        let bytes = seal(&policy, &[7; 32]).unwrap();
        let restored = unseal(&bytes, &[7; 32], "1000").unwrap();
        assert_eq!(restored.backups, policy.backups);
        policy.backups.push(policy.backups[0].clone());
        assert!(policy.validate("1000").is_err());
        policy.backups = vec![policy.profile.clone()];
        assert!(policy.validate("1000").is_err());
        policy.backups.clear();
        policy.profile.name = "x".repeat(rtrust_control::LIMIT);
        assert!(seal(&policy, &[7; 32]).is_err());
    }
}
