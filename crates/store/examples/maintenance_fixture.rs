//! Explicit maintenance fixture: preserve real data, temporarily populate only an empty vault.
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
#[derive(Serialize, Deserialize)]
struct Backup {
    original: Option<Vec<u8>>,
    previous: Option<Vec<u8>>,
    expected: Option<Vec<u8>>,
    synthetic: bool,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: maintenance_fixture begin|end PRIVATE_BACKUP_PATH".into());
    }
    let backup_path = PathBuf::from(&args[1]);
    let dir = directories::ProjectDirs::from("org", "RTrustTunnel", "RTrustTunnel")
        .ok_or("Missing data directory")?
        .data_local_dir()
        .to_path_buf();
    let current = dir.join("profiles.rtrust");
    let previous = dir.join("profiles.previous.rtrust");
    if args[0] == "begin" {
        if backup_path.exists() {
            return Err("Backup already exists; finish earlier fixture first".into());
        }
        let (vault, original) = rtrust_store::snapshot()?;
        let old_previous = if previous.exists() {
            Some(rtrust_store::read_bounded(&previous, 17 * 1024 * 1024)?)
        } else {
            None
        };
        let mut backup = Backup {
            original: original.clone(),
            previous: old_previous,
            expected: original.clone(),
            synthetic: vault.profiles.is_empty(),
        };
        // Save recovery material before any fixture mutation.
        rtrust_store::write_private(&backup_path, &serde_json::to_vec(&backup)?)?;
        if backup.synthetic {
            let profile = rtrust_profile::Profile::import(
                "hostname='maintenance.example'\naddresses=['192.0.2.1:443']\nusername='synthetic'\npassword='CI_INSTALL_RETENTION_CANARY'\n",
            )?;
            backup.expected = Some(rtrust_store::save(
                &rtrust_store::Vault {
                    profiles: vec![profile],
                    connection: Default::default(),
                },
                original,
            )?);
            rtrust_store::write_private(&backup_path, &serde_json::to_vec(&backup)?)?;
        }
        println!(
            "Prepared encrypted profile retention check; synthetic={}",
            backup.synthetic
        );
    } else if args[0] == "end" {
        let data = rtrust_store::read_bounded(&backup_path, 64 * 1024 * 1024)?;
        let backup: Backup = serde_json::from_slice(&data)?;
        let (vault, actual) = rtrust_store::snapshot()?;
        if actual != backup.expected || vault.profiles.is_empty() {
            return Err("Profile retention failed; recovery files preserved and current data not overwritten".into());
        }
        println!("PASS encrypted profile unchanged and decryptable after installer/rollback");
        if backup.synthetic {
            let lock = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(dir.join("profiles.lock"))?;
            fs2::FileExt::try_lock_exclusive(&lock)?;
            if Some(fs::read(&current)?) != backup.expected {
                return Err("Concurrent edit: fixture cleanup refused".into());
            }
            if let Some(original) = backup.original {
                rtrust_store::write_private(&current, &original)?;
            } else {
                fs::remove_file(&current)?;
            }
            if let Some(original) = backup.previous {
                rtrust_store::write_private(&previous, &original)?;
            } else if previous.exists() {
                fs::remove_file(&previous)?;
            }
            println!("Restored original empty vault state; OS key was retained");
        }
    } else {
        return Err("Invalid maintenance fixture operation".into());
    }
    Ok(())
}
