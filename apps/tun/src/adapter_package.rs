//! Portable checks for the Windows adapter package.
//!
//! The PnP calls live in `windows::driver` and compile only on Windows. These
//! checks are the part that must fail closed on every host: a leftover
//! `wintun.dll` is refused, a missing driver file is refused, and only an
//! Authenticode status of `Valid` is trusted. `TestSigned` is not success.

use std::path::Path;

/// Files that must sit beside the service before the adapter is installed.
pub const PACKAGE_FILES: &[&str] = rttun_proto::PACKAGE_FILES;

/// Authenticode status we accept. Only `Valid` is a production install.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    NotSigned,
    TestSigned,
    Other,
}

impl SignatureStatus {
    pub fn trusted(self) -> bool {
        matches!(self, Self::Valid)
    }
}

/// Parse the status token from `Get-AuthenticodeSignature`.
pub fn parse_signature_status(text: &str) -> SignatureStatus {
    match text.trim() {
        "Valid" => SignatureStatus::Valid,
        "NotSigned" => SignatureStatus::NotSigned,
        "TestSigned" => SignatureStatus::TestSigned,
        _ => SignatureStatus::Other,
    }
}

/// Refuse the old DLL and require our three package files. Does not install
/// anything and does not talk to PnP.
pub fn require_package(dir: &Path) -> Result<(), String> {
    if dir.join("wintun.dll").is_file() {
        return Err("wintun.dll is still beside the service; refusing to load it".into());
    }
    for name in PACKAGE_FILES {
        if !dir.join(name).is_file() {
            return Err(format!(
                "Missing {name} beside the service; the Rttun adapter is not installed"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_valid_catalog_is_trusted() {
        assert!(parse_signature_status("Valid").trusted());
        assert!(!parse_signature_status("NotSigned").trusted());
        assert!(!parse_signature_status("TestSigned").trusted());
        assert!(!parse_signature_status("UnknownError").trusted());
        assert!(!parse_signature_status("").trusted());
    }

    #[test]
    fn package_check_rejects_wintun_and_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("wintun.dll"), b"not-a-driver").unwrap();
        let error = require_package(dir.path()).unwrap_err();
        assert!(error.contains("wintun.dll"));
        std::fs::remove_file(dir.path().join("wintun.dll")).unwrap();
        let error = require_package(dir.path()).unwrap_err();
        assert!(error.contains("rttun.sys"));
        for name in PACKAGE_FILES {
            std::fs::write(dir.path().join(name), b"package").unwrap();
        }
        require_package(dir.path()).unwrap();
    }

    #[test]
    fn ring_keeps_packet_boundaries() {
        let mut ring = rttun_proto::Ring::new();
        ring.push(&vec![0x45; 20]).unwrap();
        let mut out = [0; 64];
        assert_eq!(ring.pop(&mut out).unwrap(), 20);
        assert_eq!(out[0], 0x45);
        assert!(ring.push(&[0x00; 20]).is_err());
    }
}
