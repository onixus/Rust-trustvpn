use super::*;
#[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_lease: Option<rtrust_control::freshness::Lease>,
    pub enabled: bool,
    pub origin: String,
    pub tracked: Vec<TrackedProfile>,
}
#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrackedProfile {
    #[serde(default = "available")]
    pub available: bool,
    pub id: String,
    pub revision: String,
    pub baseline: Profile,
}
fn available() -> bool {
    true
}
fn same_access(left: &Profile, right: &Profile) -> bool {
    // Hysteria and AmneziaWG ignore the compatibility username field.
    // Editing it cannot change ownership of the auth/private key.
    left.endpoint.password == right.endpoint.password
        && (left.protocol != rtrust_profile::Protocol::TrustTunnel
            || left.endpoint.username == right.endpoint.username)
}
impl SyncSettings {
    /// Credential ownership survives local name/policy edits and unavailable grants.
    pub fn tracks_access(&self, profile: &Profile) -> bool {
        self.tracked
            .iter()
            .any(|entry| same_access(&entry.baseline, profile))
    }
    /// Connect admission for a profile that already has endpoint credentials.
    ///
    /// Device linking delivers profiles. It is not a runtime dependency of the
    /// VPN session: a missing, expired or unreadable portal lease must not
    /// refuse a saved config. The only fail-closed case is a grant a successful
    /// sync already marked unavailable. Endpoint revoke remains a server check.
    pub fn connect_blocked(&self, profiles: &[Profile]) -> std::result::Result<(), String> {
        for profile in profiles {
            let mut matching = self
                .tracked
                .iter()
                .filter(|entry| same_access(&entry.baseline, profile))
                .peekable();
            if matching.peek().is_none() {
                continue;
            }
            if !matching.any(|entry| entry.available) {
                return Err(
                    "Cached managed access is no longer granted; resolve the portal profile".into(),
                );
            }
        }
        Ok(())
    }
    pub(super) fn validate(&self) -> Result<()> {
        if self
            .access_lease
            .as_ref()
            .is_some_and(|l| l.validate_at(l.issued_at_ms).is_err())
        {
            return Err(Error::Invalid);
        }
        if self.origin.len() > 2048 || self.tracked.len() > 200 {
            return Err(Error::Invalid);
        }
        let mut ids = std::collections::HashSet::new();
        for entry in &self.tracked {
            if entry.id.is_empty()
                || entry.id.len() > 128
                || entry.revision.len() > 256
                || !ids.insert(&entry.id)
            {
                return Err(Error::Invalid);
            }
            entry.baseline.validate().map_err(|_| Error::Invalid)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ignored_transport_username_cannot_release_managed_identity() {
        let baseline = Profile::import("hy2://synthetic-fixture-key@vpn.example:443").unwrap();
        let mut edited = baseline.clone();
        edited.endpoint.username = rtrust_profile::Secret::new("edited-unused");
        edited.validate().unwrap();
        assert!(same_access(&baseline, &edited));
    }
    #[test]
    fn expired_managed_receipt_remains_readable_but_cannot_authorize_primary_or_backup() {
        let remote=Profile::import("hostname='vpn.example'\naddresses=['192.0.2.10:443']\nusername='device'\npassword='FIXTURE-SECRET'\n").unwrap();
        let local=Profile::import("hostname='local.example'\naddresses=['192.0.2.11:443']\nusername='local'\npassword='FIXTURE-SECRET'\n").unwrap();
        let settings = SyncSettings {
            access_lease: Some(rtrust_control::freshness::Lease {
                issued_at_ms: 1,
                expires_at_ms: 1000,
            }),
            enabled: false,
            origin: "https://portal.example".into(),
            tracked: vec![TrackedProfile {
                available: true,
                id: "device".into(),
                revision: "1".into(),
                baseline: remote.clone(),
            }],
        };
        assert!(settings.validate().is_ok());
        // A saved local or portal-delivered config connects without a live lease.
        assert!(
            settings
                .connect_blocked(std::slice::from_ref(&local))
                .is_ok()
        );
        assert!(
            settings
                .connect_blocked(std::slice::from_ref(&remote))
                .is_ok()
        );
        assert!(settings.connect_blocked(&[local.clone(), remote]).is_ok());
        let mut edited = settings.tracked[0].baseline.clone();
        edited.name = "My custom name".into();
        edited.policy = serde_json::json!({});
        assert!(
            settings
                .connect_blocked(std::slice::from_ref(&edited))
                .is_ok()
        );
        // An expired receipt is not a connect refusal: the portal may be down.
        let mut revoked = settings.clone();
        revoked.tracked[0].available = false;
        assert!(
            revoked
                .connect_blocked(std::slice::from_ref(&edited))
                .is_err()
        );
        assert!(
            revoked
                .connect_blocked(std::slice::from_ref(&local))
                .is_ok()
        );
        let mut alias = revoked.tracked[0].clone();
        alias.id = "still-granted".into();
        alias.available = true;
        revoked.tracked.push(alias);
        assert!(revoked.connect_blocked(&[edited]).is_ok());
    }
}
