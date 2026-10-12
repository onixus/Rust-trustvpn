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
    pub fn lease_for(
        &self,
        assigned_routes: bool,
        profiles: &[Profile],
    ) -> std::result::Result<Option<rtrust_control::freshness::Lease>, String> {
        let mut managed = assigned_routes;
        for profile in profiles {
            let mut matching = self
                .tracked
                .iter()
                .filter(|entry| same_access(&entry.baseline, profile))
                .peekable();
            if matching.peek().is_none() {
                continue;
            }
            managed = true;
            if !matching.any(|entry| entry.available) {
                return Err(
                    "Cached managed access is no longer granted; resolve the portal profile".into(),
                );
            }
        }
        if !managed {
            return Ok(None);
        }
        let lease = self
            .access_lease
            .clone()
            .ok_or("Panel freshness confirmation required; synchronize with an updated portal")?;
        lease.validate_at(rtrust_control::freshness::now())?;
        Ok(Some(lease))
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
        assert!(
            settings
                .lease_for(false, std::slice::from_ref(&local))
                .unwrap()
                .is_none()
        );
        assert!(
            settings
                .lease_for(false, std::slice::from_ref(&remote))
                .is_err()
        );
        assert!(settings.lease_for(false, &[local.clone(), remote]).is_err());
        assert!(settings.lease_for(true, &[local]).is_err());
        let mut edited = settings.tracked[0].baseline.clone();
        edited.name = "My custom name".into();
        edited.policy = serde_json::json!({});
        assert!(
            settings
                .lease_for(false, std::slice::from_ref(&edited))
                .is_err()
        );
        let mut fresh = settings.clone();
        let now = rtrust_control::freshness::now();
        fresh.access_lease = Some(rtrust_control::freshness::Lease {
            issued_at_ms: now,
            expires_at_ms: now + 60000,
        });
        assert!(
            fresh
                .lease_for(false, std::slice::from_ref(&edited))
                .unwrap()
                .is_some()
        );
        fresh.tracked[0].available = false;
        assert!(
            fresh
                .lease_for(false, std::slice::from_ref(&edited))
                .is_err()
        );
        let mut alias = fresh.tracked[0].clone();
        alias.id = "still-granted".into();
        alias.available = true;
        fresh.tracked.push(alias);
        assert!(fresh.lease_for(false, &[edited]).unwrap().is_some());
    }
}
