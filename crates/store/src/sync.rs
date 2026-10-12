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
    pub id: String,
    pub revision: String,
    pub baseline: Profile,
}
impl SyncSettings {
    pub fn lease_for(
        &self,
        assigned_routes: bool,
        profiles: &[Profile],
    ) -> std::result::Result<Option<rtrust_control::freshness::Lease>, String> {
        if !assigned_routes
            && !profiles
                .iter()
                .any(|p| self.tracked.iter().any(|t| t.baseline == *p))
        {
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
    }
}
