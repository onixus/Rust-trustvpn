use super::*;
#[derive(Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncSettings {
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
    pub(super) fn validate(&self) -> Result<()> {
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
