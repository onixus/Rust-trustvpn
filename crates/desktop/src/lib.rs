//! Shared desktop connection and encrypted profile controller.
pub mod connection;
use rtrust_profile::Profile;
use rtrust_store::Vault;
use serde::Serialize;

#[derive(Serialize)]
pub struct Summary {
    pub name: String,
    pub hostname: String,
    pub protocol: String,
    pub default: bool,
}
#[derive(Serialize)]
pub struct View {
    pub revision: u64,
    pub profiles: Vec<Summary>,
    pub connection: rtrust_store::ConnectionSettings,
    pub connected: bool,
    pub verified: bool,
    pub status: String,
    pub observations: Option<rtrust_control::observations::Snapshot>,
}
pub struct Controller {
    pub vault: Vault,
    storage_revision: Option<Vec<u8>>,
    pub revision: u64,
    pub session: Option<connection::Session>,
    pub status: String,
    /// Shown while connected and healthy; empty means the plain "Connected".
    connected_note: &'static str,
    pending: Option<Profile>,
}
impl Controller {
    /// Isolated GUI smoke state; never reads an existing user's vault.
    pub fn smoke() -> Self {
        Self {
            vault: Vault::default(),
            storage_revision: None,
            revision: 0,
            session: None,
            status: String::new(),
            connected_note: "",
            pending: None,
        }
    }
    pub fn load() -> Result<Self, String> {
        let (vault, revision) = rtrust_store::snapshot().map_err(|e| e.to_string())?;
        Ok(Self {
            vault,
            storage_revision: revision,
            revision: 0,
            session: None,
            status: String::new(),
            connected_note: "",
            pending: None,
        })
    }
    pub fn view(&self) -> View {
        View {
            revision: self.revision,
            profiles: self
                .vault
                .profiles
                .iter()
                .enumerate()
                .map(|(i, p)| Summary {
                    name: p.name.clone(),
                    hostname: p.endpoint.hostname.clone(),
                    protocol: p.transport_name().into(),
                    default: i == 0,
                })
                .collect(),
            connection: {
                let mut c = self.vault.connection.clone();
                c.sync.tracked.clear();
                c
            },
            connected: self.session.is_some(),
            verified: self
                .session
                .as_ref()
                .is_some_and(|s| s.observations().verified()),
            observations: self.session.as_ref().map(connection::Session::observations),
            status: self.status.clone(),
        }
    }
    pub fn preview(&mut self, input: &str) -> Result<Summary, String> {
        let p = Profile::import(input).map_err(|e| e.to_string())?;
        let summary = Summary {
            name: p.name.clone(),
            hostname: p.endpoint.hostname.clone(),
            protocol: p.transport_name().into(),
            default: false,
        };
        self.pending = Some(p);
        Ok(summary)
    }
    pub fn import(&mut self, revision: u64) -> Result<(), String> {
        self.check(revision)?;
        let p = self.pending.take().ok_or("Import preview expired")?;
        let mut next = self.vault.clone();
        next.profiles.push(p);
        self.save(next)
    }
    pub fn edit(&mut self, revision: u64, action: &str, index: usize) -> Result<(), String> {
        self.check(revision)?;
        if index >= self.vault.profiles.len() {
            return Err("Profile no longer exists".into());
        }
        let mut next = self.vault.clone();
        match action {
            "default" => {
                let p = next.profiles.remove(index);
                next.profiles.insert(0, p);
            }
            "delete" => {
                next.profiles.remove(index);
            }
            _ => return Err("Unknown profile action".into()),
        }
        self.save(next)
    }
    pub fn settings(
        &mut self,
        revision: u64,
        settings: rtrust_store::ConnectionSettings,
    ) -> Result<(), String> {
        self.check(revision)?;
        settings.validate().map_err(|e| e.to_string())?;
        let mut next = self.vault.clone();
        let sync = next.connection.sync.clone();
        next.connection = settings;
        next.connection.sync = sync;
        self.save(next)
    }
    pub fn check(&self, revision: u64) -> Result<(), String> {
        if revision != self.revision {
            return Err("Profiles changed; refresh the interface".into());
        }
        if self.session.is_some() {
            return Err("Disconnect before changing profiles or settings".into());
        }
        Ok(())
    }
    pub fn save(&mut self, next: Vault) -> Result<(), String> {
        let revision =
            rtrust_store::save(&next, self.storage_revision.clone()).map_err(|e| e.to_string())?;
        self.vault = next;
        self.storage_revision = Some(revision);
        self.revision = self.revision.wrapping_add(1);
        Ok(())
    }
    pub async fn connect(&mut self, revision: u64) -> Result<(), String> {
        self.check(revision)?;
        let p = self
            .vault
            .profiles
            .first()
            .ok_or("Import a default profile first")?
            .clone();
        let c = &self.vault.connection;
        let mode = match c.mode {
            rtrust_store::Mode::Socks => connection::Mode::Socks,
            rtrust_store::Mode::Tun => connection::Mode::Tun,
            rtrust_store::Mode::Full => connection::Mode::Full,
        };
        let selection = c.effective_selection();
        let ipv4_only = mode == connection::Mode::Full && !p.endpoint.has_ipv6;
        self.session = Some(
            connection::Session::start(p, mode, c.socks_port, selection, c.dns.to_string()).await?,
        );
        self.connected_note = if ipv4_only {
            "Connected · IPv4 and DNS. The server has no IPv6, so IPv6 is blocked and apps use IPv4."
        } else {
            ""
        };
        self.status = self.connected_note.into();
        Ok(())
    }
    pub fn connected_note(&self) -> &'static str {
        self.connected_note
    }
    pub async fn disconnect(&mut self) -> Result<(), String> {
        if let Some(session) = self.session.as_ref() {
            session.clone().stop().await?;
            self.session = None;
        }
        self.connected_note = "";
        self.status.clear();
        Ok(())
    }
}

/// Localize stable machine outcomes at the UI boundary; never parse service messages.
pub fn observation_summary(
    snapshot: &rtrust_control::observations::Snapshot,
    russian: bool,
) -> String {
    use rtrust_control::observations::Outcome;
    fn label(outcome: Outcome, ru: bool) -> &'static str {
        match (outcome, ru) {
            (Outcome::Passed, true) => "проверено",
            (Outcome::Passed, false) => "verified",
            (Outcome::Failed, true) => "сбой",
            (Outcome::Failed, false) => "failed",
            (Outcome::Configured, true) => "запущен, доступность не проверена",
            (Outcome::Configured, false) => "running, availability unchecked",
            (Outcome::Stale, true) => "устарело",
            (Outcome::Stale, false) => "stale",
            (Outcome::Unsupported, true) => "проверка не поддерживается",
            (Outcome::Unsupported, false) => "check unsupported",
            (Outcome::Unknown, true) => "не проверено",
            (Outcome::Unknown, false) => "unchecked",
        }
    }
    let names = if russian {
        ["Транспорт", "маршрут", "DNS", "защита", "доступность"]
    } else {
        ["Transport", "route", "DNS", "guard", "connectivity"]
    };
    names
        .into_iter()
        .zip([
            &snapshot.transport,
            &snapshot.route,
            &snapshot.dns,
            &snapshot.guard,
            &snapshot.connectivity,
        ])
        .map(|(name, o)| format!("{name}: {}", label(o.outcome, russian)))
        .collect::<Vec<_>>()
        .join(" · ")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn webview_metadata_never_exposes_profile_or_sync_credentials() {
        let mut profile =
            Profile::import(include_str!("../../../examples/demo.endpoint.toml")).unwrap();
        profile.endpoint.password = rtrust_profile::Secret::new("regression-profile-password");
        let mut vault = Vault {
            profiles: vec![profile.clone()],
            ..Default::default()
        };
        vault
            .connection
            .sync
            .tracked
            .push(rtrust_store::TrackedProfile {
                id: "one".into(),
                revision: "one".into(),
                baseline: profile,
            });
        let controller = Controller {
            vault,
            storage_revision: None,
            revision: 7,
            session: None,
            status: String::new(),
            connected_note: "",
            pending: None,
        };
        let value = serde_json::to_value(controller.view()).unwrap();
        assert!(
            value["connection"]["sync"]["tracked"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(!value.to_string().contains("regression-profile-password"));
        assert!(value["profiles"][0].get("endpoint").is_none());
        assert!(controller.check(6).is_err());
        assert!(controller.check(7).is_ok());
    }
}
