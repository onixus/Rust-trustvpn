//! Shared desktop connection and encrypted profile controller.
pub mod connection;
pub mod diagnostics;
pub mod diagnostics_frontend;
pub mod sync;
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
    pub diagnostics: diagnostics_frontend::View,
    pub revision: u64,
    pub profiles: Vec<Summary>,
    pub connection: rtrust_store::ConnectionSettings,
    pub connected: bool,
    pub verified: bool,
    pub status: String,
    pub observations: Option<rtrust_control::observations::Snapshot>,
}
pub struct Controller {
    pub diagnostics: diagnostics_frontend::Frontend,
    pub session_epoch: u64,
    pub connected_profile: Option<usize>,
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
            diagnostics: Default::default(),
            session_epoch: 0,
            connected_profile: None,
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
            diagnostics: Default::default(),
            session_epoch: 0,
            connected_profile: None,
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
            diagnostics: self.diagnostics.view(
                self.session_epoch,
                self.session.as_ref().map(|s| s.observations().generation),
                rtrust_control::observations::now_ms(),
            ),
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
        // The local settings form cannot relabel or remove a portal policy.
        next.connection.managed_routes = self.vault.connection.managed_routes.clone();
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
        self.connect_profile(revision, 0).await
    }
    pub fn connection_profile(&self, revision: u64, index: usize) -> Result<Profile, String> {
        self.check(revision)?;
        self.vault
            .profiles
            .get(index)
            .cloned()
            .ok_or_else(|| "Selected profile no longer exists".into())
    }
    pub async fn connect_profile(&mut self, revision: u64, index: usize) -> Result<(), String> {
        let p = self.connection_profile(revision, index)?;
        let c = &self.vault.connection;
        let mode = match c.mode {
            rtrust_store::Mode::Socks => connection::Mode::Socks,
            rtrust_store::Mode::Tun => connection::Mode::Tun,
            rtrust_store::Mode::Full => connection::Mode::Full,
        };
        let selection = c.effective_selection();
        let fallbacks = c.fallbacks_for(&self.vault.profiles, Some(&p));
        let authorized = std::iter::once(p.clone())
            .chain(fallbacks.iter().cloned())
            .collect::<Vec<_>>();
        let lease = c.sync.lease_for(c.managed_routes.is_some(), &authorized)?;
        let ipv4_only = mode == connection::Mode::Full && !p.endpoint.has_ipv6;
        self.diagnostics.cancel();
        self.session_epoch = self.session_epoch.wrapping_add(1);
        self.session = Some(
            connection::Session::start_authorized(
                p,
                fallbacks,
                mode,
                c.socks_port,
                selection,
                c.dns.to_string(),
                lease,
            )
            .await?,
        );
        self.connected_profile = Some(index);
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
        self.diagnostics.cancel();
        self.session_epoch = self.session_epoch.wrapping_add(1);
        if let Some(session) = self.session.as_ref() {
            session.clone().stop().await?;
            self.session = None;
            self.connected_profile = None;
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
        .chain(recent_change(
            snapshot,
            russian,
            rtrust_control::observations::now_ms(),
        ))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// Earlier checks no longer describe the network after an OS-reported change.
fn recent_change(
    snapshot: &rtrust_control::observations::Snapshot,
    russian: bool,
    now: u64,
) -> Option<String> {
    use rtrust_control::observations::EventKind;
    const RECENT_MS: u64 = 60_000;
    let event = snapshot.events.last()?;
    if now < event.at_ms || now - event.at_ms > RECENT_MS {
        return None;
    }
    let text = match (event.kind, russian) {
        (EventKind::NetworkChanged, true) => "сеть изменилась, прежние проверки устарели",
        (EventKind::NetworkChanged, false) => "network changed, earlier checks are stale",
        (EventKind::Resumed, true) => "после сна, прежние проверки устарели",
        (EventKind::Resumed, false) => "resumed from sleep, earlier checks are stale",
        (EventKind::PolicyChanged, true) => "правила изменились, прежние проверки устарели",
        (EventKind::PolicyChanged, false) => "policy changed, earlier checks are stale",
        (EventKind::FailedOver, true) => "переключено на разрешённый резервный профиль",
        (EventKind::FailedOver, false) => "switched to an allowed backup profile",
        _ => return None,
    };
    Some(text.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_recent_network_change_or_resume_is_shown_then_ages_out() {
        use rtrust_control::observations::{Mode, Monitor, Source};
        let mut monitor = Monitor::new(Mode::Full, Source::ServiceLifecycle, 1_000);
        monitor.network_changed(2_000);
        let changed = monitor.sample(2_001);
        assert_eq!(
            recent_change(&changed, false, 3_000).as_deref(),
            Some("network changed, earlier checks are stale")
        );
        assert_eq!(recent_change(&changed, false, 70_000), None);
        assert_eq!(recent_change(&changed, true, 1_000), None);
        monitor.resumed(4_000);
        let resumed = monitor.sample(4_001);
        assert!(
            recent_change(&resumed, true, 5_000)
                .unwrap()
                .contains("сна")
        );
    }
    #[test]
    fn explicit_profile_selection_checks_revision_and_never_falls_back() {
        let mut controller = Controller::smoke();
        let mut first =
            Profile::import(include_str!("../../../examples/demo.endpoint.toml")).unwrap();
        first.name = "default".into();
        let mut second = first.clone();
        second.name = "selected".into();
        controller.vault.profiles = vec![first, second];
        assert_eq!(
            controller.connection_profile(0, 1).unwrap().name,
            "selected"
        );
        assert_eq!(controller.connection_profile(0, 0).unwrap().name, "default");
        assert!(controller.connection_profile(1, 1).is_err());
        assert!(controller.connection_profile(0, 2).is_err());
    }
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
                available: true,
                id: "one".into(),
                revision: "one".into(),
                baseline: profile,
            });
        let controller = Controller {
            diagnostics: Default::default(),
            session_epoch: 0,
            connected_profile: None,
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
