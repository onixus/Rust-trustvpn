//! Explicit, session-fenced local subscription to redacted dataplane selections.
use rtrust_engine::routing::{PolicyVersion, Router};
use rtrust_profile::routing::Decision;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::broadcast::{Receiver, error::TryRecvError};
fn revision_id(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
fn redacted_version(mut version: PolicyVersion) -> PolicyVersion {
    version.revision = revision_id(&version.revision);
    version
}
const LIMIT: usize = 32;
const MAX_SNAPSHOT_BYTES: usize = 60 * 1024;
const IDLE_LEASE: Duration = Duration::from_secs(30);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub session: u64,
    pub capture: u64,
}
#[derive(Debug, Serialize)]
pub struct Event {
    pub version: PolicyVersion,
    pub age_ms: u64,
    pub decision: Decision,
}
#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub schema: u8,
    pub token: Token,
    pub active: bool,
    pub enabled: bool,
    pub version: Option<PolicyVersion>,
    pub lagged: u64,
    pub discarded_stale: u64,
    pub discarded_oversize: u64,
    pub events: Vec<Event>,
}
#[derive(Default)]
pub struct Capture {
    session: u64,
    capture: u64,
    router: Option<Arc<Router>>,
    available: bool,
    receiver: Option<Receiver<rtrust_engine::routing::ObservedDecision>>,
    deadline: Option<Instant>,
}
impl Capture {
    pub fn attach(&mut self, router: Arc<Router>) -> u64 {
        self.detach();
        self.router = Some(router);
        self.session
    }
    pub fn detach(&mut self) {
        self.session = self.session.wrapping_add(1);
        self.capture = self.capture.wrapping_add(1);
        self.router = None;
        self.available = false;
        self.receiver = None;
        self.deadline = None;
    }
    /// Only the owning runner may change transport availability. Reconnection
    /// clears the old opt-in; healthy transport never subscribes automatically.
    pub fn transport_ready(&mut self, session: u64) {
        if self.session == session && self.router.is_some() && !self.available {
            self.available = true;
            self.capture = self.capture.wrapping_add(1);
        }
    }
    pub fn transport_lost(&mut self, session: u64) {
        if self.session == session {
            self.available = false;
            self.receiver = None;
            self.deadline = None;
            self.capture = self.capture.wrapping_add(1);
        }
    }
    pub fn detach_session(&mut self, session: u64) {
        if self.session == session {
            self.detach();
        }
    }
    pub fn expire(&mut self) {
        self.expire_at(Instant::now());
    }
    fn expire_at(&mut self, now: Instant) {
        if self.deadline.is_some_and(|deadline| now >= deadline) {
            self.receiver = None;
            self.deadline = None;
            self.capture = self.capture.wrapping_add(1);
        }
    }
    fn token(&self) -> Token {
        Token {
            session: self.session,
            capture: self.capture,
        }
    }
    /// Current identity only. Never subscribes, drains or renews by itself.
    pub fn snapshot(&mut self) -> Snapshot {
        self.expire();
        Snapshot {
            schema: 1,
            token: self.token(),
            active: self.router.is_some() && self.available,
            enabled: self.receiver.is_some(),
            version: self.router.as_ref().map(|r| redacted_version(r.version())),
            lagged: 0,
            discarded_stale: 0,
            discarded_oversize: 0,
            events: Vec::new(),
        }
    }
    /// A caller must first obtain the current token. Stale enable/close is inert.
    pub fn observe(&mut self, token: Token, enabled: bool) -> Result<Snapshot, &'static str> {
        self.expire();
        if token != self.token() || self.router.is_none() || !self.available {
            return Err("Flow capture session changed");
        }
        if enabled {
            let receiver = self
                .router
                .as_ref()
                .unwrap()
                .observe_flows()
                .map_err(|_| "Flow capture unavailable")?;
            self.receiver = Some(receiver);
            self.deadline = Some(Instant::now() + IDLE_LEASE);
        } else {
            self.receiver = None;
            self.deadline = None;
        }
        self.capture = self.capture.wrapping_add(1);
        Ok(self.snapshot())
    }
    /// Only an explicit, still-current diagnostic poll renews and consumes capture.
    pub fn poll(&mut self, token: Token) -> Result<Snapshot, &'static str> {
        let mut snapshot = self.snapshot();
        let current = self.router.as_ref().map(|r| r.version());
        if token != self.token() || self.receiver.is_none() {
            return Err("Flow capture expired or cancelled");
        }
        self.deadline = Some(Instant::now() + IDLE_LEASE);
        let receiver = self.receiver.as_mut().unwrap();
        // At most 32 reads even if packets continue arriving while UI polls.
        for _ in 0..LIMIT {
            match receiver.try_recv() {
                Ok(event)
                    if Some(&event.version) == current.as_ref() && !event.decision.prediction =>
                {
                    let mut decision = event.decision;
                    decision.context.revision =
                        decision.context.revision.as_deref().map(revision_id);
                    snapshot.events.push(Event {
                        version: redacted_version(event.version),
                        age_ms: event
                            .observed_at
                            .elapsed()
                            .as_millis()
                            .min(u64::MAX as u128) as u64,
                        decision,
                    });
                }
                Ok(_) => snapshot.discarded_stale = snapshot.discarded_stale.saturating_add(1),
                Err(TryRecvError::Lagged(n)) => snapshot.lagged = snapshot.lagged.saturating_add(n),
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }
        // Bound the actual wire representation including metadata, rule IDs and
        // counters. Future typed fields cannot silently exceed the native budget.
        while serde_json::to_vec(&snapshot).map_or(true, |json| json.len() > MAX_SNAPSHOT_BYTES) {
            if snapshot.events.pop().is_none() {
                break;
            }
            snapshot.discarded_oversize = snapshot.discarded_oversize.saturating_add(1);
        }
        Ok(snapshot)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn router() -> Arc<Router> {
        Arc::new(
            serde_json::from_str::<rtrust_engine::routing::Policy>(
                r#"{"mode":"general","exclusions":["192.0.2.1"]}"#,
            )
            .unwrap()
            .compile()
            .unwrap(),
        )
    }
    #[test]
    fn opt_in_bounds_redaction_and_cancellation() {
        let router = router();
        let mut capture = Capture::default();
        let session = capture.attach(router.clone());
        capture.transport_ready(session);
        router.route_flow("192.0.2.1:443".parse().unwrap());
        let before = capture.snapshot();
        assert!(!before.enabled);
        assert!(before.events.is_empty());
        let token = capture.observe(before.token, true).unwrap().token;
        assert!(
            capture.poll(token).unwrap().events.is_empty(),
            "no retrospective history"
        );
        for _ in 0..100 {
            router.route_flow("192.0.2.1:443".parse().unwrap());
        }
        let snapshot = capture.poll(token).unwrap();
        assert!(snapshot.lagged > 0);
        assert!(snapshot.events.len() <= LIMIT);
        assert!(!snapshot.events.is_empty());
        assert!(
            snapshot
                .events
                .iter()
                .all(|e| !e.decision.prediction && Some(&e.version) == snapshot.version.as_ref())
        );
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(!json.contains("192.0.2.1"));
        capture.detach_session(session);
        assert!(capture.poll(token).is_err());
        assert!(!capture.snapshot().active);
        let fresh_session = capture.attach(router.clone());
        capture.transport_ready(fresh_session);
        assert_ne!(fresh_session, session);
        let fresh = capture.observe(capture.token(), true).unwrap().token;
        capture.detach_session(session);
        assert!(
            capture.snapshot().active,
            "old worker exit cannot detach current session"
        );
        assert!(capture.observe(token, false).is_err());
        assert!(capture.snapshot().enabled);
        let next = capture.observe(fresh, false).unwrap().token;
        let newer = capture.observe(next, true).unwrap().token;
        assert!(
            capture.observe(fresh, false).is_err(),
            "late close cannot cancel newer capture on same session"
        );
        assert!(capture.poll(newer).is_ok());
    }
    #[test]
    fn expiry_and_old_revision_are_explicit() {
        let router = router();
        let mut capture = Capture::default();
        let session = capture.attach(router.clone());
        capture.transport_ready(session);
        let token = capture.observe(capture.token(), true).unwrap().token;
        router.route_flow("192.0.2.1:443".parse().unwrap());
        let version = router.version();
        router
            .apply_local(
                &version,
                &serde_json::from_str(r#"{"mode":"general","exclusions":[]}"#).unwrap(),
                rtrust_profile::routing::Context {
                    source: rtrust_profile::routing::Source::EmbeddedProfile,
                    revision: Some("new".into()),
                },
            )
            .unwrap();
        let snapshot = capture.poll(token).unwrap();
        assert_eq!(snapshot.discarded_stale, 1);
        assert!(snapshot.events.is_empty());
        capture.expire_at(Instant::now() + IDLE_LEASE + Duration::from_secs(1));
        assert!(!capture.snapshot().enabled);
        assert!(capture.poll(token).is_err());
    }
    #[test]
    fn free_text_revision_is_hashed_at_every_serialized_boundary() {
        let secret = "device=person@example.test password=not-for-reports";
        let policy: rtrust_engine::routing::Policy =
            serde_json::from_str(r#"{"mode":"general","exclusions":[]}"#).unwrap();
        let router = Arc::new(
            policy
                .compile_with_context(rtrust_profile::routing::Context {
                    source: rtrust_profile::routing::Source::EmbeddedProfile,
                    revision: Some(secret.into()),
                })
                .unwrap(),
        );
        let mut capture = Capture::default();
        let session = capture.attach(router.clone());
        capture.transport_ready(session);
        let identity = capture.snapshot();
        assert!(!serde_json::to_string(&identity).unwrap().contains(secret));
        let token = capture.observe(identity.token, true).unwrap().token;
        router.route_flow("192.0.2.1:443".parse().unwrap());
        let snapshot = capture.poll(token).unwrap();
        let json = serde_json::to_string(&snapshot).unwrap();
        for value in [
            secret,
            "person@example.test",
            "not-for-reports",
            "192.0.2.1",
        ] {
            assert!(!json.contains(value));
        }
        assert_eq!(snapshot.version.as_ref().unwrap().revision.len(), 64);
        assert_eq!(snapshot.events.len(), 1);
        assert_eq!(snapshot.events[0].version.revision.len(), 64);
        assert_eq!(
            snapshot.events[0]
                .decision
                .context
                .revision
                .as_ref()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(snapshot.events[0].version, snapshot.version.unwrap());
    }
    #[test]
    fn transport_failure_fences_queued_capture_during_wait_and_recovery() {
        let router = router();
        let mut capture = Capture::default();
        let owner = capture.attach(router.clone());
        assert!(!capture.snapshot().active);
        assert!(capture.observe(capture.token(), true).is_err());
        capture.transport_ready(owner);
        let old = capture.observe(capture.token(), true).unwrap().token;
        router.route_flow("192.0.2.1:443".parse().unwrap());
        capture.transport_lost(owner); // fatal authentication wait or reconnect
        assert!(capture.poll(old).is_err());
        assert!(!capture.snapshot().active);
        assert!(capture.observe(capture.token(), true).is_err());
        capture.transport_ready(owner);
        assert!(
            !capture.snapshot().enabled,
            "recovery must require fresh opt-in"
        );
        let fresh = capture.observe(capture.token(), true).unwrap().token;
        assert!(capture.poll(fresh).unwrap().events.is_empty());
        assert!(capture.observe(old, false).is_err());
        let replacement = capture.attach(router.clone());
        capture.transport_ready(replacement);
        let current = capture.observe(capture.token(), true).unwrap().token;
        capture.transport_lost(owner);
        capture.transport_ready(owner);
        capture.detach_session(owner);
        assert!(capture.snapshot().active);
        assert!(capture.poll(current).is_ok());
    }
    #[test]
    fn maximum_matching_rules_batch_is_byte_bounded_and_loss_explicit() {
        let policy = rtrust_engine::routing::Policy {
            mode: "general".into(),
            exclusions: vec!["192.0.2.1".into(); 64],
        };
        let router = Arc::new(policy.compile().unwrap());
        let mut capture = Capture::default();
        let owner = capture.attach(router.clone());
        capture.transport_ready(owner);
        let token = capture.observe(capture.token(), true).unwrap().token;
        for _ in 0..LIMIT {
            router.route_flow("192.0.2.1:443".parse().unwrap());
        }
        let snapshot = capture.poll(token).unwrap();
        assert!(serde_json::to_vec(&snapshot).unwrap().len() <= MAX_SNAPSHOT_BYTES);
        assert!(serde_json::to_vec(&snapshot).unwrap().len() < 65536);
        assert!(snapshot.discarded_oversize > 0);
        assert_eq!(
            snapshot.events.len() as u64 + snapshot.discarded_oversize,
            LIMIT as u64
        );
        assert!(snapshot.events.iter().all(|e| e.decision.rules.len() == 64));
    }
}
