//! Explicit service-owned endpoint check, never a general outbound proxy.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub lease: [u8; 16],
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Passed,
    Failed,
    Inconclusive,
    Unsupported,
    RateLimited,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    EndpointHealthy,
    ConnectionFailed,
    TlsFailed,
    AuthenticationFailed,
    ProtocolFailed,
    EndpointRejected,
    Timeout,
    PhysicalPathUnproven,
    UnsupportedTransport,
    StaleLease,
    Cancelled,
    Cooldown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Result {
    pub token: Token,
    pub active_profile: Option<u8>,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub outcome: Outcome,
    pub reason: Reason,
    /// Every socket was bound to a verified physical interface before connect.
    pub independent: bool,
}
impl Result {
    pub fn unknown(token: Token, outcome: Outcome, reason: Reason) -> Self {
        let now = crate::observations::now_ms();
        Self {
            token,
            active_profile: None,
            started_at_ms: now,
            completed_at_ms: now,
            outcome,
            reason,
            independent: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_cannot_select_arbitrary_profile_or_destination() {
        let token = Token {
            lease: [1; 16],
            generation: 1,
        };
        let command = serde_json::to_value(crate::Command::ProbeEndpoint { token }).unwrap();
        assert!(command.get("profile").is_none());
        for key in ["profile", "url", "address"] {
            let mut bad = command.clone();
            bad[key] = "attacker-controlled".into();
            assert!(serde_json::from_value::<crate::Command>(bad).is_err());
        }
    }
}
