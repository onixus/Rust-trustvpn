//! Shared, redacted policy explanation contract. It performs no network I/O.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Tunnel,
    Direct,
    Block,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Local,
    EmbeddedProfile,
    Admin,
    User,
    ManagedUnknown,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub source: Source,
    pub revision: Option<String>,
}
impl Default for Context {
    fn default() -> Self {
        Self {
            source: Source::EmbeddedProfile,
            revision: None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Basis {
    NumericDestination,
    ObservedDnsCache,
    MissingDnsName,
    SharedDnsNames,
    MissingRuntimeInputs,
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    DnsAlwaysTunneled,
    MatchedRule,
    DefaultTunnel,
    DefaultDirect,
    UnknownNameProtected,
    SharedIpConflictProtected,
    SelectedPrefix,
    ExcludedPrefix,
    ReservedAddress,
    OutsideSelection,
    EndpointBypass,
    LocalNetworkBypass,
    EndpointUnresolved,
    LocalNetworksUnobserved,
    UnsupportedFamily,
    SystemPathUnobserved,
    ProxyScope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    Flow,
    Include,
    Exclude,
    Reserved,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleId {
    pub kind: RuleKind,
    pub index: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    FlowPolicy,
    SelectedIpv4,
    SystemPath,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub action: Action,
    pub scope: Scope,
    pub rules: Vec<RuleId>,
    pub context: Context,
    pub reason: Reason,
    pub basis: Basis,
    /// Evaluation of policy inputs, never a packet capture or system-route attestation.
    pub prediction: bool,
}
impl Decision {
    pub fn unknown(context: Context, reason: Reason) -> Self {
        Self {
            action: Action::Unknown,
            scope: Scope::SystemPath,
            rules: vec![],
            context,
            reason,
            basis: Basis::MissingRuntimeInputs,
            prediction: true,
        }
    }
}
