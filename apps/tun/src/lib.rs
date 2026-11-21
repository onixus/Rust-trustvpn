//! Experimental bounded IPv4 data plane. No routing, DNS or firewall changes.
#[cfg(any(target_os = "windows", test))]
mod adapter_cleanup;
mod adapter_package;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod always_on;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
pub mod boot_policy;
pub mod echo;
pub mod fragments;
pub mod ipv6;
pub mod packet;
pub mod policy;
pub mod reason;
pub mod stack;
pub mod stats;

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod failover;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod netwatch;
#[cfg(target_os = "linux")]
pub mod service;
#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
mod sysprobe;

#[cfg(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "android",
    target_os = "ios"
))]
mod dataplane;
#[cfg(target_os = "android")]
pub use dataplane::run_with_dns as run_android;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;

/// Best-effort diagnostics. A test build must not touch the installed journal:
/// `rtrust_journal::service` is disabled only inside that crate's own tests.
/// Linux and macOS call it; Windows reaches the journal through `sysprobe`.
#[cfg_attr(target_os = "windows", allow(dead_code))]
pub(crate) fn journal(level: rtrust_journal::Level, event: &str) {
    #[cfg(not(test))]
    rtrust_journal::service().lifecycle_at(level, event);
    #[cfg(test)]
    let _ = (level, event);
}

/// A process that cannot continue. Critical lines enter even a full queue, and
/// the flush waits until the writer has taken the line. A `false` result means
/// the line was not confirmed; callers still exit, but must not claim it landed.
pub fn journal_stop(event: &str) -> bool {
    let journal = rtrust_journal::service();
    journal.lifecycle_at(rtrust_journal::Level::Critical, event);
    journal.flush(std::time::Duration::from_secs(2))
}

pub use dataplane::{
    PacketDevice, degraded, degraded_event, degraded_kind, run_with_dns as run_packet_flow,
    run_with_policy, unproven,
};
