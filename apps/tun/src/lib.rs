//! Experimental bounded IPv4 data plane. No routing, DNS or firewall changes.
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod always_on;
#[cfg(any(target_os = "linux", target_os = "windows"))]
pub mod boot_policy;
pub mod echo;
pub mod fragments;
pub mod ipv6;
pub mod packet;
pub mod stack;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod service;

#[cfg(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "android"
))]
mod dataplane;
#[cfg(target_os = "android")]
pub use dataplane::run as run_android;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "macos")]
pub mod macos;
