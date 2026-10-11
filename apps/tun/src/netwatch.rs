//! Native network-change and resume evidence for a lease (issue #31).
//!
//! Sleep is measured by the kernel, not inferred from a polling gap: the
//! difference between a clock that counts suspended time and one that does not
//! grows only while the system sleeps. A network change is a change in the
//! link state or addresses of any interface except loopback and our own TUN;
//! route edits (our guard's included) are ignored. Linux and macOS wake on
//! netlink/routing-socket messages; every platform also re-checks periodically.
//! Nothing here changes routes, DNS or the guard.
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    time::Duration,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Network,
    Resumed,
}

/// Suspended time above this is reported; timer jitter stays far below it.
const RESUME_THRESHOLD_NS: u64 = 2_000_000_000;
/// Address/link notifications arrive in bursts during one handoff.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const SETTLE: Duration = Duration::from_millis(500);
#[cfg(any(target_os = "linux", target_os = "macos"))]
const POLL: Duration = Duration::from_secs(10);
#[cfg(target_os = "windows")]
const POLL: Duration = Duration::from_secs(2);

pub struct Watch {
    exclude: &'static str,
    interfaces: Option<u64>,
    slept_ns: Option<u64>,
    tick: tokio::time::Interval,
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    notify: Option<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>,
    /// Kept here, not in the future: a `select!` that drops `next()` during
    /// the settle window resumes it instead of losing the notification.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    settle_until: Option<tokio::time::Instant>,
}

impl Watch {
    /// `exclude` is our TUN interface name: its own state changes are not a
    /// change of the underlying network.
    pub fn new(exclude: &'static str) -> Self {
        let mut tick = tokio::time::interval(POLL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        Self {
            exclude,
            interfaces: signature(exclude),
            slept_ns: slept_ns(),
            tick,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            notify: notify_socket()
                .inspect_err(|error| eprintln!("Network change notifications unavailable: {error}"))
                .ok(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            settle_until: None,
        }
    }

    /// Resolves at the next detected change. Cancel-safe for `select!`: state
    /// lives in `self`, and an interrupted check is repeated on the next call.
    pub async fn next(&mut self) -> Change {
        loop {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                if let Some(deadline) = self.settle_until {
                    tokio::time::sleep_until(deadline).await;
                    self.settle_until = None;
                    if let Some(fd) = &self.notify {
                        drain(fd.get_ref());
                    }
                } else {
                    let notify = &self.notify;
                    let notified = async move {
                        match notify {
                            Some(fd) => fd.readable().await.map(|mut guard| {
                                // Keep readiness while messages remain queued.
                                if drain(guard.get_inner()) {
                                    guard.clear_ready();
                                }
                            }),
                            None => std::future::pending().await,
                        }
                    };
                    let woken = tokio::select! {
                        _ = self.tick.tick() => None,
                        result = notified => Some(result.is_ok()),
                    };
                    match woken {
                        Some(false) => self.notify = None,
                        Some(true) => {
                            self.settle_until = Some(tokio::time::Instant::now() + SETTLE);
                            continue;
                        }
                        None => {}
                    }
                }
            }
            #[cfg(target_os = "windows")]
            self.tick.tick().await;
            if let Some(change) = self.check() {
                return change;
            }
        }
    }

    fn check(&mut self) -> Option<Change> {
        // Read interfaces after a resume too, so the same handoff is not
        // reported again as a separate change on the next tick.
        self.observe(slept_ns(), signature(self.exclude))
    }

    fn observe(&mut self, slept: Option<u64>, interfaces: Option<u64>) -> Option<Change> {
        let resumed = matches!((self.slept_ns, slept), (Some(old), Some(new))
            if new.saturating_sub(old) >= RESUME_THRESHOLD_NS);
        if slept.is_some() {
            self.slept_ns = slept;
        }
        let changed = interfaces.is_some() && interfaces != self.interfaces;
        if interfaces.is_some() {
            self.interfaces = interfaces;
        }
        if resumed {
            Some(Change::Resumed)
        } else if changed {
            Some(Change::Network)
        } else {
            None
        }
    }
}

/// Cumulative suspended time since boot.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn slept_ns() -> Option<u64> {
    fn read(clock: libc::clockid_t) -> Option<u64> {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        (unsafe { libc::clock_gettime(clock, &mut time) } == 0)
            .then(|| time.tv_sec as u64 * 1_000_000_000 + time.tv_nsec as u64)
    }
    #[cfg(target_os = "linux")]
    let (with_sleep, awake) = (libc::CLOCK_BOOTTIME, libc::CLOCK_MONOTONIC);
    // Darwin's CLOCK_MONOTONIC continues during sleep; CLOCK_UPTIME_RAW stops.
    #[cfg(target_os = "macos")]
    let (with_sleep, awake) = (libc::CLOCK_MONOTONIC, libc::CLOCK_UPTIME_RAW);
    // Read the stopping clock first: the difference can only be overstated by
    // the tiny interval between the two reads, never understated.
    let awake = read(awake)?;
    Some(read(with_sleep)?.saturating_sub(awake))
}

#[cfg(target_os = "windows")]
fn slept_ns() -> Option<u64> {
    use windows_sys::Win32::System::{
        SystemInformation::GetTickCount64, WindowsProgramming::QueryUnbiasedInterruptTime,
    };
    let mut unbiased = 0u64;
    // Unbiased interrupt time excludes sleep and hibernation; the tick count does not.
    (unsafe { QueryUnbiasedInterruptTime(&mut unbiased) } != 0).then(|| {
        let with_sleep = unsafe { GetTickCount64() };
        (with_sleep * 1_000_000).saturating_sub(unbiased * 100)
    })
}

/// A fingerprint of link state and addresses; `None` if the OS refused to list
/// interfaces, which is neither a change nor stability.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn signature(exclude: &str) -> Option<u64> {
    let mut list = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return None;
    }
    let mut rows = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        let flags = ifa.ifa_flags as u32;
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }.to_bytes();
        if flags & libc::IFF_LOOPBACK as u32 != 0 || name == exclude.as_bytes() {
            continue;
        }
        let up = flags & (libc::IFF_UP | libc::IFF_RUNNING) as u32;
        rows.push((name.to_vec(), up, unsafe { address(ifa.ifa_addr) }));
    }
    unsafe { libc::freeifaddrs(list) };
    Some(fingerprint(rows))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
unsafe fn address(addr: *const libc::sockaddr) -> Vec<u8> {
    if addr.is_null() {
        return vec![];
    }
    match unsafe { (*addr).sa_family } as i32 {
        libc::AF_INET => {
            let v4 = unsafe { &*(addr as *const libc::sockaddr_in) };
            v4.sin_addr.s_addr.to_ne_bytes().to_vec()
        }
        libc::AF_INET6 => {
            let v6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
            v6.sin6_addr.s6_addr.to_vec()
        }
        // Link-layer rows carry counters on some systems: only their flags count.
        _ => vec![],
    }
}

#[cfg(target_os = "windows")]
fn signature(exclude: &str) -> Option<u64> {
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6},
    };
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024u32;
    let mut buffer = Vec::<u64>::new();
    let mut filled = false;
    for _ in 0..3 {
        buffer.resize((size as usize).div_ceil(8), 0);
        match unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        } {
            ERROR_SUCCESS => {
                filled = true;
                break;
            }
            ERROR_BUFFER_OVERFLOW => continue,
            _ => return None,
        }
    }
    // The list kept growing: an unfilled buffer is not an adapter list.
    if !filled {
        return None;
    }
    let mut rows = Vec::new();
    let mut adapter = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !adapter.is_null() {
        let a = unsafe { &*adapter };
        adapter = a.Next;
        let name = unsafe { std::ffi::CStr::from_ptr(a.AdapterName.cast()) }.to_bytes();
        // Wintun's friendly name is the adapter name the service created.
        if a.IfType == IF_TYPE_SOFTWARE_LOOPBACK || unsafe { wide(a.FriendlyName) } == exclude {
            continue;
        }
        let up = (a.OperStatus == IfOperStatusUp) as u32;
        let mut unicast = a.FirstUnicastAddress;
        let mut addresses = Vec::new();
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            unicast = u.Next;
            let sockaddr = u.Address.lpSockaddr;
            if sockaddr.is_null() {
                continue;
            }
            match unsafe { (*sockaddr).sa_family } {
                AF_INET => addresses.extend_from_slice(&unsafe {
                    (*(sockaddr as *const SOCKADDR_IN))
                        .sin_addr
                        .S_un
                        .S_addr
                        .to_ne_bytes()
                }),
                AF_INET6 => addresses.extend_from_slice(&unsafe {
                    (*(sockaddr as *const SOCKADDR_IN6)).sin6_addr.u.Byte
                }),
                _ => {}
            }
        }
        rows.push((name.to_vec(), up, addresses));
    }
    Some(fingerprint(rows))
}

#[cfg(target_os = "windows")]
unsafe fn wide(text: *const u16) -> String {
    if text.is_null() {
        return String::new();
    }
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) })
}

fn fingerprint(mut rows: Vec<(Vec<u8>, u32, Vec<u8>)>) -> u64 {
    rows.sort();
    rows.dedup();
    let mut hasher = DefaultHasher::new();
    rows.hash(&mut hasher);
    hasher.finish()
}

/// Wake-up only: the messages are drained, never parsed or trusted.
#[cfg(target_os = "linux")]
fn notify_socket() -> std::io::Result<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>> {
    use std::os::fd::FromRawFd;
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_groups =
        (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR) as u32;
    use std::os::fd::AsRawFd;
    if unsafe {
        libc::bind(
            fd.as_raw_fd(),
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    tokio::io::unix::AsyncFd::new(fd)
}

#[cfg(target_os = "macos")]
fn notify_socket() -> std::io::Result<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    unsafe {
        let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
        if flags < 0
            || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0
            || libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    tokio::io::unix::AsyncFd::new(fd)
}

/// True when the queue is empty. Bounded: a flood of route messages must not
/// starve the lease loop; the rest is read on the next wakeup.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn drain(fd: &std::os::fd::OwnedFd) -> bool {
    use std::os::fd::AsRawFd;
    let mut buffer = [0u8; 8192];
    for _ in 0..64 {
        if unsafe { libc::recv(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len(), 0) } <= 0 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_fingerprint_ignores_order_and_duplicates() {
        let a = (b"en0".to_vec(), 1, vec![192, 0, 2, 1]);
        let b = (b"en1".to_vec(), 1, vec![]);
        assert_eq!(
            fingerprint(vec![a.clone(), b.clone()]),
            fingerprint(vec![b.clone(), a.clone(), a.clone()])
        );
        let mut down = a.clone();
        down.1 = 0;
        assert_ne!(
            fingerprint(vec![a.clone(), b.clone()]),
            fingerprint(vec![down, b.clone()])
        );
        let mut moved = a;
        moved.2 = vec![192, 0, 2, 2];
        assert_ne!(fingerprint(vec![moved, b.clone()]), fingerprint(vec![b]));
    }

    #[test]
    fn host_clocks_and_interfaces_are_readable_and_stable() {
        let first = slept_ns().expect("suspend clock");
        let second = slept_ns().expect("suspend clock");
        // No sleep between two reads: well under the reporting threshold.
        assert!(second.saturating_sub(first) < RESUME_THRESHOLD_NS);
        assert!(signature("rtrust-test-none").is_some());
    }

    #[test]
    fn a_resume_is_reported_once_and_supersedes_a_simultaneous_handoff() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut watch = Watch::new("rtrust-test-none");
            // Unprivileged processes may read netlink/routing-socket messages.
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            assert!(watch.notify.is_some());
            watch.slept_ns = Some(5);
            watch.interfaces = Some(1);
            assert_eq!(
                watch.observe(Some(5 + RESUME_THRESHOLD_NS), Some(2)),
                Some(Change::Resumed)
            );
            assert_eq!(watch.observe(Some(6 + RESUME_THRESHOLD_NS), Some(2)), None);
            assert_eq!(
                watch.observe(Some(6 + RESUME_THRESHOLD_NS), Some(3)),
                Some(Change::Network)
            );
            // A failed read is neither a change nor a new baseline.
            assert_eq!(watch.observe(None, None), None);
            assert_eq!(watch.observe(Some(7 + RESUME_THRESHOLD_NS), Some(3)), None);
            assert_eq!(
                watch.observe(Some(8 + RESUME_THRESHOLD_NS), Some(4)),
                Some(Change::Network)
            );
        });
    }

    /// Needs CAP_NET_ADMIN in a disposable namespace:
    /// `cargo test -p rtrust-tun netlink -- --ignored` inside a container.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn netlink_reports_an_address_change_before_the_poll_interval() {
        let ip = |args: &[&str]| {
            assert!(
                std::process::Command::new("ip")
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            )
        };
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let _ = std::process::Command::new("ip")
                .args(["link", "del", "rtwatch0"])
                .stderr(std::process::Stdio::null())
                .status();
            let mut watch = Watch::new("rtrust-test-none");
            assert!(watch.notify.is_some());
            watch.tick.tick().await;
            let started = std::time::Instant::now();
            ip(&["link", "add", "rtwatch0", "type", "dummy"]);
            ip(&["addr", "add", "198.51.100.7/32", "dev", "rtwatch0"]);
            // A select! that drops next() inside the settle window must not
            // lose the notification.
            assert!(
                tokio::time::timeout(SETTLE / 5, watch.next())
                    .await
                    .is_err()
            );
            assert!(watch.settle_until.is_some());
            let change = tokio::time::timeout(Duration::from_secs(5), watch.next()).await;
            assert_eq!(change.unwrap(), Change::Network);
            assert!(started.elapsed() < POLL);
            // Our own TUN is excluded by name.
            let mut ours = Watch::new("rtwatch0");
            ours.tick.tick().await;
            ip(&["addr", "add", "198.51.100.8/32", "dev", "rtwatch0"]);
            assert!(
                tokio::time::timeout(Duration::from_secs(2), ours.next())
                    .await
                    .is_err()
            );
            ip(&["link", "del", "rtwatch0"]);
        });
    }
}
