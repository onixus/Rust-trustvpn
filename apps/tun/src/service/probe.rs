//! Linux facts for the service probe: own nftables table, resolved link DNS,
//! routes and two kinds of datagrams. Read-only; every socket is unmarked.
use super::{full, routes::DEVICE};
use crate::sysprobe::{self, Attempt, Audit, Dns, Foreign, Path, linux};
use rtrust_control::observations::{SystemProbe, now_ms};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
};
const NFT: &str = "/usr/sbin/nft";
const IP: &str = "/usr/sbin/ip";
const RESOLVECTL: &str = "/usr/bin/resolvectl";
const MAX: usize = 64 * 1024;

#[derive(Clone)]
pub(super) struct Plan {
    pub dns: Ipv4Addr,
    pub endpoints: Vec<IpAddr>,
}
pub(super) async fn collect(plan: Plan) -> SystemProbe {
    let (audit, attempts, dns) = tokio::join!(audit(), attempts(&plan), dns(plan.dns));
    sysprobe::result(dns, audit, &attempts, now_ms())
}
async fn audit() -> Audit {
    match sysprobe::run(NFT, &["-j", "list", "tables"], MAX)
        .await
        .and_then(|bytes| linux::has_table(&bytes, full::NFT))
    {
        Some(true) => {}
        Some(false) => return Audit::Mismatch,
        None => return Audit::Unknown,
    }
    let mut expected: Vec<String> = full::GUARD_CHAINS.map(str::to_owned).to_vec();
    expected.extend(
        full::guard_rules()
            .into_iter()
            .map(|(_, canonical)| format!("output {canonical}")),
    );
    match sysprobe::run(NFT, &["-j", "list", "table", "inet", full::NFT], MAX).await {
        Some(bytes) => linux::audit(&bytes, &expected),
        None => Audit::Unknown,
    }
}
fn socket(v6: bool, device: &str) -> Option<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    let fd = socket.as_raw_fd();
    let name = std::ffi::CString::new(device).ok()?;
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as _,
        )
    } != 0
    {
        return None;
    }
    // The transport's mark is the guard's only exemption; never test with it.
    let mut mark = u32::MAX;
    let mut len = std::mem::size_of_val(&mark) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut mark as *mut u32).cast(),
            &mut len,
        )
    } != 0
        || mark != 0
    {
        return None;
    }
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}
/// Each physical link with a default route refuses an unmarked datagram
/// locally (nftables drop on output reports EPERM).
async fn attempts(plan: &Plan) -> Vec<Attempt> {
    if sysprobe::collides(&plan.endpoints) {
        return vec![Attempt::Unknown];
    }
    let Some(devices) = sysprobe::run(
        IP,
        &["-j", "-4", "route", "show", "table", "main", "default"],
        MAX,
    )
    .await
    .and_then(|bytes| linux::default_devices(&bytes, DEVICE)) else {
        return vec![Attempt::Unknown];
    };
    let mut attempts = Vec::new();
    for device in devices {
        for (target, absent) in [
            (sysprobe::TARGET_V4, &[][..]),
            (
                sysprobe::TARGET_V6,
                &[libc::ENETUNREACH, libc::EHOSTUNREACH, libc::EADDRNOTAVAIL][..],
            ),
        ] {
            attempts.push(match socket(target.is_ipv6(), &device) {
                Some(socket) => {
                    sysprobe::attempt(sysprobe::send(&socket, target), &[libc::EPERM], absent)
                }
                None if target.is_ipv6() => Attempt::Absent,
                None => Attempt::Unknown,
            });
        }
    }
    attempts
}
async fn values(setting: &str) -> Option<Vec<String>> {
    let bytes = sysprobe::run(RESOLVECTL, &[setting, DEVICE], MAX).await?;
    linux::link_values(std::str::from_utf8(&bytes).ok()?, DEVICE)
}
async fn dns(server: Ipv4Addr) -> Dns {
    let address = server.to_string();
    let route_args = ["-j", "-4", "route", "get", &address, "mark", "0"];
    let (servers, domains, default_route, all, route, conf, reply) = tokio::join!(
        values("dns"),
        values("domain"),
        values("default-route"),
        sysprobe::run(RESOLVECTL, &["dns"], MAX),
        sysprobe::run(IP, &route_args, MAX),
        tokio::fs::read("/etc/resolv.conf"),
        async {
            match socket(false, DEVICE) {
                Some(socket) => {
                    sysprobe::exchange(socket, SocketAddr::new(server.into(), 53)).await
                }
                None => sysprobe::Reply::None,
            }
        },
    );
    let config = match (servers, domains, default_route) {
        (Some(servers), Some(domains), Some(default_route)) => {
            if servers == [address.as_str()]
                && domains.iter().any(|d| d == "~.")
                && default_route == ["yes"]
            {
                Audit::Match
            } else {
                Audit::Mismatch
            }
        }
        _ => Audit::Unknown,
    };
    let links = all
        .as_deref()
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|text| linux::foreign_links(text, DEVICE));
    let conf = conf
        .ok()
        .filter(|b| b.len() <= MAX)
        .and_then(|b| String::from_utf8(b).ok())
        .map(|text| linux::resolv_conf_foreign(&text, server));
    Dns {
        config,
        path: match route.as_deref().and_then(linux::route_device) {
            Some(dev) if dev == DEVICE => Path::Tunnel,
            Some(_) => Path::Outside,
            None => Path::Unknown,
        },
        reply,
        foreign: match (links, conf) {
            (Some(true), _) | (_, Some(true)) => Foreign::Present,
            (Some(false), Some(false)) => Foreign::None,
            _ => Foreign::Unknown,
        },
    }
}

#[cfg(test)]
mod tester_tests {
    // tester (issue #81): Linux-only checks; nothing here sends a datagram.
    use super::*;
    #[test]
    fn probe_sockets_are_never_marked_and_unknown_devices_fail_closed() {
        assert!(socket(false, "rtcanary0").is_none());
        assert!(socket(true, "rtcanary0").is_none());
        assert!(socket(false, "bad\0name").is_none());
        // SO_BINDTODEVICE needs CAP_NET_RAW; when granted, the mark must be 0.
        if let Some(s) = socket(false, "lo") {
            let mut mark = u32::MAX;
            let mut len = std::mem::size_of_val(&mark) as libc::socklen_t;
            assert_eq!(
                unsafe {
                    libc::getsockopt(
                        s.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_MARK,
                        (&mut mark as *mut u32).cast(),
                        &mut len,
                    )
                },
                0
            );
            assert_eq!(mark, 0);
        }
    }
    #[tokio::test]
    async fn a_colliding_endpoint_makes_the_bypass_check_inconclusive() {
        let plan = Plan {
            dns: "198.51.100.53".parse().unwrap(),
            endpoints: vec![sysprobe::TARGET_V4.ip(), "203.0.113.7".parse().unwrap()],
        };
        assert_eq!(attempts(&plan).await, vec![Attempt::Unknown]);
    }
    /// Runs the real collector. Only for an isolated network namespace
    /// (e.g. `docker run --network none`): it reads host tools and could send
    /// one-byte datagrams to documentation addresses on a real host.
    #[tokio::test]
    #[ignore = "isolated network namespace only"]
    async fn collector_in_an_empty_namespace_is_unproven_and_anonymous() {
        let plan = Plan {
            dns: "198.51.100.53".parse().unwrap(),
            endpoints: vec![
                "203.0.113.7".parse().unwrap(),
                "2001:db8::53".parse().unwrap(),
            ],
        };
        let started = std::time::Instant::now();
        let probe = collect(plan).await;
        assert!(
            started.elapsed()
                < std::time::Duration::from_millis(rtrust_control::observations::PROBE_DEADLINE_MS)
        );
        assert_eq!(probe.transport_proven_at, None);
        assert_ne!(
            probe.dns.outcome,
            rtrust_control::observations::Outcome::Passed
        );
        assert_ne!(
            probe.guard.outcome,
            rtrust_control::observations::Outcome::Passed
        );
        let mut monitor = rtrust_control::observations::Monitor::new(
            rtrust_control::observations::Mode::Full,
            rtrust_control::observations::Source::ServiceLifecycle,
            now_ms(),
        );
        assert!(monitor.apply_system(monitor.generation(), probe, now_ms()));
        let mut response = rtrust_control::Response::new(rtrust_control::State::Connected, "full");
        response.observations = monitor.sample(now_ms());
        let text = serde_json::to_string(&response).unwrap();
        for canary in [
            "198.51.100.53",
            "203.0.113.7",
            "2001:db8::53",
            "rtrust0",
            "rtcanary0",
        ] {
            assert!(!text.contains(canary), "{canary}");
        }
        assert!(!response.observations.verified());
    }
}
