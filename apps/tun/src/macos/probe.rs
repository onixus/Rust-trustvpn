//! macOS facts for the service probe: own PF anchor, dynamic DNS entry,
//! routes and two kinds of datagrams. Read-only: pfctl only lists or parses
//! (`-n`), the DNS entry is compared, never installed.
use super::{capture, device::DEVICE, dns, firewall, route_table, state::DIRECTORY};
use crate::sysprobe::{self, Attempt, Audit, Dns, Foreign, Path, macos};
use rtrust_control::observations::SystemProbe;
use std::{
    io::Write,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
};
const PFCTL: &str = "/sbin/pfctl";
const MAX: usize = 64 * 1024;
static LANE: sysprobe::Lane = sysprobe::Lane::new();
/// The BPF watch blocks for up to half a second; never stack two.
static CAPTURE: sysprobe::Lane = sysprobe::Lane::new();

#[derive(Clone)]
pub(super) struct Plan {
    pub uid: u32,
    pub dns: Ipv4Addr,
    pub permits: Vec<crate::failover::Permit>,
    pub endpoints: Vec<IpAddr>,
}
pub(super) async fn collect(plan: Plan) -> SystemProbe {
    sysprobe::evidence(async {
        let (audit, attempts, dns) = tokio::join!(
            sysprobe::part(Audit::Unknown, audit(&plan)),
            sysprobe::part(vec![Attempt::Unknown], attempts(&plan)),
            sysprobe::part(Dns::UNKNOWN, dns(&plan)),
        );
        (dns, audit, attempts)
    })
    .await
}
async fn text(path: &'static str, args: &[&str]) -> Option<String> {
    String::from_utf8(sysprobe::run(path, args, MAX).await?).ok()
}
async fn audit(plan: &Plan) -> Audit {
    match text(PFCTL, &["-s", "info"])
        .await
        .as_deref()
        .and_then(macos::pf_enabled)
    {
        Some(true) => {}
        Some(false) => return Audit::Mismatch,
        None => return Audit::Unknown,
    }
    let Some(root) = text(PFCTL, &["-sr"]).await else {
        return Audit::Unknown;
    };
    let root: Vec<_> = root
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if !firewall::standard_root(&root) {
        return Audit::Mismatch;
    }
    // A foreign anchor sorting before ours could pass traffic first.
    let Some(anchors) = text(PFCTL, &["-a", "com.apple", "-s", "Anchors"]).await else {
        return Audit::Unknown;
    };
    let anchors: Vec<_> = anchors
        .lines()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .collect();
    if anchors.len() > 32 {
        return Audit::Unknown;
    }
    for anchor in anchors {
        let Some(path) = firewall::anchor_path(anchor) else {
            return Audit::Unknown;
        };
        if path == firewall::ANCHOR {
            continue;
        }
        match text(PFCTL, &["-a", &path, "-sr"]).await {
            Some(rules) if rules.trim().is_empty() => {}
            Some(_) => return Audit::Mismatch,
            None => return Audit::Unknown,
        }
    }
    let Some(loaded) = text(PFCTL, &["-a", firewall::ANCHOR, "-sr"]).await else {
        return Audit::Unknown;
    };
    let script = firewall::policy(plan.uid, true, &[], &plan.permits);
    let Ok(mut file) = tempfile::NamedTempFile::new_in(DIRECTORY) else {
        return Audit::Unknown;
    };
    let Some(path) = file
        .write_all(script.as_bytes())
        .ok()
        .and_then(|()| file.path().to_str().map(str::to_owned))
    else {
        return Audit::Unknown;
    };
    match text(PFCTL, &["-nv", "-a", firewall::ANCHOR, "-f", &path]).await {
        Some(expected) => macos::same_rules(
            &loaded,
            &expected,
            &format!("label \"rtrust-{}\"", plan.uid),
        ),
        None => Audit::Unknown,
    }
}
pub(super) fn socket(v6: bool, interface: &str) -> Option<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(if v6 { "[::]:0" } else { "0.0.0.0:0" }).ok()?;
    let name = std::ffi::CString::new(interface).ok()?;
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        return None;
    }
    let (level, option) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    };
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&index as *const u32).cast(),
            std::mem::size_of_val(&index) as _,
        )
    } != 0
    {
        return None;
    }
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}
/// Physical interfaces with a default route, each with its own gateway
/// (None when the gateway is not a usable address, e.g. `link#N`).
async fn defaults(v6: bool) -> Option<Vec<(String, Option<IpAddr>)>> {
    let table = text(
        "/usr/sbin/netstat",
        &["-rn", "-f", if v6 { "inet6" } else { "inet" }],
    )
    .await?;
    let mut interfaces: Vec<(String, Option<IpAddr>)> = Vec::new();
    for entry in route_table::parse(&table).ok()? {
        if entry.destination == "default"
            && !entry.interface.starts_with("utun")
            && entry.interface != "lo0"
            && !interfaces.iter().any(|(i, _)| *i == entry.interface)
        {
            let gateway = macos::gateway(&entry.gateway, &entry.interface);
            interfaces.push((entry.interface, gateway));
        }
    }
    (interfaces.len() <= 8).then_some(interfaces)
}
/// Our final block rule's packet counter, read back without changes.
async fn blocked_packets(uid: u32) -> Option<u64> {
    let text = text(PFCTL, &["-a", firewall::ANCHOR, "-vsr"]).await?;
    macos::block_packets(&text, &format!("label \"rtrust-{uid}\""))
}
/// A datagram bound to `interface` and sent to that interface's own default
/// gateway, watched on the interface's BPF tap. Once utun owns 0/1 and
/// 128/1, an unscoped physical default no longer answers interface-scoped
/// lookups for far targets, so 192.0.2.1 failed in routing (ENETUNREACH)
/// before PF saw it; the gateway is on-link and its scoped route is checked
/// first. PF's drop is silent, so the verdict is the tap, not the errno.
/// No route, an endpoint address or an unusable tap is Unknown.
async fn onlink(plan: &Plan, interface: &str, gateway: Option<IpAddr>) -> Attempt {
    let Some(gateway) = gateway else {
        return Attempt::Unknown;
    };
    // An endpoint permit would pass it: that tests the exemption, not the guard.
    if plan.endpoints.contains(&gateway) {
        return Attempt::Unknown;
    }
    let v6 = gateway.is_ipv6();
    let name = std::ffi::CString::new(interface).ok();
    let index = name.map_or(0, |name| unsafe { libc::if_nametoindex(name.as_ptr()) });
    if index == 0 {
        return Attempt::Unknown;
    }
    let address = match gateway {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("{ip}%{interface}"),
    };
    let family = if v6 { "-inet6" } else { "-inet" };
    let lookup = text(
        "/sbin/route",
        &["-n", "get", family, "-ifscope", interface, &address],
    )
    .await;
    if lookup
        .as_deref()
        .and_then(macos::route_interface)
        .as_deref()
        != Some(interface)
    {
        return Attempt::Unknown;
    }
    let port = sysprobe::TARGET_V4.port();
    let target = match gateway {
        IpAddr::V4(ip) => SocketAddr::new(ip.into(), port),
        IpAddr::V6(ip) => std::net::SocketAddrV6::new(ip, port, 0, index).into(),
    };
    let Some(socket) = socket(v6, interface) else {
        return Attempt::Unknown;
    };
    let before = blocked_packets(plan.uid).await;
    let name = interface.to_owned();
    let Some(watch) = CAPTURE.spawn(move || capture::watched_send(&name, socket, target)) else {
        return Attempt::Unknown;
    };
    let seen = match tokio::time::timeout(sysprobe::PART / 2, watch).await {
        Ok(Ok(seen)) => seen,
        _ => macos::Seen::Unknown,
    };
    let after = blocked_packets(plan.uid).await;
    macos::verdict(seen, before, after)
}
/// Every interface with a default route refuses a datagram to its own
/// gateway. Without an IPv6 default nothing is sent: a silent PF drop and a
/// missing path look alike, and the family has no path there to leak by.
async fn attempts(plan: &Plan) -> Vec<Attempt> {
    if sysprobe::collides(&plan.endpoints) {
        return vec![Attempt::Unknown];
    }
    let (Some(v4), Some(v6)) = tokio::join!(defaults(false), defaults(true)) else {
        return vec![Attempt::Unknown];
    };
    let mut attempts = Vec::new();
    for (interface, gateway) in v4 {
        attempts.push(onlink(plan, &interface, gateway).await);
        attempts.push(match v6.iter().find(|(i, _)| *i == interface) {
            Some((_, gateway)) => onlink(plan, &interface, *gateway).await,
            None => Attempt::Absent,
        });
    }
    attempts
}
async fn dns(plan: &Plan) -> Dns {
    let (uid, server) = (plan.uid, plan.dns);
    let address = server.to_string();
    let route_args = ["-n", "get", "-inet", &address];
    let (entry, route, config, reply) = tokio::join!(
        async {
            // configd can stall; never stack a second blocked lookup, and
            // never let it cost the tunnel reply gathered beside it.
            match LANE.spawn(move || dns::matches(uid, server)) {
                Some(lookup) => tokio::time::timeout(sysprobe::PART / 2, lookup)
                    .await
                    .ok()
                    .and_then(Result::ok),
                None => None,
            }
        },
        text("/sbin/route", &route_args),
        text("/usr/sbin/scutil", &["--dns"]),
        async {
            match socket(false, DEVICE) {
                Some(socket) => {
                    sysprobe::exchange(socket, SocketAddr::new(server.into(), 53)).await
                }
                None => sysprobe::Reply::None,
            }
        },
    );
    let resolvers = config.as_deref().and_then(macos::resolvers);
    Dns {
        config: match (entry, &resolvers) {
            (Some(Ok(false)), _) => Audit::Mismatch,
            (_, Some(found)) if !found.iter().any(|(s, _)| *s == address) => Audit::Mismatch,
            (Some(Ok(true)), Some(_)) => Audit::Match,
            _ => Audit::Unknown,
        },
        path: match route.as_deref().and_then(macos::route_interface) {
            Some(interface) if interface == DEVICE => Path::Tunnel,
            Some(_) => Path::Outside,
            None => Path::Unknown,
        },
        reply,
        // A physical-scoped resolver is foreign even with the same address.
        foreign: match resolvers {
            Some(found)
                if found.iter().any(|(s, scope)| {
                    *s != address || scope.as_deref().is_some_and(|i| i != DEVICE)
                }) =>
            {
                Foreign::Present
            }
            Some(_) => Foreign::None,
            None => Foreign::Unknown,
        },
    }
}
