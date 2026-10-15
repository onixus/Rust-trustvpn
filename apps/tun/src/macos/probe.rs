//! macOS facts for the service probe: own PF anchor, dynamic DNS entry,
//! routes and two kinds of datagrams. Read-only: pfctl only lists or parses
//! (`-n`), the DNS entry is compared, never installed.
use super::{device::DEVICE, dns, firewall, route_table, state::DIRECTORY};
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
fn socket(v6: bool, interface: &str) -> Option<std::net::UdpSocket> {
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
async fn defaults(v6: bool) -> Option<Vec<String>> {
    let table = text(
        "/usr/sbin/netstat",
        &["-rn", "-f", if v6 { "inet6" } else { "inet" }],
    )
    .await?;
    let mut interfaces = Vec::new();
    for entry in route_table::parse(&table).ok()? {
        if entry.destination == "default"
            && !entry.interface.starts_with("utun")
            && entry.interface != "lo0"
            && !interfaces.contains(&entry.interface)
        {
            interfaces.push(entry.interface);
        }
    }
    (interfaces.len() <= 8).then_some(interfaces)
}
/// Every interface with a (scoped) default route refuses a datagram bound to
/// it. pf's drop on output is expected to surface as EHOSTUNREACH; with a
/// scoped default present, routing cannot be the cause. Lab-unconfirmed.
async fn attempts(plan: &Plan) -> Vec<Attempt> {
    if sysprobe::collides(&plan.endpoints) {
        return vec![Attempt::Unknown];
    }
    let (Some(v4), Some(v6)) = tokio::join!(defaults(false), defaults(true)) else {
        return vec![Attempt::Unknown];
    };
    let mut attempts = Vec::new();
    for interface in v4 {
        attempts.push(match socket(false, &interface) {
            Some(socket) => sysprobe::attempt(
                sysprobe::send(&socket, sysprobe::TARGET_V4),
                &[libc::EHOSTUNREACH],
                &[],
            ),
            None => Attempt::Unknown,
        });
        // EHOSTUNREACH is a PF refusal only with a scoped default present.
        let scoped = v6.contains(&interface);
        let blocked: &[i32] = if scoped { &[libc::EHOSTUNREACH] } else { &[] };
        attempts.push(sysprobe::v6_attempt(
            scoped,
            socket(true, &interface).map(|socket| sysprobe::send(&socket, sysprobe::TARGET_V6)),
            blocked,
            &[libc::EHOSTUNREACH, libc::ENETUNREACH, libc::EADDRNOTAVAIL],
        ));
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
