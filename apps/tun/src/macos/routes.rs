use super::{command, route_table};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Route {
    pub v6: bool,
    pub prefix: String,
    pub gateway: String,
    pub interface: String,
    pub direct: bool,
}
impl Route {
    pub fn validate(&self) -> Result<(), String> {
        if !route_table::valid_interface(&self.interface)
            || route_table::prefix(&self.prefix, self.v6).as_deref() != Some(self.prefix.as_str())
            || (!self.direct && self.gateway.parse::<std::net::Ipv4Addr>().is_err())
            || (self.direct && self.gateway != self.interface)
        {
            return Err("Invalid route in recovery journal".into());
        }
        Ok(())
    }
    fn current<'a>(
        &self,
        rows: &'a [route_table::Entry],
    ) -> Result<Option<&'a route_table::Entry>, String> {
        self.validate()?;
        let mut matching = rows.iter().filter(|row| {
            !row.flags.contains('I')
                && route_table::prefix(&row.destination, self.v6).as_deref()
                    == Some(self.prefix.as_str())
        });
        let row = matching.next();
        if matching.next().is_some() {
            return Err("Ambiguous route ownership; protection retained".into());
        }
        Ok(row)
    }
    fn owns(&self, row: &route_table::Entry) -> bool {
        row.interface == self.interface
            && row.flags.contains('2')
            && if self.direct {
                !row.flags.contains('G')
                    && (row.gateway == self.interface
                        || row.gateway.strip_prefix("link#").is_some_and(|v| {
                            !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit())
                        }))
            } else {
                row.flags.contains('G') && row.gateway == self.gateway
            }
    }
    fn mutate(&self, remove: bool) -> Result<(), String> {
        let mut args = vec![
            "-n",
            if remove { "delete" } else { "add" },
            if self.v6 { "-inet6" } else { "-inet" },
            "-net",
            &self.prefix,
            "-proto2",
            "-ifp",
            &self.interface,
        ];
        if self.direct {
            args.push("-interface");
        }
        args.push(&self.gateway);
        command::run("/sbin/route", &args)?;
        Ok(())
    }
}
// Batch preflight and post-verification use one snapshot per address family.
// Before each deletion, re-read and verify ownership: earlier deletions may
// have given another process time to replace a later route. Darwin RTM_DELETE
// matches destination/netmask, not gateway/interface/proto2 ownership; these
// command arguments are NOT compare-and-delete predicates. A residual race
// between the fresh ownership check and delete remains, as in the original
// per-route boundary. Use the existing netstat reader until a native snapshot
// parser has independent validation; removal timing remains device-unverified.
#[derive(Clone, Copy)]
enum Operation {
    Vacant,
    Ensure,
    Remove,
}
fn batch_with(
    routes: &[Route],
    operation: Operation,
    mut read: impl FnMut(bool) -> Result<Vec<route_table::Entry>, String>,
    mut mutate: impl FnMut(&Route, bool) -> Result<(), String>,
) -> Result<(), String> {
    let mut snapshots = [vec![], vec![]];
    for v6 in [false, true] {
        if routes.iter().any(|r| r.v6 == v6) {
            snapshots[v6 as usize] = read(v6)?;
        }
    }
    let mut changes = vec![];
    for (i, route) in routes.iter().enumerate() {
        route.validate()?;
        if routes[..i]
            .iter()
            .any(|r| r.v6 == route.v6 && r.prefix == route.prefix)
        {
            return Err("Duplicate journal route; protection retained".into());
        }
        let row = route.current(&snapshots[route.v6 as usize])?;
        match (operation, row) {
            (Operation::Vacant, Some(_)) => return Err("Conflicting VPN route".into()),
            (Operation::Ensure | Operation::Remove, Some(row)) if !route.owns(row) => {
                return Err("VPN route changed externally; protection retained".into());
            }
            (Operation::Ensure, None) | (Operation::Remove, Some(_)) => changes.push(route),
            _ => {}
        }
    }
    if matches!(operation, Operation::Vacant) {
        return Ok(());
    }
    for route in changes {
        if matches!(operation, Operation::Remove) {
            let fresh = read(route.v6)?;
            match route.current(&fresh)? {
                Some(row) if route.owns(row) => {}
                Some(_) => return Err("VPN route changed externally; protection retained".into()),
                None => continue,
            }
        }
        mutate(route, matches!(operation, Operation::Remove))?;
    }
    for v6 in [false, true] {
        if !routes.iter().any(|r| r.v6 == v6) {
            continue;
        }
        let rows = read(v6)?;
        for route in routes.iter().filter(|r| r.v6 == v6) {
            let current = route.current(&rows)?;
            let verified = match operation {
                Operation::Remove => current.is_none(),
                Operation::Ensure => current.is_some_and(|row| route.owns(row)),
                Operation::Vacant => unreachable!(),
            };
            if !verified {
                return Err("VPN route batch could not be verified; protection retained".into());
            }
        }
    }
    Ok(())
}
pub(super) fn vacant(routes: &[Route]) -> Result<(), String> {
    batch_with(routes, Operation::Vacant, route_table::read, Route::mutate)
}
pub(super) fn ensure(routes: &[Route]) -> Result<(), String> {
    batch_with(routes, Operation::Ensure, route_table::read, Route::mutate)
}
pub(super) fn remove(routes: &[Route]) -> Result<(), String> {
    // Endpoint exceptions were installed first; remove tunnel routes first.
    let routes: Vec<_> = routes.iter().rev().cloned().collect();
    batch_with(&routes, Operation::Remove, route_table::read, Route::mutate)
}
/// Non-default IPv4 routes before the VPN interface exists (LAN, host and
/// other VPN routes), used to keep local networks off the tunnel.
pub(super) fn local() -> Result<Vec<rtrust_control::Ipv4Net>, String> {
    Ok(route_table::read(false)?
        .into_iter()
        .filter(|r| r.destination != "default")
        .filter_map(|r| route_table::prefix(&r.destination, false)?.parse().ok())
        .map(|n: rtrust_control::Ipv4Net| n.trunc())
        .collect())
}
pub(super) fn physical_interface() -> Result<String, String> {
    let defaults: Vec<_> = route_table::read(false)?
        .into_iter()
        .filter(|r| r.destination == "default" && !r.flags.contains('I'))
        .collect();
    if defaults.len() != 1
        || defaults[0].interface.starts_with("utun")
        || defaults[0].interface == "lo0"
    {
        return Err(
            "A unique physical IPv4 default route is required; disconnect other system VPNs first"
                .into(),
        );
    }
    Ok(defaults[0].interface.clone())
}
pub(super) fn endpoint(ip: std::net::Ipv4Addr, interface: &str) -> Result<Route, String> {
    if !route_table::valid_interface(interface) {
        return Err("Invalid physical interface".into());
    }
    let text = command::run(
        "/sbin/route",
        &["-n", "get", "-inet", "-ifscope", interface, &ip.to_string()],
    )?;
    let fields: std::collections::HashMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once(':').map(|(k, v)| (k.trim(), v.trim())))
        .collect();
    if fields.get("interface") != Some(&interface) {
        return Err("Endpoint would use an unexpected interface".into());
    }
    let gateway = fields
        .get("gateway")
        .ok_or("Endpoint gateway unavailable")?;
    let (gateway, direct) = if gateway.starts_with("link#") {
        (interface.to_owned(), true)
    } else {
        let gateway: std::net::Ipv4Addr = gateway
            .parse()
            .map_err(|_| "Unsupported physical gateway")?;
        (gateway.to_string(), false)
    };
    Ok(Route {
        v6: false,
        prefix: format!("{ip}/32"),
        gateway,
        interface: interface.into(),
        direct,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(v6: bool, prefix: &str) -> Route {
        Route {
            v6,
            prefix: prefix.into(),
            gateway: "utun5254".into(),
            interface: "utun5254".into(),
            direct: true,
        }
    }
    fn row(route: &Route) -> route_table::Entry {
        route_table::Entry {
            destination: route.prefix.clone(),
            gateway: "link#42".into(),
            interface: route.interface.clone(),
            flags: "US2".into(),
        }
    }
    #[test]
    fn ensure_reads_each_family_twice_regardless_of_route_count() {
        let routes = vec![
            fixture(false, "0.0.0.0/1"),
            fixture(false, "128.0.0.0/1"),
            fixture(true, "::/1"),
        ];
        let reads = std::cell::RefCell::new([0; 2]);
        let mutations = std::cell::Cell::new(0);
        batch_with(
            &routes,
            Operation::Ensure,
            |v6| {
                let mut reads = reads.borrow_mut();
                reads[v6 as usize] += 1;
                Ok(if reads[v6 as usize] == 2 {
                    routes.iter().filter(|r| r.v6 == v6).map(row).collect()
                } else {
                    vec![]
                })
            },
            |_, remove| {
                assert!(!remove);
                mutations.set(mutations.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(*reads.borrow(), [2, 2]);
        assert_eq!(mutations.get(), 3);
    }
    #[test]
    fn preflights_all_conflicts_and_ambiguity_before_mutation() {
        let routes = vec![fixture(false, "0.0.0.0/1"), fixture(false, "128.0.0.0/1")];
        for ambiguous in [false, true] {
            let mut rows: Vec<_> = routes.iter().map(row).collect();
            if ambiguous {
                rows.push(row(&routes[1]));
            } else {
                rows[1].interface = "en0".into();
            }
            assert!(
                batch_with(
                    &routes,
                    Operation::Remove,
                    |_| Ok(std::mem::take(&mut rows)),
                    |_, _| panic!("must preflight entire batch")
                )
                .is_err()
            );
        }
    }
    #[test]
    fn ensures_missing_routes_and_verifies_fresh_snapshot() {
        let routes = vec![fixture(false, "0.0.0.0/1"), fixture(false, "128.0.0.0/1")];
        let calls = std::cell::Cell::new(0);
        let changes = std::cell::Cell::new(0);
        batch_with(
            &routes,
            Operation::Ensure,
            |_| {
                calls.set(calls.get() + 1);
                Ok(if calls.get() == 1 {
                    vec![row(&routes[0])]
                } else {
                    routes.iter().map(row).collect()
                })
            },
            |r, remove| {
                assert!(!remove);
                assert_eq!(r, &routes[1]);
                changes.set(changes.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 2);
        assert_eq!(changes.get(), 1);
        assert!(batch_with(&routes, Operation::Ensure, |_| Ok(vec![]), |_, _| Ok(())).is_err());
    }
    #[test]
    fn partial_failure_and_foreign_post_snapshot_never_report_success() {
        let routes = vec![fixture(false, "0.0.0.0/1"), fixture(false, "128.0.0.0/1")];
        let mut mutations = 0;
        assert!(
            batch_with(
                &routes,
                Operation::Remove,
                |_| Ok(routes.iter().map(row).collect()),
                |_, _| {
                    mutations += 1;
                    if mutations == 2 {
                        Err("synthetic failure".into())
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_eq!(mutations, 2);
        let mut calls = 0;
        assert!(
            batch_with(
                &routes,
                Operation::Remove,
                |_| {
                    calls += 1;
                    let mut rows: Vec<_> = routes.iter().map(row).collect();
                    if calls > 1 {
                        rows[0].flags = "US".into();
                    }
                    Ok(rows)
                },
                |_, _| Ok(())
            )
            .is_err()
        );
    }
    #[test]
    fn deletion_rechecks_later_route_replaced_during_earlier_delete() {
        let routes = vec![
            Route {
                v6: false,
                prefix: "192.0.2.1/32".into(),
                gateway: "192.0.2.254".into(),
                interface: "en0".into(),
                direct: false,
            },
            Route {
                v6: false,
                prefix: "192.0.2.2/32".into(),
                gateway: "192.0.2.254".into(),
                interface: "en0".into(),
                direct: false,
            },
        ];
        for changed in ["protocol", "interface", "gateway", "ambiguity"] {
            let table = std::cell::RefCell::new(
                routes
                    .iter()
                    .map(|r| route_table::Entry {
                        destination: r.prefix.clone(),
                        gateway: r.gateway.clone(),
                        interface: r.interface.clone(),
                        flags: "UGHS2".into(),
                    })
                    .collect::<Vec<_>>(),
            );
            let deletes = std::cell::RefCell::new(vec![]);
            let result = batch_with(
                &routes,
                Operation::Remove,
                |_| {
                    Ok(table
                        .borrow()
                        .iter()
                        .map(|r| route_table::Entry {
                            destination: r.destination.clone(),
                            gateway: r.gateway.clone(),
                            interface: r.interface.clone(),
                            flags: r.flags.clone(),
                        })
                        .collect())
                },
                |route, remove| {
                    assert!(remove);
                    deletes.borrow_mut().push(route.prefix.clone());
                    assert_eq!(
                        route.prefix, routes[0].prefix,
                        "foreign replacement must never be deleted"
                    );
                    let mut table = table.borrow_mut();
                    table.remove(0);
                    match changed {
                        "protocol" => table[0].flags = "UGHS".into(),
                        "interface" => table[0].interface = "en1".into(),
                        "gateway" => table[0].gateway = "192.0.2.253".into(),
                        "ambiguity" => table.push(route_table::Entry {
                            destination: routes[1].prefix.clone(),
                            gateway: "192.0.2.253".into(),
                            interface: "en1".into(),
                            flags: "UGHS".into(),
                        }),
                        _ => unreachable!(),
                    }
                    Ok(())
                },
            );
            assert!(result.is_err());
            assert_eq!(*deletes.borrow(), vec![routes[0].prefix.clone()]);
            assert!(
                !table.borrow().is_empty(),
                "partial failure preserves foreign state"
            );
        }
    }
    #[test]
    fn disappeared_route_is_not_deleted_and_unreadable_fresh_snapshot_fails_closed() {
        let routes = vec![fixture(false, "0.0.0.0/1")];
        let mut reads = 0;
        batch_with(
            &routes,
            Operation::Remove,
            |_| {
                reads += 1;
                Ok(if reads == 1 {
                    vec![row(&routes[0])]
                } else {
                    vec![]
                })
            },
            |_, _| panic!("route already disappeared"),
        )
        .unwrap();
        assert_eq!(reads, 3);
        let mut reads = 0;
        assert!(
            batch_with(
                &routes,
                Operation::Remove,
                |_| {
                    reads += 1;
                    if reads == 1 {
                        Ok(vec![row(&routes[0])])
                    } else {
                        Err("synthetic unreadable table".into())
                    }
                },
                |_, _| panic!("cannot delete without fresh ownership evidence")
            )
            .is_err()
        );
    }
    #[test]
    fn scoped_foreign_route_does_not_replace_unscoped_owner() {
        let route = fixture(false, "0.0.0.0/1");
        let mut foreign = row(&route);
        foreign.interface = "en0".into();
        foreign.flags = "USI".into();
        assert!(route.current(&[foreign]).unwrap().is_none());
        let mut malformed = row(&route);
        malformed.gateway = "192.0.2.1".into();
        assert!(!route.owns(&malformed));
    }
    #[test]
    fn recovery_requires_interface_and_protocol_marker_and_gateway() {
        let route = Route {
            v6: false,
            prefix: "192.0.2.4/32".into(),
            gateway: "192.168.1.1".into(),
            interface: "en0".into(),
            direct: false,
        };
        let mut row = route_table::Entry {
            destination: "192.0.2.4".into(),
            gateway: route.gateway.clone(),
            interface: "en0".into(),
            flags: "UGHS2".into(),
        };
        assert!(route.owns(&row));
        row.flags = "UGHS".into();
        assert!(!route.owns(&row));
        row.flags = "UGHS2".into();
        row.interface = "en1".into();
        assert!(!route.owns(&row));
        row.interface = "en0".into();
        row.gateway = "192.168.1.2".into();
        assert!(!route.owns(&row));
    }
    #[test]
    fn journal_rejects_option_injection_and_family_confusion() {
        let mut route = Route {
            v6: false,
            prefix: "0.0.0.0/1".into(),
            gateway: "utun5254".into(),
            interface: "utun5254".into(),
            direct: true,
        };
        assert!(route.validate().is_ok());
        route.prefix = "::/1".into();
        assert!(route.validate().is_err());
        route.prefix = "0.0.0.0/1".into();
        route.interface = "-ifscope en0".into();
        assert!(route.validate().is_err());
    }
}
