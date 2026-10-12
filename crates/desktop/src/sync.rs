//! Apply a fully downloaded portal snapshot as one local transaction.
use rtrust_portal::{RoutingState, Snapshot};
use rtrust_store::{ManagedRoutes, TrackedProfile, Vault};

/// Pure preparation: a conflict or invalid revision leaves the original vault
/// intact. Persist the returned vault once, using the caller's storage fence.
pub fn prepare(vault: &Vault, snapshot: Snapshot) -> Result<Vault, String> {
    let mut next = vault.clone();
    if vault.connection.sync.access_lease.is_some() && snapshot.freshness.is_none() {
        return Err("Portal freshness capability disappeared".into());
    }
    next.connection.sync.access_lease = snapshot.freshness;
    let managed = match snapshot.routing {
        RoutingState::Unsupported if vault.connection.managed_routes.is_some() => {
            return Err("Portal no longer supports the assigned routing policy".into());
        }
        RoutingState::Unsupported | RoutingState::Available(None) => None,
        RoutingState::Available(Some(policy)) => {
            let routes = ManagedRoutes {
                group: policy.group,
                revision: policy.revision,
                selection: rtrust_control::Selection {
                    include: policy.include,
                    exclude: policy.exclude,
                    exclude_lan: policy.exclude_lan,
                },
            };
            routes
                .validate()
                .map_err(|_| "Invalid portal routing policy")?;
            Some(routes)
        }
    };
    if let (Some(old), Some(new)) = (&vault.connection.managed_routes, &managed)
        && old.revision == new.revision
        && old != new
    {
        return Err("Routing policy changed without a new revision".into());
    }
    for (meta, profile) in &snapshot.profiles {
        if let Some(old) = vault
            .connection
            .sync
            .tracked
            .iter()
            .find(|p| p.id == meta.id)
        {
            if old.revision == meta.revision {
                if old.baseline != *profile {
                    return Err("Profile content changed without a new revision".into());
                }
                continue;
            }
            let matches: Vec<_> = vault
                .profiles
                .iter()
                .enumerate()
                .filter(|(_, p)| **p == old.baseline)
                .map(|(i, _)| i)
                .collect();
            if matches.len() != 1
                || vault
                    .connection
                    .sync
                    .tracked
                    .iter()
                    .filter(|entry| entry.baseline == old.baseline)
                    .count()
                    != 1
            {
                return Err(
                    "Local profile conflict; resolve it before applying the portal snapshot".into(),
                );
            }
            next.profiles[matches[0]] = profile.clone();
        } else {
            next.profiles.push(profile.clone());
        }
        next.connection.sync.tracked.retain(|p| p.id != meta.id);
        next.connection.sync.tracked.push(TrackedProfile {
            id: meta.id.clone(),
            revision: meta.revision.clone(),
            baseline: profile.clone(),
        });
    }
    // No longer delivered does not prove endpoint revocation. Retain independent
    // local copies, but stop tracking unavailable remote profiles.
    next.connection
        .sync
        .tracked
        .retain(|p| snapshot.profiles.iter().any(|(meta, _)| meta.id == p.id));
    next.connection.managed_routes = managed;
    next.connection
        .validate()
        .map_err(|_| "Invalid portal snapshot")?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_portal::{RemoteProfile, RoutingPolicy, Summary};
    fn profile(name: &str) -> rtrust_profile::Profile {
        let mut p =
            rtrust_profile::Profile::import(include_str!("../../../examples/demo.endpoint.toml"))
                .unwrap();
        p.name = name.into();
        p
    }
    fn remote(revision: &str) -> RemoteProfile {
        RemoteProfile {
            id: "one".into(),
            revision: revision.into(),
            origin: "external_stored".into(),
            summary: Summary {
                name: "one".into(),
                hostname: "test.example".into(),
            },
        }
    }
    fn routes() -> RoutingPolicy {
        RoutingPolicy {
            group: "test".into(),
            revision: "r1".into(),
            include: vec!["203.0.113.0/24".parse().unwrap()],
            exclude: vec![],
            exclude_lan: false,
        }
    }
    fn vault() -> Vault {
        let mut v = Vault {
            profiles: vec![profile("one"), profile("independent")],
            ..Default::default()
        };
        v.connection.sync.tracked.push(TrackedProfile {
            id: "one".into(),
            revision: "1".into(),
            baseline: profile("one"),
        });
        v
    }
    #[test]
    fn conflict_rejects_profiles_and_routes_together() {
        let mut v = vault();
        v.profiles[0].name = "edited".into();
        assert!(
            prepare(
                &v,
                Snapshot {
                    freshness: None,
                    profiles: vec![(remote("2"), profile("new"))],
                    routing: RoutingState::Available(Some(routes()))
                }
            )
            .is_err()
        );
        assert!(v.connection.managed_routes.is_none());
        assert_eq!(v.profiles[0].name, "edited");
    }
    #[test]
    fn policy_and_profiles_apply_together_without_deleting_local_profiles() {
        let v = vault();
        let next = prepare(
            &v,
            Snapshot {
                freshness: None,
                profiles: vec![(remote("2"), profile("new"))],
                routing: RoutingState::Available(Some(routes())),
            },
        )
        .unwrap();
        assert_eq!(next.profiles[0].name, "new");
        assert_eq!(next.profiles[1].name, "independent");
        assert_eq!(next.connection.managed_routes.unwrap().revision, "r1");
        assert_eq!(v.profiles[0].name, "one");
    }
    #[test]
    fn unchanged_revision_cannot_rewrite_content_or_drop_managed_routes() {
        let v = vault();
        assert!(
            prepare(
                &v,
                Snapshot {
                    freshness: None,
                    profiles: vec![(remote("1"), profile("new"))],
                    routing: RoutingState::Unsupported
                }
            )
            .is_err()
        );
        let mut v = prepare(
            &v,
            Snapshot {
                freshness: None,
                profiles: vec![],
                routing: RoutingState::Available(Some(routes())),
            },
        )
        .unwrap();
        assert!(
            prepare(
                &v,
                Snapshot {
                    freshness: None,
                    profiles: vec![],
                    routing: RoutingState::Unsupported
                }
            )
            .is_err()
        );
        let mut changed = routes();
        changed.exclude_lan = true;
        assert!(
            prepare(
                &v,
                Snapshot {
                    freshness: None,
                    profiles: vec![],
                    routing: RoutingState::Available(Some(changed))
                }
            )
            .is_err()
        );
        v = prepare(
            &v,
            Snapshot {
                freshness: None,
                profiles: vec![],
                routing: RoutingState::Available(None),
            },
        )
        .unwrap();
        assert!(v.connection.managed_routes.is_none());
        assert_eq!(v.profiles.len(), 2);
    }
}
