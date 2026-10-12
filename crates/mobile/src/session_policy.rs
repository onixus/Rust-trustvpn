//! Local flow policy belongs to the logical session, not one network runner.
use rtrust_engine::routing::{Policy, Router};
use std::sync::Arc;

#[derive(Default)]
pub struct SessionPolicy {
    retained: Option<(u64, Policy, Arc<Router>)>,
}
impl SessionPolicy {
    /// Call only after the previous packet worker and its socket owners joined.
    /// Managed or multi-profile policies always use their freshly prepared router.
    pub fn restore(
        &mut self,
        session: u64,
        baseline: &Policy,
        prepared: Arc<Router>,
        mutable_local: bool,
    ) -> Result<Arc<Router>, String> {
        if session == 0 {
            return Err("Invalid logical policy session".into());
        }
        if let Some((id, prior, router)) = &self.retained
            && *id == session
        {
            if !mutable_local
                || prior.mode != baseline.mode
                || prior.exclusions != baseline.exclusions
            {
                return Err("Policy ownership or baseline changed within the session".into());
            }
            router.reset_dns_evidence();
            return Ok(router.clone());
        }
        self.retained = mutable_local.then(|| (session, baseline.clone(), prepared.clone()));
        Ok(prepared)
    }
    /// Explicit Disconnect/revoke/destruction ends the policy session.
    pub fn clear(&mut self) {
        self.retained = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrust_engine::routing::{Action, Context};
    fn original() -> Policy {
        Policy {
            mode: "general".into(),
            exclusions: vec!["203.0.113.0/24".into()],
        }
    }
    #[test]
    fn tightened_policy_and_rollback_survive_network_runner_replacement() {
        let baseline = original();
        let mut state = SessionPolicy::default();
        let router = state
            .restore(1, &baseline, Arc::new(baseline.compile().unwrap()), true)
            .unwrap();
        let initial = router.version();
        let destination = "203.0.113.1:443".parse().unwrap();
        assert_eq!(router.route_flow(destination), Action::Direct);
        let tightened = router
            .apply_local(
                &initial,
                &Policy {
                    mode: "general".into(),
                    exclusions: vec![],
                },
                Context::default(),
            )
            .unwrap();
        let resumed = state
            .restore(1, &baseline, Arc::new(baseline.compile().unwrap()), true)
            .unwrap();
        assert_eq!(resumed.route_flow(destination), Action::Tunnel);
        assert_eq!(resumed.version(), tightened);
        let rolled_back = resumed
            .rollback_local(&tightened, &initial.revision)
            .unwrap();
        let resumed = state
            .restore(1, &baseline, Arc::new(baseline.compile().unwrap()), true)
            .unwrap();
        assert_eq!(resumed.route_flow(destination), Action::Direct);
        assert_eq!(resumed.version(), rolled_back);
        assert!(
            resumed
                .apply_local(
                    &initial,
                    &Policy {
                        mode: "general".into(),
                        exclusions: vec![]
                    },
                    Context::default()
                )
                .is_err()
        );
    }
    #[test]
    fn explicit_stop_new_session_and_owner_changes_cannot_reuse_override() {
        let baseline = original();
        let mut state = SessionPolicy::default();
        let router = state
            .restore(1, &baseline, Arc::new(baseline.compile().unwrap()), true)
            .unwrap();
        router
            .apply_local(
                &router.version(),
                &Policy {
                    mode: "general".into(),
                    exclusions: vec![],
                },
                Context::default(),
            )
            .unwrap();
        assert!(
            state
                .restore(1, &baseline, Arc::new(baseline.compile().unwrap()), false)
                .is_err()
        );
        let changed = Policy {
            mode: "selective".into(),
            exclusions: baseline.exclusions.clone(),
        };
        assert!(
            state
                .restore(1, &changed, Arc::new(changed.compile().unwrap()), true)
                .is_err()
        );
        let new = state
            .restore(2, &baseline, Arc::new(baseline.compile().unwrap()), true)
            .unwrap();
        assert_eq!(
            new.route_flow("203.0.113.1:443".parse().unwrap()),
            Action::Direct
        );
        new.apply_local(
            &new.version(),
            &Policy {
                mode: "general".into(),
                exclusions: vec![],
            },
            Context::default(),
        )
        .unwrap();
        state.clear();
        let reset = state
            .restore(2, &baseline, Arc::new(baseline.compile().unwrap()), true)
            .unwrap();
        assert_eq!(reset.version().epoch, 1);
        assert_eq!(
            reset.route_flow("203.0.113.1:443".parse().unwrap()),
            Action::Direct
        );
        let managed = baseline
            .compile_with_context(Context {
                source: rtrust_profile::routing::Source::ManagedUnknown,
                revision: Some("managed:2".into()),
            })
            .unwrap();
        let managed = state
            .restore(3, &baseline, Arc::new(managed), false)
            .unwrap();
        assert!(
            managed
                .apply_local(
                    &managed.version(),
                    &Policy {
                        mode: "general".into(),
                        exclusions: vec![]
                    },
                    Context::default()
                )
                .is_err()
        );
    }
}
