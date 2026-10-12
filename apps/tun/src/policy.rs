//! Bounded live flow-policy requests, committed only by the packet worker.
//! OS routes, DNS, endpoint pins and socket-protection permissions stay fixed.
use rtrust_engine::routing::{Context, Policy, PolicyVersion, PreparedPolicy, Router};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};

pub(crate) struct Request {
    pub expected: PolicyVersion,
    pub change: Change,
    pub reply: oneshot::Sender<Result<PolicyVersion, String>>,
}
pub(crate) enum Change {
    Apply(Policy, Context),
    Rollback(String),
}
#[derive(Clone)]
pub struct Controller {
    router: Arc<Router>,
    sender: mpsc::Sender<Request>,
}
pub struct Receiver {
    pub(crate) input: mpsc::Receiver<Request>,
}
impl Controller {
    pub fn new(router: Arc<Router>) -> (Self, Receiver) {
        let (sender, input) = mpsc::channel(4);
        (Self { router, sender }, Receiver { input })
    }
    pub fn version(&self) -> PolicyVersion {
        self.router.version()
    }
    pub fn preview(
        &self,
        expected: &PolicyVersion,
        policy: &Policy,
        destination: std::net::SocketAddr,
    ) -> Result<rtrust_profile::routing::Decision, String> {
        self.router
            .prepare_local(expected, policy, Context::default())
            .map_err(|e| e.to_string())?;
        Ok(policy
            .compile()
            .map_err(|e| e.to_string())?
            .decide(destination))
    }
    pub async fn apply(
        &self,
        expected: PolicyVersion,
        policy: Policy,
        context: Context,
    ) -> Result<PolicyVersion, String> {
        // Validate before enqueue too; an invalid/unauthorized candidate must
        // neither consume the queue nor interrupt existing connections.
        self.router
            .prepare_local(&expected, &policy, context.clone())
            .map_err(|e| e.to_string())?;
        let (reply, result) = oneshot::channel();
        self.sender
            .try_send(Request {
                expected,
                change: Change::Apply(policy, context),
                reply,
            })
            .map_err(|_| "Policy worker unavailable or busy")?;
        tokio::time::timeout(std::time::Duration::from_secs(10), result)
            .await
            .map_err(|_| "Policy change timed out; refresh its version")?
            .map_err(|_| "Policy worker stopped")?
    }
}
impl Controller {
    pub async fn rollback(
        &self,
        expected: PolicyVersion,
        revision: String,
    ) -> Result<PolicyVersion, String> {
        self.router
            .prepare_rollback(&expected, &revision)
            .map_err(|e| e.to_string())?;
        let (reply, result) = oneshot::channel();
        self.sender
            .try_send(Request {
                expected,
                change: Change::Rollback(revision),
                reply,
            })
            .map_err(|_| "Policy worker unavailable or busy")?;
        tokio::time::timeout(std::time::Duration::from_secs(10), result)
            .await
            .map_err(|_| "Policy change timed out; refresh its version")?
            .map_err(|_| "Policy worker stopped")?
    }
}
impl Request {
    pub fn prepare(&self, router: &Router) -> Result<PreparedPolicy, String> {
        if self.reply.is_closed() {
            return Err("Policy request cancelled".into());
        }
        match &self.change {
            Change::Apply(policy, context) => {
                router.prepare_local(&self.expected, policy, context.clone())
            }
            Change::Rollback(revision) => router.prepare_rollback(&self.expected, revision),
        }
        .map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn router() -> Arc<Router> {
        Arc::new(
            Policy {
                mode: "general".into(),
                exclusions: vec!["192.0.2.1".into()],
            }
            .compile()
            .unwrap(),
        )
    }
    #[tokio::test]
    async fn cancelled_queued_policy_is_inert_and_invalid_policy_never_queues() {
        let router = router();
        let initial = router.version();
        let (controller, mut receiver) = Controller::new(router.clone());
        assert!(
            controller
                .apply(
                    initial.clone(),
                    Policy {
                        mode: "wrong".into(),
                        exclusions: vec![]
                    },
                    Context::default()
                )
                .await
                .is_err()
        );
        assert!(receiver.input.try_recv().is_err());
        let task = tokio::spawn(async move {
            controller
                .apply(
                    initial,
                    Policy {
                        mode: "general".into(),
                        exclusions: vec![],
                    },
                    Context::default(),
                )
                .await
        });
        let request = receiver.input.recv().await.unwrap();
        task.abort();
        let _ = task.await;
        assert!(request.prepare(&router).is_err());
        assert_eq!(router.version().epoch, 1);
    }
    #[tokio::test]
    async fn stale_commit_cannot_overwrite_a_newer_revision() {
        let router = router();
        let initial = router.version();
        let prepared = router
            .prepare_local(
                &initial,
                &Policy {
                    mode: "general".into(),
                    exclusions: vec![],
                },
                Context::default(),
            )
            .unwrap();
        let current = router
            .apply_local(
                &initial,
                &Policy {
                    mode: "general".into(),
                    exclusions: vec!["192.0.2.2".into()],
                },
                Context::default(),
            )
            .unwrap();
        assert!(router.commit_local(&initial, prepared).is_err());
        assert_eq!(router.version(), current);
    }
}
