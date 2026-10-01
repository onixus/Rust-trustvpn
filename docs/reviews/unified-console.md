# Unified console code review

Scope: FastAPI authorization/CSRF and job persistence, root Unix-socket agent,
release verification, route/update recovery, campaign consent, browser rendering
and the additive installer. Reviewed for the R-TrustTunnel pull request.

## Findings resolved

- **P1 — Campaign consent could come from an unselected identity.** A selected
  contact revoked consent, but another account sharing its destination still
  authorized delivery. Persisted bindings now restrict the dispatch-time consent
  lookup to the explicitly selected identities and original address. Old drafts
  without bindings fail closed. Regression failed before the fix and passes now.
- **P2 — Normalized job payloads broke idempotent retries.** Hysteria creation
  adds default limits, so retrying the original request produced HTTP 409.
  Existing requests now compare canonical payloads without repeating mutable
  preconditions. Regression failed before the fix and passes now.
- **P1 — Installer rollback left a new privileged service or removed the prior
  console too early.** First-install failures now stop/disable/remove the new
  service and restore inherited files/state. Container replacement is tracked:
  failures before replacement preserve the old container. The fresh-install
  regression failed before the fix; both fresh and existing-install cases pass.

## Validation and limits

- 18 isolated API/agent tests, 2 installer rollback tests and 7 profile exchange
  tests with the actual Rust codec. Transport and systemd/Docker operations in
  unit tests are mocked; no notifications, root commands or live VPN changes.
- Python/JavaScript syntax passed. Gitleaks found no secrets and Trivy found
  no HIGH/CRITICAL vulnerabilities or configuration failures in the staged source
  snapshot. Local ignored packages, credentials and test output were excluded
  by scanning the exact PR snapshot. Console and installer regression tests are
  also included in the Jenkins macOS server-validation steps.
- Current review fixes have not been deployed or exercised on the live server.
  The documented October 1 acceptance describes the preceding deployment.
- The installer/agent remain adapters for the existing server layout. The agent
  socket's group membership is a privileged trust boundary. Server-update crash
  recovery remains manual; routing has a watchdog. No cross-protocol failover,
  independent RBAC or fresh-server installer is claimed.
