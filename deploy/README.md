# Portal deployment, 2026-09-30

The live portal is https://onixus-rf.duckdns.org/profiles. Native clients accept
HTTPS origins only. The legacy HTTP listener on port 18082 still exists; use the
HTTPS URL for credentials and enrollment.

Build `portal.Dockerfile` from the repository root on the x86_64 server. Its base
is the locally retained `trusttunnel-web:dns-20260929` image, not a public image.
The overlay and Rust codec are installed additively; `portal_patch.py` checks its
insertion anchors before registering the router and browser navigation link.

Live paths:
- Compose: `/opt/trusttunnel-web/compose.yaml`, image `trusttunnel-web:profiles-20260930`.
- Release files: `/opt/rtrust-releases/20260930-portal`.
- Private SQLite backup and profile encryption key:
  `/opt/trusttunnel-web/data/.rtrust-backups/20260930-portal`.
- Prior compose: release directory `compose.before.yaml` (private).
- HTTPS container: `rtrust-portal-https`, nginx digest
  `sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236`.
  Docker network `trusttunnel-web_default`, TCP 443 published; UDP 443 unchanged.
  Read-only root, tmpfs `/var/cache/nginx`, `/var/run`, `/tmp`, no-new-privileges,
  restart unless-stopped. Mount `portal-nginx.conf` as
  `/etc/nginx/conf.d/default.conf:ro` and `/opt/trusttunnel-web/certs:/certs:ro`.
- `rtrust-portal-cert-reload.timer` reloads nginx hourly after certificate renewal.

Before any upgrade preserve a SQLite online backup, the current image/compose,
and `/data/.rtrust-profile-key`. Keep the key with encrypted database backups,
under equally restrictive permissions. Test migration against a copy first.
For application rollback restore `compose.before.yaml` and run compose up for
`trusttunnel-web`; old code ignores the additive tables. Do not restore an old
SQLite backup over newer user changes without a separate recovery decision.
The deployment script retained remotely has automatic rollback on failed checks.

Verified: isolated staging, migration twice on the production DB copy, old-image
read compatibility, public TLS verification, real Rust enrollment/upload/download
with a disposable account, and removal of that account. Production rollback and
automated browser E2E have not been exercised. This change does not provision VPN
credentials for imported profiles or revoke previously downloaded VPN passwords.
