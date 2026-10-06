# Portal deployment, 2026-09-30

Use your portal URL, for example `https://vpn.example.com/profiles` (placeholder). Native clients accept
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

## Publishing device route groups (API v2 routing=1)

The group editor lives at `/profiles`; it is part of the profile-exchange overlay
in **this repository**, not `tunnel/server/console`. `/portal/v2/routing` delivers
the authenticated device's assigned group. Rebuilding only `vpn-console` from an
old `trusttunnel-web` base does **not** install this API or editor. The ingress
routes `/profiles`, `/static/rtrust-profiles.*` and `/portal/v2/*` to the portal.

Build the additive update on the deployment host from the reviewed source tree:

```sh
# Read only the image IDs; do not dump container environments (they hold secrets).
portal_base=$(docker inspect --format '{{.Image}}' trusttunnel-web)
console_base=$(docker inspect --format '{{.Image}}' vpn-console)
python3 deploy/prepare-portal-update.py --base-image "$portal_base" --tag trusttunnel-web:route-groups-RELEASE
python3 deploy/prepare-portal-update.py --base-image "$console_base" --tag vpn-console:route-groups-RELEASE
```

Replace `RELEASE` with a unique release/commit identifier. These commands build
untagged candidate images and check them with a disposable SQLite database, no
network and no live mounts. Existing output tags are rejected, including when
the base is specified by image ID. The release tag is assigned only after the
candidate passes; a failed candidate remains untagged for diagnosis. They **do not deploy or restart anything**. The inherited endpoint,
console, dependencies, entrypoint and codec are preserved; only the overlay and
its idempotent registration are updated. Keep both output manifests with the
release. Never use a historical portal image as the base of an upgrade: that
would undo subsequent endpoint and console fixes.

Before deployment, take an online backup of the portal SQLite database, preserve
`.rtrust-profile-key`, save private Compose/container configuration and record the
old image IDs. Test migration on a protected copy. Update the portal service's
image in its existing Compose deployment while retaining every environment,
mount, network and capability setting. Recreating this container restarts its
VPN endpoint, so use an approved maintenance window. If the separate console is
also updated, retain its existing configuration and use the new console image;
do not replace it with the portal image. A later console rebuild must inherit
the updated portal image. Roll back image/configuration on failed acceptance;
do not overwrite newer database changes with the backup.

Acceptance after a separately approved deployment:

1. Verify `/portal/v2/capabilities` returns `routing: 1` through public HTTPS.
2. Sign in to `/profiles`, create a route group and assign a registered desktop
   device. No device token may create/edit groups or read another owner's group.
3. In the desktop app enable server synchronization, stop VPN and refresh.
   The app must show the assigned group under TUN routes. Start a new connection
   and verify included/excluded destination traffic on that platform.
4. Change the group, synchronize again while disconnected and confirm the new
   revision. Moving/removing membership or deleting a group must replace/clear
   the managed selection; stale edits must return 409.

The current route-group contract is **desktop TUN, IPv4 only**. It does not push
live changes into an active VPN and is not consumed by the Android/iOS clients.
Their profile-embedded route policy is a separate mechanism. Do not advertise
mobile group synchronization until those clients implement `/portal/v2/routing`.

Local isolated regression checks (no production access):

```sh
cargo build --locked -p rtrust-codec
cargo build --locked -p rtrust-portal --examples
python3 server/tests/test_publication.py
# Use the Python environment and RTRUST_PORTAL_SRC described in server/README.md.
.ci-server/bin/python server/tests/test_exchange.py
.ci-server/bin/python server/tests/routing_exchange.py
```

The TLS test uses a real Rust client against the owner API's published group,
covering assignment, revision update, stale writes, group move/deletion and device
revocation. Native sync tests additionally check persistence, replacement, clearing
and refusal of unusable route selections. This is not a physical VPN traffic test.
