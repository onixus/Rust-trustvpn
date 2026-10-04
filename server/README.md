# Profile exchange v2 — integration work in progress

The portal source itself lives in the private [onixus/tunnel](https://github.com/onixus/tunnel)
repository (`server/upstream`); this repository keeps only the extension.
`overlay/app/` adds profile import/export and per-device access. Deployed on
2026-09-30 with UI route `/profiles` and API `/portal/v2`; the deployment hostname is omitted.
The native client now has a Server panel page: enter the HTTPS origin, bind using
a one-time code from the browser, grant device access in the browser and refresh.
Optional native pull synchronization now tracks revisions and preserves local
conflicts. External stored profiles can be replaced with revision-checked
preview/commit; managed endpoint credentials remain read-only.
Downloads enter the normal local import preview; uploads require explicit password
transfer consent, a server preview and a separate commit. API tokens are stored in
the OS keyring; deleting the local binding does not revoke the server device.

The overlay uses `rtrust-codec` built from this workspace for TOML/JSON/tt parsing
and serialization. Imports are external stored profiles, not new credentials
provisioned on the endpoint. Managed server profiles are exportable, never
replaceable by this API. Device access revocation does not invalidate VPN
passwords already downloaded.

Before deployment: back up SQLite using its backup API and preserve the existing
image/config; include `.rtrust-profile-key` in subsequent protected backups.
The additional encrypted tables cannot be restored without that key. Build the
codec for the server architecture, install it as `/usr/local/bin/rtrust-codec`,
install `cryptography`, merge overlay files into the existing app, then call
`rtrust_profiles.install(app)` after constructing the FastAPI application.
The existing database initialization remains responsible for legacy tables.
Link `/profiles` from the client navigation. Validate the upgrade in an isolated
copy before changing the live image. The live deployment followed these steps; details are in `deploy/README.md`.

Local integration checks (synthetic users, temporary SQLite, real Rust codec). They need
the portal source: a `tunnel` checkout next to this one, or `RTRUST_PORTAL_SRC` pointing
at its `server/upstream`. GitHub checks cannot reach that private repository, so these
tests run in Jenkins and locally only.

```
cargo build -p rtrust-codec --locked
python3 -m venv /tmp/rtrust-portal-venv
/tmp/rtrust-portal-venv/bin/pip install -r server/test-environment/requirements.txt
/tmp/rtrust-portal-venv/bin/python server/tests/test_exchange.py
```

The tests cover encrypted persistence, export consent/revision, idempotent commit,
owner isolation, CSRF, one-time enrollment, explicit grants, revocation, malformed
input and size limits. A manual browser smoke also exercised TOML paste, redacted preview, explicit
commit and export with a synthetic account on localhost. The screenshot is
`dist/portal-ui-smoke.png`. Native HTTPS E2E also covers TLS rejection, enrollment replay, preview/commit,
idempotency and download roundtrip. It passed against the deployed server using a
temporary synthetic account, then removed that account and its data. Automated
browser E2E remains outstanding. Migration was tested on a database copy and the
old image read that migrated copy; an actual production rollback was not exercised.
