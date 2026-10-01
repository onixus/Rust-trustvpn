# Signed desktop updates

Windows Settings exposes explicit check, download and install actions. Packages
use an Ed25519 envelope pinned in the application, a monotonically increasing
release sequence, target and IPC bounds, expiry, exact size and SHA-256. HTTPS
fetches are restricted to the deployment origin and release path; redirects are
not followed. Authenticode is separate and is not claimed by this implementation.
The offline signing key is excluded from CI snapshots and stays on the publisher's
machine. Losing that key requires a separately trusted bootstrap installer.

Before install, the client downloads both the new package and the signed package
for its exact current sequence. An expired historical rollback envelope is usable
only for that exact sequence. The helper locks verified package files against
replacement, waits for the GUI to exit, acquires an idle-service maintenance lease
and saves the encrypted profile vault. UAC elevates only the verified installer.
The service refuses maintenance while a tunnel or retained network guard exists.
Older services without the maintenance command require one ordinary bootstrap
installation; unsupported IPC never bypasses the check.

After Setup, the helper launches the installed GUI smoke mode. A failed health
check installs and checks the previous signed package. If the replacement service
is unavailable, active, or retains a guard, automatic rollback stops safely;
packages, encrypted backup and logs remain in the transaction directory. The
helper does not clear a network guard or overwrite the user's vault. A successful
update restarts the GUI; after rollback the user can restart the previous version.
No downgrade migration is promised for arbitrary old vault formats.

`prepare-signed-release.py` accepts only artifacts from a completed successful
Jenkins build whose pinned root matches the local root. `publish-signed-release.py`
publishes immutable version directories. Promoting `latest.json` is a separate
explicit step after maintenance validation. Private keys are never published.

`ci/windows_signed_update_e2e.py` runs only with explicit existing-installation
maintenance authorization. It executes a preserved old-version test runner against
real signed new/old installers: upgrade, injected failed health check, rollback,
launch check, then successful upgrade. `maintenance_fixture` preserves existing
profiles or temporarily populates an empty vault and checks encrypted bytes and
OS-keyring decryption afterward. Ordinary CI does not run this invasive test.

macOS system-service installation and Flatpak updates are delivered in their
platform stages; the Windows installer helper is not used on those platforms.

## Verified Windows maintenance, 2026-09-30

Completed Jenkins #36 (0.2.0, sequence 2) and #37 (0.2.1, sequence 3): full
unit/Clippy, native smoke, keyring, Linux network E2E, Gitleaks and Trivy gates.
Installed-client maintenance was run separately on the authorized Windows host.
The preserved sequence-2 test runner passed the actual 2→3→2 rollback→3 cycle
in 16.87 seconds. The encrypted fixture remained byte-identical and decryptable;
the original empty user vault was restored afterward. Installed GUI, updater and
SCM service hashes match build #37, service ownership is unchanged, and autostart
remains disabled. Temporary scheduled tasks were removed.

The surrounding PowerShell wrapper initially reported failure because a null
startup value produced no snapshot file. The actual Rust E2E and vault-retention
checks had passed. A separate final verification confirmed absence of the startup
entry and all installed hashes; the original failed wrapper log was retained.
This was a harness bookkeeping defect, not a rollback success inferred from logs.

Installer SHA-256 for build #37:
`b344a751bb93c231d0a8126cb1064ee711d188692357f7491f5483763a0a1d1e`.
Maintenance used a temporary interactive elevated task; production UAC prompting
was not automated. Ordinary CI continues to skip the invasive Windows installer,
Wintun and whole-host WFP tests unless explicitly enabled.

## Withheld candidate

Sequence 4 (0.3.0, build #46) has immutable versioned artifacts but is **not**
promoted to latest: its authorized Windows always-on SCM restart runtime failed.
Do not use it for delivery. At rejection, latest remained sequence 3. The replacement sequence 6 below
passed runtime and real signed upgrade/rollback verification before promotion.

## Delivered sequence 6

Build #53 completed SUCCESS. Version 0.3.2 / sequence 6 passed authorized
Windows full-tunnel/always-on runtime and genuine signed 3→6 upgrade with an
injected failed health check, verified rollback to 3, and successful retry to 6.
The transaction took 16.98 seconds; encrypted vault retention/decryption, original
empty-vault restoration, autostart, LocalSystem/desktop SID and installed hashes
were verified. Setup was delivered to the Windows user's Downloads directory.

Setup SHA-256: `31202330accd7dc2b34ea0dfbb38964a99ae8acd092007ceaf5f9591703a53c2`.
Sequence 4 was withheld from latest; sequence 5 was prepared locally but not published.
