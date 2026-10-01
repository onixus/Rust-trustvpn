# Android native preview

The Android client uses native Android widgets (Java), a foreground `VpnService`
and the same Rust profile codec, HTTP/2 transport and IPv4/IPv6 packet engine as
the desktop client. There is no WebView, CLI subprocess or privileged host service.
Baseline: Android 10/API 29+, arm64-v8a; x86_64 is also built for emulator testing.
Acceptance uses Android 16/API 36 x86_64 and a physical POCO X3 NFC running Android 12/API 31.

Current signed preview: **0.3.2-preview.5** (versionCode **30206**), validated
from source commit `2809bea` by Android Jenkins #16 on October 1, 2026. The signed
APK was installed and its force-stop/recovery behavior retested on the physical
phone. Build outputs are local artifacts, not published GitHub release assets:
`dist/android/R-TrustTunnel-Android-preview.apk` and its `.sha256` sidecar.

## Implemented

- A bottom-anchored Connect/Disconnect button: gray when off, green when connected,
  amber while connecting/reconnecting and red on error. Status text remains visible.
- Device-local app routing: all apps (default), or only selected installed apps,
  with searchable selection stored in the encrypted vault. Unselected apps use
  their normal network, or lose connectivity under system lockdown. Disconnect before editing the selection; reconnect to apply.
  Empty or missing-app allowlists are rejected instead of silently routing all apps.
  Android routes by UID, so apps sharing a UID follow the same rule. The app inventory
  is used locally and is not included in profile exports.
- Compact profile list, default-profile Connect/Disconnect, import preview for
  files/pasted text/`tt://`, export via the system document picker and deletion.
- JSON, endpoint TOML, full CLI TOML and `tt://` use the Rust codec. Full CLI
  configurations can be stored/exported, but their desktop policy is rejected
  at connection time. Explicitly export/import endpoint TOML to select Android's
  full-tunnel behavior. Policy is never silently dropped from the saved profile.
- Profiles and default selection are encrypted with AES-256-GCM and an Android
  Keystore key. Atomic writes, authenticated reads, no plaintext fallback and
  no automatic reset on corruption. Files live in `noBackupFilesDir`; application
  backup and device transfer are also excluded. Screenshots of the app are blocked.
- System consent precedes VPN setup. A persistent notification has Disconnect when system Always-on is disabled.
  Closing the Activity leaves the foreground service running.
- IPv4 and DNS use the TUN. IPv6 is advertised only when the profile sets
  `has_ipv6=true`; otherwise Android blocks that family without direct bypass.
  An IPv6 DNS server is rejected for an IPv4-only endpoint. Every endpoint socket is protected
  and bound to the underlying non-VPN network before connect; protection failure
  rejects the attempt. A blocking TUN is established before endpoint DNS resolution. Startup waits for an underlying network and retries unavailable DNS, including offline startup.
- Rust duplicates the TUN FD, cancels/joins its worker before closing the duplicate,
  and retains TUN while reconnecting. The Java service owns the original FD.
  Stop/revoke closes both. Temporary handshake EOF/reset remains retryable;
  invalid certificates remain fatal, with traffic blocked until Disconnect.
- Stored HTTP/3 remains unchanged; the system session uses HTTP/2. HTTP/3 system
  VPN belongs to [wave 3](technical-debt.md).

## Build

Provision Rust 1.98.1 with `x86_64-linux-android` and `aarch64-linux-android`,
JDK 17+, Gradle 8.13, Android SDK platform 36/build-tools 36.0.0 and NDK
28.2.13676358. AGP is pinned to 8.13.2. Accept Android SDK licenses explicitly.

```sh
export ANDROID_HOME="$HOME/Android/Sdk"
rustup target add x86_64-linux-android aarch64-linux-android
python3 scripts/build-android.py --gradle /path/to/gradle-8.13/bin/gradle
# Unsigned release APK; signing is a separate operation with an external key.
python3 scripts/build-android.py --gradle /path/to/gradle-8.13/bin/gradle --release
```

`apps/android/app/build/outputs/apk` contains the outputs. Do not distribute the
instrumentation test APK. Preserve the release signing key to allow future
in-place updates; a debug certificate cannot update a release-signed installation.
Native ELF load segments use 16 KiB alignment on both ABIs.

## Validation

`Jenkinsfile.android` runs Gitleaks/Trivy, Rust tests, both ABI builds, Android
lint and instrumentation on an explicitly selected, isolated API 36 emulator.
The Linux agent needs Docker, the toolchain above, KVM and a running
`rtrust-ci-api36` emulator at the configured serial. `ci/android.py` never changes
host routes or switches the host VPN. It creates a temporary loopback-only
TrustTunnel endpoint in its own Docker network and removes it afterward.

The emulator tests intentionally replace this app's test installation. They cover:

- JNI parsing/export, four-format round trips and redacted errors;
- Keystore persistence, ciphertext inspection and tamper rejection;
- real IPv4/IPv6 TCP 512 KiB, UDP 1/1472/5000/60000 bytes and system DNS;
- endpoint outage, blocked traffic during reconnect, recovery, Activity close
  and explicit Stop;
- process restart, reinstall and increasing-version APK upgrade, including
  preservation of the default profile and Keystore-protected credentials.

VPN consent is shell-granted in automated network tests; those tests do not
establish human acceptance of the system permission dialog. Device-specific
battery/OEM behavior is not established by emulator success.

On the physical Android 12 phone, acceptance covered Russian resources, system
file-picker TOML import and all four export formats (JSON, endpoint TOML, CLI
TOML and tt), including credential-preserving JSON export across process
recreation. JSON and TOML filename extensions were verified after correcting
the export MIME types. Image QR import and a real camera scan also passed. HTTPS portal enrollment,
download, synthetic upload, grant withdrawal/removal and regrant/re-download
passed without changing the local default. Temporary server profiles were revoked.
System Always-on and lockdown were enabled through Android settings. An independent
app UID first verified VPN egress; after force-stop, the VPN process was absent,
lockdown remained enabled, and a direct-IP HTTPS request was blocked. Reboot before
first unlock and other OEMs are not established by this test.

## Configuration and remaining release work

The native UI supports English and Russian system locales, offline camera/image
QR import, and the existing HTTPS portal v2 enrollment and profile exchange API.
Use **Server profiles** to enter a one-time code created in the server UI, grant
profiles to that device on the server, then synchronize. Synchronization is manual
and requires disconnecting VPN: it atomically replaces downloaded profiles and
removes withdrawn grants while preserving locally imported profiles. Failed or
unauthorized requests preserve the local vault; server credential revocation is
still enforced by the endpoint. Upload creates a new external profile after
explicit consent to transfer its credentials. Device tokens remain encrypted.
Removing registration locally also removes downloaded profiles; revoke the device
in the server UI to invalidate its token. HTTPS redirects are never followed.

**Always-on / block bypass** opens Android VPN settings. Enable both Always-on VPN
and Block connections without VPN for system protection after process death or
force-stop. The service supports sticky restart and offline startup. Android
controls restart scheduling; reopening the app and pressing Connect may be
necessary after force-stop. Blocking while stopped does not mean the tunnel is connected.
App Disconnect is disabled while Always-on is active; change that system setting
first. Excluded apps have no Internet under lockdown. Credentials remain in
credential-encrypted storage; no plaintext direct-boot copy is created. Before
first unlock the system policy, rather than an established tunnel, must provide
blocking. Android may exempt some system traffic from VPN policy.

QR camera permission is requested only when scanning; camera/image decoding is
local and always leads to the normal profile confirmation. File export is explicit
plaintext credential export. Pending export is encrypted across Activity/process
recreation, expires after one hour, and is consumed on completion or cancellation.

Remaining stable-release work includes additional Samsung/Pixel devices, reboot
and overnight soak coverage, automatic background portal synchronization, and
native desktop-policy/encrypted-DNS support. Numeric DNS servers are supported.

The architecture and later milestones remain in [android-macos.md](android-macos.md).
Android foreground-service eligibility follows the official
[VPN](https://developer.android.com/develop/connectivity/vpn) and
[systemExempted](https://developer.android.com/develop/background-work/services/fgs/service-types#system-exempted)
documentation. The manifest narrowly annotates an AGP lint false positive that
models the alarm-permission alternative but not VPN consent; no alarm permission
is requested, and real foreground-service startup is tested on API 36.

To sign a release without exposing the private key to CI:

```sh
python3 scripts/sign-android.py \
  --input dist/android/R-TrustTunnel-Android-unsigned.apk \
  --output dist/android/R-TrustTunnel-Android-preview.apk \
  --keystore /private/signing/android.p12 \
  --password-file /private/signing/android-password.txt \
  --apksigner-jar /path/to/android-sdk/build-tools/36.0.0/lib/apksigner.jar
```

The key and password files must be owner-only regular files. The script verifies
the APK signature and writes a SHA256 sidecar. Keep an encrypted offline backup
of the signing key and password; losing them prevents updates to that app identity.
