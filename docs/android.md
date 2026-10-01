# Android native preview

The Android client uses native Android widgets (Java), a foreground `VpnService`
and the same Rust profile codec, TrustTunnel HTTP/2 and Hysteria 2 transports and IPv4/IPv6 packet engine as
the desktop client. There is no WebView, CLI subprocess or privileged host service.
Baseline: Android 10/API 29+, arm64-v8a; x86_64 is also built for emulator testing.
Acceptance uses Android 16/API 36 x86_64 and physical POCO X3 NFC and Huawei DEL-LX9 phones running Android 12/API 31.

Current published package: [v0.3.2-ui.1](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.3.2-ui.1),
versionCode **30208**, versionName **0.3.2-preview.6**. The displayed version name
is unchanged; Android uses the increased versionCode for this in-place update.
The APK is signed with the existing release key. It was installed on Huawei with
the saved default profile, active VPN and system Always-on/lockdown retained.
The UI build and Android lint passed. The native libraries are unchanged from
successful Android Jenkins #26; their source hashes were checked before packaging.
This UI release did not repeat the full Android network acceptance pipeline.

## Navigation

The default profile appears at the top, with Connect/Disconnect at the bottom.
**+ Add profile** groups file, pasted configuration/link and QR import.
**Settings** contains Server profiles and the entry to system Always-on controls.
**VPN apps** remains on the home screen. English/Russian labels follow the system
locale. Screenshots are blocked by `FLAG_SECURE` in the released Android app;
do not disable that protection or publish real profiles to create documentation.

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
- JSON, endpoint TOML, full CLI TOML and `tt://` use the Rust codec. Portable CLI routing policies now support general/selective routing, IP/CIDR,
  domain/wildcard/port rules, included/excluded routes, DNS and MTU. Unsupported
  security fields are rejected; saved policy is never silently discarded.
- DNS-over-TLS and DNS-over-HTTPS run through the VPN with certificate validation.
  There is no direct resolver fallback. Mixed numeric/encrypted resolver lists,
  DoQ and DNS stamps are currently rejected. Domain routing uses correlated DNS
  answers; conflicting shared-IP identities conservatively stay on VPN.
- Hysteria 2 links and client YAML/JSON are detected automatically; see
  [protocol support and limits](hysteria2.md). JSON preserves the complete profile.
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
- Stored TrustTunnel HTTP/3 remains unchanged; the system session uses HTTP/2. HTTP/3 system
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

On the POCO X3 NFC, acceptance covered Russian resources, system
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

### Huawei DEL-LX9 acceptance — October 1, 2026

The same signed preview APK (versionCode 30206) was tested on a second physical
arm64 phone, Huawei DEL-LX9 / Android 12 / API 31, with Russian system locale.
The following checks passed:

- Fresh installation, real system VPN consent, production portal enrollment and
  manual profile synchronization.
- Independent app UID verification of VPN egress, system DNS, Google HTTPS 200
  and UDP DNS; backgrounding and Wi-Fi → mobile → Wi-Fi handoff.
- Real camera QR scan, QR image and TOML import through the system file picker.
- All four SAF export formats with synthetic credentials verified; JSON export
  completed after the client process was killed while the save picker was open.
- Empty allowlist rejection; an excluded app used direct egress, while an included
  app passed VPN egress, DNS, HTTPS and UDP checks. All-app routing was restored.
- A brief 80-second screen-off check retained the VPN process and passed
  the independent DNS/HTTPS/UDP probe. This was not a forced-Doze or overnight test.
- Same-version signed APK reinstall preserved local/server profiles, the default
  profile, app routing and portal registration; authenticated synchronization
  succeeded afterward. This is not an increasing-version upgrade test on Huawei.
- Always-on and lockdown enabled through Huawei Settings. After force-stop the VPN
  process was absent and an independent app UID could not reach direct-IP HTTPS;
  the same URL had a successful baseline before stopping. Reopening the client
  restored VPN egress, DNS, HTTPS and UDP.

Huawei exposes these switches under **VPN settings → long-press R-TrustTunnel →
Edit**: enable **Always-on VPN** and **Allow connections only through VPN**.
The production VPN and both system protections were left enabled. Temporary
profiles, exported fixtures and the probe app were removed after testing.
These checks do not establish reboot-before-unlock, overnight battery behavior,
IPv6 acceptance on the phone or support for every Huawei firmware.

## Configuration and remaining release work

The native UI supports English and Russian system locales, offline camera/image
QR import, and the existing HTTPS portal v2 enrollment and profile exchange API.
Use **Server profiles** to enter a one-time code created in the server UI, grant
profiles to that device on the server, then synchronize. Manual synchronization
requires disconnecting VPN. Optional background synchronization uses WorkManager
with an hourly network-constrained schedule and retry backoff; Android/OEM battery
policy may delay it. The running tunnel keeps its profile until reconnect. Synchronization atomically replaces downloaded profiles and
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
and overnight soak coverage. Background synchronization, portable routing and
encrypted DNS are implemented. Candidate 0.3.2-preview.6 (30207) passed Jenkins #26
with both TrustTunnel and Hysteria 2. On Huawei, Hysteria production egress, DNS,
Google HTTPS, UDP, DoH and DoT passed from a separate app UID. A real portal Worker
updated its success timestamp without breaking the active tunnel; JobScheduler
forced that run, so OEM hourly scheduling/battery behavior remains unverified.
Portable IP/domain/port policy combinations passed emulator tests.

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
