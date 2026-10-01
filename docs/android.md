# Android native preview

The Android client uses native Android widgets (Java), a foreground `VpnService`
and the same Rust profile codec, HTTP/2 transport and IPv4/IPv6 packet engine as
the desktop client. There is no WebView, CLI subprocess or privileged host service.
Baseline: Android 10/API 29+, arm64-v8a; x86_64 is also built for emulator testing.
The current runtime acceptance environment is Android 16/API 36 x86_64.

## Implemented

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
- System consent precedes VPN setup. A persistent notification has Disconnect.
  Closing the Activity leaves the foreground service running.
- Both default routes and DNS use the TUN. Every endpoint socket is protected
  and bound to the underlying non-VPN network before connect; protection failure
  rejects the attempt. Endpoint DNS resolution happens before TUN establishment.
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

## Still required before a stable mobile release

Physical arm64 device acceptance (including Samsung/Pixel), Wi-Fi/mobile handoff,
Doze/screen-off/reboot and long soak; interactive permission and document-picker
acceptance; portal enrollment/sync, QR and localization. Always-on/OS lockdown is
explicitly disabled in this preview. The session guard does not promise protection
following force-stop, process death or explicit Disconnect. Android OS may exempt
some system traffic from a VPN. Non-default desktop routing and encrypted DNS
configuration are not implemented. Numeric DNS server addresses are supported.

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
