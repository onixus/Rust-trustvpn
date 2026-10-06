#!/bin/bash
# Build static Rust core then the iPhone app + Network Extension.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
mode="${1:-device}"
case "$mode" in
  device|archive) rust_target=aarch64-apple-ios; sdk=iphoneos; destination='generic/platform=iOS' ;;
  simulator) rust_target=aarch64-apple-ios-sim; sdk=iphonesimulator; destination='generic/platform=iOS Simulator' ;;
  *) echo 'Usage: scripts/build-ios.sh [device|simulator|archive]' >&2; exit 2 ;;
esac
# Check license/first-launch prerequisites before changing toolchain state.
xcodebuild -checkFirstLaunchStatus
xcrun --sdk "$sdk" --show-sdk-path >/dev/null
if ! rustup target list --installed | /usr/bin/grep -qx "$rust_target"; then
  echo "Install Rust target first: rustup target add $rust_target" >&2
  exit 1
fi
python3 scripts/generate-ios-project.py
export IPHONEOS_DEPLOYMENT_TARGET=16.0
cargo build --locked --release --lib -p rtrust-ios --target "$rust_target"
args=(-project apps/ios/RTrustTunnel.xcodeproj -scheme RTrustTunnel -configuration Release -destination "$destination" -derivedDataPath "$PWD/target/ios-xcode")
if [[ "$mode" == archive ]]; then
  : "${APPLE_TEAM_ID:?Set APPLE_TEAM_ID to your Apple Developer team identifier}"
  : "${IOS_BUNDLE_ID:?Set IOS_BUNDLE_ID to your registered app identifier}"
  xcodebuild "${args[@]}" archive -archivePath "$PWD/dist/R-TrustTunnel-iOS.xcarchive" DEVELOPMENT_TEAM="$APPLE_TEAM_ID" RTRUST_BUNDLE_ID="$IOS_BUNDLE_ID"
  echo 'Archive created. Export a signed IPA through Xcode Organizer using matching provisioning profiles.'
elif [[ "$mode" == simulator ]]; then
  # Ad-hoc simulator signing supplies shared Keychain entitlements without an Apple account.
  xcodebuild "${args[@]}" build CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- CODE_SIGNING_REQUIRED=NO AppIdentifierPrefix=SIMULATOR.
  echo 'Simulator app built with local ad-hoc signing.'
else
  xcodebuild "${args[@]}" build CODE_SIGNING_ALLOWED=NO
  echo 'Unsigned app built; this is not an installable signed IPA.'
fi
