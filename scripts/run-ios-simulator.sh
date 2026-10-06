#!/bin/bash
# Launch the compiled preview in an existing iPhone simulator.
set -euo pipefail
cd "$(dirname "$0")/.."
export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
app="$PWD/target/ios-xcode/Build/Products/Release-iphonesimulator/R-TrustTunnel.app"
if [[ ! -d "$app" ]]; then
  echo 'Build first: scripts/build-ios.sh simulator' >&2
  exit 1
fi
simulator_id="${1:-}"
if [[ -z "$simulator_id" ]]; then
  simulator_id="$(xcrun simctl list devices available -j | python3 -c '
import json,sys
phones=[d for devices in json.load(sys.stdin)["devices"].values() for d in devices if "iPhone" in d["name"] or d["name"] == "R-TrustTunnel Test"]
phones.sort(key=lambda d: d["state"] != "Booted")
if not phones: sys.exit("No iPhone simulator. Install an iOS runtime and create an iPhone in Xcode first.")
print(phones[0]["udid"])
')"
fi
# bootstatus -b boots only when needed and waits for SpringBoard readiness.
xcrun simctl bootstatus "$simulator_id" -b
xcrun simctl install "$simulator_id" "$app"
xcrun simctl launch --terminate-running-process "$simulator_id" org.rtrusttunnel.ios
if [[ -d "$DEVELOPER_DIR/../Applications/DeviceHub.app" ]]; then
  open -a "$DEVELOPER_DIR/../Applications/DeviceHub.app"
else
  open -a "$DEVELOPER_DIR/Applications/Simulator.app" --args -CurrentDeviceUDID "$simulator_id"
fi
echo "R-TrustTunnel running on $simulator_id"
