# Desktop UI choices

Native (Rust/iced) remains the default. The additional WebView frontend is a
standalone Tauri application with bundled local assets; ordinary operation needs
no browser or local HTTP server. Both share Rust connection code, the encrypted
vault, default-profile selection and profile revision checks. Tokens and profile
credentials are not included in WebView's normal view model.

WebView implements file/link import with confirmation, JSON export, profile
management, default-profile connect/disconnect, SOCKS/TUN/full-tunnel settings,
portal enrollment/sync/upload, autoconnect and a tray. Closing hides the window;
tray Quit stops the session before exit. Advanced conflict resolution, boot-policy
controls and update/recovery screens still use Native. Simultaneous frontend
editing is protected by revision checks; seamless transfer of an active
frontend-owned session is not claimed.

## Everyday navigation

Native follows UI variant 3: a left sidebar (Home, Profiles, Checks, Network,
Sync, Settings, and Updates on Windows) and dark or frosted light themes that
follow the system unless chosen in Settings (stored outside the vault). Home
shows the state chip, a two-line headline, the five service observations
(transport, route, DNS, guard, connectivity), the selected and backup profiles,
mode/DNS/sync/auto-connect tiles and a large connect pill. Green means every
observation passed and is fresh in whole-computer mode (split TUN and SOCKS stay
blue); any failure is yellow; otherwise a live tunnel is blue, and a check
without a result reads "no data". After failover the backup carrying traffic
is named. Lost contact with an Always-on service shows an unknown state. Network holds mode,
routes, backups and Always-on; Settings holds appearance, startup and storage
recovery. Real blur exists only with the macOS glass material. As in the
mockups, the light theme puts three soft colour fields behind translucent cards;
the first takes the state colour on Home and Checks (blue elsewhere). The shell,
Home, Profiles, Add profile and Checks follow the system language (Russian or
English); deeper section and status messages remain Russian.

WebView uses UI variant 3: a sidebar with Home, Profiles (with Add profile),
Checks, Network, Sync and Settings, a black dark theme and a frosted-glass light
theme that follow the system unless Settings overrides them (stored only in the
WebView's local storage). Home shows a state chip, a two-line headline, one row
per check, the profile Connect will use, the first backup named by the
connection settings, mode/DNS/sync/autoconnect tiles and a large connect pill.
The state is grey off, blue connecting or running, green only in whole-device
mode when all five checks of the existing observation snapshot passed within
their TTL (capped at 6 s) and Rust reports verified (split and proxy sessions
stay blue), yellow when any check failed (named in the
text), and red after a failed connect or when the state cannot be read. Checks
without a result show "no data". The view model gained the index of the
profile the live session was started from and, after failover, the backup the
service reports as active; it still carries no credentials or portal
baselines. A revision conflict reloads the view with a neutral notice. Network shows only mode-relevant fields, profile deletion
needs a second click, and import keeps the preview and explicit confirmation.
Copy follows the system language (Russian or English); messages from the Rust
core stay English except the observation summary. Not in WebView: QR import,
drag and drop, rename, editing backup profiles, an action search and hotkeys.

Android follows UI variant 3 with a slide-to-connect/disconnect control,
Home/Profiles/Add/Checks/Actions/VPN apps, dark and frosted light themes, and
foldable split layout. The app checks route/DNS/HTTPS through its own VPN
network on Android 12+; it has no direct fallback. Green reflects these fresh
checks, not packet-level proof or enforced lockdown. See
[Android UI and limitations](android.md).

## Packaging

- Windows Setup defines Native, WebView, Both and custom component choices.
  Native has no WebView2 requirement; WebView choices require an installed
  Microsoft WebView2 Runtime. Windows build/install/update checks for this change
  are deferred while the Windows node is offline.
- `scripts/package-macos-ui-choices.py --binary-dir target/release` creates an
  unsigned DMG containing three clearly named PKGs. Choose one PKG. Each installs
  the shared root service and selected frontend(s). Gatekeeper approval may still
  be required because there is no Developer ID/notarization. Switching to Native
  does not automatically delete an already installed secondary WebView app.
- `scripts/package-flatpak.py --ui native|webview|both` creates the selected Linux
  bundle. Native uses Freedesktop 25.08. WebView/Both use GNOME 50 for WebKit and
  require `--webview-libs` pointing to the verified tray libraries produced by CI.
  All variants keep `org.rtrusttunnel.Native` for the same sandbox/vault identity.
  Both exports two desktop launchers. The host VPN service is installed separately.

Build the WebView binary with `cargo build --release -p rtrust-webview --locked`.
Linux compilation additionally requires WebKitGTK 4.1 and Ayatana AppIndicator
development packages. Linux selects the Wayland backend and grants no X11 socket.

The macOS build/package and initial WebView import/save smoke have passed.
A local-assets/IPC/close-to-hide/restore smoke also passed on macOS.
WebView-only and Both Flatpaks passed the same smoke in a physical Plasma Wayland
session with DISPLAY unset; the Native executable in Both also passed its GUI smoke.
Temporary CI branches were uninstalled and the original signed Native commit retained.
Physical tray-menu/restart acceptance for WebView and Windows validation remain
separate checks; package generation alone does not establish that they passed.

## Published UI refresh

[v0.3.2-ui.2](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.3.2-ui.2)
ships the macOS UI Choices DMG and signed x86_64 Native/WebView/Both Flatpaks.
macOS #69 and Linux #20 completed successfully. The installed Native clients and
host services were upgraded; macOS retained the exact encrypted vault bytes.
All three Linux packages passed smoke on physical KDE Wayland; temporary variant
branches were removed and the updated Native master retained. This does not
establish physical WebView tray/restart parity or Windows acceptance.

See the [actual release screenshots](screenshots/README.md).
