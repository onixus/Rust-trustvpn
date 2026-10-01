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

The default profile and connect/disconnect action stay at the top of desktop
windows. Native highlights the active sidebar section; network mode, DNS and
proxy settings live in Settings. WebView separates Profiles, Settings and Sync,
shows only mode-relevant network fields, and asks for a second click before
removing a profile. Its import options are grouped under Add a profile.

Android keeps the status-colored connection button at the bottom. The home
screen shows the default profile, saved profiles and app selection. Add a profile
opens file, paste and QR import; Settings opens server synchronization and system
Always-on VPN controls. New Android navigation labels are localized in English
and Russian. Profile storage and tunnel behavior are unchanged.

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
