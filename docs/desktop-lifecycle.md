# Desktop lifecycle

Windows and Linux TUN/full-tunnel use HTTP/2 regardless of the imported profile's
HTTP/3 preference. This is applied to a runtime copy before IPC; saved configs,
exports and SOCKS5 retain their original transport. Certificate verification,
hostname, credentials and endpoint addresses remain unchanged. The endpoint must
accept HTTP/2 on the configured port. HTTP/3 system tunneling is not implemented.
macOS currently supports SOCKS5 (HTTP/2 and HTTP/3), not a system tunnel.

Profile add/replace/delete/rename, default selection and connection settings are
automatically saved after a short debounce. The existing encrypted vault and OS
keyring remain authoritative. Closing flushes pending changes first. Save errors
keep/show the window and retain dirty data for retry; no plaintext fallback.
The application loads the vault on restart and does not auto-connect.

Close / “В трей” hides the window while preserving the connection. The native
menu offers Open, Connect/disconnect and Exit. Exit flushes the vault, then waits
for system-service cleanup before termination. While connecting it asks the user
to cancel or wait instead of abandoning a system tunnel. A failed cleanup keeps
the window open. Windows/macOS use native tray APIs on the window event-loop
thread. Linux uses StatusNotifierItem and DBusMenu (KDE/Wayland), without X11.
If no tray host is available, close minimizes the window instead of making it
unreachable. If the Linux tray host disappears, the window is restored.

Regression coverage: dirty-close/save failure, debounce retry suppression,
close-to-tray preserving connection attempts, runtime transport selection,
real credential-store write and decryption by a separate process using an
isolated credential, GUI hide/restore smoke and a Linux D-Bus tray host fixture.
CI never overwrites a user's profile vault or changes their installed client.


## Login startup

The Settings page provides opt-in application startup for the current OS user.
It is off until explicitly enabled. Windows uses the dedicated `RTrustTunnel`
value in HKCU Run; Linux uses an XDG autostart desktop file; macOS uses a user
LaunchAgent with RunAtLoad and no KeepAlive. No shell command, VPN credentials,
profile path or elevation is added to the entry. Automatic VPN connection is a
separate opt-in vault setting, disabled by default.
`--autostart` is a launch mode, not a profile filename; the app loads its vault
and closes to the tray (or minimizes when a tray host is unavailable).

The checkbox reads the installed OS entry instead of copying this machine-local
setting into exported profiles. OS login-item policies can still disable/delay
startup. A moved executable is detected as a stale entry and can be rebound by
explicitly enabling it again. macOS requires launching a stable installed copy,
not the DMG/App Translocation copy. Disabling only removes this app's entry and
takes effect at the next login; it does not kill the current process.

Tests use temporary files and an isolated Windows registry subkey, never the
real login startup locations. No user's autostart is enabled by CI. Actual
logout/login is not performed by the automated pipeline. Disable autostart
before manually deleting a portable app or the macOS application bundle.

Windows uninstall removes only matching startup commands for this installation from loaded user hives; it does not mount offline profiles or delete other applications' startup values.

Linux login startup rejects executable paths containing `=` (Desktop Entry rule)
or `%` (GLib checks executable existence before expanding `%%`). Move the app
to a path without these characters before enabling login startup. Spaces, quotes,
backslashes, dollar signs and backticks are covered by a real `gio launch` test.

## Optional connection on application launch

The Settings checkbox enables one connection attempt using the first/default
profile and saved mode after a successful initial vault load. It does not connect
immediately when toggled. Ordinary launches and --autostart can connect; file/tt
launches and subsequent manual vault loads cannot. Missing profiles, a locked
keyring or an unsupported saved mode keep the error window visible. Cancelling
does not trigger another startup attempt. The existing tunnel reconnect policy
still applies once a connection is established. This is not pre-login always-on
protection; traffic before connection is not protected. The preference is encrypted
in the vault, not included in exported endpoint/tt profiles. Older clients that
reject unknown vault settings cannot read a vault saved with this new field; retain
a backup before downgrading. Automated tests do not log the user out or reboot.

## Concurrent save and recovery

A changed encrypted file revision is distinguished from a temporarily locked
store. The conflict panel offers local, disk, or both profile sets. Keeping both
removes exact duplicates and retains local connection settings/default profile.
Every subsequent save still compares the current revision: a second concurrent
edit causes a new conflict, never a forced overwrite. Reading a disk version or
recovery preview does not trigger autoconnect.

Before replacing a valid encrypted vault, save preserves its authenticated bytes
as profiles.previous.rtrust with the same private-write mechanism. Recovery in
Settings previews this copy and requires confirmation before writing it back.
There is no silent fallback at startup. Recovering a corrupted current file does
not overwrite the valid backup with corrupt bytes. The backup contains secrets
in encrypted form and requires the same OS keyring key; it is not a key backup.
