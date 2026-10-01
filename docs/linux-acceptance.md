# Linux acceptance — 2026-10-01

Candidate: native x86_64 on Arch Linux, KDE Plasma Wayland, systemd,
NetworkManager and systemd-resolved. X11 support remains excluded.

## Completed

- Jenkins `rtrust-linux` #5: completed SUCCESS, including Gitleaks, Trivy,
  workspace unit/Clippy, Wayland/tray and all network namespace E2E.
- Full-tunnel reconnect with strict reverse-path filtering, endpoint outage,
  physical-interface/gateway handoff and return, GUI/service crash, early guard,
  corrupted always-on policy, exact route/firewall restoration.
- Actual Plasma tray/menu/hide/restore and sandbox-to-root authenticated IPC.
- Encrypted synthetic vault and KWallet credential across two processes.
- Real Document Portal single-file grant: private atomic write/readback.
  Background Portal: enable/disable and actual autostart entry creation/removal.
- Arch host package: upgrade refusal while protection exists, update, rollback,
  uninstall/reinstall and authenticated Flatpak service channel.
- Private signed Flatpak installation: install/update/rollback, rejection of an
  unsigned application commit despite a signed summary, uninstall.
- Installed service live test `rtrust-linux-live-5b`: IPv4/IPv6 TCP 512 KiB,
  UDP through 60 KB, ICMP 56/5000, system DNS, physical-bound bypass rejection,
  endpoint outage/reconnect, Stop, GUI disconnect and service SIGKILL/restart.
  WireGuard and the previous tunnel service were restored, test TUN/rules
  removed, backup timer stopped and the temporary endpoint shut down.

The first live run exposed a test-driver error: Linux closes its IPC lease
after Stop. The driver now opens a fresh lease before the next scenario.
No production credentials or endpoint configuration were changed.

## Remaining acceptance

- Physical reboot/suspend/resume and login autostart: require explicit permission
  to interrupt desktop applications.
- Human interaction with KDE file chooser and polkit setup dialog. Portal APIs
  and the underlying package/setup operations were tested separately.
- Production GPG key and public HTTPS repository publication. Signing and
  rejection behavior were tested with an isolated temporary CI key.
- ARM64 physical desktop acceptance; its earlier container evidence remains.

Detailed local logs are under `reports/linux-runtime/` and are intentionally
excluded from Git. Installers are candidates, not a declaration of stable release.
