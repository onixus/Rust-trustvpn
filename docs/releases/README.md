# Release assets

After v0.6.2-beta.1 a GitHub release publishes one macOS file:
`R-TrustTunnel-macOS-arm64-UI-Choices.dmg`. It contains the Native, WebView and
Both PKG installers; the user installs exactly one.

Jenkins still builds and archives other macOS files, but they are not uploaded
to the GitHub release:

| Jenkins artifact | Why it is built |
| --- | --- |
| `R-TrustTunnel-macOS-arm64-system-candidate[-webview\|-both].pkg/.dmg` | Inputs for the UI Choices DMG; the same PKGs are inside it. |
| `R-TrustTunnel-macOS-arm64-preview.dmg` | Payload of the signed desktop update channel (`scripts/prepare-signed-release.py`). Profiles/SOCKS5 only, not system VPN. |

`bundled-candidate` is no longer built: it had the same contents as
`system-candidate` under another name.

On October 16, 2026 the other macOS files were removed from the v0.6.1 release and
its `SHA256SUMS` was regenerated; the remaining digests did not change.
v0.6.2-beta.1 (published before this change) has the six system-candidate
DMG/PKG files and no UI Choices DMG; earlier releases keep their full sets.

The current published Latest desktop/phone release is
[v0.7.1](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.1)
([notes](v0.7.1.md), `55bc488`).
Android TV is a separate pre-release,
[v0.7.1-tv.3](https://github.com/onixus/Rust-trustvpn/releases/tag/v0.7.1-tv.3),
and is not a desktop update and not the 0.7.1 phone package. Commits on `main`
after `232fd7b` are not in the v0.7.0 assets; they are what 0.7.1 packages.
