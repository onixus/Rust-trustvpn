# Release assets

From v0.6.2 a GitHub release publishes one macOS file:
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

Releases up to v0.6.1 keep their full macOS asset sets.
