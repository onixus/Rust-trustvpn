# Flow icon

Option 6, **Flow / Поток**, is the selected R-TrustTunnel client icon.
`icon.svg` is the canonical desktop vector; `tray.svg` is its transparent,
single-color small-size variant. Android uses matching vector paths with an
adaptive background and a monochrome notification/themed icon.

Generated PNG, ICO, ICNS and raw RGBA files are committed so CI can package
icons without graphics dependencies. Regenerate with `scripts/generate-icons.py`
using Node.js with Sharp and Python with Pillow. `--node` and `--node-modules`
allow using an existing runtime installation.

macOS app bundles declare `CFBundleIconFile`; Windows embeds the ICO in the
native executable and uses it for the installer and shortcuts. Both desktop
frontends share the window and tray artwork. Flatpak installs the scalable SVG.
Android launcher assets support adaptive and Android 13 monochrome icons.
