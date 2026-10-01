# R-TrustTunnel local h2 compatibility patch

Upstream: h2 0.4.19, MIT, source commit
`d57d1b852fec9dda6d42d3454502006d52104da8`.
Original crates.io archive SHA-256:
`ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16`.
Upstream LICENSE is retained. The root workspace pins this copy through
`[patch.crates-io]`; it affects both the native SOCKS client and TUN backend.

Only `src/proto/streams/counts.rs` changes runtime behavior. Endpoint 1.1.0
emits empty non-final DATA frames during backpressure. Upstream h2 counts
these over the entire connection lifetime and disconnects after 100, even
while useful traffic makes progress. The isolated TUN test reproducibly
failed during four simultaneous downloads with `too_many_data_frames`.

This patch retains a burst allowance of 100 and restores one empty-frame
credit per 16 KiB **consumed by the application**. Merely receiving payload
does not restore credits. Empty-frame consumption restores none. Credits
cannot exceed the original burst allowance, and historical traffic cannot
bank unlimited credits. The separate small-frame memory budget, HTTP/2
flow control, reset protections and protocol validation remain intact.

Tests cover useful progress, empty-only floods, byte-based credit accounting,
unconsumed payload, and inability to bank past payload. The interoperability
harness verifies the formerly failing official-endpoint scenario.

```sh
CARGO_TARGET_DIR=target/h2-tests cargo test \
  --manifest-path vendor/h2/Cargo.toml --lib --locked \
  -- --skip hpack::test::fixture
```

The published crate excludes the external HPACK fixture files; running its
entire library suite without filtering produces missing-file failures.
This command runs all packaged, self-contained unit tests; it does not
claim validation of the omitted fixture suite. Do not remove this patch
or replace it with an unbounded allowance when upgrading h2. Re-run both
its guard tests and `scripts/tun-interop.py`, then reassess whether an
upstream release provides equivalent bounded compatibility.
