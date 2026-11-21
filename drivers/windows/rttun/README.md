# rttun — Windows adapter for R-TrustTunnel

This directory replaces the WireGuard `wintun.dll` dependency. The service no
longer loads that DLL and has no fallback to it.

## What is implemented

`rttun-proto` (sibling crate) is the packet contract: raw IPv4/IPv6 only, a
fixed 256-slot ring that drops when full, and the names the installer and the
recovery path must match (`RTrustTunnel`, `ROOT\Rttun`). Those tests run on any
host.

`apps/tun/src/windows/driver.rs` is the service-side client. On Windows it:

1. refuses to proceed if `wintun.dll` is still beside the service;
2. requires `rttun.sys`, `rttun.inf` and `rttun.cat` beside the service;
3. checks the catalog Authenticode status and refuses a missing or test signature;
4. registers the package with `pnputil /add-driver` and creates one
   `SWD\Rttun` device named `RTrustTunnel`;
5. reads that device's interface index once;
6. opens `\\.\RTrustTunnel` and exchanges raw IP packets. If that handle does
   not open, connect fails before routes or DNS change.

If catalog verification, package registration, device creation or the first
index lookup fails, this attempt removes only the device it created. It does
not call `--recover`, does not delete a foreign driver, and does not load
`wintun.dll`.

## Build evidence

On the Windows Jenkins node, WDK 10.0.26100 and LLVM 23.1.6 are now installed.
`wdk-build` compiled `drivers/windows/rttun-umdf` there: `rttun_umdf.dll`,
210944 bytes, Authenticode status `NotSigned`. That file is not copied into
the service package. A `NotSigned` or `TestSigned` catalog is not a successful
install, and signature enforcement is not disabled.

The compiled crate is a UMDF host DLL. It creates a WDF device and stops.
This WDK does have a user-mode NetAdapter at
`Include\10.0.26100.0\um\netcx\umdf\adapter\2.5\netadapter.h`, with
`NetAdapterInitAllocate`, `NetAdapterCreate` and `NetAdapterStart`. Those
functions are inline calls through `NetFunctions[]`, and the stub library
exports that table. `rttun-umdf` calls those functions through the stub table, links
`netadaptercxstub` statically, and registers datapath callbacks. Those
callbacks call `NetTxQueueCreate` and `NetRxQueueCreate`. Advance calls
`NetTxQueueGetRingCollection` and reads the packet ring from slot 0 of
`NET_RING_COLLECTION`, then `BeginIndex`/`EndIndex`. The earlier read treated
the collection itself as a ring. `NET_FRAGMENT` is 8 bytes of lengths and an offset. The
packet bytes are `NET_FRAGMENT_VIRTUAL_ADDRESS`, reached through
`NetExtensionGetFragmentVirtualAddress`. Queue creation queries `ms_fragment_virtualaddress`. Advance copies one raw IPv4 or IPv6 fragment into a driver-local slot.
Queue cancel drops that slot. A sequential WDF queue is the device default queue and completes a service
`ReadFile` from that slot.
The queue layout was measured with the UMDF 2.31 x64 compiler: 96 bytes,
dispatch 1, `WdfUseDefault` 2, read callback at offset 24. This has not been
loaded. The DLL remains `NotSigned` and is not installed, so the read is not
a device proof. The DLL is
still `NotSigned` and is not installed. After the WDF
device exists, the driver creates `\DosDevices\RTrustTunnel`, the name the
service opens as `\\.\RTrustTunnel`.
The DLL and a `makecat` catalog were signed on the Windows node with a local
`CN=R-TrustTunnel Driver` certificate. Its public certificate is in that
machine's Root and TrustedPublisher stores. Signature enforcement was not
disabled. `pnputil /add-driver` accepted the package. The package that includes `netcxrd.inf` installed and created `ROOT\NET\0004`.
Its problem changed from 56 to 31. The UMDF host failed to load `rttun_umdf.dll` with Win32 error 577
(`ERROR_INVALID_IMAGE_HASH`). Signing the DLL again with page hashes
(`/ph`) did not change that error. The stored DLL still has Authenticode
status `Valid` for `CN=R-TrustTunnel Driver`. Windows did not load it.
The failed node and published package were removed. Signature enforcement
was not disabled. The existing `RTrustTunnel` adapter belongs to
`SWD\Wintun` and was not removed. The published package was then deleted with
`/delete-driver oem133.inf /uninstall`; the foreign Wintun device remained.
The private key stays on that machine and is not committed. This signature is
not trusted by another Windows installation.

## What this machine cannot build

The packet path is the WDK user-mode NetAdapter, not the generic UMDF sample.
It still needs a publisher catalog. Neither the macOS host nor the unsigned
DLL on the Windows node can provide that. `rttun.inf` is the package contract the Windows CI
node builds against. A missing `rttun.sys` or a catalog that is not `Valid`
fails the install closed; the absence is not hidden and test-signing is not a
success path.

Device acceptance (packet path, WFP, DNS, reboot, leftover adapter) is not
claimed until that Windows node runs it.
