# macOS system VPN — candidate, not accepted release

The working tree now includes a root LaunchDaemon, reserved `utun5254`, authenticated
Unix IPC restricted to the configured desktop UID, selected IPv4 networks and
full IPv4/IPv6 tunnel modes. The native UI uses the same IPC contract as Windows
and Linux and preserves stored HTTP/3 profiles while selecting HTTP/2 at runtime.

The service adds only its own PF anchor, routes tagged with `RTF_PROTO2`, and a
SystemConfiguration DNS entry. Recovery verifies ownership before deletion.
Foreign VPN routes, PF rules or existing PF states cause preflight refusal.
Transport reconnect retains the utun device. GUI/service failure retains the
session guard until explicit recovery. macOS boot always-on is not implemented.
Network handoff to a different physical gateway is not yet accepted.

`scripts/package-macos-system.py` creates a package inside a DMG, without
Developer ID signing or notarization. The root helper is nested inside
`R-TrustTunnel.app/Contents/Library/LaunchServices` and the complete application
is ad-hoc sealed. Installation requires normal macOS administrator authorization.
The preinstall refuses an active GUI, active/recovery journal or desktop-owner
change. A race with Start is detected after stopping the old daemon, which is
then restored before refusing the package.

Jenkins #61 finished SUCCESS and its system candidate was installed on October 1.
The package's desktop-UID IPC probe passed again after the service crash test.
The helper runs inside the ad-hoc sealed application; this supersedes the old
standalone-helper Gatekeeper failure in `reports/macos-runtime/gatekeeper-56.json`.
Installed package SHA-256:
`c726b95e002e35f83cc4e81846bf81a4c911a40d3d7baff7c924e90ae203d792`.
DMG SHA-256:
`1c2ff3d01fe42e3edfa1bcec54b6a44eeb624efae5680700730834217079575a`.

Live acceptance passed IPv4/IPv6 TCP 512 KiB, UDP payloads up to 60 KB,
ICMP echo with 5000-byte fragmentation, system DNS, blocking a physical-bound
bypass, endpoint outage, automatic reconnect and explicit Stop. GUI/IPC crash
and an actual service SIGKILL followed by launchd restart retained the guard;
explicit authorized recovery restored physical access and removed the utun.
Evidence: `reports/macos-runtime/acceptance-61.json` and
`reports/macos-runtime/live-61-service-crash.log`.
The preceding run also passed data/outage/GUI checks but timed out waiting for
an external SIGKILL trigger; it is preserved as `live-61-crash.log`, not a pass.

The intermittent transfer failure observed in #58–60 was traced to endpoint
1.1.0 closing `_udp2` after an ICMP port-unreachable. Previously the dataplane
reset the entire transport, aborting unrelated TCP downloads. It now reopens
only UDP with bounded backoff while retaining TCP/ICMP and the independent
endpoint health check. The deterministic Linux regression fails on the old
binary and passes on the fix (`udp-regression-before.log`,
`udp-regression-after.log`); build #61 includes this regression in CI.

The Mac UDP probe enlarges only its own socket buffers; Darwin's default
9216-byte buffer otherwise rejects the 60 KB test locally. Global buffer
settings are unchanged. The driver recovers the service and original VPN on
failure as well as success. Hiddify connection and on-demand were restored.

Pending: sleep/network handoff, boot always-on, clean install on another Mac,
and automatic signed update/rollback. The tested artifact remains a candidate
with these explicit limits, without Developer ID signing or notarization.
