# Persistent connection event journal (#107)

The desktop system VPN services and the GUI's automatic SOCKS recovery keep a
best-effort local journal. No upload, telemetry service, network probe or new
permission prompt is added. Existing redacted macOS lifecycle events use the
same persistent bounded writer; the old ephemeral `/private/var/run/rtrust/events.log`
logger is no longer used. Existing files there are not migrated or deleted.

## Locations and access

| Producer | Location | Access |
|---|---|---|
| macOS system service | `/Library/Logs/R-TrustTunnel/events.log` | root owns; directory 0755, files 0644 |
| Linux system service | `/var/log/rtrust/events.log` | root owns; directory 0755, files 0644 |
| Windows system service | native ProgramData known folder, `R-TrustTunnel/logs/events.log` | SYSTEM/Administrators full control; Users read/traverse only; protected DACL |
| macOS automatic SOCKS | `~/Library/Logs/R-TrustTunnel/socks-events.log` | current user only; directory 0700, files 0600 |
| Linux automatic SOCKS | XDG state directory, `rtrust/logs/socks-events.log` | current user only; directory 0700, files 0600 |
| Windows automatic SOCKS | native LocalAppData known folder, `R-TrustTunnel/logs/socks-events.log` | current user and SYSTEM only; protected DACL |

Windows paths use the known-folder API, not a user-controlled ProgramData
environment variable. Linux's unit declares `LogsDirectory=rtrust`, writable
under its existing `ProtectSystem=strict` policy. It does not make other paths
writable or grant new networking capabilities. Service logs are shared across
service instances and serialized with a non-waiting cross-process lock.

Unix opens use directory handles and no-follow operations and check regular files,
expected ownership and link count. Under either service umask (including 0077),
provably new files receive exact modes only after exclusive creation and fd
verification. Newly created root directories receive 0755 only under a pinned,
same-owner immediate parent without group/other write and only when their opened
mode is a subset of the desired mode. Otherwise they retain private 0700 modes;
new files inside such a private leaf are 0600. Existing private 0700 directories
and 0600 files are never widened, including when retention rewrites their content
into a replacement inode. Newly created intermediates follow the same protected-
parent rule; existing ancestors are never repaired. User-owned journals remain
0700/0600. The system-service table describes a fresh journal under a protected
parent; an existing/private or group-managed-parent fallback can intentionally
remain unreadable to a non-root GUI. Before fresh-install validation, an
administrator must check the parent ownership/mode and verify a non-root reader.
The journal does not repair group-managed parents or migrate existing private
content; any manual namespace or access change needs separate operator review.
A retention rewrite's initial creation mode and final exact mode never exceed
the verified target's existing permissions.
Root-owned intermediate directories may be group-writable (for example a
root:syslog 0775 `/var/log`), but never other-writable or foreign-owned; no
ancestor modes are changed. The root-owned journal leaf rejects group/other
write and setuid/setgid/sticky bits. A trusted intermediate group can still
rename owned namespace entries or disrupt logging; no permission widening,
symlink following, or privilege grant is allowed by this compatibility policy.
Windows rejects reparse points and hardlinks, verifies trusted ownership,
repairs the protected DACL only on the journal leaf/files (never ancestors),
and retains parent handles with list access and without share-delete against
replacement. User-owned directories and every newly created journal file have
explicit TokenUser ownership, including under elevated tokens; existing foreign
owners are rejected, not taken over.
An unsafe object, busy lock, full disk or inaccessible directory disables/drops
logging for that operation; it does not prevent VPN operation. Do not create
symlinks, hardlinks or custom directories at journal filenames.

## Closed failure schema

Example (synthetic):

```text
1700000000000 pid=123 connect_failed path=reconnect class=tls transport=h3 attempt=2 budget=burst duration_ms=187
```

- `path`: `start`, `reconnect`, `wake_reconnect`, `socks_recovery`.
- `class`: `endpoint_unreachable`, `tls`, `authentication`, `profile`, `timeout`,
  `local_bind`, `protocol`, `cancelled`, `other`.
- `transport`: `h2`, `h3`, `hysteria`, `amneziawg`, `unknown`, from planned engine
  dispatch, never a profile-provided raw string.
- `attempt`: startup candidate attempts, or the scheduled 1-based burst attempt.
  The attempt following the five-minute cooldown is attempt 1 with `budget=cooldown`.
- `duration_ms`: monotonic elapsed attempt time, excluding automatic retry delay.
  Start includes preparation. A worker panic or post-connect OS guard failure
  can have duration 0 when a completed transport timer is unavailable.

Engine errors are classified while typed, before GUI string conversion. Strings,
credential material, profile names, hostnames, SNI, endpoint addresses, selected
routes, request destinations and traffic history are not accepted by the failure
record API. Existing GUI error messages and retry decisions are unchanged.
A failed Start emits one final record, not one per fallback candidate. A successful
Start emits none. Accepted automatic failures emit once; late SOCKS epochs and
pre-wake macOS worker results emit none. Cancelling an initial preparation emits
`cancelled`; superseded recovery work is discarded rather than logged as a new
active failure. Linux/Windows snapshot the path when scheduling each attempt:
a pre-wake worker keeps its original label, and a resume while a healthy tunnel
survives cannot label an unrelated later outage. A resume during recovery marks
subsequent attempts `wake_reconnect` until transport admission. Selection/pin
validation is `profile`, DNS pin timeout is `timeout`, local utun contention is
`local_bind`, and managed-access lease expiry is `authentication`, not a user
cancellation. Initial user SOCKS starts are outside this journal's
automatic-recovery scope.

## Bounded persistence

The active file is `events.log` (or `socks-events.log`); completed segments have
monotonically numbered suffixes, e.g. `events.log.12`. Higher suffixes are newer;
gaps are normal. Active is newest. Each segment is at most 1,000,000 bytes. The
writer evicts oldest managed segments **before** an append or retention rewrite
would exceed **15,000,000 bytes** (decimal 15 MB), including rewrite temporary
data. A mixed retention target is copied only after evicting older segments;
if older history cannot provide enough temporary space, that oldest target is
discarded instead of evicting newer segments to preserve it. No
truncate-and-start-over rotation is used. Empty lock files carry no record data.
Unknown files in the directory are not managed or deleted.

Every record older than seven days is removed, including expired prefixes of a
mixed active/rotated file. Pruning runs at writer startup, before each append,
and every 60 seconds while idle. Malformed and incomplete records are discarded.
Future-dated records survive an RTC rollback; they remain byte-cap bounded and
age out once wall time advances beyond their timestamp plus seven days. No
process can prune while it is stopped; the next writer startup performs retention
before its first append. Copy logs for support before they age out. Persisted
records survive normal service/app restarts and runtime-directory cleanup.
There is no shutdown flush integration: even normal process shutdown can lose
queued tail records, and abrupt power loss can also lose buffered records.
This is not an audit or guaranteed-delivery log.

Producers use `try_send` into a bounded 256-entry queue. One dedicated writer
thread performs path discovery, ACL/mode operations, scans, rotation and writes;
async connection paths do no journal filesystem I/O or lock waits. A later
`journal_dropped count=N` marker summarizes dropped events when storage recovers.
Initialization/thread failures and writer panics do not propagate into VPN
control. Shutdown does not wait for an unbounded disk operation.

## Verification and remaining device gates

Unit fixtures use temporary directories/injected sinks, never service paths or
real HOME journal files. Coverage includes all nine typed classes, transport
whitelisting and privacy canaries, exactly-once guards, queue saturation,
writer initialization/panic/lock failures, append/restart preservation, per-record
retention with an injected idle clock, near-cap mixed rewrites, and unsafe Unix
symlink/hardlink/directory objects. SOCKS loopback TLS/h2 fixtures exercise actual
endpoint refusal, TLS identity mismatch, rejected authentication, protocol
rejection and occupied local bind, and verify stale/accepted epoch publication.
Profile/timeout/cancelled/other classification units are controlled typed faults,
not claims that a real endpoint produced each condition.

Unix mode unit fixtures run in a bounded subprocess with umask 0077; they share
Root desired creation modes with a current-UID internal policy, not Root
privilege/authorization. A separate ignored `unix::tests::native_root_umask_gate`
requires euid 0 and an explicitly supplied `RTRUST_JOURNAL_ROOT_BASE`: an already
existing root-owned 0755 absolute directory whose ancestors are also root-owned,
non-symlink 0755 directories. Missing authorization fails with `NOT RUN`, never a
successful native gate. The test changes umask only in its child, creates/removes
only a unique fixture subtree, and tests an unrelated numeric reader identity
with supplementary groups cleared before dropping gid/uid. Run it by its exact
name with `--ignored`; it is not automatically executed by ordinary tests and
does not replace installed-package acceptance.

Native Windows ACL/reparse acceptance, native Linux packaged-service acceptance,
and installed macOS package reboot persistence must still be run on those
platforms. Host compilation and synthetic tests do **not** satisfy these gates,
do not prove leak/kill-switch behavior, and do not authorize closing #107.
