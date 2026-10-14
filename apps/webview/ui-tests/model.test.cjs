// Run: node apps/webview/ui-tests/model.test.cjs  (synthetic snapshots only)
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const M = require(path.join(__dirname, '..', 'ui', 'model.js'));

const now = 1_000_000;
const obs = (outcome, age = 1000, ttl = 6000) => ({ outcome, source: 'service_lifecycle', observed_at_ms: now - age, valid_for_ms: ttl, mode: 'full', reason: 'not_checked' });
const snap = (o = {}) => ({ schema: 2, generation: 1, events: [], ...Object.fromEntries(M.KEYS.map(k => [k, o[k] || { outcome: 'unknown', source: 'not_observed', observed_at_ms: null, valid_for_ms: 6000, mode: 'full', reason: 'not_checked' }])) });
const allPassed = () => snap(Object.fromEntries(M.KEYS.map(k => [k, obs('passed')])));
const base = { connected: true, verified: true, full: true, phase: null, error: null, unavailable: false, now };

// Green only when every check passed, is fresh, and Rust agrees.
assert.equal(M.derive({ ...base, snapshot: allPassed() }), 'verified');
assert.equal(M.derive({ ...base, verified: false, snapshot: allPassed() }), 'running');
// Split or proxy sessions never turn green, even when every check passed.
assert.equal(M.derive({ ...base, full: false, snapshot: allPassed() }), 'running');
// Time passing alone leaves green: 6.5 s later every result is stale (no new fetch needed).
const fresh = allPassed();
assert.equal(M.derive({ ...base, snapshot: fresh }), 'verified');
assert.equal(M.derive({ ...base, snapshot: fresh, now: now + 6500 }), 'running');
assert.deepEqual(M.pending(fresh, now + 6500), M.KEYS);
// Pending lists only checks without a fresh result, stale transport included.
const mixed = snap({ transport: obs('configured', 9000), route: obs('passed'), dns: obs('failed') });
assert.deepEqual(M.pending(mixed, now), ['transport', 'guard', 'connectivity']);
assert.equal(M.derive({ ...base, connected: true, phase: 'reconnecting', snapshot: fresh }), 'connecting');
// TTL decay: older than min(valid_for_ms, 6 s) is stale, even if the service claims a longer TTL.
const old = allPassed(); old.dns = obs('passed', 7000, 60000);
assert.equal(M.outcome(old.dns, now), 'stale');
assert.equal(M.derive({ ...base, snapshot: old }), 'running');
// A future timestamp is not trusted.
assert.equal(M.outcome(obs('passed', -500), now), 'stale');
// Unknown checks are never shown as passed.
assert.equal(M.derive({ ...base, snapshot: snap({ transport: obs('configured') }) }), 'running');
assert.deepEqual(M.rows({ ...base, snapshot: snap({ transport: obs('configured') }) }, 'running').map(r => r.value), ['configured', 'unknown', 'unknown', 'unknown', 'unknown']);
// Any failure is a warning and is named.
const bad = snap({ transport: obs('configured'), dns: { ...obs('failed'), observed_at_ms: null } });
assert.equal(M.derive({ ...base, snapshot: bad }), 'warning');
assert.deepEqual(M.failed(bad, now), ['dns']);
// Wrong schema or missing snapshot: no data, never verified.
assert.equal(M.derive({ ...base, snapshot: { ...allPassed(), schema: 1 } }), 'running');
assert.equal(M.derive({ ...base, snapshot: null }), 'running');
assert.equal(M.outcome({ outcome: 'bogus' }, now), 'unknown');
// Lifecycle states.
assert.equal(M.derive({ ...base, connected: false, snapshot: null }), 'off');
assert.equal(M.derive({ ...base, connected: false, error: 'boom', snapshot: null }), 'error');
assert.equal(M.derive({ ...base, connected: false, phase: 'connecting', snapshot: null }), 'connecting');
assert.equal(M.derive({ ...base, phase: 'disconnecting', snapshot: allPassed() }), 'disconnecting');
// Same tone as native Level::Disconnecting and iOS TunnelLevel.disconnecting.
assert.equal(M.TONE.disconnecting, 'blue');
assert.equal(M.derive({ ...base, unavailable: true, snapshot: allPassed() }), 'error');
assert.deepEqual(M.rows({ ...base, connected: false, snapshot: null }, 'off').map(r => r.value), ['off', 'unknown', 'unknown', 'unknown', 'unknown']);
assert.deepEqual(M.rows({ ...base, connected: false, phase: 'connecting', snapshot: null }, 'connecting').map(r => r.value), ['connecting', 'unknown', 'unknown', 'unknown', 'unknown']);
assert.deepEqual(M.rows({ ...base, connected: false, error: 'x', snapshot: null }, 'error').map(r => r.value), ['error', 'unknown', 'unknown', 'unknown', 'unknown']);
assert.deepEqual(M.rows({ ...base, unavailable: true, snapshot: allPassed() }, 'error').map(r => r.value), ['unknown', 'unknown', 'unknown', 'unknown', 'unknown']);
// Service probes (issue #81): their own TTL cap, failure expiry and split labels.
const sys = (outcome, age = 1000, ttl = 25000) => ({ ...obs(outcome, age, ttl), source: 'system_probe', reason: 'configuration_applied' });
const probed = allPassed(); probed.transport = sys('passed'); probed.dns = sys('passed'); probed.guard = sys('passed');
probed.route = obs('passed', 1000, 6000); probed.connectivity = obs('passed', 1000, 6000);
assert.equal(M.outcome(probed.dns, now + 10000), 'passed');
assert.equal(M.outcome(probed.dns, now + M.PROBE_TTL_MS), 'stale');
assert.equal(M.outcome(sys('passed', 1000, 600000), now + M.PROBE_TTL_MS), 'stale');
assert.equal(M.outcome(obs('passed', 1000, 25000), now + 10000), 'stale', 'lifecycle rows keep the 6 s cap');
assert.equal(M.outcome(sys('failed'), now), 'failed');
assert.equal(M.outcome(sys('failed'), now + M.PROBE_TTL_MS), 'stale');
assert.equal(M.outcome(obs('failed'), now + 60000), 'failed', 'other failures persist until replaced');
assert.equal(M.derive({ ...base, snapshot: { ...probed, guard: sys('failed') } }), 'warning');
assert.deepEqual(M.failed({ ...probed, guard: sys('failed') }, now), ['guard']);
const unsup = { outcome: 'unsupported', source: 'service_lifecycle', observed_at_ms: null, valid_for_ms: 6000, mode: 'split', reason: 'check_unavailable' };
const split = snap({ transport: { ...obs('configured'), mode: 'split' }, dns: unsup, guard: unsup });
assert.deepEqual(M.rows({ ...base, full: false, snapshot: split }, 'running').map(r => r.value), ['configured', 'unknown', 'na', 'guard_off', 'unknown']);
assert.equal(M.ROW_TONE.na, 'grey');
assert.equal(M.derive({ ...base, full: false, snapshot: split }), 'running');
assert.deepEqual(M.rows({ ...base, snapshot: snap({ transport: obs('configured'), guard: { ...unsup, mode: 'full' } }) }, 'running').map(r => r.value)[3], 'unsupported');
// Status line: an action error stays across polls until the service status changes.
let line = M.statusLine({ notice: 'Unsupported profile format', noticeBase: undefined, status: '', connected: false, connectError: null });
assert.deepEqual(line, { text: 'Unsupported profile format', keepNotice: true, noticeBase: '' });
line = M.statusLine({ notice: 'Unsupported profile format', noticeBase: line.noticeBase, status: '', connected: false, connectError: null });
assert.equal(line.text, 'Unsupported profile format');
line = M.statusLine({ notice: 'Unsupported profile format', noticeBase: line.noticeBase, status: 'Pending import: Office. Confirm it under Profiles, Add profile.', connected: false, connectError: null });
assert.deepEqual(line, { text: 'Pending import: Office. Confirm it under Profiles, Add profile.', keepNotice: false, noticeBase: undefined });
// Without a notice: service status, else the last connect error while disconnected.
assert.equal(M.statusLine({ notice: '', status: '', connected: false, connectError: 'refused' }).text, 'refused');
assert.equal(M.statusLine({ notice: '', status: '', connected: true, connectError: 'refused' }).text, '');
console.log('PASS webview state model');
