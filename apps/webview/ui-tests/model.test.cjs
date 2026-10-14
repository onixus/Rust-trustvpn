// Run: node apps/webview/ui-tests/model.test.cjs  (synthetic snapshots only)
'use strict';
const assert = require('node:assert/strict');
const path = require('node:path');
const M = require(path.join(__dirname, '..', 'ui', 'model.js'));

const now = 1_000_000;
const obs = (outcome, age = 1000, ttl = 6000) => ({ outcome, source: 'service_lifecycle', observed_at_ms: now - age, valid_for_ms: ttl, mode: 'full', reason: 'not_checked' });
const snap = (o = {}) => ({ schema: 2, generation: 1, events: [], ...Object.fromEntries(M.KEYS.map(k => [k, o[k] || { outcome: 'unknown', source: 'not_observed', observed_at_ms: null, valid_for_ms: 6000, mode: 'full', reason: 'not_checked' }])) });
const allPassed = () => snap(Object.fromEntries(M.KEYS.map(k => [k, obs('passed')])));
const base = { connected: true, verified: true, phase: null, error: null, unavailable: false, now };

// Green only when every check passed, is fresh, and Rust agrees.
assert.equal(M.derive({ ...base, snapshot: allPassed() }), 'verified');
assert.equal(M.derive({ ...base, verified: false, snapshot: allPassed() }), 'running');
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
assert.equal(M.derive({ ...base, unavailable: true, snapshot: allPassed() }), 'error');
assert.deepEqual(M.rows({ ...base, connected: false, snapshot: null }, 'off').map(r => r.value), ['off', 'unknown', 'unknown', 'unknown', 'unknown']);
assert.deepEqual(M.rows({ ...base, connected: false, phase: 'connecting', snapshot: null }, 'connecting').map(r => r.value), ['connecting', 'unknown', 'unknown', 'unknown', 'unknown']);
assert.deepEqual(M.rows({ ...base, connected: false, error: 'x', snapshot: null }, 'error').map(r => r.value), ['error', 'unknown', 'unknown', 'unknown', 'unknown']);
assert.deepEqual(M.rows({ ...base, unavailable: true, snapshot: allPassed() }, 'error').map(r => r.value), ['unknown', 'unknown', 'unknown', 'unknown', 'unknown']);
console.log('PASS webview state model');
