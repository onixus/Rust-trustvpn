'use strict';
// Presentation-only state model. Rust supplies the observation snapshot and the
// verified verdict; this file never upgrades a result, it only decays it.
(function (root) {
 const KEYS = ['transport', 'route', 'dns', 'guard', 'connectivity'];
 const OUTCOMES = ['passed', 'failed', 'configured', 'stale', 'unsupported'];
 // Same cap as the Rust core FRESH_MS and Android ObservationStatus.
 const MAX_TTL_MS = 6000;
 // The service's own repeated probes: Rust observations::PROBE_TTL_MS.
 const PROBE_TTL_MS = 30000;
 function ttlCap(o) { return o && o.source === 'system_probe' ? PROBE_TTL_MS : MAX_TTL_MS; }

 function snapshot(s) { return s && s.schema === 2 ? s : null; }

 /** Normalised outcome: passed/configured become stale after their TTL. */
 function outcome(o, now) {
  let out = o && typeof o.outcome === 'string' ? o.outcome : 'unknown';
  if (!OUTCOMES.includes(out)) return 'unknown';
  // A service probe failure must not outlive the runs that stopped confirming it.
  if (out === 'passed' || out === 'configured' || (out === 'failed' && o.source === 'system_probe')) {
   const time = typeof o.observed_at_ms === 'number' ? o.observed_at_ms : -1;
   const ttl = Math.min(ttlCap(o), Number(o.valid_for_ms) || 0);
   if (time < 0 || now < time || now - time > ttl) out = 'stale';
  }
  return out;
 }

 function outcomes(s, now) {
  s = snapshot(s);
  const result = {};
  for (const key of KEYS) result[key] = s ? outcome(s[key], now) : 'unknown';
  return result;
 }

 /** running | verified | warning, exactly as Android ObservationStatus.level. */
 function level(s, now) {
  const o = outcomes(s, now);
  let verified = true;
  for (const key of KEYS) {
   if (o[key] === 'failed') return 'warning';
   if (o[key] !== 'passed') verified = false;
  }
  return verified ? 'verified' : 'running';
 }

 function failed(s, now) {
  const o = outcomes(s, now);
  return KEYS.filter(key => o[key] === 'failed');
 }

 /** Checks without a fresh result: neither passed nor failed (stale transport included). */
 function pending(s, now) {
  const o = outcomes(s, now);
  return KEYS.filter(key => o[key] !== 'passed' && o[key] !== 'failed');
 }

 /**
  * input: {connected, verified, full, snapshot, phase, error, unavailable, now}
  * phase is the frontend's own pending action ('connecting'|'reconnecting'|'disconnecting'|null).
  * full: whole-device mode. Split and proxy sessions cover only part of the
  * traffic, so they never turn green (as the previous WebView UI).
  */
 function derive(input) {
  if (input.unavailable) return 'error';
  if (input.phase === 'connecting' || input.phase === 'reconnecting') return 'connecting';
  if (input.phase === 'disconnecting') return 'disconnecting';
  if (!input.connected) return input.error ? 'error' : 'off';
  const l = level(input.snapshot, input.now);
  if (l === 'warning') return 'warning';
  // Green needs both the Rust verdict and a fresh client-side reading.
  if (l === 'verified' && input.verified === true && input.full === true) return 'verified';
  return 'running';
 }

 const TONE = { off: 'grey', connecting: 'blue', disconnecting: 'blue', running: 'blue', verified: 'green', warning: 'yellow', error: 'red' };

 /** One row per check. Pseudo-values describe the transport when no session exists. */
 function rows(input, key) {
  const live = input.connected && !input.unavailable && key !== 'connecting';
  const o = live ? outcomes(input.snapshot, input.now) : {};
  const s = live ? snapshot(input.snapshot) : null;
  const split = s && s.transport && s.transport.mode === 'split';
  return KEYS.map(name => {
   let value = live ? o[name] : 'unknown';
   // Split DNS is not probed (it may or may not use the VPN); split TUN has no kill switch.
   if (split && value === 'unsupported' && name === 'dns') value = 'na';
   if (split && value === 'unsupported' && name === 'guard') value = 'guard_off';
   if (!live && name === 'transport') {
    if (key === 'connecting') value = 'connecting';
    else if (key === 'error' && !input.unavailable) value = 'error';
    else if (key === 'off') value = 'off';
   }
   return { key: name, value };
  });
 }

 // dot style per row value: fill colour or an empty ring
 const ROW_TONE = { passed: 'green', failed: 'yellow', configured: 'blue', stale: 'ring-grey', unsupported: 'grey', na: 'grey', guard_off: 'grey', unknown: 'ring', off: 'ring', connecting: 'ring-blue', error: 'red' };

 /**
  * Status line for one poll. An action's error/notice stays until the service
  * status changes after it was shown: noticeBase is the status seen at the
  * first poll after the notice (undefined until then), so a later event such
  * as a link's pending import replaces a stale error.
  * input: {notice, noticeBase, status, connected, connectError}
  * returns {text, keepNotice, noticeBase}
  */
 function statusLine(input) {
  const status = input.status || '';
  const fallback = status || (!input.connected && input.connectError) || '';
  if (!input.notice) return { text: fallback, keepNotice: false, noticeBase: undefined };
  if (input.noticeBase === undefined || input.noticeBase === status)
   return { text: input.notice, keepNotice: true, noticeBase: status };
  return { text: fallback, keepNotice: false, noticeBase: undefined };
 }

 const api = { KEYS, MAX_TTL_MS, PROBE_TTL_MS, snapshot, outcome, outcomes, level, failed, pending, derive, statusLine, rows, TONE, ROW_TONE };
 if (typeof module !== 'undefined' && module.exports) module.exports = api;
 else root.RTModel = Object.freeze(api);
})(typeof window !== 'undefined' ? window : globalThis);
