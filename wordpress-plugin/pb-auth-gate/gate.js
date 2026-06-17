/* pb-auth-gate/gate.js — client-side gate controller
 *
 * Runs fully in the browser so it works even when LiteSpeed/CDN caches
 * the page (server-side PHP cookies never fire on cached responses).
 *
 * Decision tree:
 *   1. Valid pb_session JWT present and not expired? → authed, do nothing.
 *   2. pb_refresh cookie present? → try silent refresh first.
 *   3. Metered mode: localStorage read count > freeReads? → show gate.
 *   4. Immediate mode? → show gate.
 *   Otherwise: free read, gate stays hidden.
 */
(function () {
  'use strict';

  var cfg = window.PB_GATE;
  if (!cfg) return;

  var FREE_READS  = cfg.freeReads   || 2;
  var MODE        = cfg.gateMode    || 'metered';
  var AUTH_SVC    = cfg.authService || 'https://auth.paisabot.com';
  var COUNTER_KEY = 'pb_reads';

  // ── Helpers ────────────────────────────────────────────────────────────────

  function getCookie(name) {
    var m = document.cookie.match('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)');
    return m ? decodeURIComponent(m[1]) : null;
  }

  function jwtExpiry(token) {
    try {
      var payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
      return payload.exp || 0;
    } catch (e) { return 0; }
  }

  function isAuthed() {
    var token = getCookie('pb_session');
    if (!token) return false;
    return jwtExpiry(token) > Math.floor(Date.now() / 1000);
  }

  function getReadCount() {
    return parseInt(localStorage.getItem(COUNTER_KEY) || '0', 10);
  }

  function incrementReadCount() {
    var n = getReadCount() + 1;
    localStorage.setItem(COUNTER_KEY, String(n));
    return n;
  }

  // ── Gate elements ──────────────────────────────────────────────────────────

  var root    = document.getElementById('pb-gate-root');
  var spinner = document.getElementById('pb-gate-spinner');
  if (!root) return;

  function revealGate() {
    if (spinner) spinner.style.display = 'none';
    // .pb-gated-visible carries the fixed-overlay layout (see gate.css).
    // Don't set inline display — it would override the CSS flex layout.
    root.classList.add('pb-gated-visible');
    document.documentElement.style.overflow = 'hidden'; // lock scroll behind the gate
    trapFocus(root);
  }

  function trapFocus(el) {
    var focusable = el.querySelectorAll('a[href], button, input, [tabindex]:not([tabindex="-1"])');
    if (!focusable.length) return;
    var first = focusable[0];
    var last  = focusable[focusable.length - 1];
    first.focus();
    el.addEventListener('keydown', function (e) {
      if (e.key !== 'Tab') return;
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else {
        if (document.activeElement === last)  { e.preventDefault(); first.focus(); }
      }
    });
  }

  // ── Decision ───────────────────────────────────────────────────────────────

  // Step 1: already authed — nothing to do
  if (isAuthed()) return;

  // Step 2: has refresh token — try silent re-auth, then decide
  if (getCookie('pb_refresh')) {
    if (spinner) spinner.style.display = 'flex';
    fetch(AUTH_SVC + '/refresh', { method: 'POST', credentials: 'include' })
      .then(function (r) { r.ok ? window.location.reload() : decideGate(); })
      .catch(decideGate);
    return;
  }

  decideGate();

  function decideGate() {
    if (MODE === 'immediate') { revealGate(); return; }
    if (incrementReadCount() > FREE_READS) revealGate();
    // else: free read, gate stays hidden
  }

}());
