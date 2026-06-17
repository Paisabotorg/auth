/* pb-auth-gate/interstitial.js — Cross-language story interstitial (Phase 5)
 *
 * PB_INTERSTITIAL (localized by PHP) contains:
 *   prefLang    — user's saved language preference (e.g. 'hi')
 *   siteLang    — this site's language (e.g. 'ml')
 *   prefName    — native name of preferred lang (e.g. 'हिंदी')
 *   siteName    — native name of site lang (e.g. 'മലയാളം')
 *   variantUrl  — URL of this story in the preferred language
 *   clusterId   — cluster_id for dismissal cookie key
 *   authService — e.g. 'https://auth.paisabot.com'
 */

(function () {
  'use strict';

  var d = window.PB_INTERSTITIAL;
  if (!d) return;

  // Per-story dismissal cookie: key = pb_xl_<first8ofClusterId>
  var DISMISS_KEY = 'pb_xl_' + d.clusterId.replace(/-/g, '').slice(0, 8);

  function getCookie(name) {
    var m = document.cookie.match('(?:^|; )' + name + '=([^;]*)');
    return m ? decodeURIComponent(m[1]) : null;
  }

  function setDismissCookie() {
    var exp = new Date(Date.now() + 30 * 60 * 1000); // 30 min — don't nag same session
    document.cookie = DISMISS_KEY + '=1; path=/; expires=' + exp.toUTCString() +
                      (location.protocol === 'https:' ? '; Secure' : '') + '; SameSite=Lax';
  }

  // Already dismissed this story this session?
  if (getCookie(DISMISS_KEY)) return;

  // ── Build the interstitial card ───────────────────────────────────────────

  var root = document.createElement('div');
  root.id = 'pb-xl-root';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-modal', 'true');
  root.setAttribute('aria-label', 'Language preference');
  root.innerHTML =
    '<div class="pb-xl-backdrop" id="pb-xl-backdrop"></div>' +
    '<div class="pb-xl-card">' +
      '<p class="pb-xl-msg">' +
        'You usually read in <strong>' + d.prefName + '</strong>. ' +
        'This story is in <strong>' + d.siteName + '</strong>.' +
      '</p>' +
      '<div class="pb-xl-actions">' +
        '<a href="' + d.variantUrl + '" class="pb-xl-btn-pref" id="pb-xl-go">' +
          'Read in ' + d.prefName +
        '</a>' +
        '<button class="pb-xl-btn-stay" id="pb-xl-stay">' +
          'Continue in ' + d.siteName +
        '</button>' +
      '</div>' +
      '<label class="pb-xl-remember">' +
        '<input type="checkbox" id="pb-xl-chk"> Remember my choice' +
      '</label>' +
    '</div>';

  document.body.appendChild(root);

  // Trap focus within card
  var focusable = root.querySelectorAll('a, button, input');
  var first = focusable[0];
  var last  = focusable[focusable.length - 1];
  root.addEventListener('keydown', function (e) {
    if (e.key !== 'Tab') return;
    if (e.shiftKey) { if (document.activeElement === first) { e.preventDefault(); last.focus(); } }
    else            { if (document.activeElement === last)  { e.preventDefault(); first.focus(); } }
  });
  root.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') dismiss(false);
  });

  // Show after a short tick so CSS transition fires
  requestAnimationFrame(function () {
    requestAnimationFrame(function () { root.classList.add('pb-xl-visible'); });
  });
  first.focus();

  // ── Persistence helper ────────────────────────────────────────────────────

  function saveRouting(value) {
    // Best-effort PATCH; no blocking on failure
    fetch(d.authService + '/me', {
      method: 'PATCH',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cross_lang_routing: value }),
    }).catch(function () {});
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  function dismiss(remember) {
    root.classList.remove('pb-xl-visible');
    setDismissCookie();
    if (remember) saveRouting('never');
    setTimeout(function () { root.remove(); }, 250);
  }

  document.getElementById('pb-xl-stay').addEventListener('click', function () {
    var remember = document.getElementById('pb-xl-chk').checked;
    dismiss(remember);
  });

  document.getElementById('pb-xl-backdrop').addEventListener('click', function () {
    dismiss(false);
  });

  // "Read in pref" — let the link navigate, but save 'always' if checked
  document.getElementById('pb-xl-go').addEventListener('click', function () {
    var remember = document.getElementById('pb-xl-chk').checked;
    if (remember) saveRouting('always');
    setDismissCookie();
    // navigation proceeds via href
  });

}());
