/* pb-auth-gate/account.js — [pb_account] self-service panel
 *
 * Renders: profile, active sessions (with revoke), logout-everywhere, and
 * DPDP account deletion. Talks to the auth service with credentials:'include'.
 */
(function () {
  'use strict';

  var cfg  = window.PB_ACCOUNT;
  var root = document.getElementById('pb-account-root');
  if (!cfg || !root) return;

  var SVC = cfg.authService;

  function h(html) { root.innerHTML = html; }
  function esc(s)  { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
  }); }

  function fmtDate(iso) {
    try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
  }

  function deviceLabel(ua) {
    if (!ua) return 'Unknown device';
    if (/iPhone|iPad/.test(ua)) return 'iOS · ' + (/Safari/.test(ua) ? 'Safari' : 'app');
    if (/Android/.test(ua))     return 'Android';
    if (/Macintosh/.test(ua))   return 'Mac · ' + (/Chrome/.test(ua) ? 'Chrome' : /Safari/.test(ua) ? 'Safari' : 'browser');
    if (/Windows/.test(ua))     return 'Windows';
    return ua.slice(0, 40);
  }

  function api(path, opts) {
    return fetch(SVC + path, Object.assign({ credentials: 'include' }, opts || {}));
  }

  function renderLoggedOut() {
    h(
      '<div class="pb-acc-card">' +
        '<h3>You are signed out</h3>' +
        '<p class="pb-acc-muted">Sign in to manage your account and devices.</p>' +
        '<a class="pb-acc-btn pb-acc-primary" href="' + esc(cfg.loginUrl) + '">Continue with Google</a>' +
      '</div>'
    );
  }

  function renderAccount(me, sessions) {
    var rows = sessions.map(function (s) {
      return (
        '<li class="pb-acc-session' + (s.current ? ' pb-acc-current' : '') + '">' +
          '<div class="pb-acc-sess-main">' +
            '<span class="pb-acc-dev">' + esc(deviceLabel(s.user_agent)) +
              (s.current ? ' <span class="pb-acc-badge">This device</span>' : '') + '</span>' +
            '<span class="pb-acc-meta">' + esc(s.ip || '') + ' · last active ' + esc(fmtDate(s.last_used_at)) + '</span>' +
          '</div>' +
          (s.current ? '' :
            '<button class="pb-acc-btn pb-acc-ghost" data-revoke="' + esc(s.id) + '">Revoke</button>') +
        '</li>'
      );
    }).join('');

    h(
      '<div class="pb-acc-card">' +
        '<div class="pb-acc-profile">' +
          (me.picture ? '<img class="pb-acc-avatar" src="' + esc(me.picture) + '" alt="">' : '') +
          '<div>' +
            '<div class="pb-acc-name">' + esc(me.name || 'Reader') + '</div>' +
            '<div class="pb-acc-muted">' + esc(me.email || (me.role === 'guest' ? 'Guest account' : '')) + '</div>' +
          '</div>' +
        '</div>' +
      '</div>' +

      '<div class="pb-acc-card">' +
        '<h3>Active sessions</h3>' +
        '<ul class="pb-acc-sessions">' + (rows || '<li class="pb-acc-muted">No active sessions.</li>') + '</ul>' +
        '<button class="pb-acc-btn pb-acc-ghost" id="pb-acc-logout-all">Sign out of all other devices</button>' +
      '</div>' +

      '<div class="pb-acc-card pb-acc-danger">' +
        '<h3>Delete account</h3>' +
        '<p class="pb-acc-muted">Permanently erases your account and all data (DPDP right to erasure). This cannot be undone.</p>' +
        '<button class="pb-acc-btn pb-acc-destructive" id="pb-acc-delete">Delete my account</button>' +
        '<a class="pb-acc-btn pb-acc-ghost" href="' + esc(cfg.logoutUrl) + '">Sign out</a>' +
      '</div>'
    );

    // Revoke a single session
    root.querySelectorAll('[data-revoke]').forEach(function (btn) {
      btn.addEventListener('click', function () {
        btn.disabled = true; btn.textContent = 'Revoking…';
        api('/sessions/' + encodeURIComponent(btn.getAttribute('data-revoke')) + '/revoke', { method: 'POST' })
          .then(function (r) { if (r.ok) load(); else { btn.disabled = false; btn.textContent = 'Revoke'; } })
          .catch(function () { btn.disabled = false; btn.textContent = 'Revoke'; });
      });
    });

    // Sign out of all other devices: revoke each non-current session
    var logoutAll = document.getElementById('pb-acc-logout-all');
    if (logoutAll) logoutAll.addEventListener('click', function () {
      var others = sessions.filter(function (s) { return !s.current; });
      if (!others.length) return;
      logoutAll.disabled = true; logoutAll.textContent = 'Signing out…';
      Promise.all(others.map(function (s) {
        return api('/sessions/' + encodeURIComponent(s.id) + '/revoke', { method: 'POST' });
      })).then(load).catch(load);
    });

    // Delete account (double confirm)
    var del = document.getElementById('pb-acc-delete');
    if (del) del.addEventListener('click', function () {
      if (!window.confirm('Delete your account and all data permanently? This cannot be undone.')) return;
      del.disabled = true; del.textContent = 'Deleting…';
      api('/me', {
        method:  'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ confirm: 'DELETE' }),
      }).then(function (r) {
        if (r.ok) { window.location.href = cfg.logoutUrl; }
        else { del.disabled = false; del.textContent = 'Delete my account'; }
      }).catch(function () { del.disabled = false; del.textContent = 'Delete my account'; });
    });
  }

  function load() {
    h('<div class="pb-acc-card pb-acc-muted">Loading your account…</div>');
    api('/me').then(function (r) {
      if (r.status === 401 || r.status === 403) { renderLoggedOut(); return null; }
      return r.json();
    }).then(function (me) {
      if (!me) return;
      api('/sessions').then(function (r) { return r.ok ? r.json() : []; })
        .then(function (sessions) { renderAccount(me, sessions || []); });
    }).catch(renderLoggedOut);
  }

  load();
}());
