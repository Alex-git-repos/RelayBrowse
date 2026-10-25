(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var form = $('f'), field = $('k'), btn = $('b'), msg = $('m');
  var API = String(window.APP_API || '').replace(/\/+$/, '');
  var TOKEN_KEY = 'app.t';   // read by ../app.js

  function say(text) { msg.textContent = text || ''; }

  function save(token) {
    try { localStorage.setItem(TOKEN_KEY, token); return true; } catch (e) { return false; }
  }

  function signIn(key) {
    return fetch(API + '/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: key }),
      referrerPolicy: 'no-referrer',
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok || !d.frameToken) throw new Error(d.error || 'Sign-in failed.');
        if (!save(d.frameToken)) throw new Error('Storage is blocked here, so the sign-in can’t be kept.');
      });
    });
  }

  // Back to the main page, carrying over an optional ?go= from the link used to get here.
  function leave() {
    var go = new URLSearchParams(location.search).get('go');
    location.replace('../' + (go ? '?go=' + encodeURIComponent(go) : ''));
  }

  function attempt(key) {
    btn.disabled = true;
    say('Please wait…');
    return signIn(key).then(leave).catch(function (err) {
      btn.disabled = false;
      say(err && err.message === 'Failed to fetch' ? 'Couldn’t connect. Try again in a moment.' : (err && err.message) || 'Sign-in failed.');
      field.focus();
    });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var key = field.value.trim();
    if (key) attempt(key);
  });

  // A link ending in #key=... signs in once and scrubs the key from the address bar first.
  var m = /[#&]key=([^&]+)/.exec(location.hash);
  if (m) {
    history.replaceState(null, '', location.pathname + location.search);
    var key = '';
    try { key = decodeURIComponent(m[1]); } catch (e) { key = m[1]; }
    attempt(key);
  } else {
    field.focus();
  }
})();
