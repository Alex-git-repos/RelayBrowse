(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var home = $('home'), shell = $('shell'), view = $('view'), addr = $('addr');
  var hint = $('hint'), progress = $('progress'), recentBox = $('recent');
  var STORE_KEY = 'relay-recent';
  var TOKEN_KEY = 'relay-frame-token';
  var BACKEND = String(window.RELAY_BACKEND || '').replace(/\/+$/, '');
  var gate = $('gate'), gateForm = $('gateForm'), gateKey = $('gateKey'), gateMsg = $('gateMsg');
  var frameToken = '';

  function loadToken() { try { return localStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; } }
  function saveToken(t) { try { if (t) localStorage.setItem(TOKEN_KEY, t); else localStorage.removeItem(TOKEN_KEY); } catch (e) {} }
  frameToken = loadToken();

  function showGate(msg) {
    home.hidden = true; shell.hidden = true; gate.hidden = false;
    gateMsg.textContent = msg || '';
    gateKey.focus();
  }

  // Trade the access key for a frame token. Cross-origin, so no cookies are involved.
  function signIn(key) {
    gateMsg.textContent = 'Connecting\u2026 (the server may take up to a minute to wake up)';
    return fetch(BACKEND + '/api/auth', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: key }),
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) {
        if (!r.ok || !d.frameToken) throw new Error(d.error || 'Could not sign in.');
        frameToken = d.frameToken; saveToken(frameToken);
      });
    });
  }

  function normalize(raw) {
    var v = (raw || '').trim();
    if (!v) return null;
    if (/^https?:\/\//i.test(v)) return v;
    if (/^(javascript|data|file|ftp|blob|about|mailto):/i.test(v)) return null;
    if (/^[^\s\/]+\.[^\s\/]{2,}(\/.*)?$/.test(v)) return 'https://' + v;
    return 'https://duckduckgo.com/html/?q=' + encodeURIComponent(v);
  }

  function getRecent() {
    try { return JSON.parse(localStorage.getItem(STORE_KEY)) || []; } catch (e) { return []; }
  }
  function remember(url) {
    try {
      var list = getRecent().filter(function (u) { return u !== url; });
      list.unshift(url);
      localStorage.setItem(STORE_KEY, JSON.stringify(list.slice(0, 5)));
    } catch (e) { /* storage unavailable */ }
  }
  function label(url) {
    try { var u = new URL(url); return u.hostname.replace(/^www\./, '') + (u.pathname.length > 1 ? u.pathname : ''); }
    catch (e) { return url; }
  }
  function renderRecent() {
    var list = getRecent();
    recentBox.innerHTML = '';
    if (!list.length) { recentBox.hidden = true; return; }
    var s = document.createElement('span');
    s.textContent = 'Recent';
    recentBox.appendChild(s);
    list.forEach(function (u) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'chip'; b.textContent = label(u); b.title = u;
      b.addEventListener('click', function () { open(u); });
      recentBox.appendChild(b);
    });
    recentBox.hidden = false;
  }

  function setLoading(on) {
    progress.classList.remove('on');
    if (on) { void progress.offsetWidth; progress.classList.add('on'); }
  }

  function open(url) {
    home.hidden = true;
    shell.hidden = false;
    addr.value = url;
    setLoading(true);
    view.src = BACKEND + '/proxy?url=' + encodeURIComponent(url) + '&t=' + encodeURIComponent(frameToken);
    remember(url);
  }

  function submit(raw, fromHome) {
    if (!frameToken) { showGate(); return; }
    var url = normalize(raw);
    if (!url) {
      if (fromHome) hint.textContent = 'Enter a web address that starts with http or https, or type a search.';
      return;
    }
    hint.textContent = '';
    open(url);
  }

  function goHome() {
    shell.hidden = true;
    home.hidden = false;
    view.src = 'about:blank';
    addr.value = '';
    document.title = 'Relay Browse';
    renderRecent();
    $('homeInput').focus();
  }

  $('goForm').addEventListener('submit', function (e) { e.preventDefault(); submit($('homeInput').value, true); });
  $('addrForm').addEventListener('submit', function (e) { e.preventDefault(); submit(addr.value, false); });
  gateForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var key = gateKey.value.trim();
    if (!key) return;
    signIn(key).then(function () {
      gateKey.value = ''; gate.hidden = true; home.hidden = false; gateMsg.textContent = '';
      $('homeInput').focus();
    }).catch(function (err) {
      gateMsg.textContent = err && err.message === 'Failed to fetch' ? 'Couldn\u2019t reach the server. Try again.' : (err.message || 'Could not sign in.');
    });
  });
  $('forgetBtn').addEventListener('click', function () { frameToken = ''; saveToken(''); showGate('Access key forgotten on this device.'); });
  $('homeBtn').addEventListener('click', goHome);
  // The page lives in an opaque-origin sandbox, so the shell can only talk to it by message.
  function cmd(c) { try { view.contentWindow.postMessage({ type: 'proxy-cmd', cmd: c }, '*'); } catch (e) {} }
  $('backBtn').addEventListener('click', function () { cmd('back'); });
  $('fwdBtn').addEventListener('click', function () { cmd('forward'); });
  $('reloadBtn').addEventListener('click', function () { setLoading(true); cmd('reload'); });
  document.querySelectorAll('[data-go]').forEach(function (b) {
    b.addEventListener('click', function () { open(b.getAttribute('data-go')); });
  });

  view.addEventListener('load', function () { setLoading(false); });

  // The injected script reports the real address of the page being shown.
  window.addEventListener('message', function (e) {
    if (e.source !== view.contentWindow) return; // sandboxed frames have origin "null"
    var d = e.data;
    if (!d || d.type !== 'proxy-nav' || typeof d.url !== 'string' || !/^https?:\/\//i.test(d.url)) return;
    addr.value = d.url;
    document.title = (d.title || label(d.url)) + ' \u2013 Relay Browse';
  });

  renderRecent();

  // A link like https://your-frontend/#key=SECRET signs in once, then removes the key from the address bar.
  var hashKey = (/[#&]key=([^&]+)/.exec(location.hash) || [])[1];
  if (hashKey) {
    history.replaceState(null, '', location.pathname + location.search);
    signIn(decodeURIComponent(hashKey)).then(start).catch(function (err) { showGate(err.message); });
  } else {
    start();
  }

  function start() {
    var go = new URLSearchParams(location.search).get('go');
    if (!frameToken) { showGate(); return; }
    gate.hidden = true; home.hidden = false;
    if (go) submit(go, true);
    else $('homeInput').focus();
  }
})();
