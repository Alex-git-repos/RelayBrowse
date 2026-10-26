(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var home = $('home'), locked = $('locked'), shell = $('shell'), view = $('view'), addr = $('addr');
  var hint = $('hint'), progress = $('progress'), recentBox = $('recent');
  var backBtn = $('backBtn'), fwdBtn = $('fwdBtn');
  var STORE_KEY = 'relay-recent';
  var TOKEN_KEY = 'app.t';                 // written by the sign-in page
  var LEGACY_TOKEN_KEY = 'relay-frame-token';
  var API = String(window.APP_API || window.RELAY_BACKEND || '').replace(/\/+$/, '');

  function loadToken() {
    try {
      var t = localStorage.getItem(TOKEN_KEY);
      if (!t) { // one-time migration from the old key name
        t = localStorage.getItem(LEGACY_TOKEN_KEY);
        if (t) { localStorage.setItem(TOKEN_KEY, t); localStorage.removeItem(LEGACY_TOKEN_KEY); }
      }
      return t || '';
    } catch (e) { return ''; }
  }
  function saveToken(t) { try { if (t) localStorage.setItem(TOKEN_KEY, t); else localStorage.removeItem(TOKEN_KEY); } catch (e) {} }
  var frameToken = loadToken();

  /* The page is no longer in an iframe. The backend sends an HTML fragment (scripts, handlers and
     frames already removed) and htmx's requests bring it here; it is shown in a shadow root so the
     site's CSS can't touch this interface and ours can't touch the site. */
  var htmx = window.htmx;
  htmx.config.selfRequestsOnly = false;  // the backend is usually on another origin (see validateUrl below)
  htmx.config.allowScriptTags = false;   // never run scripts that arrive in a response
  htmx.config.allowEval = false;         // hx-on:* and friends can't execute code
  htmx.config.historyEnabled = false;    // we keep our own history
  htmx.config.ignoreTitle = true;        // the title comes with the HX-Trigger header instead
  var apiOrigin = '';
  try { apiOrigin = new URL(API || '/', location.href).origin; } catch (e) { /* stays empty */ }

  var shadow = view.attachShadow({ mode: 'open' });
  shadow.innerHTML = '<style>:host{all:initial;display:block;flex:1;min-height:0;overflow:auto;background:#fff;color:#000;color-scheme:light;font:16px/normal serif}' +
    '.pv-doc{display:block;min-height:100%;box-sizing:border-box}img,video{max-width:100%}</style><div id="pv"></div>';
  var pv = shadow.getElementById('pv');
  view.setAttribute('hx-sync', 'this:replace'); // a new page request cancels the one still loading

  function isProxyRequest(e) {
    var d = e.detail || {}, p = (d.pathInfo && d.pathInfo.requestPath) || (d.requestConfig && d.requestConfig.path) || '';
    try { var u = new URL(p, location.href); return u.origin === apiOrigin && u.pathname === '/proxy'; } catch (err) { return false; }
  }
  function clearView() { htmx.trigger(view, 'htmx:abort'); pv.innerHTML = ''; }
  function showMessage(title, text) {
    pv.innerHTML = '';
    var box = document.createElement('div'), h = document.createElement('h1'), p = document.createElement('p');
    box.className = 'pv-doc'; box.style.cssText = 'padding:48px 24px;font:17px/1.6 system-ui,sans-serif;max-width:460px;margin:0 auto';
    h.style.cssText = 'font-size:1.6rem;margin:0 0 10px'; h.textContent = title;
    p.style.cssText = 'margin:0;color:#5a6579'; p.textContent = text;
    box.appendChild(h); box.appendChild(p); pv.appendChild(box);
  }

  // Not signed in: send the visitor to the sign-in page (APP_GATE in config.js). The "not available"
  // page stays visible only as a fallback if the redirect can't happen. An optional ?go= is carried
  // along so the sign-in page can return to it afterwards.
  function toGate() {
    home.hidden = true; shell.hidden = true; locked.hidden = false;
    clearView();
    var gate = String(window.APP_GATE || '');
    if (!/^[\w-][\w\-.]*\/index\.html$/.test(gate)) return; // <sibling folder>/index.html only
    var go = new URLSearchParams(location.search).get('go');
    location.replace(gate + (go ? '?go=' + encodeURIComponent(go) : ''));
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

  /* Our own history. The page sits in a sandboxed frame that shares session history with
     this one, so calling history.back() inside it could navigate away from the app. */
  var stack = [], idx = -1, replaceNext = false;

  function updateNav() {
    backBtn.disabled = idx <= 0;
    fwdBtn.disabled = idx >= stack.length - 1;
  }

  function open(url, fromStack) {
    locked.hidden = true; home.hidden = true; shell.hidden = false;
    addr.value = url;
    setLoading(true);
    if (!fromStack) { stack = stack.slice(0, idx + 1); stack.push(url); idx = stack.length - 1; }
    replaceNext = true; // the first report after a load may be the post-redirect address
    htmx.ajax('GET', API + '/proxy', { source: view, target: view, swap: 'none', values: { url: url, t: frameToken, __pf: '1' } });
    remember(url);
    updateNav();
  }

  function submit(raw, fromHome) {
    if (!frameToken) { toGate(); return; }
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
    clearView();
    addr.value = '';
    stack = []; idx = -1; updateNav();
    document.title = 'Relay Browse';
    renderRecent();
    $('homeInput').focus();
  }

  $('goForm').addEventListener('submit', function (e) { e.preventDefault(); submit($('homeInput').value, true); });
  $('addrForm').addEventListener('submit', function (e) { e.preventDefault(); submit(addr.value, false); });
  $('forgetBtn').addEventListener('click', function () { frameToken = ''; saveToken(''); toGate(); });
  $('homeBtn').addEventListener('click', goHome);
  backBtn.addEventListener('click', function () { if (idx > 0) { idx--; open(stack[idx], true); } });
  fwdBtn.addEventListener('click', function () { if (idx < stack.length - 1) { idx++; open(stack[idx], true); } });
  $('reloadBtn').addEventListener('click', function () { if (idx >= 0) open(stack[idx], true); });
  document.querySelectorAll('[data-go]').forEach(function (b) {
    b.addEventListener('click', function () { open(b.getAttribute('data-go')); });
  });

  // htmx may only talk to our own backend, whatever a page tries.
  document.addEventListener('htmx:validateUrl', function (e) {
    var u = e.detail && e.detail.url;
    if (!u || u.origin !== apiOrigin) e.preventDefault();
  });

  // The response is rendered here, not swapped in by htmx, so it can go into the shadow root.
  document.addEventListener('htmx:beforeSwap', function (e) {
    if (!isProxyRequest(e)) return;
    var d = e.detail;
    d.shouldSwap = false; d.isError = false; // error pages from the backend are fragments too
    pv.innerHTML = d.serverResponse;         // inserted as markup only: scripts and handlers were removed server-side and CSP forbids them anyway
    htmx.process(pv);                        // wires up the links and forms the backend rewrote
    view.scrollTop = 0;
    setLoading(false);
  });
  document.addEventListener('htmx:beforeRequest', function (e) { if (isProxyRequest(e)) setLoading(true); });
  document.addEventListener('htmx:afterRequest', function (e) { if (isProxyRequest(e)) setLoading(false); });
  ['htmx:sendError', 'htmx:timeout'].forEach(function (name) {
    document.addEventListener(name, function (e) {
      if (isProxyRequest(e)) showMessage('Couldn’t reach the server', 'It may be starting up. Try again in a moment.');
    });
  });

  // In-page #links: the browser would change this page's address instead of scrolling the shadow content.
  shadow.addEventListener('click', function (e) {
    var a = e.target && e.target.closest && e.target.closest('a[href^="#"]');
    if (!a) return;
    e.preventDefault();
    var id = a.getAttribute('href').slice(1);
    try { id = decodeURIComponent(id); } catch (err) { /* keep as is */ }
    var t = id ? pv.querySelector('[id="' + CSS.escape(id) + '"], a[name="' + CSS.escape(id) + '"]') : null;
    if (t) t.scrollIntoView(); else if (!id) view.scrollTop = 0;
  });

  // The backend reports the real address and title of each page it sends (HX-Trigger header).
  document.addEventListener('proxy-nav', function (e) {
    var d = e.detail;
    if (!d || typeof d.url !== 'string' || !/^https?:\/\//i.test(d.url)) return;
    var url = d.url;
    if (idx < 0) { stack = [url]; idx = 0; }
    else if (url !== stack[idx]) {
      if (replaceNext) stack[idx] = url; // redirected
      else { stack = stack.slice(0, idx + 1); stack.push(url); idx = stack.length - 1; } // followed a link
    }
    replaceNext = false;
    if (document.activeElement !== addr) addr.value = url; // don't clobber what's being typed
    var title = typeof d.title === 'string' && d.title ? d.title.slice(0, 120) : label(url);
    document.title = title + ' – Relay Browse';
    updateNav();
  });

  renderRecent();
  updateNav();

  // Old-style links put the key in the address bar of this page. Never leave it there.
  if (/[#&]key=/.test(location.hash)) history.replaceState(null, '', location.pathname + location.search);

  if (!frameToken) {
    toGate();
  } else {
    locked.hidden = true; home.hidden = false;
    var go = new URLSearchParams(location.search).get('go');
    if (go) submit(go, true); else $('homeInput').focus();
    // Check the saved sign-in in the background. A network error (the server may be waking
    // up) is not treated as signed out; only an explicit "no" is.
    fetch(API + '/api/session?t=' + encodeURIComponent(frameToken), { referrerPolicy: 'no-referrer' })
      .then(function (r) { if (r.status === 401) { frameToken = ''; saveToken(''); toGate(); } })
      .catch(function () { /* offline or waking up */ });
  }
})();
