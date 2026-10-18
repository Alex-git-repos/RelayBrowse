(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var home = $('home'), shell = $('shell'), view = $('view'), addr = $('addr');
  var hint = $('hint'), progress = $('progress'), recentBox = $('recent');
  var STORE_KEY = 'relay-recent';

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
    view.src = '/proxy?url=' + encodeURIComponent(url);
    remember(url);
  }

  function submit(raw, fromHome) {
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
  $('homeBtn').addEventListener('click', goHome);
  $('backBtn').addEventListener('click', function () { try { view.contentWindow.history.back(); } catch (e) {} });
  $('fwdBtn').addEventListener('click', function () { try { view.contentWindow.history.forward(); } catch (e) {} });
  $('reloadBtn').addEventListener('click', function () { setLoading(true); try { view.contentWindow.location.reload(); } catch (e) {} });
  document.querySelectorAll('[data-go]').forEach(function (b) {
    b.addEventListener('click', function () { open(b.getAttribute('data-go')); });
  });

  view.addEventListener('load', function () { setLoading(false); });

  // The injected script reports the real address of the page being shown.
  window.addEventListener('message', function (e) {
    if (e.origin !== location.origin || e.source !== view.contentWindow) return;
    var d = e.data;
    if (!d || d.type !== 'proxy-nav' || typeof d.url !== 'string' || !/^https?:\/\//i.test(d.url)) return;
    addr.value = d.url;
    document.title = (d.title || label(d.url)) + ' \u2013 Relay Browse';
  });

  renderRecent();
  var start = new URLSearchParams(location.search).get('go');
  if (start) submit(start, true);
  else $('homeInput').focus();
})();
