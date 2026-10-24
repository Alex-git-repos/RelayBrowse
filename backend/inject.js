/*
 * Injected at the top of every proxied HTML page.
 *
 * Pages build URLs in JavaScript (fetch, XHR, dynamic <script> tags, history,
 * links added with innerHTML), and the server can't see those, so they are
 * rerouted here. Anything this file cannot reach is still contained by the
 * sandbox and Content-Security-Policy the server sends with every page.
 *
 * Known limit: assigning to location (location.href = ..., location.assign())
 * cannot be intercepted by any script, because the Location object is
 * unforgeable. The server rewrites every link and redirect it can see, but a
 * page that navigates itself that way leaves the proxy.
 */
(function () {
  'use strict';
  var BASE = window.__PROXY_BASE__;                  // base for resolving relative URLs (honours <base href>)
  if (!BASE || window.__PROXY_PATCHED__) return;
  window.__PROXY_PATCHED__ = true;
  var TOKEN = window.__PROXY_TOKEN__ || '';
  var PARENT = window.__PROXY_PARENT__ || '*';       // origin of the shell that frames us
  var PAGE = window.__PROXY_URL__ || BASE;           // real address of this page

  var SELF_ORIGIN = '';
  try { SELF_ORIGIN = new URL(location.href).origin; } catch (e) { /* ignore */ }

  var SKIP = /^\s*(#|javascript:|data:|blob:|mailto:|tel:|about:)/i;
  var OURS = /^\/proxy\?(?:url|__pa|__pt)=/;          // already points through the proxy

  function enc(s) {
    return encodeURIComponent(s).replace(/[!'()*]/g, function (c) {
      return '%' + c.charCodeAt(0).toString(16).toUpperCase();
    });
  }

  /** Turns any URL a page uses into one that goes through the proxy. Safe to apply twice. */
  function prox(u) {
    if (u == null) return u;
    var s = String(u);
    if (SKIP.test(s) || OURS.test(s)) return s;
    try {
      var abs = new URL(s, BASE);
      if (abs.origin === SELF_ORIGIN) {
        // Already ours (read back from el.src and set again): don't wrap it a second time.
        if (abs.pathname === '/proxy') return abs.pathname + abs.search;
        // Built from location.origin (which is the proxy's): re-point it at the real site.
        abs = new URL(abs.pathname + abs.search + abs.hash, BASE);
      }
      return '/proxy?url=' + enc(abs.href) + '&t=' + TOKEN;
    } catch (e) { return s; }
  }

  function proxSrcset(v) {
    return String(v).split(/,\s+/).map(function (part) {
      var p = part.trim().split(/\s+/);
      if (p[0]) p[0] = prox(p[0]);
      return p.join(' ');
    }).join(', ');
  }

  /* ---------------- network ---------------- */

  var nativeFetch = window.fetch;
  if (nativeFetch) {
    window.fetch = function (input, init) {
      try {
        if (typeof Request !== 'undefined' && input instanceof Request) {
          var ru = new URL(input.url);
          if (!(ru.origin === SELF_ORIGIN && ru.pathname === '/proxy')) input = new Request(prox(input.url), input);
        } else if (input != null) {
          input = prox(input);
        }
      } catch (e) { /* use the original */ }
      return nativeFetch.call(this, input, init);
    };
  }

  var nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var args = Array.prototype.slice.call(arguments);
    args[1] = prox(url);
    return nativeOpen.apply(this, args);
  };

  // Popups would escape the sandbox, so "open" navigates this frame instead.
  window.open = function (url) {
    if (url) { try { location.assign(prox(url)); } catch (e) { /* ignore */ } }
    return null;
  };

  // Close side channels that bypass the proxy.
  ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport'].forEach(function (n) {
    try { Object.defineProperty(window, n, { value: undefined, configurable: false, writable: false }); } catch (e) { /* ignore */ }
  });
  window.WebSocket = function () { throw new DOMException('WebSockets are disabled', 'SecurityError'); };
  if (window.EventSource) {
    var NativeES = window.EventSource;
    var ProxiedES = function (u, o) { return new NativeES(prox(u), o); };
    ProxiedES.prototype = NativeES.prototype; // keep instanceof and the constants working
    ['CONNECTING', 'OPEN', 'CLOSED'].forEach(function (k) { ProxiedES[k] = NativeES[k]; });
    window.EventSource = ProxiedES;
  }
  if (navigator.sendBeacon) {
    var nativeBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function (u, d) { return nativeBeacon.call(navigator, prox(u), d); };
  }
  if (navigator.serviceWorker) { try { Object.defineProperty(navigator, 'serviceWorker', { value: undefined }); } catch (e) { /* ignore */ } }

  /* ---------------- address bar reporting + history ---------------- */

  var current = PAGE;

  function report() {
    try { window.parent.postMessage({ type: 'proxy-nav', url: current, title: document.title }, PARENT); } catch (e) { /* not framed */ }
  }

  function realFromLocation() {
    try { return new URL(location.href).searchParams.get('url'); } catch (e) { return null; }
  }

  // pushState/replaceState take the page's real URL; the browser is given the proxied one.
  ['pushState', 'replaceState'].forEach(function (name) {
    var native = history[name];
    history[name] = function (state, title, url) {
      var abs = null;
      if (url != null && url !== '') { try { abs = new URL(String(url), current).href; } catch (e) { /* bad URL: let the browser complain */ } }
      var result = native.call(history, state, title, abs ? prox(abs) : url);
      if (abs) { current = abs; report(); }
      return result;
    };
  });
  window.addEventListener('popstate', function () {
    var u = realFromLocation();
    if (u) { current = u; report(); }
  });

  if (window.parent !== window) {
    document.addEventListener('DOMContentLoaded', function () {
      report();
      var t = document.querySelector('title'); // keep the shell's title current for single-page apps
      if (t && window.MutationObserver) new MutationObserver(report).observe(t, { childList: true, characterData: true, subtree: true });
    });
    window.addEventListener('load', report);
  }

  // Reload requests from the shell. (Back/forward are handled by the shell itself:
  // history.back() in a frame can walk the whole browser's history, not just this page's.)
  window.addEventListener('message', function (e) {
    if (e.source !== window.parent || !e.data || e.data.type !== 'proxy-cmd') return;
    if (PARENT !== '*' && e.origin !== PARENT) return;
    if (e.data.cmd === 'reload') location.reload();
  });

  /* ---------------- elements created or changed by scripts ---------------- */

  // Which attributes carry URLs, and on which elements. Anything else (a custom
  // element's own "src", a data-* style attribute) is left alone.
  var ATTRS = {
    src: /^(script|img|iframe|frame|embed|source|track|video|audio|input)$/,
    href: /^(a|area|link|image)$/,
    poster: /^video$/,
    data: /^object$/,
  };
  var has = Object.prototype.hasOwnProperty;

  function patchProp(proto, prop, fn) {
    if (!proto) return;
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      configurable: true,
      enumerable: d.enumerable,
      get: d.get,
      set: function (v) { d.set.call(this, fn(v)); },
    });
  }
  [
    ['HTMLScriptElement', 'src'], ['HTMLImageElement', 'src'], ['HTMLIFrameElement', 'src'],
    ['HTMLSourceElement', 'src'], ['HTMLMediaElement', 'src'], ['HTMLTrackElement', 'src'],
    ['HTMLEmbedElement', 'src'], ['HTMLInputElement', 'src'], ['HTMLLinkElement', 'href'],
    ['HTMLAnchorElement', 'href'], ['HTMLAreaElement', 'href'], ['HTMLVideoElement', 'poster'],
    ['HTMLObjectElement', 'data'],
  ].forEach(function (p) { patchProp(window[p[0]] && window[p[0]].prototype, p[1], prox); });
  patchProp(window.HTMLImageElement && HTMLImageElement.prototype, 'srcset', proxSrcset);
  patchProp(window.HTMLSourceElement && HTMLSourceElement.prototype, 'srcset', proxSrcset);

  var nativeSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    var n = String(name).toLowerCase(), tag = this.localName;
    if (has.call(ATTRS, n) && ATTRS[n].test(tag)) value = prox(value);
    else if (n === 'xlink:href' && tag === 'image') value = prox(value);
    else if (n === 'srcset' && (tag === 'img' || tag === 'source')) value = proxSrcset(value);
    return nativeSetAttribute.call(this, name, value);
  };

  /** Rewrites the URL attributes of one element, if they aren't already ours. */
  function fixAttrs(el) {
    var tag = el.localName, n, v, p;
    for (n in ATTRS) {
      if (!has.call(ATTRS, n) || !ATTRS[n].test(tag) || !el.hasAttribute(n)) continue;
      v = el.getAttribute(n); p = prox(v);
      if (p !== v) nativeSetAttribute.call(el, n, p);
    }
    if (tag === 'image' && el.hasAttribute('xlink:href')) {
      v = el.getAttribute('xlink:href'); p = prox(v);
      if (p !== v) nativeSetAttribute.call(el, 'xlink:href', p);
    }
    if ((tag === 'img' || tag === 'source') && el.hasAttribute('srcset')) {
      v = el.getAttribute('srcset'); p = proxSrcset(v);
      if (p !== v) nativeSetAttribute.call(el, 'srcset', p);
    }
  }

  // Content added with innerHTML / insertAdjacentHTML never passed through the server's rewriter.
  var SELECTOR = 'a[href],area[href],link[href],script[src],img[src],img[srcset],source[src],source[srcset],' +
    'video[src],video[poster],audio[src],track[src],iframe[src],frame[src],embed[src],object[data],input[src],image[href]';
  if (window.MutationObserver) {
    new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (node.nodeType !== 1) continue;
          fixAttrs(node);
          if (node.querySelectorAll) {
            var found = node.querySelectorAll(SELECTOR);
            for (var k = 0; k < found.length; k++) fixAttrs(found[k]);
          }
        }
      }
    }).observe(document, { childList: true, subtree: true });
  }

  /* ---------------- clicks and form submits (the last line of defence) ---------------- */

  function findAnchor(e) {
    var path = e.composedPath ? e.composedPath() : [];
    for (var i = 0; i < path.length; i++) {
      var el = path[i];
      if (el && el.localName && (el.localName === 'a' || el.localName === 'area') && el.hasAttribute && el.hasAttribute('href')) return el;
    }
    return e.target && e.target.closest ? e.target.closest('a[href],area[href]') : null;
  }

  // Runs before the browser follows a link, so links the server never saw still stay inside.
  document.addEventListener('click', function (e) {
    var a = findAnchor(e);
    if (!a) return;
    var raw = a.getAttribute('href'), p = prox(raw);
    if (p !== raw) nativeSetAttribute.call(a, 'href', p);
    var t = a.getAttribute('target');
    if (t && t !== '_self') nativeSetAttribute.call(a, 'target', '_self');
  }, true);

  function addHidden(form, name, value) {
    var input = document.createElement('input');
    input.type = 'hidden'; input.name = name; input.value = value;
    form.appendChild(input);
  }

  /** Points a form the server never saw (built or changed by a script) through the proxy. */
  function fixForm(f) {
    var action = f.getAttribute('action') || '';
    if (/^\/proxy(\?|$)/.test(action) || /^\s*javascript:/i.test(action)) return; // ours already, or script-handled
    var abs;
    try { abs = new URL(SKIP.test(action) ? '' : action, BASE).href; } catch (e) { return; }
    if ((f.getAttribute('method') || 'get').toLowerCase() === 'post') {
      nativeSetAttribute.call(f, 'action', prox(abs));
    } else {
      // A GET form replaces the action's query string with its fields, so the real
      // target and the token travel as fields and the server puts the address back together.
      nativeSetAttribute.call(f, 'action', '/proxy');
      addHidden(f, '__pt', TOKEN);
      addHidden(f, '__pa', abs);
    }
    var t = f.getAttribute('target');
    if (t && t !== '_self') nativeSetAttribute.call(f, 'target', '_self');
  }

  document.addEventListener('submit', function (e) {
    if (e.target && e.target.localName === 'form') { try { fixForm(e.target); } catch (err) { /* ignore */ } }
  }, true);

  // form.submit() doesn't fire a submit event, so cover it directly.
  if (window.HTMLFormElement) {
    var nativeSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function () {
      try { fixForm(this); } catch (err) { /* ignore */ }
      return nativeSubmit.apply(this, arguments);
    };
  }
})();
