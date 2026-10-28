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

  // Keep the JavaScript identity consistent with the browser identity used for
  // upstream requests. A sandboxed iframe otherwise advertises mixed platform
  // values that bot checks and complex app bootstraps commonly reject.
  var ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  function navValue(name, value) {
    try { Object.defineProperty(Navigator.prototype, name, { configurable: true, get: function () { return value; } }); }
    catch (e) { /* ignore */ }
  }
  navValue('userAgent', ua);
  navValue('appVersion', ua);
  navValue('platform', 'Win32');
  navValue('vendor', 'Google Inc.');
  navValue('hardwareConcurrency', 8);
  navValue('deviceMemory', 8);
  navValue('maxTouchPoints', 0);
  navValue('webdriver', false);
  navValue('languages', ['en-US', 'en']);
  navValue('language', 'en-US');
  try {
    Object.defineProperty(Navigator.prototype, 'userAgentData', {
      configurable: true,
      get: function () { return { brands: [{ brand: 'Google Chrome', version: '131' }, { brand: 'Chromium', version: '131' }, { brand: 'Not_A Brand', version: '24' }], mobile: false, platform: 'Windows', getHighEntropyValues: function () { return Promise.resolve({ platform: 'Windows', platformVersion: '15.0.0', architecture: 'x86', model: '', uaFullVersion: '131.0.0.0', fullVersionList: this.brands }); }; }; }
    });
  } catch (e) { /* ignore */ }

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
      // Keep the #fragment outside url= (same as the server) so anchors and <use href="x.svg#id"> work.
      var h = abs.hash;
      abs.hash = '';
      return '/proxy?url=' + enc(abs.href) + '&t=' + TOKEN + h;
    } catch (e) { return s; }
  }

  function proxSrcset(v) {
    // Commas may or may not be followed by a space: "a.png 1x,b.png 2x".
    return String(v).replace(/\s*([^\s,]+(?:,[^\s,]+)*)\s*([^,]*)(,|$)/g, function (m, u, desc, comma) {
      return prox(u) + (desc.trim() ? ' ' + desc.trim() : '') + (comma ? ', ' : '');
    });
  }

  /** url(...) and @import inside CSS text set from script (style.cssText, insertRule, <style> text). */
  function proxCss(css) {
    var s = String(css);
    if (s.indexOf('url(') < 0 && s.indexOf('@import') < 0 && s.indexOf('image-set') < 0) return s;
    return s
      .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, function (m, q, u) { var p = prox(u); return p !== u ? 'url(' + q + p + q + ')' : m; })
      .replace(/@import\s+(['"])(.*?)\1/gi, function (m, q, u) { var p = prox(u); return p !== u ? '@import ' + q + p + q : m; })
      .replace(/((?:-webkit-)?image-set\()([^)]*)\)/gi, function (m, head, inner) {
        return head + inner.replace(/(["'])(?!\/proxy\?url=)(.*?)\1/g, function (mm, q, u) { var p = prox(u); return p !== u ? q + p + q : mm; }) + ')';
      });
  }

  /* ---------------- the sandbox's missing storage ---------------- */

  // The page runs in an opaque origin (sandbox without allow-same-origin), where
  // localStorage, sessionStorage, document.cookie, indexedDB and CacheStorage throw
  // SecurityError. Plenty of scripts touch them at startup and die, taking the whole
  // page with them, so give them in-memory stand-ins that last for this page view.
  function throws(fn) { try { fn(); return false; } catch (e) { return true; } }

  function makeStorage() {
    var data = Object.create(null);
    var methods = {
      getItem: function (k) { k = String(k); return k in data ? data[k] : null; },
      setItem: function (k, v) { data[String(k)] = String(v); },
      removeItem: function (k) { delete data[String(k)]; },
      clear: function () { data = Object.create(null); },
      key: function (i) { var ks = Object.keys(data); return i >= 0 && i < ks.length ? ks[i] : null; },
    };
    return new Proxy(methods, {
      get: function (t, p) {
        if (p === 'length') return Object.keys(data).length;
        if (typeof p === 'symbol') return p === Symbol.toStringTag ? 'Storage' : undefined;
        if (p in data) return data[p];
        return methods[p];
      },
      set: function (t, p, v) { if (typeof p === 'string') data[p] = String(v); return true; },
      deleteProperty: function (t, p) { delete data[p]; return true; },
      has: function (t, p) { return p in data || p in methods; },
      ownKeys: function () { return Object.keys(data); },
      getOwnPropertyDescriptor: function (t, p) {
        return p in data ? { value: data[p], writable: true, enumerable: true, configurable: true } : undefined;
      },
    });
  }

  var opaque = throws(function () { return window.localStorage; }); // true inside the sandbox

  ['localStorage', 'sessionStorage'].forEach(function (name) {
    if (!throws(function () { return window[name]; })) return;
    var store = makeStorage();
    try { Object.defineProperty(window, name, { configurable: true, enumerable: true, get: function () { return store; } }); } catch (e) { /* ignore */ }
  });

  if (throws(function () { return document.cookie; })) {
    var jar = Object.create(null);
    try {
      Object.defineProperty(Document.prototype, 'cookie', {
        configurable: true,
        enumerable: true,
        get: function () { return Object.keys(jar).map(function (k) { return k + '=' + jar[k]; }).join('; '); },
        set: function (line) {
          var parts = String(line).split(';'), kv = parts[0], eq = kv.indexOf('=');
          var name = (eq < 0 ? '' : kv.slice(0, eq)).trim(), val = eq < 0 ? kv.trim() : kv.slice(eq + 1).trim();
          var expired = false;
          for (var i = 1; i < parts.length; i++) {
            var a = parts[i].trim().toLowerCase();
            if (a.indexOf('max-age=') === 0 && parseInt(a.slice(8), 10) <= 0) expired = true;
            if (a.indexOf('expires=') === 0 && Date.parse(a.slice(8)) <= Date.now()) expired = true;
          }
          if (expired) delete jar[name]; else jar[name] = val;
        },
      });
    } catch (e) { /* ignore */ }
  }

  // Better "not supported" (libraries then fall back) than a SecurityError at first use.
  if (opaque) {
    ['indexedDB', 'caches'].forEach(function (name) {
      try { Object.defineProperty(window, name, { configurable: true, value: undefined }); } catch (e) { /* ignore */ }
    });
  }

  /* ---------------- what the page believes its own address is ---------------- */

  // location itself can't be replaced, but these can, and scripts read them for
  // base URLs, same-site checks and feature gating.
  var pageUrl = function () { return current; };
  function defGetter(proto, prop, fn) {
    try { Object.defineProperty(proto, prop, { configurable: true, enumerable: true, get: fn }); } catch (e) { /* ignore */ }
  }
  defGetter(Document.prototype, 'URL', pageUrl);
  defGetter(Document.prototype, 'documentURI', pageUrl);
  defGetter(Node.prototype, 'baseURI', function () { return BASE; });
  defGetter(Document.prototype, 'domain', function () { try { return new URL(current).hostname; } catch (e) { return ''; } });
  defGetter(window, 'origin', function () { try { return new URL(current).origin; } catch (e) { return 'null'; } });

  /* ---------------- dynamic import() ---------------- */

  // The server rewrites every import() in scripts it serves to __PXI(<script's real URL>, spec).
  // Relative names resolve against the script's real address and then go through the proxy;
  // bare names (import maps) and data:/blob: URLs are passed on unchanged.
  // The result must be absolute: inside the sandbox, import() called from a script that
  // came from another origin has no base URL, so "/proxy?url=..." would not resolve.
  function absProx(u) {
    try { return new URL(prox(u), SELF_ORIGIN || location.href).href; } catch (e) { return String(u); }
  }
  window.__PXI = function (base, spec, opts) {
    var s = String(spec);
    if (/^(?:\.{0,2}\/|[a-z][a-z0-9+.-]*:\/\/)/i.test(s)) {
      try { s = absProx(new URL(s, base).href); } catch (e) { /* let import() report it */ }
    }
    return opts === undefined ? import(s) : import(s, opts);
  };

  /* ---------------- web workers ---------------- */

  // A worker script must be same-origin with its page, which an opaque sandbox never is, so
  // the real script is loaded from a tiny blob worker. Classic workers also get fetch() and
  // importScripts() routed through the proxy, since a blob: base can't resolve relative URLs.
  ['Worker', 'SharedWorker'].forEach(function (n) {
    var Native = window[n];
    if (!Native) return;
    var Wrapped = function (url, opts) {
      var u = String(url);
      if (!SKIP.test(u)) {
        var code;
        if (opts && opts.type === 'module') {
          code = 'import ' + JSON.stringify(absProx(u)) + ';';
        } else {
          code = '(function(){var B=' + JSON.stringify(BASE) + ',P=' + JSON.stringify(SELF_ORIGIN) + ',T=' + JSON.stringify(TOKEN) + ';' +
            'function px(u){try{if(String(u).indexOf(P+"/proxy?")===0)return u;return P+"/proxy?url="+encodeURIComponent(new URL(u,B).href)+"&t="+T}catch(e){return u}}' +
            'var is=self.importScripts;self.importScripts=function(){return is.apply(self,[].map.call(arguments,px))};' +
            'var f=self.fetch;self.fetch=function(i,o){return f.call(self,(typeof i==="string"||i instanceof URL)?px(i):i,o)};' +
            'importScripts(' + JSON.stringify(absProx(u)) + ');})();';
        }
        try { u = URL.createObjectURL(new Blob([code], { type: 'text/javascript' })); } catch (e) { /* fall through */ }
      }
      return new Native(u, opts);
    };
    Wrapped.prototype = Native.prototype;
    window[n] = Wrapped;
  });

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
  // The proxy can't carry WebSockets. Instead of throwing (which crashes scripts that never
  // expected "new WebSocket" to fail), behave like a connection that couldn't be made, so
  // the page's own error/reconnect handling runs.
  if (window.WebSocket && window.EventTarget) {
    var WS_STATES = { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 };
    var fireWs = function (ws, type, init) {
      var ev;
      try { ev = type === 'close' ? new CloseEvent('close', init) : new Event(type); } catch (e) { ev = new Event(type); }
      try { ws.dispatchEvent(ev); } catch (e) { /* ignore */ }
      var h = ws['on' + type];
      if (typeof h === 'function') { try { h.call(ws, ev); } catch (e) { /* the page's handler failed, not us */ } }
    };
    var BlockedWebSocket = function (url) {
      var ws = Reflect.construct(EventTarget, [], BlockedWebSocket);
      ws.url = String(url); ws.readyState = 0; ws.bufferedAmount = 0; ws.extensions = ''; ws.protocol = ''; ws.binaryType = 'blob';
      ws.onopen = ws.onerror = ws.onclose = ws.onmessage = null;
      setTimeout(function () {
        ws.readyState = 3;
        fireWs(ws, 'error');
        fireWs(ws, 'close', { code: 1006, reason: '', wasClean: false });
      }, 0);
      return ws;
    };
    BlockedWebSocket.prototype = Object.create(EventTarget.prototype, {
      constructor: { value: BlockedWebSocket, writable: true, configurable: true },
      send: { value: function () { if (this.readyState === 0) throw new DOMException('Still in CONNECTING state.', 'InvalidStateError'); }, writable: true, configurable: true },
      close: { value: function () { this.readyState = 3; }, writable: true, configurable: true },
    });
    Object.keys(WS_STATES).forEach(function (k) {
      BlockedWebSocket[k] = WS_STATES[k];
      Object.defineProperty(BlockedWebSocket.prototype, k, { value: WS_STATES[k] });
    });
    window.WebSocket = BlockedWebSocket;
  } else {
    window.WebSocket = function () { throw new DOMException('WebSockets are disabled', 'SecurityError'); };
  }
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
  try {
    if (navigator.serviceWorker) Object.defineProperty(navigator, 'serviceWorker', { value: undefined });
  } catch (e) { /* service workers are unavailable in the opaque sandbox */ }

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
    href: /^(a|area|link|image|use)$/,
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
    else if (n === 'xlink:href' && (tag === 'image' || tag === 'use')) value = prox(value);
    else if (n === 'srcset' && (tag === 'img' || tag === 'source')) value = proxSrcset(value);
    else if (n === 'style') value = proxCss(value);
    return nativeSetAttribute.call(this, name, value);
  };

  // new Audio('song.mp3') sets src internally, without going through the setter patched above.
  if (window.Audio) {
    var NativeAudio = window.Audio;
    var ProxiedAudio = function (src) {
      var a = new NativeAudio();
      if (src !== undefined) a.src = src;
      return a;
    };
    ProxiedAudio.prototype = NativeAudio.prototype;
    window.Audio = ProxiedAudio;
  }

  // Backgrounds, cursors, masks and the like set from script: el.style.backgroundImage = 'url(/a.png)'.
  var CSS_PROPS = ['background', 'backgroundImage', 'border', 'borderImage', 'borderImageSource', 'content', 'cursor',
    'filter', 'listStyle', 'listStyleImage', 'mask', 'maskImage', 'webkitMaskImage', 'webkitMaskBoxImage', 'shapeOutside', 'src'];
  [window.CSSStyleDeclaration, window.CSSStyleProperties].forEach(function (C) {
    if (!C) return;
    CSS_PROPS.forEach(function (p) {
      patchProp(C.prototype, p, proxCss);
      patchProp(C.prototype, p.replace(/[A-Z]/g, function (c) { return '-' + c.toLowerCase(); }), proxCss);
    });
    patchProp(C.prototype, 'cssText', proxCss);
    var nativeSetProperty = C.prototype.setProperty;
    if (nativeSetProperty && !has.call(C.prototype, '__proxPatched')) {
      Object.defineProperty(C.prototype, '__proxPatched', { value: true });
      C.prototype.setProperty = function (name, value, priority) {
        return nativeSetProperty.call(this, name, typeof value === 'string' ? proxCss(value) : value, priority);
      };
    }
  });
  if (window.CSSStyleSheet) {
    var sheetProto = CSSStyleSheet.prototype;
    ['insertRule', 'replace', 'replaceSync'].forEach(function (m) {
      var native = sheetProto[m];
      if (!native) return;
      sheetProto[m] = function (css) {
        var args = Array.prototype.slice.call(arguments);
        args[0] = proxCss(css);
        return native.apply(this, args);
      };
    });
  }

  // document.write('<script src="/x.js">') is plain text, so rewrite its URL attributes before it is parsed.
  function proxHtml(s) {
    return String(s).replace(/(\b(?:src|href|poster|data)\s*=\s*)(["'])([^"']*)\2/gi, function (m, a, q, u) { return a + q + prox(u) + q; });
  }
  ['write', 'writeln'].forEach(function (m) {
    var native = Document.prototype[m];
    if (!native) return;
    Document.prototype[m] = function () {
      var args = Array.prototype.map.call(arguments, function (x) { return typeof x === 'string' ? proxHtml(x) : x; });
      return native.apply(this, args);
    };
  });

  /** Rewrites the URL attributes of one element, if they aren't already ours. */
  function fixAttrs(el) {
    var tag = el.localName, n, v, p;
    for (n in ATTRS) {
      if (!has.call(ATTRS, n) || !ATTRS[n].test(tag) || !el.hasAttribute(n)) continue;
      v = el.getAttribute(n); p = prox(v);
      if (p !== v) nativeSetAttribute.call(el, n, p);
    }
    if ((tag === 'image' || tag === 'use') && el.hasAttribute('xlink:href')) {
      v = el.getAttribute('xlink:href'); p = prox(v);
      if (p !== v) nativeSetAttribute.call(el, 'xlink:href', p);
    }
    if ((tag === 'img' || tag === 'source') && el.hasAttribute('srcset')) {
      v = el.getAttribute('srcset'); p = proxSrcset(v);
      if (p !== v) nativeSetAttribute.call(el, 'srcset', p);
    }
    if (el.hasAttribute('style')) {
      v = el.getAttribute('style'); p = proxCss(v);
      if (p !== v) nativeSetAttribute.call(el, 'style', p);
    }
  }

  /** <style> elements filled in by script (textContent = '...', innerHTML) never saw the server's CSS rewriter. */
  function fixStyleEl(el) {
    var v = el.textContent, p = proxCss(v);
    if (p !== v) el.textContent = p; // second pass changes nothing, so this settles
  }

  // Content added with innerHTML / insertAdjacentHTML never passed through the server's rewriter.
  var SELECTOR = 'a[href],area[href],link[href],script[src],img[src],img[srcset],source[src],source[srcset],' +
    'video[src],video[poster],audio[src],track[src],iframe[src],frame[src],embed[src],object[data],input[src],image[href],use[href],use[*|href],[style]';
  if (window.MutationObserver) {
    new MutationObserver(function (records) {
      for (var i = 0; i < records.length; i++) {
        var added = records[i].addedNodes;
        for (var j = 0; j < added.length; j++) {
          var node = added[j];
          if (node.nodeType === 3) { // text put into an existing <style>
            if (node.parentNode && node.parentNode.localName === 'style') fixStyleEl(node.parentNode);
            continue;
          }
          if (node.nodeType !== 1) continue;
          fixAttrs(node);
          if (node.localName === 'style') fixStyleEl(node);
          if (node.querySelectorAll) {
            var found = node.querySelectorAll(SELECTOR);
            for (var k = 0; k < found.length; k++) fixAttrs(found[k]);
            var styles = node.querySelectorAll('style');
            for (var s = 0; s < styles.length; s++) fixStyleEl(styles[s]);
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
