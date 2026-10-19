/*
 * Injected at the top of every proxied HTML page.
 * Pages build URLs in JavaScript (fetch, XHR, dynamic <script> tags, history),
 * and the server can't see those, so we reroute them here.
 */
(function () {
  'use strict';
  var BASE = window.__PROXY_BASE__;
  if (!BASE) return;
  var TOKEN = window.__PROXY_TOKEN__ || '';

  var SKIP = /^\s*(#|javascript:|data:|blob:|mailto:|tel:|about:)/i;

  function enc(s) {
    return encodeURIComponent(s).replace(/[!'()*]/g, function (c) {
      return '%' + c.charCodeAt(0).toString(16).toUpperCase();
    });
  }

  function prox(u) {
    if (u == null) return u;
    var s = String(u);
    if (SKIP.test(s) || s.indexOf('/proxy?') === 0) return s;
    try { return '/proxy?url=' + enc(new URL(s, BASE).href) + '&t=' + TOKEN; } catch (e) { return s; }
  }

  // fetch
  var nativeFetch = window.fetch;
  if (nativeFetch) {
    window.fetch = function (input, init) {
      if (typeof input === 'string' || input instanceof URL) {
        input = prox(input);
      } else if (input && typeof Request !== 'undefined' && input instanceof Request) {
        var u = new URL(input.url);
        if (u.origin === new URL(document.baseURI).origin && u.pathname !== '/proxy') input = new Request(prox(u.pathname + u.search), input);
      }
      return nativeFetch.call(this, input, init);
    };
  }

  // XMLHttpRequest
  var nativeOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    var args = Array.prototype.slice.call(arguments);
    args[1] = prox(url);
    return nativeOpen.apply(this, args);
  };

  // window.open
  // Popups would escape the sandbox, so "open" navigates this frame instead.
  window.open = function (url) {
    if (url) { try { location.assign(prox(url)); } catch (e) {} }
    return null;
  };

  // Close side channels that bypass the proxy.
  ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel', 'WebTransport'].forEach(function (n) {
    try { Object.defineProperty(window, n, { value: undefined, configurable: false, writable: false }); } catch (e) {}
  });
  window.WebSocket = function () { throw new DOMException('WebSockets are disabled', 'SecurityError'); };
  if (window.EventSource) {
    var NativeES = window.EventSource;
    window.EventSource = function (u, o) { return new NativeES(prox(u), o); };
  }
  if (navigator.sendBeacon) {
    var nativeBeacon = navigator.sendBeacon;
    navigator.sendBeacon = function (u, d) { return nativeBeacon.call(navigator, prox(u), d); };
  }
  if (navigator.serviceWorker) { try { Object.defineProperty(navigator, 'serviceWorker', { value: undefined }); } catch (e) {} }

  // history: keep the real URL out of the address bar of our own origin
  ['pushState', 'replaceState'].forEach(function (name) {
    var native = history[name];
    history[name] = function (state, title, url) {
      return native.call(history, state, title, url == null ? url : prox(url));
    };
  });

  // Elements created or changed by scripts
  function patchProp(proto, prop) {
    if (!proto) return;
    var d = Object.getOwnPropertyDescriptor(proto, prop);
    if (!d || !d.set) return;
    Object.defineProperty(proto, prop, {
      configurable: true,
      enumerable: d.enumerable,
      get: d.get,
      set: function (v) { d.set.call(this, prox(v)); },
    });
  }
  patchProp(window.HTMLScriptElement && HTMLScriptElement.prototype, 'src');
  patchProp(window.HTMLImageElement && HTMLImageElement.prototype, 'src');
  patchProp(window.HTMLIFrameElement && HTMLIFrameElement.prototype, 'src');
  patchProp(window.HTMLSourceElement && HTMLSourceElement.prototype, 'src');
  patchProp(window.HTMLMediaElement && HTMLMediaElement.prototype, 'src');
  patchProp(window.HTMLLinkElement && HTMLLinkElement.prototype, 'href');
  patchProp(window.HTMLAnchorElement && HTMLAnchorElement.prototype, 'href');

  var URL_ATTR = { src: 1, href: 1, action: 1, poster: 1, data: 1 };
  var nativeSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name, value) {
    if (URL_ATTR[String(name).toLowerCase()] && this.tagName !== 'BASE') value = prox(value);
    return nativeSetAttribute.call(this, name, value);
  };

  // Tell the shell which real URL is showing, so its address bar stays accurate.
  function report() {
    try {
      window.parent.postMessage({ type: 'proxy-nav', url: BASE, title: document.title }, '*'); // our frame has origin "null"
    } catch (e) { /* not framed */ }
  }
  if (window.parent !== window) {
    window.addEventListener('load', report);
    document.addEventListener('DOMContentLoaded', report);
  }

  // Back / forward / reload requests from the shell.
  window.addEventListener('message', function (e) {
    if (e.source !== window.parent || !e.data || e.data.type !== 'proxy-cmd') return;
    if (e.data.cmd === 'back') history.back();
    else if (e.data.cmd === 'forward') history.forward();
    else if (e.data.cmd === 'reload') location.reload();
  });
})();
