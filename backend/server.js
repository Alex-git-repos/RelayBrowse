'use strict';

/**
 * Pear Proxy: backend (API only, no UI).
 *
 *   POST /api/auth         { token } -> { frameToken }   (exchange the access key)
 *   GET  /proxy?url=&t=    fetch a page and rewrite it so links, images,
 *                          styles, scripts and forms keep going through us
 *   POST /proxy?url=&t=    forwards form posts
 *   GET  /inject.js        client-side patch loaded into every proxied page
 *   GET  /api/session?t=   200 if the saved frame token is still valid, else 401
 *   GET  /health           liveness check
 *
 * The frontend lives on a different origin, so there are no cookies: it
 * trades the access key for a frame token and puts that token on /proxy URLs.
 *
 * Environment variables:
 *   AUTH_TOKEN       REQUIRED in production: the secret access key
 *   FRONTEND_ORIGIN  origin of the frontend, e.g. https://relaybrowse.example.com
 *                    (used for CORS and frame-ancestors; "*" if unset)
 *   PORT             port to listen on                     (default 3000)
 *   HOST             interface to bind                     (default 0.0.0.0)
 *   RATE_LIMIT       max requests per IP per minute        (default 600)
 *   TRUST_PROXY      "1" to read client IP from X-Forwarded-For (set on Render)
 *   ALLOW_PRIVATE    "1" to allow private/loopback targets (testing only!)
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const dns = require('node:dns');
const net = require('node:net');
const crypto = require('node:crypto');
const { Readable, Transform, pipeline } = require('node:stream');
const { fetch, Agent } = require('undici');
const cheerio = require('cheerio');

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const GENERATED_TOKEN = !process.env.AUTH_TOKEN;
// No hard-coded fallback secret: without AUTH_TOKEN a random one is used for this run.
const AUTH_TOKEN = process.env.AUTH_TOKEN || crypto.randomBytes(32).toString('hex');
const FRONTEND_ORIGIN = (process.env.FRONTEND_ORIGIN || '').replace(/\/+$/, '');
const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 600;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';

const MAX_RESPONSE_BYTES = 25 * 1024 * 1024; // cap on any upstream response
const MAX_REWRITE_BYTES = 16 * 1024 * 1024; // cap on HTML/CSS/JS we rewrite in memory
const MAX_REQUEST_BODY = 1 * 1024 * 1024; // cap on form posts
const UPSTREAM_TIMEOUT_MS = Number(process.env.UPSTREAM_TIMEOUT_MS) || 25_000;
const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);

/* ------------------------------------------------------------------ */
/* SSRF protection: never let the proxy reach internal networks        */
/* ------------------------------------------------------------------ */

const V4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4],
];
const blocked = new net.BlockList();
for (const [addr, prefix] of V4_BLOCKED) {
  blocked.addSubnet(addr, prefix, 'ipv4');
  // The same private ranges can hide inside IPv6 transition addresses (NAT64
  // 64:ff9b::/96 and 6to4 2002::/16). Block only those that wrap a private
  // IPv4 address, so public sites on IPv6-only networks keep working.
  const o = addr.split('.').map(Number);
  const hi = ((o[0] << 8) | o[1]).toString(16);
  const lo = ((o[2] << 8) | o[3]).toString(16);
  blocked.addSubnet(`64:ff9b::${hi}:${lo}`, 96 + prefix, 'ipv6');
  blocked.addSubnet(`2002:${hi}:${lo}::`, 16 + prefix, 'ipv6');
}
// ::/96 covers "::", "::1" and the old IPv4-compatible form; the rest are
// unique-local, link-local, site-local, multicast, discard, Teredo and docs ranges.
[['::', 96], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8], ['100::', 64], ['2001::', 32], ['2001:db8::', 32]]
  .forEach(([addr, prefix]) => blocked.addSubnet(addr, prefix, 'ipv6'));

/** "::ffff:7f00:1" and "::ffff:127.0.0.1" are both just 127.0.0.1; unwrap them. */
function unmap(ip) {
  let m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (m) return m[1];
  m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip); // the form URL() normalises to
  if (m) {
    const hi = parseInt(m[1], 16), lo = parseInt(m[2], 16);
    return [hi >> 8, hi & 255, lo >> 8, lo & 255].join('.');
  }
  return ip;
}

function isBlockedAddress(ip) {
  ip = unmap(String(ip).replace(/%.*$/, '')); // drop any IPv6 zone id
  const family = net.isIP(ip);
  if (!family) return true; // anything we can't parse is refused
  try { return blocked.check(ip, family === 4 ? 'ipv4' : 'ipv6'); } catch { return true; }
}

/**
 * Validates the address at connection time, so a hostname that resolves to
 * a private IP (or flips there after a check, "DNS rebinding") is refused.
 */
function safeLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    if (!ALLOW_PRIVATE && addresses.some((a) => isBlockedAddress(a.address))) {
      return callback(new Error('blocked address'));
    }
    if (options && options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

const agent = new Agent({ connect: { lookup: safeLookup }, headersTimeout: UPSTREAM_TIMEOUT_MS });

// Names that only ever exist on a private network. Public sites always have a
// dot in their name, so single-label hosts ("router", "redis") are refused too.
const INTERNAL_NAME = /(^|\.)(localhost|local|internal|localdomain|home\.arpa|svc)$/;

/** Returns an error string if the target must not be fetched, else null. */
function checkTarget(url, selfHost) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'Only http and https addresses are supported.';
  if (ALLOW_PRIVATE) return null;
  const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
  if (!ALLOWED_PORTS.has(port)) return `Port ${port} is not allowed.`;
  const host = url.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  if (net.isIP(host)) {
    // IP literals skip DNS, so check them here. URL() has already normalised
    // odd forms like 0x7f.1 or 2130706433 into dotted notation.
    if (isBlockedAddress(host)) return 'That address is on a private network.';
  } else {
    if (!host.includes('.') || INTERNAL_NAME.test(host)) return 'That address is on a private network.';
    // Fetching ourselves would loop back into the proxy (and its login endpoint).
    if (selfHost && host === selfHost) return 'The server can’t open itself.';
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// encodeURIComponent leaves ! ' ( ) * alone, which breaks url('...') in CSS.
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
// Pages run in a sandbox with no cookies, so each proxied URL carries a
// capability token (derived from AUTH_TOKEN, useless for anything else).
const FRAME_TOKEN = crypto.createHmac('sha256', AUTH_TOKEN).update('relay-frame-v1').digest('hex');
// The #fragment stays outside the url= parameter, where the browser can see it: that keeps
// "page#section" jumps working and lets <use href="sprite.svg#icon"> find its symbol.
// `extra` (e.g. "&__pf=1") goes before the fragment so it stays part of the query.
const prox = (absUrl, extra = '') => {
  const i = absUrl.indexOf('#');
  return '/proxy?url=' + enc(i < 0 ? absUrl : absUrl.slice(0, i)) + '&t=' + FRAME_TOKEN + extra + (i < 0 ? '' : absUrl.slice(i));
};

const SKIP = /^\s*(#|javascript:|data:|mailto:|tel:|blob:|about:)/i;

function resolveUrl(value, base) {
  if (value == null || SKIP.test(value)) return null;
  try { return new URL(value.trim(), base).href; } catch { return null; }
}

function errorPage(res, status, title, message) {
  if (res.__fragment) { // shown inside the shell's shadow root, where <body>/<style> rules don't apply
    res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    return res.end(`<div class="pv-doc" style="padding:48px 24px;font:17px/1.6 system-ui,sans-serif;max-width:460px;margin:0 auto"><h1 style="font-size:1.6rem;margin:0 0 10px">${esc(title)}</h1><p style="margin:0;color:#5a6579">${esc(message)}</p></div>`);
  }
  const body = `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title>
<style>
  body{font:17px/1.6 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#eef1f6;color:#0f1a2e}
  main{max-width:460px;padding:32px}h1{font-size:1.6rem;margin:0 0 10px}p{margin:0;color:#5a6579}
  @media(prefers-color-scheme:dark){body{background:#0b1220;color:#e8edf8}p{color:#97a3bb}}
</style>
<main><h1>${esc(title)}</h1><p>${esc(message)}</p></main>`;
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(body);
}

function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('Request body too large.'), { status: 413 })); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readLimited(stream, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) throw Object.assign(new Error('The page is too large to display.'), { status: 413 });
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function decodeBody(buf, contentType, isHtml) {
  let charset = (/charset=([^;]+)/i.exec(contentType) || [])[1];
  if (!charset && isHtml) {
    const head = buf.subarray(0, 2048).toString('latin1');
    charset = (/<meta[^>]+charset\s*=\s*["']?\s*([\w-]+)/i.exec(head) || [])[1];
  }
  try { return new TextDecoder((charset || 'utf-8').trim().replace(/["']/g, '')).decode(buf); }
  catch { return new TextDecoder('utf-8').decode(buf); }
}

/* ------------------------------------------------------------------ */
/* Rewriting                                                            */
/* ------------------------------------------------------------------ */

/** html/body/:root rules mean nothing inside a shadow root; point them at the wrapper div instead. */
function scopeCss(css) {
  return css.replace(/([^{};]+)\{/g, (m, sel) =>
    sel.replace(/(^|[\s,>+~(])(?:html|body|:root)(?![\w-])/g, '$1.pv-doc')
      // "html[lang=en] body" -> ".pv-doc[lang=en] .pv-doc" would match nothing; both are the wrapper.
      .replace(/(\.pv-doc(?:\[[^\]]*\]|:[\w-]+(?:\([^)]*\))?|\.[\w-]+)*)\s+\.pv-doc(?![\w-])/g, '$1') + '{');
}

// opts.origin: prefix for URLs that end up in a page on another origin (htmx fragments).
// opts.scoped: the CSS is for a fragment, so rewrite html/body selectors (see scopeCss).
function rewriteCss(css, base, opts = {}) {
  const origin = opts.origin || '';
  const swap = (u, extra = '') => {
    if (u.startsWith('/proxy?url=') || (origin && u.startsWith(origin + '/proxy?url='))) return null; // already ours
    const abs = resolveUrl(u, base);
    return abs ? origin + prox(abs, extra) : null;
  };
  const impExtra = opts.scoped ? '&__ps=1' : ''; // an @imported stylesheet needs scoping too
  const out = css
    .replace(/@import\s+url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => { const p = swap(u, impExtra); return p ? `@import url(${q}${p}${q})` : m; })
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => { const p = swap(u); return p ? `url(${q}${p}${q})` : m; })
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => { const p = swap(u, impExtra); return p ? `@import ${q}${p}${q}` : m; })
    // image-set("a.png" 1x, "b.png" 2x): plain strings, which the url() pass above can't see.
    .replace(/((?:-webkit-)?image-set\()([^)]*)\)/gi, (m, head, inner) =>
      head + inner.replace(/(["'])(?!\/proxy\?url=)(.*?)\1/g, (mm, q, u) => { const p = swap(u); return p ? q + p + q : mm; }) + ')');
  return opts.scoped ? scopeCss(out) : out;
}

/* JavaScript: modules resolve their imports against the URL they were loaded
   from, which for us is /proxy?url=..., so "./util.js" would land on this
   server instead of the real site. Imports are therefore rewritten to proxy
   URLs here, dynamic import() goes through window.__PXI (see inject.js), and
   import.meta.url reports the module's real address. Bare names ("react")
   are left alone for the page's import map. */
const MODULE_SPEC = /^(?:\.{0,2}\/|[a-z][a-z0-9+.-]*:\/\/)/i;
const jsonLit = (v) => JSON.stringify(v).replace(/</g, '\\u003c');

function modSpec(s, base) {
  if (!MODULE_SPEC.test(s) || /^\/proxy\?url=/.test(s)) return null;
  const abs = resolveUrl(s, base);
  return abs ? prox(abs) : null;
}

function rewriteJs(js, base) {
  if (!/\b(?:import|export)\b/.test(js)) return js;
  const baseLit = jsonLit(base);
  const swap = (m, pre, q, s) => { const p = modSpec(s, base); return p ? pre + q + p + q : m; };
  return js
    .replace(/(\bfrom\s*)(["'])([^"'\n\\]{1,2048})\2/g, swap)               // import x from '..' / export * from '..'
    .replace(/((?<![.\w$])import\s*)(["'])([^"'\n\\]{1,2048})\2/g, swap)     // import '..'
    .replace(/(?<![.\w$])import\s*\(/g, () => `__PXI(${baseLit},`)            // import(..)
    .replace(/(?<![.\w$])import\.meta\.url\b/g, () => `(${baseLit})`);
}

function rewriteImportMap(text, base) {
  let map;
  try { map = JSON.parse(text); } catch { return text; }
  const fix = (o) => {
    if (!o || typeof o !== 'object') return o;
    const out = {};
    for (const [k, v] of Object.entries(o)) {
      // A trailing "/" marks a prefix mapping, which can't survive being wrapped in a query string.
      const nk = MODULE_SPEC.test(k) && !k.endsWith('/') ? modSpec(k, base) || k : k;
      out[nk] = typeof v === 'string' && !v.endsWith('/') ? (modSpec(v, base) || v) : v;
    }
    return out;
  };
  if (map.imports) map.imports = fix(map.imports);
  if (map.scopes && typeof map.scopes === 'object') for (const s of Object.keys(map.scopes)) map.scopes[s] = fix(map.scopes[s]);
  return JSON.stringify(map).replace(/</g, '\\u003c');
}

/** srcset="a.png 1x,b.png 2x": commas may or may not be followed by a space. */
function mapSrcset(value, fn) {
  return value.replace(/\s*([^\s,]+(?:,[^\s,]+)*)\s*([^,]*)(,|$)/g, (m, u, desc, comma) =>
    fn(u) + (desc.trim() ? ' ' + desc.trim() : '') + (comma ? ', ' : ''));
}

// With X-Content-Type-Options: nosniff the browser refuses scripts and styles that
// arrive as text/plain, octet-stream or with no type at all, so infer one from the name.
const EXT_TYPES = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.cjs': 'text/javascript', '.css': 'text/css',
  '.json': 'application/json', '.map': 'application/json', '.wasm': 'application/wasm',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif',
  '.webp': 'image/webp', '.avif': 'image/avif', '.ico': 'image/x-icon', '.bmp': 'image/bmp',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf',
  '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg', '.wav': 'audio/wav',
};
function effectiveType(contentType, pathname) {
  const base = contentType.split(';')[0].trim().toLowerCase();
  if (base && base !== 'application/octet-stream' && base !== 'binary/octet-stream' && base !== 'text/plain') return contentType;
  return EXT_TYPES[path.extname(pathname || '').toLowerCase()] || contentType;
}
const JS_TYPE = /^(?:text|application)\/(?:x-)?(?:java|ecma)script/i;
const SCRIPT_TYPE = /^$|^module$|^(?:text|application)\/(?:x-)?(?:java|ecma)script$/i;

const URL_ATTRS = [
  ['a', 'href'], ['area', 'href'], ['link', 'href'], ['image', 'href'], ['image', 'xlink:href'],
  ['script', 'src'], ['img', 'src'], ['source', 'src'], ['video', 'src'],
  ['video', 'poster'], ['audio', 'src'], ['track', 'src'], ['iframe', 'src'],
  ['frame', 'src'], ['embed', 'src'], ['input', 'src'], ['object', 'data'],
  ['use', 'href'], ['use', 'xlink:href'], // external SVG sprites: <use href="icons.svg#home">
];

function rewriteHtml(html, pageUrl) {
  const $ = cheerio.load(html);

  // Honour <base href>, then remove it so it can't point the browser elsewhere.
  let base = pageUrl;
  const baseTag = $('base[href]').first();
  if (baseTag.length) {
    try { base = new URL(baseTag.attr('href'), pageUrl).href; } catch { /* ignore */ }
    $('base').remove();
  }

  // Policies written for the original site would block our rewritten URLs.
  $('meta[http-equiv]').filter((_, el) => /content-security-policy|x-frame-options/i.test($(el).attr('http-equiv'))).remove();
  $('[integrity]').removeAttr('integrity');
  $('[nonce]').removeAttr('nonce');
  $('[crossorigin]').removeAttr('crossorigin');

  for (const [tag, attr] of URL_ATTRS) {
    $(tag).each((_, el) => {
      const abs = resolveUrl($(el).attr(attr), base);
      if (abs) $(el).attr(attr, prox(abs));
    });
  }

  $('[srcset], [imagesrcset]').each((_, el) => {
    for (const a of ['srcset', 'imagesrcset']) {
      const v = $(el).attr(a);
      if (v) $(el).attr(a, mapSrcset(v, (u) => { const abs = resolveUrl(u, base); return abs ? prox(abs) : u; }));
    }
  });

  // Legacy presentational attributes that still load images.
  $('body[background], table[background], td[background], th[background]').each((_, el) => {
    const abs = resolveUrl($(el).attr('background'), base);
    if (abs) $(el).attr('background', prox(abs));
  });

  $('form').each((_, el) => {
    const $f = $(el);
    const abs = resolveUrl($f.attr('action') || '', base) || base;
    if (($f.attr('method') || 'get').toLowerCase() === 'post') {
      $f.attr('action', prox(abs));
    } else {
      // A GET form replaces the action's query string with its fields, so we
      // pass the real target in a hidden field and rebuild it server-side.
      // The token uses its own field name (__pt) so a site's own field called
      // "t" is no longer swallowed.
      $f.attr('action', '/proxy');
      $f.prepend(`<input type="hidden" name="__pt" value="${FRAME_TOKEN}"><input type="hidden" name="__pa" value="${esc(abs)}">`);
    }
  });

  // Keep navigation inside the proxy's frame.
  $('[target]').attr('target', '_self');
  $('[ping]').removeAttr('ping');
  $('[formaction]').each((_, el) => {
    const abs = resolveUrl($(el).attr('formaction'), base);
    if (abs) $(el).attr('formaction', prox(abs)); else $(el).removeAttr('formaction');
  });

  $('meta[http-equiv]').each((_, el) => {
    if (!/^refresh$/i.test($(el).attr('http-equiv'))) return;
    const content = $(el).attr('content') || '';
    const m = /^(\s*[\d.]+\s*;\s*url\s*=\s*)(.+)$/i.exec(content);
    const abs = m && resolveUrl(m[2].replace(/^['"]|['"]$/g, ''), base);
    if (abs) $(el).attr('content', m[1] + prox(abs));
  });

  $('style').each((_, el) => { $(el).text(rewriteCss($(el).text(), base)); });
  $('[style]').each((_, el) => { $(el).attr('style', rewriteCss($(el).attr('style'), base)); });

  // Inline scripts: module imports and import() inside them have the same problem as external ones.
  $('script:not([src])').each((_, el) => {
    const type = ($(el).attr('type') || '').trim().toLowerCase();
    if (type === 'importmap') { $(el).text(rewriteImportMap($(el).text(), base)); return; }
    if (SCRIPT_TYPE.test(type)) { const t = $(el).text(); if (t) $(el).text(rewriteJs(t, base)); }
  });

  // Patch fetch/XHR/history in the page before any of its own scripts run.
  const baseJson = JSON.stringify(base).replace(/</g, '\\u003c');
  const parentJson = JSON.stringify(FRONTEND_ORIGIN || '*').replace(/</g, '\\u003c');
  // __PROXY_BASE__ is where relative URLs resolve (a <base href> can move it); __PROXY_URL__
  // is the page's own address, which is what the shell's address bar should show.
  const pageJson = JSON.stringify(pageUrl).replace(/</g, '\\u003c');
  $('head').prepend(`<script>window.__PROXY_BASE__=${baseJson};window.__PROXY_URL__=${pageJson};window.__PROXY_TOKEN__="${FRAME_TOKEN}";window.__PROXY_PARENT__=${parentJson};</script><script src="/inject.js"></script>`);

  return $.html();
}

/* ------------------------------------------------------------------ */
/* /proxy                                                               */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* htmx fragments                                                       */
/* ------------------------------------------------------------------ */

/*
 * Fragment clients ask for /proxy?...&__pf=1 and get back an HTML *fragment*
 * instead of a whole page: the page's styles plus its <body>, which the shell
 * may drop into a shadow root in their own DOM. The fragment is scrubbed hard:
 * no scripts, no inline handlers, no frames,
 * and no hx-* attributes from the site (htmx would act on them). Links and forms
 * are replaced with our own hx-get/hx-post, and every resource URL is absolute
 * (PUBLIC_URL, or taken from the request) because the page is no longer served from here.
 */

const PUBLIC_URL = (process.env.PUBLIC_URL || '').replace(/\/+$/, '');
function publicOrigin(req) {
  if (PUBLIC_URL) return PUBLIC_URL;
  const proto = TRUST_PROXY && /^https\b/i.test(String(req.headers['x-forwarded-proto'] || '')) ? 'https' : 'http';
  const host = /^[\w.\-:[\]]+$/.test(req.headers.host || '') ? req.headers.host : 'localhost';
  return `${proto}://${host}`;
}

/** Header value for the shell's address bar. Non-ASCII is \u-escaped because HTTP headers can't carry it. */
function navHeader(url, title) {
  return JSON.stringify({ 'proxy-nav': { url, title } }).replace(/[\u007f-￿]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

const ALWAYS_DROP_ATTRS = new Set(['srcdoc', 'integrity', 'nonce', 'crossorigin', 'ping', 'target', 'formaction']);
const SCRIPTY_URL = /^\s*(?:javascript|vbscript|data:text\/html)/i;

function rewriteFragment(html, pageUrl, origin) {
  const $ = cheerio.load(html, { scriptingEnabled: false }); // <noscript> content becomes real markup
  let base = pageUrl;
  const baseTag = $('base[href]').first();
  if (baseTag.length) { try { base = new URL(baseTag.attr('href'), pageUrl).href; } catch { /* ignore */ } }
  const P = (abs, extra = '') => origin + prox(abs, extra);

  $('noscript').each((_, el) => { $(el).replaceWith($(el).contents()); });
  const title = $('title').first().text().replace(/\s+/g, ' ').trim().slice(0, 120);
  $('script, iframe, frame, frameset, object, embed, applet, base, meta, template, title, link:not([rel~="stylesheet"])').remove();

  // Anything that could run code, or be picked up by the shell's htmx, goes.
  $('*').each((_, el) => {
    const a = el.attribs;
    if (!a) return;
    for (const name of Object.keys(a)) {
      const n = name.toLowerCase();
      if (/^(?:on|hx-|data-hx-)/.test(n) || ALWAYS_DROP_ATTRS.has(n)) delete a[name];
      else if (/^(?:href|xlink:href|src|action|data|poster|background)$/.test(n) && SCRIPTY_URL.test(a[name])) delete a[name];
    }
  });

  // The fragment client handles these links; the plain href stays for fallback navigation.
  $('a[href], area[href]').each((_, el) => {
    const abs = resolveUrl($(el).attr('href'), base);
    if (!abs) return; // #anchors, mailto:, tel: are left alone (the shell scrolls anchors itself)
    $(el).attr({ href: P(abs), 'hx-get': P(abs, '&__pf=1'), 'hx-swap': 'none' });
  });

  for (const [tag, attr] of URL_ATTRS) {
    if (['a', 'area', 'iframe', 'frame', 'embed', 'object'].includes(tag)) continue;
    $(tag).each((_, el) => {
      const abs = resolveUrl($(el).attr(attr), base);
      if (abs) $(el).attr(attr, P(abs, tag === 'link' ? '&__ps=1' : ''));
    });
  }
  $('[srcset], [imagesrcset]').each((_, el) => {
    for (const a of ['srcset', 'imagesrcset']) {
      const v = $(el).attr(a);
      if (v) $(el).attr(a, mapSrcset(v, (u) => { const abs = resolveUrl(u, base); return abs ? P(abs) : u; }));
    }
  });
  $('body[background], table[background], td[background], th[background]').each((_, el) => {
    const abs = resolveUrl($(el).attr('background'), base);
    if (abs) $(el).attr('background', P(abs));
  });

  $('form').each((_, el) => {
    const $f = $(el);
    const abs = resolveUrl($f.attr('action') || '', base) || base;
    const post = ($f.attr('method') || 'get').toLowerCase() === 'post';
    const multipart = /multipart/i.test($f.attr('enctype') || '');
    $f.removeAttr('action').removeAttr('method').removeAttr('enctype').attr('hx-swap', 'none');
    if (post) {
      $f.attr('hx-post', P(abs, '&__pf=1'));
      if (multipart) $f.attr('hx-encoding', 'multipart/form-data');
    } else {
      // A GET form replaces the action's query string with its fields, so the real target
      // travels in a hidden field and the server rebuilds it (same trick as the iframe version).
      $f.attr('hx-get', origin + '/proxy');
      $f.prepend(`<input type="hidden" name="__pt" value="${FRAME_TOKEN}"><input type="hidden" name="__pa" value="${esc(abs)}"><input type="hidden" name="__pf" value="1">`);
    }
  });

  $('[style]').each((_, el) => { $(el).attr('style', rewriteCss($(el).attr('style'), base, { origin })); });

  // Styles move to the front of the fragment; selectors for html/body are redirected to the wrapper.
  const sheets = [];
  $('link[rel~="stylesheet"], style').each((_, el) => {
    if (el.name === 'style') $(el).text(rewriteCss($(el).text(), base, { origin, scoped: true }));
    sheets.push($.html(el));
  }).remove();

  const $body = $('body').first();
  const cls = ['pv-doc', $body.attr('class'), $('html').attr('class')].filter(Boolean).join(' ');
  const bg = $body.attr('bgcolor') ? `background-color:${$body.attr('bgcolor')};` : '';
  const style = bg + ($body.attr('style') || '');
  return {
    title,
    html: `<div class="${esc(cls)}"${style ? ` style="${esc(style)}"` : ''}>${sheets.join('')}${$body.html() || ''}</div>`,
  };
}

/** Images, video and audio can be shown directly; anything else gets a link. */
function nonHtmlFragment(type, abs, origin) {
  const src = esc(origin + prox(abs));
  const t = String(type).split(';')[0].trim().toLowerCase();
  let inner;
  if (t.startsWith('image/')) inner = `<img src="${src}" style="max-width:100%">`;
  else if (t.startsWith('video/')) inner = `<video src="${src}" controls style="max-width:100%"></video>`;
  else if (t.startsWith('audio/')) inner = `<audio src="${src}" controls></audio>`;
  else inner = `<h1 style="font-size:1.4rem;margin:0 0 10px">This file can’t be shown here</h1><p style="margin:0 0 12px;color:#5a6579">${esc(t || 'Unknown type')}</p><a href="${src}" target="_blank" rel="noopener">Open or download it</a>`;
  return `<div class="pv-doc" style="padding:24px;font:17px/1.6 system-ui,sans-serif">${inner}</div>`;
}

const FORWARD_RESPONSE_HEADERS =['content-type', 'cache-control', 'last-modified', 'etag', 'content-language', 'content-disposition'];

// Every proxied response is locked into a sandbox: opaque origin (no access to
// the proxy UI, its storage or other sites), no top navigation, no popups, and
// the browser may only load from this server. Inside that box the policy is kept
// loose on purpose (data:/blob: everywhere, workers, modals, downloads) so that
// ordinary sites' styles and scripts run without tripping over it.
const ISOLATION_HEADERS = {
  'Content-Security-Policy': `sandbox allow-scripts allow-forms allow-modals allow-downloads; default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob:; style-src 'self' 'unsafe-inline' data: blob:; worker-src 'self' data: blob:; connect-src 'self' data: blob:; frame-src 'self' data: blob:; form-action 'self'; base-uri 'self'; object-src 'none'; frame-ancestors ${FRONTEND_ORIGIN || '*'}`,
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), display-capture=(), usb=(), serial=(), hid=(), bluetooth=(), payment=(), clipboard-read=(), publickey-credentials-get=()',
  'Cross-Origin-Resource-Policy': 'cross-origin',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, OPTIONS',
  'Access-Control-Allow-Headers': '*',
  'Access-Control-Allow-Credentials': 'true',
  'Access-Control-Expose-Headers': 'HX-Trigger, Set-Cookie', // htmx reads the page's real address from it
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'Vary': 'Origin',
};

function applyProxyCors(req, res) {
  // Credentialed fetch/XHR requests require an explicit, matching origin.
  // Opaque sandboxed frames send "null" rather than the proxy origin.
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
}

async function handleProxy(req, res, reqUrl) {
  for (const [k, v] of Object.entries(ISOLATION_HEADERS)) res.setHeader(k, v);
  applyProxyCors(req, res);
  if (req.method === 'OPTIONS') { res.writeHead(204, { 'Access-Control-Max-Age': '600' }); return res.end(); }
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST') {
    return errorPage(res, 405, 'Method not allowed', 'This proxy supports GET and POST requests.');
  }

  // __pf=1: the htmx shell wants an HTML fragment (see rewriteFragment), not a whole page.
  // __ps=1: this stylesheet belongs to such a fragment, so html/body rules are redirected to its wrapper.
  const fragment = reqUrl.searchParams.get('__pf') === '1';
  const scopedCss = reqUrl.searchParams.get('__ps') === '1';
  res.__fragment = fragment; // lets errorPage() answer in the same shape
  const origin = fragment ? publicOrigin(req) : '';

  let targetStr = reqUrl.searchParams.get('url');
  const formTarget = reqUrl.searchParams.get('__pa');
  if (formTarget) {
    // Rebuild a GET form submission: real action URL + the form's fields.
    // Only our own fields are removed; a site field named "t" is kept.
    reqUrl.searchParams.delete('__pa');
    reqUrl.searchParams.delete('__pt');
    reqUrl.searchParams.delete('__pf');
    let t;
    try { t = new URL(formTarget); } catch { return errorPage(res, 400, 'Invalid address', 'The form target is not a valid URL.'); }
    t.search = '';
    for (const [k, v] of reqUrl.searchParams) t.searchParams.append(k, v);
    targetStr = t.href;
  }
  if (!targetStr) return errorPage(res, 400, 'No address given', 'Add a ?url= parameter, or use the address bar on the home page.');

  let target;
  try { target = new URL(targetStr); } catch { return errorPage(res, 400, 'Invalid address', 'That doesn\u2019t look like a valid URL.'); }
  const selfHost = (req.headers.host || '').toLowerCase().replace(/:\d+$/, '');
  const problem = checkTarget(target, selfHost);
  if (problem) return errorPage(res, 403, 'Address not allowed', problem);
  target.username = '';
  target.password = '';

  let body;
  if (req.method === 'POST') body = await readBody(req, MAX_REQUEST_BODY);

  const headers = {
    // Fixed identity: nothing about the user's browser is passed to sites.
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'sec-ch-ua': '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    accept: fragment ? 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8' : (req.headers.accept || '*/*'),
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding': 'identity',
  };
  // The site's own address, never anything about the visitor. Many CDNs and form handlers
  // refuse requests that arrive with no Referer/Origin at all.
  headers.referer = target.origin + '/';
  if (req.method === 'POST') headers.origin = target.origin;
  if (body && req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers.range) headers.range = req.headers.range; // lets audio/video seek

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  res.on('close', () => { clearTimeout(timer); controller.abort(); });

  let upstream;
  try {
    upstream = await fetch(target.href, {
      method: req.method, headers, body, redirect: 'manual', dispatcher: agent, signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timer);
    const cause = (err && err.cause && err.cause.message) || '';
    if (/blocked address/.test(cause)) return errorPage(res, 403, 'Address not allowed', 'That host resolves to a private network address.');
    if (err.name === 'AbortError') return errorPage(res, 504, 'The site took too long', 'It didn\u2019t respond in time. Try again in a moment.');
    if (/ENOTFOUND|EAI_AGAIN/.test(cause)) return errorPage(res, 502, 'Site not found', `Couldn\u2019t find ${target.hostname}. Check the spelling.`);
    return errorPage(res, 502, 'Couldn\u2019t reach the site', cause || 'The connection failed.');
  }

  // The timer only guards "no response yet". Once headers are in, a long download, video or
  // event stream must not be cut off at 25 seconds (a stalled body still hits undici's own timeout).
  clearTimeout(timer);

  try {
    // Send redirects back through the proxy so each hop is validated again.
    const location = upstream.headers.get('location');
    if (upstream.status >= 300 && upstream.status < 400 && location) {
      const next = resolveUrl(location, target.href);
      if (upstream.body) upstream.body.cancel().catch(() => {});
      if (!next) return errorPage(res, 502, 'Bad redirect', 'The site redirected to an address we can\u2019t follow.');
      res.writeHead(upstream.status, { Location: prox(next) + (fragment ? '&__pf=1' : ''), 'Cache-Control': 'no-store' });
      return res.end();
    }

    const rawType = upstream.headers.get('content-type') || '';
    const contentType = effectiveType(rawType, target.pathname);
    const out = { 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };
    for (const h of FORWARD_RESPONSE_HEADERS) {
      const v = upstream.headers.get(h);
      if (v) out[h] = v;
    }
    if (contentType !== rawType) out['content-type'] = contentType; // nosniff would otherwise block it

    const isHtml = /^(text\/html|application\/xhtml\+xml)/i.test(contentType);
    const isCss = /^text\/css/i.test(contentType);
    const isJs = JS_TYPE.test(contentType);
    // Scripts are only rewritten when they fit in memory; a huge bundle streams through untouched.
    const declared = Number(upstream.headers.get('content-length')) || 0;
    const rewritable = isHtml || isCss || (isJs && declared <= MAX_REWRITE_BYTES);

    // Something other than a web page was asked for as a page: show it, or offer it as a download.
    if (fragment && !isHtml) {
      if (upstream.body) upstream.body.cancel().catch(() => {});
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'HX-Trigger': navHeader(target.href, '') });
      return res.end(req.method === 'HEAD' ? '' : nonHtmlFragment(contentType, target.href, origin));
    }

    if (rewritable && upstream.body && req.method !== 'HEAD' && upstream.status !== 206) {
      // Pages and stylesheets are buffered, so a stalled body gets its own deadline.
      const bodyTimer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
      let buf;
      try { buf = await readLimited(upstream.body, MAX_REWRITE_BYTES); } finally { clearTimeout(bodyTimer); }
      const text = decodeBody(buf, contentType, isHtml);
      let rewritten;
      if (isHtml && fragment) {
        const f = rewriteFragment(text, target.href, origin);
        rewritten = f.html;
        out['HX-Trigger'] = navHeader(target.href, f.title);
        out['Cache-Control'] = 'no-store';
      } else {
        rewritten = isHtml ? rewriteHtml(text, target.href)
          : isCss ? rewriteCss(text, target.href, { scoped: scopedCss })
          : rewriteJs(text, target.href);
      }
      delete out.etag;
      delete out['last-modified'];
      out['content-type'] = `${isHtml ? 'text/html' : isCss ? 'text/css' : 'text/javascript'}; charset=utf-8`;
      res.writeHead(upstream.status, out);
      return res.end(rewritten);
    }

    // Untouched files (media, images, downloads) keep their range/length info.
    // content-length is only safe when the body wasn't compressed upstream,
    // because fetch() hands us the decoded bytes.
    for (const h of ['content-range', 'accept-ranges']) {
      const v = upstream.headers.get(h);
      if (v) out[h] = v;
    }
    const encoding = upstream.headers.get('content-encoding') || '';
    const length = upstream.headers.get('content-length');
    if (length && (!encoding || /^identity$/i.test(encoding))) out['content-length'] = length;

    res.writeHead(upstream.status, out);
    if (!upstream.body || req.method === 'HEAD') return res.end();

    let total = 0;
    const limiter = new Transform({
      transform(chunk, _enc, cb) {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) return cb(new Error('too large'));
        cb(null, chunk);
      },
    });
    pipeline(Readable.fromWeb(upstream.body), limiter, res, () => clearTimeout(timer));
  } catch (err) {
    clearTimeout(timer);
    if (!res.headersSent) return errorPage(res, err.status || 502, 'Couldn\u2019t load the page', err.message);
    res.destroy();
  }
}

/* ------------------------------------------------------------------ */
/* Static files, auth, rate limiting                                    */
/* ------------------------------------------------------------------ */

function serveInject(res) {
  fs.readFile(path.join(__dirname, 'inject.js'), (err, data) => {
    if (err) return errorPage(res, 500, 'Server error', 'Couldn\u2019t read the file.');
    res.writeHead(200, {
      'Content-Type': 'text/javascript; charset=utf-8',
      'Cache-Control': 'no-cache',
      'Access-Control-Allow-Origin': '*',
      'Cross-Origin-Resource-Policy': 'cross-origin',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(data);
  });
}

const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

/** Plain decoy page shown to anyone without the auth cookie. */
function defaultPage(res) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Welcome</title>
<style>body{font:17px/1.6 system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#fff;color:#222}main{text-align:center;padding:32px}h1{font-size:1.5rem;margin:0 0 8px}p{margin:0;color:#777}</style>
<main><h1>Welcome</h1><p>There is nothing to see here yet.</p></main>`);
}

const hits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (v.reset < now) hits.delete(k); }, 60_000).unref();
function rateLimited(ip) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || h.reset < now) { h = { count: 0, reset: now + 60_000 }; hits.set(ip, h); }
  return ++h.count > RATE_LIMIT;
}

const authHits = new Map();
setInterval(() => { const now = Date.now(); for (const [k, v] of authHits) if (v.reset < now) authHits.delete(k); }, 60_000).unref();
function authRateLimited(ip) {
  const now = Date.now();
  let h = authHits.get(ip);
  if (!h || h.reset < now) { h = { count: 0, reset: now + 60_000 }; authHits.set(ip, h); }
  return ++h.count > 10; // access-key guesses per IP per minute
}

function json(res, status, obj, extra) {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...extra });
  res.end(JSON.stringify(obj));
}

const apiCors = (methods) => ({
  'Access-Control-Allow-Origin': FRONTEND_ORIGIN || '*',
  'Access-Control-Allow-Methods': methods,
  'Access-Control-Allow-Headers': 'Content-Type',
  'Vary': 'Origin',
});

/** Lets the frontend ask "is my saved token still good?" without loading a page. */
function handleSession(req, res, url) {
  const cors = apiCors('GET, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204, { ...cors, 'Access-Control-Max-Age': '600' }); return res.end(); }
  if (req.method !== 'GET') return json(res, 405, { error: 'Method not allowed' }, cors);
  if (!safeEqual(url.searchParams.get('t') || '', FRAME_TOKEN)) return json(res, 401, { error: 'Session expired.' }, cors);
  return json(res, 200, { ok: true }, cors);
}

async function handleAuth(req, res, ip) {
  const cors = apiCors('POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.writeHead(204, { ...cors, 'Access-Control-Max-Age': '600' }); return res.end(); }
  if (req.method !== 'POST') return json(res, 405, { error: 'Method not allowed' }, cors);
  if (authRateLimited(ip)) return json(res, 429, { error: 'Too many attempts. Try again in a minute.' }, { ...cors, 'Retry-After': '60' });
  let token = '';
  try { token = String(JSON.parse((await readBody(req, 4096)).toString('utf8')).token || ''); }
  catch { return json(res, 400, { error: 'Bad request' }, cors); }
  if (!safeEqual(token, AUTH_TOKEN)) return json(res, 401, { error: 'Wrong access key.' }, cors);
  return json(res, 200, { frameToken: FRAME_TOKEN }, cors);
}

const server = http.createServer(async (req, res) => {
  try {
    const ip = (TRUST_PROXY && (req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
    if (rateLimited(ip)) {
      res.writeHead(429, { 'Retry-After': '60', 'Content-Type': 'text/plain' });
      return res.end('Too many requests. Try again in a minute.');
    }
    // Every response, on every path, tells crawlers to keep out of the index.
    res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive, nosnippet');
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
    // inject.js holds no secrets; sandboxed pages can't send credentials anyway.
    if (url.pathname === '/inject.js') return serveInject(res);
    if (url.pathname === '/api/auth') return await handleAuth(req, res, ip);
    if (url.pathname === '/api/session') return handleSession(req, res, url);
    // /proxy is authenticated by the frame token the frontend got from /api/auth.
    // GET forms carry it as __pt (so a site's own "t" field can't collide); links use t.
    if (url.pathname === '/proxy') {
      const given = url.searchParams.get('__pt') || url.searchParams.get('t') || '';
      if (!safeEqual(given, FRAME_TOKEN)) return defaultPage(res);
      return await handleProxy(req, res, url);
    }
    return defaultPage(res);
  } catch (err) {
    if (!res.headersSent) errorPage(res, err.status || 500, 'Something went wrong', err.message || 'Unexpected error.');
    else res.destroy();
  }
});

// Started only when run directly (`node server.js`); tests require() this file and
// use the exports below without opening a port of their own.
if (require.main === module) {
  server.listen(PORT, HOST, () => {
    console.log(`Pear Proxy backend listening on http://${HOST}:${PORT}`);
    if (ALLOW_PRIVATE) console.warn('WARNING: ALLOW_PRIVATE=1, private network targets are reachable. Use for testing only.');
    else if (process.env.ALLOW_PRIVATE) console.warn(`Note: ALLOW_PRIVATE="${process.env.ALLOW_PRIVATE}" is ignored. Only the exact value 1 enables it; private targets stay blocked.`);
    if (GENERATED_TOKEN) console.warn(`WARNING: AUTH_TOKEN is not set. Using a random key for this run only: ${AUTH_TOKEN}`);
    if (!FRONTEND_ORIGIN) console.warn('WARNING: FRONTEND_ORIGIN is not set; CORS and framing are open to any site.');
  });
}

module.exports = {
  server, FRAME_TOKEN, AUTH_TOKEN,
  unmap, isBlockedAddress, checkTarget, esc, enc, prox, resolveUrl, decodeBody,
  scopeCss, rewriteCss, modSpec, rewriteJs, rewriteImportMap, mapSrcset, effectiveType,
  rewriteHtml, rewriteFragment, nonHtmlFragment, navHeader, safeEqual,
};
