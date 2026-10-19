'use strict';

/**
 * Relay web proxy: backend.
 *
 *   GET  /                 the browser-style frontend
 *   GET  /proxy?url=...    fetch a page and rewrite it so links, images,
 *                          styles, scripts and forms keep going through us
 *   POST /proxy?url=...    forwards form posts
 *
 * Environment variables (all optional):
 *   PORT             port to listen on                     (default 3000)
 *   HOST             interface to bind                     (default 127.0.0.1)
 *   AUTH_TOKEN       secret token; visiting /<token> sets the auth cookie
 *   RATE_LIMIT       max requests per IP per minute        (default 600)
 *   TRUST_PROXY      "1" to read client IP from X-Forwarded-For
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
const HOST = process.env.HOST || '127.0.0.1';
const AUTH_TOKEN = process.env.AUTH_TOKEN || '3c94e25a79b587b24a0cd93294d6ff63dc8c9b100dcb769a2decee0450dc7bda';
const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 600;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE === '1';

const MAX_RESPONSE_BYTES = 25 * 1024 * 1024; // cap on any upstream response
const MAX_REWRITE_BYTES = 8 * 1024 * 1024; // cap on HTML/CSS we rewrite in memory
const MAX_REQUEST_BODY = 1 * 1024 * 1024; // cap on form posts
const UPSTREAM_TIMEOUT_MS = 25_000;
const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);

/* ------------------------------------------------------------------ */
/* SSRF protection: never let the proxy reach internal networks        */
/* ------------------------------------------------------------------ */

const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([addr, prefix]) => blocked.addSubnet(addr, prefix, 'ipv4'));
[['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]]
  .forEach(([addr, prefix]) => blocked.addSubnet(addr, prefix, 'ipv6'));

function isBlockedAddress(ip) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip); // IPv4-mapped IPv6
  if (mapped) ip = mapped[1];
  const family = net.isIP(ip);
  if (!family) return true;
  return blocked.check(ip, family === 4 ? 'ipv4' : 'ipv6');
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

/** Returns an error string if the target must not be fetched, else null. */
function checkTarget(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return 'Only http and https addresses are supported.';
  if (ALLOW_PRIVATE) return null;
  const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
  if (!ALLOWED_PORTS.has(port)) return `Port ${port} is not allowed.`;
  // IP literals skip DNS, so check them here. URL() has already normalised
  // odd forms like 0x7f.1 or 2130706433 into dotted notation.
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && isBlockedAddress(host)) return 'That address is on a private network.';
  return null;
}

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// encodeURIComponent leaves ! ' ( ) * alone, which breaks url('...') in CSS.
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
const prox = (absUrl) => '/proxy?url=' + enc(absUrl);

const SKIP = /^\s*(#|javascript:|data:|mailto:|tel:|blob:|about:)/i;

function resolveUrl(value, base) {
  if (value == null || SKIP.test(value)) return null;
  try { return new URL(value.trim(), base).href; } catch { return null; }
}

function errorPage(res, status, title, message) {
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

function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (m, q, u) => {
      const abs = resolveUrl(u, base);
      return abs ? `url(${q}${prox(abs)}${q})` : m;
    })
    .replace(/@import\s+(['"])(.*?)\1/gi, (m, q, u) => {
      const abs = resolveUrl(u, base);
      return abs ? `@import ${q}${prox(abs)}${q}` : m;
    });
}

const URL_ATTRS = [
  ['a', 'href'], ['area', 'href'], ['link', 'href'],
  ['script', 'src'], ['img', 'src'], ['source', 'src'], ['video', 'src'],
  ['video', 'poster'], ['audio', 'src'], ['track', 'src'], ['iframe', 'src'],
  ['frame', 'src'], ['embed', 'src'], ['input', 'src'], ['object', 'data'],
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

  $('[srcset]').each((_, el) => {
    const out = $(el).attr('srcset').split(/,\s+/).map((part) => {
      const [u, ...rest] = part.trim().split(/\s+/);
      const abs = resolveUrl(u, base);
      return [abs ? prox(abs) : u, ...rest].join(' ');
    });
    $(el).attr('srcset', out.join(', '));
  });

  $('form').each((_, el) => {
    const $f = $(el);
    const abs = resolveUrl($f.attr('action') || '', base) || base;
    if (($f.attr('method') || 'get').toLowerCase() === 'post') {
      $f.attr('action', prox(abs));
    } else {
      // A GET form replaces the action's query string with its fields, so we
      // pass the real target in a hidden field and rebuild it server-side.
      $f.attr('action', '/proxy');
      $f.prepend(`<input type="hidden" name="__pa" value="${esc(abs)}">`);
    }
  });

  // Keep navigation inside the proxy's frame.
  $('[target="_top"], [target="_parent"]').attr('target', '_self');

  $('meta[http-equiv]').each((_, el) => {
    if (!/^refresh$/i.test($(el).attr('http-equiv'))) return;
    const content = $(el).attr('content') || '';
    const m = /^(\s*[\d.]+\s*;\s*url\s*=\s*)(.+)$/i.exec(content);
    const abs = m && resolveUrl(m[2].replace(/^['"]|['"]$/g, ''), base);
    if (abs) $(el).attr('content', m[1] + prox(abs));
  });

  $('style').each((_, el) => { $(el).text(rewriteCss($(el).text(), base)); });
  $('[style]').each((_, el) => { $(el).attr('style', rewriteCss($(el).attr('style'), base)); });

  // Patch fetch/XHR/history in the page before any of its own scripts run.
  const baseJson = JSON.stringify(base).replace(/</g, '\\u003c');
  $('head').prepend(`<script>window.__PROXY_BASE__=${baseJson};</script><script src="/inject.js"></script>`);

  return $.html();
}

/* ------------------------------------------------------------------ */
/* /proxy                                                               */
/* ------------------------------------------------------------------ */

const FORWARD_RESPONSE_HEADERS = ['content-type', 'cache-control', 'last-modified', 'etag', 'content-language', 'content-disposition'];

async function handleProxy(req, res, reqUrl) {
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.method !== 'POST') {
    return errorPage(res, 405, 'Method not allowed', 'This proxy supports GET and POST requests.');
  }

  let targetStr = reqUrl.searchParams.get('url');
  const formTarget = reqUrl.searchParams.get('__pa');
  if (formTarget) {
    // Rebuild a GET form submission: real action URL + the form's fields.
    reqUrl.searchParams.delete('__pa');
    let t;
    try { t = new URL(formTarget); } catch { return errorPage(res, 400, 'Invalid address', 'The form target is not a valid URL.'); }
    t.search = '';
    for (const [k, v] of reqUrl.searchParams) t.searchParams.append(k, v);
    targetStr = t.href;
  }
  if (!targetStr) return errorPage(res, 400, 'No address given', 'Add a ?url= parameter, or use the address bar on the home page.');

  let target;
  try { target = new URL(targetStr); } catch { return errorPage(res, 400, 'Invalid address', 'That doesn\u2019t look like a valid URL.'); }
  const problem = checkTarget(target);
  if (problem) return errorPage(res, 403, 'Address not allowed', problem);
  target.username = '';
  target.password = '';

  let body;
  if (req.method === 'POST') body = await readBody(req, MAX_REQUEST_BODY);

  const headers = {
    'user-agent': req.headers['user-agent'] || 'Mozilla/5.0',
    accept: req.headers.accept || '*/*',
    'accept-language': req.headers['accept-language'] || 'en-US,en;q=0.9',
    'accept-encoding': 'identity',
  };
  if (body && req.headers['content-type']) headers['content-type'] = req.headers['content-type'];

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

  try {
    // Send redirects back through the proxy so each hop is validated again.
    const location = upstream.headers.get('location');
    if (upstream.status >= 300 && upstream.status < 400 && location) {
      const next = resolveUrl(location, target.href);
      if (upstream.body) upstream.body.cancel().catch(() => {});
      if (!next) return errorPage(res, 502, 'Bad redirect', 'The site redirected to an address we can\u2019t follow.');
      res.writeHead(upstream.status, { Location: prox(next), 'Cache-Control': 'no-store' });
      return res.end();
    }

    const contentType = upstream.headers.get('content-type') || '';
    const out = { 'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff' };
    for (const h of FORWARD_RESPONSE_HEADERS) {
      const v = upstream.headers.get(h);
      if (v) out[h] = v;
    }

    const isHtml = /^(text\/html|application\/xhtml\+xml)/i.test(contentType);
    const isCss = /^text\/css/i.test(contentType);

    if ((isHtml || isCss) && upstream.body && req.method !== 'HEAD') {
      const buf = await readLimited(upstream.body, MAX_REWRITE_BYTES);
      const text = decodeBody(buf, contentType, isHtml);
      const rewritten = isHtml ? rewriteHtml(text, target.href) : rewriteCss(text, target.href);
      delete out.etag;
      delete out['last-modified'];
      out['content-type'] = `${isHtml ? 'text/html' : 'text/css'}; charset=utf-8`;
      res.writeHead(upstream.status, out);
      return res.end(rewritten);
    }

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

const PUBLIC_DIR = path.join(__dirname, 'public');
const STATIC = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/app.js': ['app.js', 'text/javascript; charset=utf-8'],
  '/inject.js': ['inject.js', 'text/javascript; charset=utf-8'],
};

const UI_CSP = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-src 'self'; base-uri 'none'; form-action 'self'";

function serveStatic(pathname, res) {
  const entry = STATIC[pathname];
  if (!entry) return errorPage(res, 404, 'Not found', 'There is nothing at this address.');
  fs.readFile(path.join(PUBLIC_DIR, entry[0]), (err, data) => {
    if (err) return errorPage(res, 500, 'Server error', 'Couldn\u2019t read the file.');
    const headers = { 'Content-Type': entry[1], 'Cache-Control': 'no-cache' };
    if (entry[0] === 'index.html') headers['Content-Security-Policy'] = UI_CSP;
    res.writeHead(200, headers);
    res.end(data);
  });
}

const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

function getCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

function authorised(req) {
  return safeEqual(getCookie(req, 'auth'), AUTH_TOKEN);
}

function isSecure(req) {
  return Boolean(req.socket.encrypted) || (TRUST_PROXY && /^https/i.test(req.headers['x-forwarded-proto'] || ''));
}

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

const server = http.createServer(async (req, res) => {
  try {
    const ip = (TRUST_PROXY && (req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';
    if (rateLimited(ip)) {
      res.writeHead(429, { 'Retry-After': '60', 'Content-Type': 'text/plain' });
      return res.end('Too many requests. Try again in a minute.');
    }
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
    if (url.pathname === '/' + AUTH_TOKEN) {
      res.writeHead(302, {
        'Set-Cookie': `auth=${AUTH_TOKEN}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax${isSecure(req) ? '; Secure' : ''}`,
        Location: '/',
        'Cache-Control': 'no-store',
      });
      return res.end();
    }
    if (!authorised(req)) return defaultPage(res);
    if (url.pathname === '/proxy') return await handleProxy(req, res, url);
    return serveStatic(url.pathname, res);
  } catch (err) {
    if (!res.headersSent) errorPage(res, err.status || 500, 'Something went wrong', err.message || 'Unexpected error.');
    else res.destroy();
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Relay web proxy running at http://${HOST}:${PORT}`);
  if (ALLOW_PRIVATE) console.warn('WARNING: ALLOW_PRIVATE=1, private network targets are reachable. Use for testing only.');
  if (!process.env.AUTH_TOKEN) console.warn('WARNING: using the built-in default AUTH_TOKEN. Set AUTH_TOKEN in the environment.');
});
