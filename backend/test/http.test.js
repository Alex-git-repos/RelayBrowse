'use strict';
process.env.AUTH_TOKEN = 'test-secret';
process.env.ALLOW_PRIVATE = '1'; // lets the proxy reach the local upstream below
process.env.FRONTEND_ORIGIN = 'https://front.test';
process.env.RATE_LIMIT = '100000';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { server, FRAME_TOKEN } = require('../server.js');

let proxy, upstream, PU, UU;
const seen = [];

const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(`http://127.0.0.1:${srv.address().port}`)));

test.before(async () => {
  upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      const p = req.url.split('?')[0];
      switch (p) {
        case '/html': res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('<title>T</title><img src="/i.png"><a href="/n">n</a>');
        case '/css': res.writeHead(200, { 'Content-Type': 'text/css' }); return res.end('a{background:url(/i.png)}');
        case '/app.js': res.writeHead(200, { 'Content-Type': 'application/octet-stream' }); return res.end(`import x from './m.js';`);
        case '/noct.css': res.writeHead(200); return res.end('p{background:url(/i.png)}');
        case '/redir': res.writeHead(302, { Location: '/html' }); return res.end();
        case '/redir-abs': res.writeHead(301, { Location: 'http://127.0.0.1:1/x' }); return res.end();
        case '/post': res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('got:' + Buffer.concat(chunks).toString());
        case '/echo': res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end(req.url);
        case '/img': res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'max-age=60', ETag: '"abc"' }); return res.end(Buffer.from([1, 2, 3, 4]));
        case '/range': res.writeHead(206, { 'Content-Type': 'video/mp4', 'Content-Range': 'bytes 0-1/10', 'Accept-Ranges': 'bytes' }); return res.end(Buffer.from([9, 9]));
        case '/404': res.writeHead(404, { 'Content-Type': 'text/html' }); return res.end('<p>gone</p>');
        case '/latin': res.writeHead(200, { 'Content-Type': 'text/html; charset=iso-8859-1' }); return res.end(Buffer.from('<p>caf\xe9</p>', 'latin1'));
        case '/big': res.writeHead(200, { 'Content-Type': 'text/html' }); return res.end('x'.repeat(2000));
        default: res.writeHead(404); return res.end('nope');
      }
    });
  });
  UU = await listen(upstream);
  proxy = server;
  PU = await listen(proxy);
});
test.after(() => { proxy.close(); upstream.close(); proxy.closeAllConnections?.(); upstream.closeAllConnections?.(); });

const purl = (target, extra = '') => `${PU}/proxy?url=${encodeURIComponent(target)}&t=${FRAME_TOKEN}${extra}`;
const get = (u, opts) => fetch(u, { redirect: 'manual', ...opts });

test('/health', async () => {
  const r = await get(`${PU}/health`);
  assert.equal(r.status, 200);
  assert.equal(await r.text(), 'ok');
});
test('every response is noindex', async () => {
  for (const p of ['/health', '/', '/nothing', '/inject.js']) {
    assert.match((await get(PU + p)).headers.get('x-robots-tag'), /noindex/, p);
  }
});
test('unknown paths show the decoy page', async () => {
  const r = await get(`${PU}/admin`);
  assert.equal(r.status, 200);
  assert.match(await r.text(), /Welcome/);
});
test('/inject.js is served as javascript', async () => {
  const r = await get(`${PU}/inject.js`);
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /javascript/);
  assert.match(await r.text(), /__PROXY_BASE__/);
});

/* ---------- auth ---------- */

test('auth: correct key returns the frame token', async () => {
  const r = await get(`${PU}/api/auth`, { method: 'POST', body: JSON.stringify({ token: 'test-secret' }), headers: { 'Content-Type': 'application/json' } });
  assert.equal(r.status, 200);
  assert.equal((await r.json()).frameToken, FRAME_TOKEN);
  assert.equal(r.headers.get('access-control-allow-origin'), 'https://front.test');
});
test('auth: wrong key is 401', async () => {
  const r = await get(`${PU}/api/auth`, { method: 'POST', body: JSON.stringify({ token: 'nope' }) });
  assert.equal(r.status, 401);
});
test('auth: bad JSON is 400', async () => {
  const r = await get(`${PU}/api/auth`, { method: 'POST', body: '{not json' });
  assert.equal(r.status, 400);
});
test('auth: missing token field is 401', async () => {
  const r = await get(`${PU}/api/auth`, { method: 'POST', body: '{}' });
  assert.equal(r.status, 401);
});
test('auth: GET is 405 and OPTIONS answers CORS preflight', async () => {
  assert.equal((await get(`${PU}/api/auth`)).status, 405);
  const o = await get(`${PU}/api/auth`, { method: 'OPTIONS' });
  assert.equal(o.status, 204);
  assert.match(o.headers.get('access-control-allow-methods'), /POST/);
});
test('auth: oversized body is rejected', async () => {
  const r = await get(`${PU}/api/auth`, { method: 'POST', body: JSON.stringify({ token: 'x'.repeat(10000) }) }).catch(() => ({ status: 'reset' }));
  assert.ok(r.status === 413 || r.status === 400 || r.status === 'reset', String(r.status));
});
test('session: valid token 200, invalid or missing 401', async () => {
  assert.equal((await get(`${PU}/api/session?t=${FRAME_TOKEN}`)).status, 200);
  assert.equal((await get(`${PU}/api/session?t=bad`)).status, 401);
  assert.equal((await get(`${PU}/api/session`)).status, 401);
  assert.equal((await get(`${PU}/api/session?t=${FRAME_TOKEN}`, { method: 'POST' })).status, 405);
});

/* ---------- proxy: gating ---------- */

test('proxy: missing or wrong token gets the decoy, upstream is never hit', async () => {
  const before = seen.length;
  for (const u of [`${PU}/proxy?url=${encodeURIComponent(UU + '/html')}`, `${PU}/proxy?url=${encodeURIComponent(UU + '/html')}&t=wrong`]) {
    const r = await get(u);
    assert.match(await r.text(), /Welcome/);
  }
  assert.equal(seen.length, before);
});
test('proxy: missing url is 400', async () => {
  assert.equal((await get(`${PU}/proxy?t=${FRAME_TOKEN}`)).status, 400);
});
test('proxy: invalid url is 400', async () => {
  assert.equal((await get(`${PU}/proxy?url=not%20a%20url&t=${FRAME_TOKEN}`)).status, 400);
});
test('proxy: unsupported schemes are 403', async () => {
  assert.equal((await get(purl('file:///etc/passwd'))).status, 403);
  assert.equal((await get(purl('ftp://example.com/'))).status, 403);
});
test('proxy: unsupported methods are 405', async () => {
  assert.equal((await get(purl(UU + '/html'), { method: 'DELETE' })).status, 405);
  assert.equal((await get(purl(UU + '/html'), { method: 'PUT', body: 'x' })).status, 405);
});
test('proxy: OPTIONS preflight is 204 with CORS', async () => {
  const r = await get(purl(UU + '/html'), { method: 'OPTIONS' });
  assert.equal(r.status, 204);
  assert.equal(r.headers.get('access-control-allow-origin'), '*');
});

/* ---------- proxy: content ---------- */

test('proxy: html is rewritten and gets isolation headers', async () => {
  const r = await get(purl(UU + '/html'));
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /^text\/html; charset=utf-8/);
  const csp = r.headers.get('content-security-policy');
  assert.match(csp, /^sandbox allow-scripts allow-forms/);
  assert.ok(!/allow-same-origin/.test(csp), 'sandbox must stay opaque');
  assert.ok(!/allow-top-navigation|allow-popups/.test(csp));
  assert.match(csp, /frame-ancestors https:\/\/front\.test/);
  assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(r.headers.get('referrer-policy'), 'no-referrer');
  const body = await r.text();
  assert.ok(body.includes('/inject.js'));
  assert.ok(body.includes(encodeURIComponent(UU + '/i.png')));
});
test('proxy: permissions policy blocks the sensitive features', async () => {
  const pp = (await get(purl(UU + '/html'))).headers.get('permissions-policy');
  for (const f of ['camera', 'microphone', 'geolocation', 'payment', 'usb']) assert.match(pp, new RegExp(f + '=\\(\\)'));
});
test('proxy: css is rewritten', async () => {
  const r = await get(purl(UU + '/css'));
  assert.match(r.headers.get('content-type'), /^text\/css/);
  assert.ok((await r.text()).includes('/proxy?url=' + encodeURIComponent(UU + '/i.png')));
});
test('proxy: css with no content-type is detected by name', async () => {
  const r = await get(purl(UU + '/noct.css'));
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /^text\/css/); // nosniff would block it otherwise
  assert.ok((await r.text()).includes('/proxy?url=' + encodeURIComponent(UU + '/i.png')));
});
test('proxy: js served as octet-stream gets a javascript type and rewritten imports', async () => {
  const r = await get(purl(UU + '/app.js'));
  assert.equal(r.status, 200);
  assert.match(r.headers.get('content-type'), /^text\/javascript/);
  assert.ok((await r.text()).includes('/proxy?url=' + encodeURIComponent(UU + '/m.js')));
});
test('proxy: binary passes through with its type and caching headers', async () => {
  const r = await get(purl(UU + '/img'));
  assert.equal(r.headers.get('content-type'), 'image/png');
  assert.equal(r.headers.get('cache-control'), 'max-age=60');
  assert.equal(r.headers.get('etag'), '"abc"');
  assert.deepEqual([...Buffer.from(await r.arrayBuffer())], [1, 2, 3, 4]);
});
test('proxy: range requests are forwarded and 206 preserved', async () => {
  const before = seen.length;
  const r = await get(purl(UU + '/range'), { headers: { Range: 'bytes=0-1' } });
  assert.equal(r.status, 206);
  assert.equal(r.headers.get('content-range'), 'bytes 0-1/10');
  assert.equal(seen[before].headers.range, 'bytes=0-1');
});
test('proxy: upstream status codes are preserved', async () => {
  const r = await get(purl(UU + '/404'));
  assert.equal(r.status, 404);
  assert.match(await r.text(), /gone/);
});
test('proxy: legacy charsets are decoded', async () => {
  const r = await get(purl(UU + '/latin'));
  assert.match(await r.text(), /café/);
});
test('proxy: HEAD returns headers without a body', async () => {
  const r = await get(purl(UU + '/img'), { method: 'HEAD' });
  assert.equal(r.status, 200);
  assert.equal((await r.text()), '');
});

/* ---------- proxy: request side ---------- */

test('proxy: sends a fixed user agent and no visitor identity', async () => {
  const before = seen.length;
  await get(purl(UU + '/echo'), { headers: { 'User-Agent': 'MyBrowser/1.0', Cookie: 'secret=1', Authorization: 'Bearer x', 'X-Forwarded-For': '9.9.9.9' } });
  const h = seen[before].headers;
  assert.match(h['user-agent'], /Chrome/);
  assert.ok(!h.cookie && !h.authorization && !h['x-forwarded-for']);
  assert.equal(h['accept-encoding'], 'identity');
});
test('proxy: sets the target site as Referer', async () => {
  const before = seen.length;
  await get(purl(UU + '/echo'));
  assert.equal(seen[before].headers.referer, UU + '/');
});
test('proxy: POST forwards body, content-type and sets Origin', async () => {
  const before = seen.length;
  const r = await get(purl(UU + '/post'), { method: 'POST', body: 'a=1&b=2', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
  assert.equal(await r.text(), 'got:a=1&b=2');
  assert.equal(seen[before].headers['content-type'], 'application/x-www-form-urlencoded');
  assert.equal(seen[before].headers.origin, UU);
});
test('proxy: GET carries no Origin header', async () => {
  const before = seen.length;
  await get(purl(UU + '/echo'));
  assert.equal(seen[before].headers.origin, undefined);
});
test('proxy: oversized POST body is 413', async () => {
  const r = await get(purl(UU + '/post'), { method: 'POST', body: Buffer.alloc(1024 * 1024 + 10, 97), headers: { 'Content-Type': 'text/plain' } }).catch(() => ({ status: 'reset' }));
  assert.ok(r.status === 413 || r.status === 'reset', String(r.status));
});
test('proxy: credentials in the target URL are not forwarded', async () => {
  const before = seen.length;
  const u = new URL(UU + '/echo'); u.username = 'bob'; u.password = 'pw';
  await get(purl(u.href));
  assert.ok(!seen[before].headers.authorization);
});

/* ---------- proxy: GET form rebuilding ---------- */

test('proxy: GET form fields are merged into the real target and ours removed', async () => {
  const before = seen.length;
  const r = await get(`${PU}/proxy?__pt=${FRAME_TOKEN}&__pa=${encodeURIComponent(UU + '/echo?old=1')}&q=hello&t=sitefield&__pf=0`);
  assert.equal(r.status, 200);
  const url = seen[before].url;
  assert.ok(url.includes('q=hello'));
  assert.ok(url.includes('t=sitefield'), 'a site field named t must survive');
  assert.ok(!url.includes('old=1'), 'the action query string is replaced by the form fields');
  assert.ok(!url.includes('__pa') && !url.includes('__pt'));
});
test('proxy: bad form target is 400', async () => {
  assert.equal((await get(`${PU}/proxy?__pt=${FRAME_TOKEN}&__pa=nonsense`)).status, 400);
});
test('proxy: form target pointing at a private host is still refused when private is off', async () => {
  // checkTarget is covered in ssrf.test.js; here we just confirm the form route calls it
  const r = await get(`${PU}/proxy?__pt=${FRAME_TOKEN}&__pa=${encodeURIComponent('ftp://x.test/')}`);
  assert.equal(r.status, 403);
});

/* ---------- proxy: redirects ---------- */

test('proxy: redirects go back through the proxy', async () => {
  const r = await get(purl(UU + '/redir'));
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('location'), `/proxy?url=${encodeURIComponent(UU + '/html')}&t=${FRAME_TOKEN}`);
  assert.equal(r.headers.get('cache-control'), 'no-store');
});
test('proxy: fragment redirects keep __pf', async () => {
  const r = await get(purl(UU + '/redir', '&__pf=1'));
  assert.match(r.headers.get('location'), /&__pf=1$/);
});
test('proxy: redirect to another host is returned as a proxy URL, not followed', async () => {
  const r = await get(purl(UU + '/redir-abs'));
  assert.equal(r.status, 301);
  assert.ok(r.headers.get('location').startsWith('/proxy?url=http%3A%2F%2F127.0.0.1%3A1%2Fx'));
});

/* ---------- proxy: fragments ---------- */

test('fragment: html becomes a script-free fragment with HX-Trigger nav info', async () => {
  const r = await get(purl(UU + '/html', '&__pf=1'));
  assert.equal(r.status, 200);
  const trig = JSON.parse(r.headers.get('hx-trigger'));
  assert.equal(trig['proxy-nav'].url, UU + '/html');
  assert.equal(trig['proxy-nav'].title, 'T');
  const body = await r.text();
  assert.ok(body.startsWith('<div class="pv-doc"'));
  assert.ok(!body.includes('<script'));
  assert.ok(body.includes(PU + '/proxy?url='), 'resource urls are absolute');
});
test('fragment: non-html is wrapped for display', async () => {
  const r = await get(purl(UU + '/img', '&__pf=1'));
  assert.match(await r.text(), /<img src="/);
});
test('fragment: errors come back as fragments too', async () => {
  const r = await get(purl('ftp://x.test/', '&__pf=1'));
  assert.equal(r.status, 403);
  assert.match(await r.text(), /^<div class="pv-doc"/);
});

/* ---------- misc ---------- */

test('proxy: unreachable upstream is a 502', async () => {
  const r = await get(purl('http://127.0.0.1:1/'));
  assert.equal(r.status, 502);
});
test('proxy: error pages escape their message', async () => {
  const r = await get(`${PU}/proxy?url=${encodeURIComponent('http://<img src=x onerror=alert(1)>/')}&t=${FRAME_TOKEN}`);
  assert.ok(!(await r.text()).includes('<img src=x'));
});
