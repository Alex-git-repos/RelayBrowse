'use strict';
process.env.AUTH_TOKEN = 'test-secret';
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../server.js');
const { FRAME_TOKEN } = S;

const BASE = 'https://site.test/dir/page.html';
const P = (abs) => S.prox(abs);

/* ---------- small helpers ---------- */

test('esc escapes html metacharacters', () => {
  assert.equal(S.esc(`<a href="x" onclick='y'>&</a>`), '&lt;a href=&quot;x&quot; onclick=&#39;y&#39;&gt;&amp;&lt;/a&gt;');
  assert.equal(S.esc(5), '5');
  assert.equal(S.esc(''), '');
});
test('enc percent-encodes the characters encodeURIComponent leaves', () => {
  assert.equal(S.enc("a'b(c)d*e!f"), 'a%27b%28c%29d%2Ae%21f');
  assert.equal(S.enc('https://x.test/a b?c=d&e'), 'https%3A%2F%2Fx.test%2Fa%20b%3Fc%3Dd%26e');
});
test('prox builds a tokenised proxy URL', () => {
  assert.equal(P('https://a.test/x?y=1'), `/proxy?url=https%3A%2F%2Fa.test%2Fx%3Fy%3D1&t=${FRAME_TOKEN}`);
});
test('FRAME_TOKEN is a 64-char hex digest, not the secret', () => {
  assert.match(FRAME_TOKEN, /^[0-9a-f]{64}$/);
  assert.notEqual(FRAME_TOKEN, 'test-secret');
});
test('safeEqual compares strings in constant-time form', () => {
  assert.equal(S.safeEqual('abc', 'abc'), true);
  assert.equal(S.safeEqual('abc', 'abd'), false);
  assert.equal(S.safeEqual('', 'x'), false);
  assert.equal(S.safeEqual('a', 'a'.repeat(1000)), false);
});

test('resolveUrl: relative, absolute, protocol-relative, query-only', () => {
  assert.equal(S.resolveUrl('x.css', BASE), 'https://site.test/dir/x.css');
  assert.equal(S.resolveUrl('/x.css', BASE), 'https://site.test/x.css');
  assert.equal(S.resolveUrl('../x.css', BASE), 'https://site.test/x.css');
  assert.equal(S.resolveUrl('//cdn.test/x.js', BASE), 'https://cdn.test/x.js');
  assert.equal(S.resolveUrl('?q=1', BASE), 'https://site.test/dir/page.html?q=1');
  assert.equal(S.resolveUrl('  spaced.png  ', BASE), 'https://site.test/dir/spaced.png');
  assert.equal(S.resolveUrl('http://o.test/a', BASE), 'http://o.test/a');
});
test('resolveUrl: skips non-fetchable schemes and anchors', () => {
  for (const v of ['#top', 'javascript:void(0)', 'JAVASCRIPT:alert(1)', 'data:image/png;base64,AAAA', 'mailto:a@b.c', 'tel:123', 'blob:abc', 'about:blank', '  #x']) {
    assert.equal(S.resolveUrl(v, BASE), null, v);
  }
  assert.equal(S.resolveUrl(null, BASE), null);
  assert.equal(S.resolveUrl(undefined, BASE), null);
});
test('resolveUrl: bad URL returns null', () => {
  assert.equal(S.resolveUrl('http://', BASE), null);
  assert.equal(S.resolveUrl('http://[bad', BASE), null);
});

test('effectiveType: keeps real types', () => {
  assert.equal(S.effectiveType('text/css; charset=utf-8', '/a.css'), 'text/css; charset=utf-8');
  assert.equal(S.effectiveType('application/json', '/a.js'), 'application/json');
});
test('effectiveType: infers from extension when type is missing or generic', () => {
  for (const ct of ['', 'text/plain', 'application/octet-stream', 'binary/octet-stream', 'TEXT/PLAIN; charset=utf-8']) {
    assert.equal(S.effectiveType(ct, '/a/app.js'), 'text/javascript', ct);
    assert.equal(S.effectiveType(ct, '/a/s.CSS'), 'text/css', ct);
    assert.equal(S.effectiveType(ct, '/f.woff2'), 'font/woff2', ct);
    assert.equal(S.effectiveType(ct, '/m.mjs'), 'text/javascript', ct);
    assert.equal(S.effectiveType(ct, '/i.svg'), 'image/svg+xml', ct);
  }
});
test('effectiveType: unknown extension keeps the original', () => {
  assert.equal(S.effectiveType('text/plain', '/readme'), 'text/plain');
  assert.equal(S.effectiveType('', '/x.unknownext'), '');
  assert.equal(S.effectiveType('', undefined), '');
});

test('decodeBody: utf-8 default and header charset', () => {
  assert.equal(S.decodeBody(Buffer.from('héllo', 'utf8'), 'text/html', true), 'héllo');
  assert.equal(S.decodeBody(Buffer.from([0x68, 0xe9]), 'text/html; charset=iso-8859-1', true), 'hé');
});
test('decodeBody: charset from <meta>', () => {
  const buf = Buffer.concat([Buffer.from('<meta charset="windows-1252"><p>'), Buffer.from([0xe9])]);
  assert.match(S.decodeBody(buf, 'text/html', true), /é$/);
});
test('decodeBody: unknown charset falls back to utf-8', () => {
  assert.equal(S.decodeBody(Buffer.from('ok'), 'text/html; charset=bogus-9000', true), 'ok');
});

test('navHeader: valid JSON with non-ASCII escaped', () => {
  const h = S.navHeader('https://a.test/ü', 'Zürich – “x”');
  assert.match(h, /^[\x20-\x7e]*$/);
  assert.deepEqual(JSON.parse(h), { 'proxy-nav': { url: 'https://a.test/ü', title: 'Zürich – “x”' } });
});

test('mapSrcset handles spaced and unspaced commas and descriptors', () => {
  const f = (u) => `<${u}>`;
  assert.equal(S.mapSrcset('a.png 1x, b.png 2x', f), '<a.png> 1x, <b.png> 2x');
  assert.equal(S.mapSrcset('a.png 1x,b.png 2x', f), '<a.png> 1x, <b.png> 2x');
  assert.equal(S.mapSrcset('a.png', f), '<a.png>');
  assert.equal(S.mapSrcset('a.png 100w, b.png 200w, c.png 300w', f), '<a.png> 100w, <b.png> 200w, <c.png> 300w');
});

/* ---------- CSS ---------- */

test('rewriteCss: url() with and without quotes', () => {
  const out = S.rewriteCss(`a{background:url(i.png)} b{background:url("j.png")} c{background:url( 'k.png' )}`, BASE);
  assert.ok(out.includes(`url(${P('https://site.test/dir/i.png')})`));
  assert.ok(out.includes(`url("${P('https://site.test/dir/j.png')}")`));
  assert.ok(out.includes(`url('${P('https://site.test/dir/k.png')}')`));
});
test('rewriteCss: leaves data:, #fragment and already-proxied urls alone', () => {
  const css = `a{background:url(data:image/png;base64,AAAA)} b{filter:url(#blur)} c{background:url(/proxy?url=x&t=y)}`;
  assert.equal(S.rewriteCss(css, BASE), css);
});
test('rewriteCss: @import url() and @import "string"', () => {
  const out = S.rewriteCss(`@import url(a.css); @import "b.css"; @import url("c.css");`, BASE);
  assert.ok(out.includes(`@import url(${P('https://site.test/dir/a.css')})`));
  assert.ok(out.includes(`@import "${P('https://site.test/dir/b.css')}"`));
  assert.ok(out.includes(`@import url("${P('https://site.test/dir/c.css')}")`));
});
test('rewriteCss: @import inside a fragment stylesheet gets scoping flag', () => {
  const out = S.rewriteCss(`@import "b.css";`, BASE, { scoped: true });
  assert.ok(out.includes('&__ps=1'));
});
test('rewriteCss: image-set strings', () => {
  const out = S.rewriteCss(`a{background:image-set("a.png" 1x, "b.png" 2x)}`, BASE);
  assert.ok(out.includes(P('https://site.test/dir/a.png')));
  assert.ok(out.includes(P('https://site.test/dir/b.png')));
  assert.ok(out.includes('1x') && out.includes('2x'));
});
test('rewriteCss: -webkit-image-set', () => {
  const out = S.rewriteCss(`a{background:-webkit-image-set("a.png" 1x)}`, BASE);
  assert.ok(out.includes(P('https://site.test/dir/a.png')));
});
test('rewriteCss: origin prefix is used for fragments and not double-applied', () => {
  const out = S.rewriteCss(`a{background:url(x.png)}`, BASE, { origin: 'https://relay.test' });
  assert.ok(out.includes('url(https://relay.test/proxy?url='));
  assert.equal(S.rewriteCss(out, BASE, { origin: 'https://relay.test' }), out);
});
test('rewriteCss: font-face urls with format() are rewritten', () => {
  const out = S.rewriteCss(`@font-face{font-family:T;src:url(f.woff2) format("woff2"),url(f.woff) format("woff")}`, BASE);
  assert.equal((out.match(/\/proxy\?url=/g) || []).length, 2);
  assert.ok(out.includes('format("woff2")'));
});
test('rewriteCss: urls containing parentheses-safe encoding survive', () => {
  const out = S.rewriteCss(`a{background:url("it's (1).png")}`, BASE);
  assert.ok(!/url\("[^"]*['()][^"]*"\)/.test(out.replace(/\(1\)\.png"\)$/, '')) || out.includes('%27'));
  assert.ok(out.includes('%27') && out.includes('%28'));
});
test('rewriteCss: is idempotent', () => {
  const once = S.rewriteCss(`@import "a.css"; a{background:url(x.png)}`, BASE);
  assert.equal(S.rewriteCss(once, BASE), once);
});
test('rewriteCss: empty input', () => assert.equal(S.rewriteCss('', BASE), ''));
test('rewriteCss: protocol-relative and absolute urls', () => {
  const out = S.rewriteCss(`a{background:url(//cdn.test/a.png)} b{background:url(https://o.test/b.png)}`, BASE);
  assert.ok(out.includes(P('https://cdn.test/a.png')));
  assert.ok(out.includes(P('https://o.test/b.png')));
});

test('scopeCss: html/body/:root become the wrapper', () => {
  assert.equal(S.scopeCss('body{margin:0}'), '.pv-doc{margin:0}');
  assert.equal(S.scopeCss('html{color:red}'), '.pv-doc{color:red}');
  assert.equal(S.scopeCss(':root{--a:1}'), '.pv-doc{--a:1}');
  assert.equal(S.scopeCss('html body{x:y}'), '.pv-doc{x:y}');
  assert.equal(S.scopeCss('body > p, html a{x:y}'), '.pv-doc > p, .pv-doc a{x:y}');
});
test('scopeCss: leaves other selectors alone', () => {
  assert.equal(S.scopeCss('.body{x:y}'), '.body{x:y}');
  assert.equal(S.scopeCss('#html{x:y}'), '#html{x:y}');
  assert.equal(S.scopeCss('bodyguard{x:y}'), 'bodyguard{x:y}');
  assert.equal(S.scopeCss('p{x:y}'), 'p{x:y}');
});

/* ---------- JS ---------- */

test('modSpec: relative and absolute specifiers become proxy urls', () => {
  assert.equal(S.modSpec('./a.js', BASE), P('https://site.test/dir/a.js'));
  assert.equal(S.modSpec('../a.js', BASE), P('https://site.test/a.js'));
  assert.equal(S.modSpec('/a.js', BASE), P('https://site.test/a.js'));
  assert.equal(S.modSpec('https://cdn.test/a.js', BASE), P('https://cdn.test/a.js'));
});
test('modSpec: bare names and proxied urls are untouched', () => {
  assert.equal(S.modSpec('react', BASE), null);
  assert.equal(S.modSpec('@scope/pkg', BASE), null);
  assert.equal(S.modSpec('/proxy?url=x&t=y', BASE), null);
});

test('rewriteJs: no import/export leaves code alone', () => {
  const code = 'var x = 1; fetch("/a");';
  assert.equal(S.rewriteJs(code, BASE), code);
});
test('rewriteJs: static imports and re-exports', () => {
  const out = S.rewriteJs(`import a from './a.js';\nimport {b} from "../b.js";\nexport * from './c.js';\nimport './side.js';`, BASE);
  assert.ok(out.includes(`from './a.js'`) === false);
  assert.ok(out.includes(P('https://site.test/dir/a.js')));
  assert.ok(out.includes(P('https://site.test/b.js')));
  assert.ok(out.includes(P('https://site.test/dir/c.js')));
  assert.ok(out.includes(P('https://site.test/dir/side.js')));
});
test('rewriteJs: bare imports are left for the import map', () => {
  const code = `import React from 'react';`;
  assert.equal(S.rewriteJs(code, BASE), code);
});
test('rewriteJs: dynamic import() goes through __PXI with the real base', () => {
  const out = S.rewriteJs(`import('./x.js').then(m=>m)`, BASE);
  assert.ok(out.startsWith(`__PXI(${JSON.stringify(BASE)},'./x.js')`));
});
test('rewriteJs: does not touch method calls named import', () => {
  const code = `obj.import('x'); loader.import ("y"); export const a = 1;`;
  const out = S.rewriteJs(code, BASE);
  assert.ok(out.includes(`obj.import('x')`));
  assert.ok(out.includes(`loader.import ("y")`));
});
test('rewriteJs: import.meta.url becomes the script real address', () => {
  const out = S.rewriteJs(`export const u = import.meta.url;`, BASE);
  assert.ok(out.includes(`(${JSON.stringify(BASE)})`));
  assert.ok(!out.includes('import.meta.url'));
});
test('rewriteJs: base containing </script> sequences are escaped', () => {
  const out = S.rewriteJs(`import('x'); export {}`, 'https://a.test/</script><b>.js');
  assert.ok(!out.includes('</script>'));
  assert.ok(out.includes('\\u003c'));
});
test('rewriteJs: idempotent for already proxied imports', () => {
  const once = S.rewriteJs(`import a from './a.js';`, BASE);
  assert.equal(S.rewriteJs(once, BASE), once);
});

test('rewriteImportMap: rewrites exact mappings, keeps prefix mappings', () => {
  const out = JSON.parse(S.rewriteImportMap(JSON.stringify({ imports: { a: './a.js', 'b/': './b/', 'https://x.test/y.js': './z.js' } }), BASE));
  assert.equal(out.imports.a, P('https://site.test/dir/a.js'));
  assert.equal(out.imports['b/'], './b/');
  assert.equal(out.imports[P('https://x.test/y.js')], P('https://site.test/dir/z.js'));
});
test('rewriteImportMap: scopes are rewritten too', () => {
  const out = JSON.parse(S.rewriteImportMap(JSON.stringify({ scopes: { '/s/': { a: 'https://cdn.test/a.js' } } }), BASE));
  assert.equal(out.scopes['/s/'].a, P('https://cdn.test/a.js'));
});
test('rewriteImportMap: invalid JSON is returned unchanged', () => {
  assert.equal(S.rewriteImportMap('{nope', BASE), '{nope');
});
test('rewriteImportMap: escapes < so it cannot close the script tag', () => {
  const out = S.rewriteImportMap(JSON.stringify({ imports: { a: 'https://x.test/</script>' } }), BASE);
  assert.ok(!out.includes('</script>'));
});

/* ---------- HTML ---------- */

const html = (inner, head = '') => `<!doctype html><html><head>${head}</head><body>${inner}</body></html>`;
// Serialised attributes carry "&amp;" (correct HTML); undo it so URLs can be compared as written.
const unamp = (s) => s.replace(/&amp;/g, '&');
const rw = (inner, head, base = BASE) => unamp(S.rewriteHtml(html(inner, head), base));

test('rewriteHtml: injects the proxy bootstrap first in <head>', () => {
  const out = rw('<p>x</p>', '<title>t</title>');
  const head = out.slice(out.indexOf('<head>'), out.indexOf('<title>'));
  assert.ok(head.includes('window.__PROXY_BASE__='));
  assert.ok(head.includes('<script src="/inject.js"></script>'));
  assert.ok(head.includes(`window.__PROXY_TOKEN__="${FRAME_TOKEN}"`));
});
test('rewriteHtml: stylesheet, script, image, media attributes', () => {
  const out = rw(
    '<img src="a.png"><script src="s.js"></script><video src="v.mp4" poster="p.png"></video><audio src="a.mp3"></audio><source src="s.webm"><track src="t.vtt"><embed src="e.swf"><input type="image" src="i.png">',
    '<link rel="stylesheet" href="c.css">');
  for (const f of ['a.png', 's.js', 'v.mp4', 'p.png', 'a.mp3', 's.webm', 't.vtt', 'e.swf', 'i.png', 'c.css']) {
    assert.ok(out.includes(`url=${S.enc('https://site.test/dir/' + f)}`), f);
  }
});
test('rewriteHtml: links and areas', () => {
  const out = rw('<a href="/x">x</a><map><area href="y"></map>');
  assert.ok(out.includes(`href="${P('https://site.test/x')}"`));
  assert.ok(out.includes(`href="${P('https://site.test/dir/y')}"`));
});
test('rewriteHtml: anchors, mailto, tel and javascript: links are not touched', () => {
  const out = rw('<a href="#top">a</a><a href="mailto:a@b.c">b</a><a href="tel:1">c</a><a href="javascript:void(0)">d</a>');
  for (const h of ['#top', 'mailto:a@b.c', 'tel:1', 'javascript:void(0)']) assert.ok(out.includes(`href="${h}"`), h);
});
test('rewriteHtml: srcset and imagesrcset', () => {
  const out = rw('<img srcset="a.png 1x,b.png 2x">', '<link rel="preload" as="image" href="a.png" imagesrcset="c.png 1x, d.png 2x">');
  for (const f of ['a.png', 'b.png', 'c.png', 'd.png']) assert.ok(out.includes(S.enc('https://site.test/dir/' + f)), f);
});
test('rewriteHtml: <base href> is honoured then removed', () => {
  const out = rw('<img src="a.png">', '<base href="https://other.test/root/">');
  assert.ok(!/<base/i.test(out));
  assert.ok(out.includes(S.enc('https://other.test/root/a.png')));
  assert.ok(out.includes('window.__PROXY_BASE__="https://other.test/root/"'));
  assert.ok(out.includes(`window.__PROXY_URL__=${JSON.stringify(BASE)}`));
});
test('rewriteHtml: strips CSP and X-Frame-Options meta, integrity, nonce, crossorigin', () => {
  const out = rw('<script src="a.js" integrity="sha256-x" nonce="n" crossorigin="anonymous"></script>',
    `<meta http-equiv="Content-Security-Policy" content="default-src 'none'"><meta http-equiv="X-Frame-Options" content="DENY"><meta http-equiv="content-type" content="text/html">`);
  assert.ok(!/Content-Security-Policy/i.test(out));
  assert.ok(!/X-Frame-Options/i.test(out));
  assert.ok(!/integrity=|nonce=|crossorigin=/.test(out));
  assert.ok(/content-type/i.test(out), 'unrelated meta kept');
});
test('rewriteHtml: meta refresh is proxied', () => {
  const out = rw('', '<meta http-equiv="refresh" content="5; url=/next">');
  assert.ok(out.includes(`content="5; url=${P('https://site.test/next')}"`));
});
test('rewriteHtml: meta refresh with quoted url', () => {
  const out = rw('', `<meta http-equiv="refresh" content="0;URL='/n'">`);
  assert.ok(out.includes(P('https://site.test/n')));
});
test('rewriteHtml: GET form gets hidden token and target fields', () => {
  const out = rw('<form action="/search"><input name="q"></form>');
  assert.ok(out.includes('action="/proxy"'));
  assert.ok(out.includes(`name="__pt" value="${FRAME_TOKEN}"`));
  assert.ok(out.includes('name="__pa" value="https://site.test/search"'));
});
test('rewriteHtml: POST form action is proxied', () => {
  const out = rw('<form method="POST" action="/login"></form>');
  assert.ok(out.includes(`action="${P('https://site.test/login')}"`));
  assert.ok(!out.includes('__pa'));
});
test('rewriteHtml: form with no action posts back to the page', () => {
  const out = rw('<form method="post"></form>');
  assert.ok(out.includes(`action="${P(BASE)}"`));
});
test('rewriteHtml: form action containing quotes is escaped', () => {
  const out = rw(`<form action='/s?a="b"'></form>`);
  assert.ok(!out.includes('value="https://site.test/s?a="b""'));
});
test('rewriteHtml: target attributes forced to _self, ping removed', () => {
  const out = rw('<a href="/x" target="_blank" ping="https://t.test/p">x</a><form target="_top"></form>');
  assert.ok(!out.includes('_blank') && !out.includes('_top') && !out.includes('ping='));
  assert.ok(out.includes('target="_self"'));
});
test('rewriteHtml: formaction proxied or removed', () => {
  const out = rw('<form method="post"><button formaction="/go">a</button><button formaction="javascript:x()">b</button></form>');
  assert.ok(out.includes(`formaction="${P('https://site.test/go')}"`));
  assert.ok(!out.includes('javascript:x'));
});
test('rewriteHtml: <style> blocks and style attributes', () => {
  const out = rw('<p style="background:url(b.png)">x</p>', '<style>a{background:url(a.png)}</style>');
  assert.ok(out.includes(S.enc('https://site.test/dir/a.png')));
  assert.ok(out.includes(S.enc('https://site.test/dir/b.png')));
});
test('rewriteHtml: legacy background attributes', () => {
  const out = S.rewriteHtml('<body background="bg.png"><table background="t.png"><tr><td background="td.png">x</td></tr></table></body>', BASE);
  for (const f of ['bg.png', 't.png', 'td.png']) assert.ok(out.includes(S.enc('https://site.test/dir/' + f)), f);
});
test('rewriteHtml: inline module script imports are rewritten', () => {
  const out = rw(`<script type="module">import {a} from './m.js'; import('./n.js');</script>`);
  assert.ok(out.includes(S.enc('https://site.test/dir/m.js')));
  assert.ok(out.includes('__PXI('));
});
test('rewriteHtml: inline importmap is rewritten, other script types untouched', () => {
  const out = rw(`<script type="importmap">{"imports":{"a":"./a.js"}}</script><script type="application/ld+json">{"import":"./x"}</script>`);
  assert.ok(out.includes(S.enc('https://site.test/dir/a.js')));
  assert.ok(out.includes('{"import":"./x"}'));
});
test('rewriteHtml: inline classic scripts without import keep their text exactly', () => {
  const code = `window.x = "a > b && c";`;
  const out = rw(`<script>${code}</script>`);
  assert.ok(out.includes(code));
});
test('rewriteHtml: page URL in the bootstrap cannot break out of the script tag', () => {
  const out = S.rewriteHtml('<p>x</p>', 'https://a.test/</script><script>alert(1)</script>');
  const boot = out.slice(0, out.indexOf('/inject.js'));
  assert.ok(!boot.includes('</script><script>alert'));
});
test('rewriteHtml: iframes are proxied', () => {
  const out = rw('<iframe src="/f"></iframe>');
  assert.ok(out.includes(P('https://site.test/f')));
});
test('rewriteHtml: svg <image> href and xlink:href', () => {
  const out = rw('<svg><image href="a.png"/><image xlink:href="b.png"/></svg>');
  assert.ok(out.includes(S.enc('https://site.test/dir/a.png')));
  assert.ok(out.includes(S.enc('https://site.test/dir/b.png')));
});
test('rewriteHtml: object data attribute', () => {
  assert.ok(rw('<object data="o.swf"></object>').includes(S.enc('https://site.test/dir/o.swf')));
});

/* ---------- fragments ---------- */

const ORIGIN = 'https://relay.test';
const frag = (inner, head = '') => {
  const f = S.rewriteFragment(html(inner, head), BASE, ORIGIN);
  return { ...f, html: unamp(f.html) };
};

test('rewriteFragment: title extracted and wrapped in pv-doc', () => {
  const f = frag('<p>hi</p>', '<title>  My   Page </title>');
  assert.equal(f.title, 'My Page');
  assert.ok(f.html.startsWith('<div class="pv-doc"'));
  assert.ok(f.html.includes('<p>hi</p>'));
  assert.ok(!f.html.includes('<title'));
});
test('rewriteFragment: scripts, frames, objects, base, meta removed', () => {
  const f = frag('<script>x()</script><iframe src="/a"></iframe><object data="o"></object><embed src="e"><p>k</p>', '<base href="/"><meta charset="utf-8">');
  for (const t of ['<script', '<iframe', '<object', '<embed', '<base', '<meta']) assert.ok(!f.html.includes(t), t);
  assert.ok(f.html.includes('<p>k</p>'));
});
test('rewriteFragment: inline handlers and hx-* attributes dropped', () => {
  const f = frag('<a href="/x" onclick="evil()" hx-get="/steal" data-hx-post="/p" onmouseover="e()">x</a><div hx-trigger="load" hx-get="/x"></div>');
  assert.ok(!/onclick|onmouseover|data-hx-|hx-trigger/.test(f.html));
  assert.ok(!f.html.includes('/steal'));
});
test('rewriteFragment: srcdoc, integrity, nonce, crossorigin, target dropped', () => {
  const f = frag('<img src="a.png" crossorigin="anonymous" integrity="x" nonce="n"><a href="/x" target="_blank">x</a>');
  assert.ok(!/srcdoc|integrity|nonce|crossorigin|_blank/.test(f.html));
});
test('rewriteFragment: javascript: and data:text/html URLs removed', () => {
  const f = frag('<a href="javascript:alert(1)">a</a><img src="JavaScript:alert(1)"><a href="data:text/html,<script>x</script>">b</a>');
  assert.ok(!/javascript:/i.test(f.html));
  assert.ok(!/data:text\/html/i.test(f.html));
});
test('rewriteFragment: links get hx-get with __pf and absolute origin', () => {
  const f = frag('<a href="/x">x</a>');
  assert.ok(f.html.includes(`hx-get="${ORIGIN}${P('https://site.test/x')}&amp;__pf=1"`) || f.html.includes(`hx-get="${ORIGIN}${P('https://site.test/x')}&__pf=1"`));
  assert.ok(f.html.includes('hx-swap="none"'));
});
test('rewriteFragment: anchors stay as they are', () => {
  const f = frag('<a href="#sec">x</a>');
  assert.ok(f.html.includes('href="#sec"'));
  assert.ok(!f.html.includes('hx-get'));
});
test('rewriteFragment: images and stylesheets use absolute proxy urls', () => {
  const f = frag('<img src="a.png">', '<link rel="stylesheet" href="c.css">');
  assert.ok(f.html.includes(ORIGIN + P('https://site.test/dir/a.png')));
  assert.ok(f.html.includes(ORIGIN + P('https://site.test/dir/c.css')));
  assert.ok(f.html.includes('__ps=1'));
});
test('rewriteFragment: non-stylesheet <link> elements removed', () => {
  const f = frag('<p>x</p>', '<link rel="icon" href="/f.ico"><link rel="preload" href="/p.js" as="script">');
  assert.ok(!f.html.includes('f.ico') && !f.html.includes('p.js'));
});
test('rewriteFragment: GET form becomes hx-get with hidden fields', () => {
  const f = frag('<form action="/s"><input name="q"></form>');
  assert.ok(f.html.includes(`hx-get="${ORIGIN}/proxy"`));
  assert.ok(f.html.includes('name="__pa"') && f.html.includes('name="__pf"'));
  assert.ok(!f.html.includes('action='));
});
test('rewriteFragment: POST form becomes hx-post, multipart sets encoding', () => {
  const f = frag('<form method="post" action="/p" enctype="multipart/form-data"></form>');
  assert.ok(f.html.includes('hx-post='));
  assert.ok(f.html.includes('hx-encoding="multipart/form-data"'));
  assert.ok(!f.html.includes('enctype'));
});
test('rewriteFragment: <style> is scoped to the wrapper and moved to the front', () => {
  const f = frag('<p>x</p>', '<style>body{margin:0}</style>');
  assert.ok(f.html.includes('.pv-doc{margin:0}'));
  assert.ok(f.html.indexOf('<style') < f.html.indexOf('<p>x</p>'));
});
test('rewriteFragment: body class/bgcolor/style carried onto wrapper', () => {
  const f = S.rewriteFragment('<html class="h"><body class="b" bgcolor="#fff" style="color:red"><p>x</p></body></html>', BASE, ORIGIN);
  assert.ok(/class="pv-doc b h"/.test(f.html));
  assert.ok(f.html.includes('background-color:#fff;color:red'));
});
test('rewriteFragment: <noscript> content is exposed', () => {
  const f = frag('<noscript><img src="n.png"></noscript>');
  assert.ok(f.html.includes('n.png') || f.html.includes(S.enc('https://site.test/dir/n.png')));
  assert.ok(!f.html.includes('<noscript'));
});
test('rewriteFragment: empty body is fine', () => {
  const f = S.rewriteFragment('', BASE, ORIGIN);
  assert.equal(f.title, '');
  assert.ok(f.html.startsWith('<div class="pv-doc"'));
});

test('nonHtmlFragment: images, video, audio embed; others link', () => {
  assert.match(S.nonHtmlFragment('image/png', 'https://a.test/x.png', ORIGIN), /<img src="https:\/\/relay\.test\/proxy/);
  assert.match(S.nonHtmlFragment('video/mp4; x=y', 'https://a.test/x.mp4', ORIGIN), /<video /);
  assert.match(S.nonHtmlFragment('audio/ogg', 'https://a.test/x.ogg', ORIGIN), /<audio /);
  const other = S.nonHtmlFragment('application/pdf', 'https://a.test/x.pdf', ORIGIN);
  assert.match(other, /application\/pdf/);
  assert.match(other, /<a href=/);
});
test('nonHtmlFragment: content type is escaped', () => {
  const out = S.nonHtmlFragment('x/<script>alert(1)</script>', 'https://a.test/x', ORIGIN);
  assert.ok(!out.includes('<script>'));
});
