'use strict';
process.env.AUTH_TOKEN = 'test-secret';
delete process.env.ALLOW_PRIVATE;
const test = require('node:test');
const assert = require('node:assert/strict');
const { unmap, isBlockedAddress, checkTarget } = require('../server.js');

const T = (s, self) => checkTarget(new URL(s), self);

test('unmap: IPv4-mapped IPv6, dotted form', () => {
  assert.equal(unmap('::ffff:127.0.0.1'), '127.0.0.1');
  assert.equal(unmap('::FFFF:10.1.2.3'), '10.1.2.3');
});
test('unmap: IPv4-mapped IPv6, hex form', () => {
  assert.equal(unmap('::ffff:7f00:1'), '127.0.0.1');
  assert.equal(unmap('::ffff:a9fe:a9fe'), '169.254.169.254');
});
test('unmap: leaves ordinary addresses alone', () => {
  assert.equal(unmap('8.8.8.8'), '8.8.8.8');
  assert.equal(unmap('2606:4700::1111'), '2606:4700::1111');
});

for (const ip of [
  '0.0.0.0', '0.1.2.3', '10.0.0.1', '10.255.255.255', '100.64.0.1', '100.127.255.254', '127.0.0.1', '127.1.2.3',
  '169.254.169.254', '172.16.0.1', '172.31.255.255', '192.0.0.1', '192.0.2.5', '192.168.0.1', '192.168.255.255',
  '198.18.0.1', '198.19.255.255', '198.51.100.7', '203.0.113.9', '224.0.0.1', '239.255.255.255', '240.0.0.1', '255.255.255.255',
  '::', '::1', 'fc00::1', 'fd12:3456::1', 'fe80::1', 'fe80::1%eth0', 'fec0::1', 'ff02::1', '100::1', '2001::1', '2001:db8::1',
  '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:10.0.0.1', '::ffff:c0a8:1',
  '64:ff9b::7f00:1', '64:ff9b::a00:1', '2002:7f00:1::1', '2002:c0a8:1::',
]) {
  test(`isBlockedAddress blocks ${ip}`, () => assert.equal(isBlockedAddress(ip), true));
}

for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.255.255', '172.32.0.1', '100.63.255.255', '100.128.0.1',
  '169.253.1.1', '192.167.1.1', '198.17.255.255', '198.20.0.1', '223.255.255.255',
  '2606:4700:4700::1111', '2a00:1450:4001::200e', '64:ff9b::808:808', '2002:808:808::1']) {
  test(`isBlockedAddress allows public ${ip}`, () => assert.equal(isBlockedAddress(ip), false));
}

test('isBlockedAddress refuses anything unparseable', () => {
  for (const bad of ['', 'not-an-ip', '999.1.1.1', '1.2.3', '1.2.3.4.5', 'g::1', undefined, null]) {
    assert.equal(isBlockedAddress(bad), true, String(bad));
  }
});

test('checkTarget: only http and https', () => {
  for (const u of ['ftp://example.com/', 'file:///etc/passwd', 'gopher://example.com/', 'ws://example.com/', 'data:text/html,hi']) {
    assert.match(T(u) || '', /http/i, u);
  }
});
test('checkTarget: public sites pass', () => {
  for (const u of ['http://example.com/', 'https://example.com/a/b?c=d', 'https://sub.example.co.uk:8443/', 'http://example.com:8080/', 'https://8.8.8.8/', 'https://[2606:4700:4700::1111]/']) {
    assert.equal(T(u), null, u);
  }
});
test('checkTarget: disallowed ports', () => {
  for (const u of ['http://example.com:22/', 'http://example.com:25/', 'https://example.com:6379/', 'http://example.com:3306/', 'http://example.com:9200/']) {
    assert.match(T(u) || '', /Port \d+ is not allowed/, u);
  }
});
test('checkTarget: default ports are allowed', () => {
  assert.equal(T('http://example.com:80/'), null);
  assert.equal(T('https://example.com:443/'), null);
});
test('checkTarget: private IP literals, however written', () => {
  for (const u of ['http://127.0.0.1/', 'http://2130706433/', 'http://0x7f.1/', 'http://0177.0.0.1/', 'http://127.1/', 'http://[::1]/', 'http://[::ffff:127.0.0.1]/',
    'http://169.254.169.254/latest/meta-data/', 'http://10.0.0.5/', 'http://192.168.1.1/', 'http://[fe80::1]/', 'http://0.0.0.0/']) {
    assert.match(T(u) || '', /private network/, u);
  }
});
test('checkTarget: internal-only hostnames', () => {
  for (const u of ['http://localhost/', 'http://LOCALHOST/', 'http://localhost./', 'http://foo.localhost/', 'http://printer.local/', 'http://db.internal/', 'http://x.localdomain/', 'http://router.home.arpa/', 'http://redis.svc/']) {
    assert.match(T(u) || '', /private network/, u);
  }
});
test('checkTarget: single-label hostnames', () => {
  for (const u of ['http://router/', 'http://redis/', 'http://metadata/']) assert.match(T(u) || '', /private network/, u);
});
test('checkTarget: names that merely contain internal words are fine', () => {
  for (const u of ['http://localhost.example.com/', 'http://example.local.test.com/', 'http://myinternal.com/', 'http://notlocal.com/']) assert.equal(T(u), null, u);
});
test('checkTarget: refuses the proxy itself', () => {
  assert.match(T('https://proxy.example.com/', 'proxy.example.com') || '', /itself/);
  assert.equal(T('https://other.example.com/', 'proxy.example.com'), null);
});
test('checkTarget: trailing dot on own host is still refused', () => {
  assert.match(T('https://proxy.example.com./', 'proxy.example.com') || '', /itself/);
});
test('checkTarget: credentials in the URL do not hide the host', () => {
  assert.match(T('http://example.com@127.0.0.1/') || '', /private network/);
  assert.match(T('http://user:pw@localhost/') || '', /private network/);
});
test('checkTarget: bracketed IPv6 public address works', () => {
  assert.equal(T('http://[2a00:1450:4001::200e]/'), null);
});
