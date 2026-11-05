import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createAssignments, parseParticipants } from '../src/matching.js';
import { ADMIN_TTL, ASSIGNMENT_TTL, createTokenService } from '../src/tokens.js';

const env = {
  ADMIN_PASSWORD: 'a-long-test-password-only',
  SESSION_SECRET: 'a-test-only-secret-with-at-least-32-bytes-of-material',
  PARTICIPANTS: 'Alice,Bob,Charlie,Dave',
};

test('configuration rejects missing or unsafe secrets and production origins', () => {
  assert.throws(() => loadConfig({}), /ADMIN_PASSWORD/);
  assert.throws(() => loadConfig({ ...env, SESSION_SECRET: 'short' }), /SESSION_SECRET/);
  assert.throws(() => loadConfig({ ...env, PORT: 'NaN' }), /PORT/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production' }), /APP_URL/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production', APP_URL: 'http://example.com' }), /HTTPS/);
  assert.throws(() => loadConfig({ ...env, APP_URL: 'https://example.com/path' }), /path/);
  assert.throws(() => loadConfig({ ...env, APP_URL: 'https://user:pass@example.com' }), /credentials/);
  assert.throws(() => loadConfig({ ...env, TRUST_PROXY: 'true' }), /TRUST_PROXY/);
  assert.equal(loadConfig({ ...env, NODE_ENV: 'production', RAILWAY_PUBLIC_DOMAIN: 'santa.up.railway.app' }).origin, 'https://santa.up.railway.app');
});

test('participant parsing handles lines, commas, Unicode, and rejects ambiguity', () => {
  assert.deepEqual(parseParticipants(' Alice, Bob\r\nChloé\nDave, '), ['Alice', 'Bob', 'Chloé', 'Dave']);
  for (const input of ['', 'Alice', 'Alice,alice', 'Éva,E\u0301va', 'Bob,Ｂｏｂ', `Alice,${'x'.repeat(81)}`, 'Alice,Bob\u202E', Array.from({ length: 101 }, (_, i) => `Person ${i}`).join(',')]) {
    assert.throws(() => parseParticipants(input));
  }
});

test('derangements give and receive exactly once, never oneself, including two participants', () => {
  for (const size of [2, 3, 4, 10, 100]) {
    const names = Array.from({ length: size }, (_, i) => `Person ${i}`);
    for (let attempt = 0; attempt < 100; attempt++) {
      const assignments = createAssignments(names);
      assert.deepEqual(assignments.map(a => a.giver), names);
      assert.deepEqual(assignments.map(a => a.recipient).sort(), [...names].sort());
      assert.ok(assignments.every(a => a.giver !== a.recipient));
    }
  }
  assert.deepEqual(createAssignments(['Alice', 'Bob']), [{ giver: 'Alice', recipient: 'Bob' }, { giver: 'Bob', recipient: 'Alice' }]);
});

test('authenticated encryption hides contents, randomizes tokens, and separates purposes', () => {
  const tokens = createTokenService(env.SESSION_SECRET);
  const data = { giver: 'Alice', recipient: 'Bob', drawId: 'draw-1' };
  const token = tokens.seal('invitation', data, ASSIGNMENT_TTL);
  assert.equal(tokens.open('invitation', token).recipient, 'Bob');
  assert.notEqual(token, tokens.seal('invitation', data, ASSIGNMENT_TTL));
  assert.equal(token.includes('Alice'), false);
  assert.equal(tokens.open('admin', token), null);
  assert.equal(tokens.open('assignment', token), null);
  assert.equal(createTokenService('another-entirely-different-secret').open('invitation', token), null);
  const bytes = Buffer.from(token.slice(3), 'base64url');
  bytes[30] ^= 1;
  assert.equal(tokens.open('invitation', `v1.${bytes.toString('base64url')}`), null);
  for (const value of [undefined, null, {}, '', 'v1.bad', `${token}=`, 'x'.repeat(4000)]) {
    assert.equal(tokens.open('invitation', value), null);
  }
});

test('tokens enforce expiration, issuance time and maximum lifetime', () => {
  let now = 10000000;
  const tokens = createTokenService(env.SESSION_SECRET, () => now);
  const token = tokens.seal('invitation', { giver: 'Alice' }, ASSIGNMENT_TTL);
  now += ASSIGNMENT_TTL - 1;
  assert.ok(tokens.open('invitation', token));
  now++;
  assert.equal(tokens.open('invitation', token), null);
  assert.equal(tokens.open('admin', tokens.seal('admin', {}, ADMIN_TTL + 1)), null);
  const future = tokens.seal('assignment', {}, ASSIGNMENT_TTL);
  now--;
  assert.equal(tokens.open('assignment', future), null);
});

async function fixture(t, overrides = {}) {
  const config = { ...loadConfig({ ...env, ...overrides }) };
  const server = createApp(config).listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = `http://127.0.0.1:${server.address().port}`;
  if (!config.production) config.origin = address;
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  function client(initialCookies = new Map()) {
    const cookies = new Map(initialCookies);
    async function request(path, fields, headers = {}) {
      const response = await fetch(`${address}${path}`, {
        method: fields === undefined ? 'GET' : 'POST', redirect: 'manual',
        headers: { Cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; '), ...(fields === undefined ? {} : { Origin: config.origin }), ...headers },
        ...(fields === undefined ? {} : { body: new URLSearchParams(fields) }),
      });
      for (const cookie of response.headers.getSetCookie()) {
        const pair = cookie.split(';')[0];
        const equals = pair.indexOf('=');
        const expires = cookie.match(/Expires=([^;]+)/u)?.[1];
        const deleted = /Max-Age=0(?:;|$)/u.test(cookie) || (expires && Date.parse(expires) <= Date.now());
        if (pair.slice(equals + 1) && !deleted) cookies.set(pair.slice(0, equals), pair.slice(equals + 1));
        else cookies.delete(pair.slice(0, equals));
      }
      const text = await response.text();
      return { status: response.status, headers: response.headers, text, csrf: text.match(/name="_csrf" value="([a-f0-9]+)"/u)?.[1] };
    }
    return { request, cookies };
  }
  return { config, client, tokens: createTokenService(config.sessionSecret) };
}

async function login(admin) {
  const page = await admin.request('/admin');
  assert.equal(page.status, 200);
  const result = await admin.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD });
  assert.equal(result.status, 303);
  return admin.request('/admin');
}

const getLinks = page => [...page.text.matchAll(/type="text" value="(https?:[^" ]+#token=v1\.[A-Za-z0-9_-]+)"/gu)].map(match => match[1]);

test('full admin-to-participant flow persists encrypted assignments across app restarts', async t => {
  const f = await fixture(t);
  const admin = f.client();
  const dashboard = await login(admin);
  assert.match(dashboard.text, /Alice\nBob\nCharlie\nDave/u);
  const generated = await admin.request('/admin/generate', { _csrf: dashboard.csrf, participants: 'Alice,Bob,Charlie,Dave' });
  assert.equal(generated.status, 200);
  const links = getLinks(generated);
  assert.equal(links.length, 4);
  const assignments = links.map(link => f.tokens.open('invitation', new URL(link).hash.slice(7)));
  assert.ok(assignments.every(a => a.giver !== a.recipient));
  assert.equal(new Set(assignments.map(a => a.recipient)).size, 4);

  const participant = f.client();
  const welcome = await participant.request('/reveal');
  assert.doesNotMatch(welcome.text, /class="recipient"/u);
  assert.match(welcome.text, /<html lang="es">/u);
  const redemption = await participant.request('/reveal', { _csrf: welcome.csrf, token: links[0] });
  assert.equal(redemption.status, 303);
  assert.equal(redemption.headers.get('location'), '/reveal');
  const cookie = redemption.headers.getSetCookie().find(value => value.startsWith('santa_assignment='));
  assert.match(cookie, /Max-Age=5184000/u);
  assert.match(cookie, /HttpOnly/u);
  assert.match(cookie, /SameSite=Lax/u);
  assert.doesNotMatch(cookie, /Alice|Bob|Charlie|Dave/u);
  const reveal = await participant.request('/');
  assert.match(reveal.text, new RegExp(`class="recipient">${assignments[0].recipient}<`));
  assert.match(reveal.text, /TE TOCA REGALARLE A/u);
  const restarted = await fixture(t);
  const remembered = restarted.client(participant.cookies);
  assert.match((await remembered.request('/reveal')).text, new RegExp(`class="recipient">${assignments[0].recipient}<`));
  const adminAfterRestart = restarted.client(admin.cookies);
  assert.match((await adminAfterRestart.request('/admin')).text, /The guest list/u);
  // No server-side copy of the links or a transient draw/session Map exists.
  assert.equal(getLinks(await adminAfterRestart.request('/admin')).length, 0);
  const forgotten = await participant.request('/forget', { _csrf: reveal.csrf });
  assert.equal(forgotten.status, 303);
  assert.doesNotMatch((await participant.request('/')).text, /class="recipient"/u);
});

test('late redemption starts its own full 60-day cookie lifetime', async t => {
  const f = await fixture(t);
  const oldTokens = createTokenService(env.SESSION_SECRET, () => Math.floor(Date.now() / 1000) - ASSIGNMENT_TTL + 60);
  const invitation = oldTokens.seal('invitation', { giver: 'Alice', recipient: 'Bob', drawId: 'old-draw' }, ASSIGNMENT_TTL);
  const browser = f.client();
  const home = await browser.request('/');
  const response = await browser.request('/reveal', { _csrf: home.csrf, token: invitation });
  assert.equal(response.status, 303);
  const value = decodeURIComponent(browser.cookies.get('santa_assignment'));
  const signed = cookieUnsign(value, f.tokens.cookieSecret);
  const assignment = f.tokens.open('assignment', signed);
  assert.equal(assignment.exp - assignment.iat, ASSIGNMENT_TTL);
  assert.ok(assignment.exp > Math.floor(Date.now() / 1000) + ASSIGNMENT_TTL - 5);
});

// cookie-parser's public helper also verifies the cookie signature independently.
import cookieParser from 'cookie-parser';
const cookieUnsign = (value, secret) => cookieParser.signedCookie(value, secret);

test('CSRF, cross-origin requests, authentication failures and logout are enforced', async t => {
  const f = await fixture(t);
  const browser = f.client();
  assert.equal((await browser.request('/admin/generate', { participants: 'Alice,Bob' })).status, 303);
  const page = await browser.request('/admin');
  assert.equal((await browser.request('/admin/login', { password: env.ADMIN_PASSWORD })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { Origin: 'null' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { Origin: 'null', 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: 'wrong-password' })).status, 401);
  const dashboard = await login(browser);
  // Browsers can send null origins for no-referrer form navigations.
  assert.equal((await browser.request('/admin/generate', { _csrf: dashboard.csrf, participants: 'Alice,Bob' }, { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' })).status, 200);
  assert.equal((await browser.request('/admin/generate', { participants: 'Alice,Bob' })).status, 403);
  assert.equal((await browser.request('/admin/generate', { _csrf: dashboard.csrf, participants: 'Alice,Alice' })).status, 400);
  assert.equal((await browser.request('/admin/logout', { _csrf: dashboard.csrf })).status, 303);
  assert.match((await browser.request('/admin')).text, /name="password"/u);
  assert.equal((await browser.request('/admin/generate', { _csrf: dashboard.csrf, participants: 'Alice,Bob' })).status, 303);
});

test('invalid invitations cannot overwrite an existing match and names are HTML escaped', async t => {
  const f = await fixture(t);
  const browser = f.client();
  const home = await browser.request('/');
  const dangerous = '<img src=x onerror=alert(1)>';
  const invitation = f.tokens.seal('invitation', { giver: dangerous, recipient: '<script>alert(1)</script>', drawId: 'test' }, ASSIGNMENT_TTL);
  assert.equal((await browser.request('/reveal', { _csrf: home.csrf, token: invitation })).status, 303);
  const saved = browser.cookies.get('santa_assignment');
  assert.equal((await browser.request('/reveal', { _csrf: home.csrf, token: `${invitation}x` })).status, 400);
  assert.equal(browser.cookies.get('santa_assignment'), saved);
  const reveal = await browser.request('/reveal');
  assert.match(reveal.text, /&lt;script&gt;/u);
  assert.doesNotMatch(reveal.text, /<img src=x|<script>alert/u);
  const admin = f.client();
  const dashboard = await login(admin);
  const generated = await admin.request('/admin/generate', { _csrf: dashboard.csrf, participants: `${dangerous},Bob` });
  assert.equal(generated.status, 200);
  assert.doesNotMatch(generated.text, /<img src=x/u);
  assert.match(generated.text, /&lt;img/u);
});

test('production sends secure host-only cookies, HTTPS redirects and security headers', async t => {
  const f = await fixture(t, { NODE_ENV: 'production', APP_URL: 'https://santa.example' });
  const browser = f.client();
  assert.equal((await browser.request('/health')).status, 200);
  const redirect = await browser.request('/admin');
  assert.equal(redirect.status, 308);
  assert.equal(redirect.headers.get('location'), 'https://santa.example/admin');
  const page = await browser.request('/admin', undefined, { 'X-Forwarded-Proto': 'https' });
  assert.equal(page.status, 200);
  const cookies = page.headers.getSetCookie();
  assert.ok(cookies.every(cookie => cookie.startsWith('__Host-') && cookie.includes('Secure') && cookie.includes('HttpOnly') && cookie.includes('Path=/') && !cookie.includes('Domain=')));
  assert.equal(page.headers.get('cache-control'), 'no-store');
  assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/u);
  assert.ok(page.headers.get('strict-transport-security'));
  assert.equal(page.headers.get('x-powered-by'), null);
  const session = await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { 'X-Forwarded-Proto': 'https' });
  assert.equal(session.status, 303);
  assert.ok(session.headers.getSetCookie().some(cookie => cookie.startsWith('__Host-santa_admin=') && cookie.includes('Secure')));
});

test('password changes invalidate existing admin sessions; expired and tampered cookies fail closed', async t => {
  const first = await fixture(t);
  const admin = first.client();
  await login(admin);
  const changed = await fixture(t, { ADMIN_PASSWORD: 'a-new-and-different-password' });
  const browser = changed.client(admin.cookies);
  assert.match((await browser.request('/admin')).text, /name="password"/u);
  const visitor = first.client(new Map([['santa_assignment', 's%3Av1.bad.not-a-signature']]));
  assert.doesNotMatch((await visitor.request('/')).text, /class="recipient"/u);
  assert.equal(visitor.cookies.has('santa_assignment'), false);
  const expiredService = createTokenService(env.SESSION_SECRET, () => Math.floor(Date.now() / 1000) - ASSIGNMENT_TTL - 1);
  const expired = expiredService.seal('invitation', { giver: 'Alice', recipient: 'Bob', drawId: 'old' }, ASSIGNMENT_TTL);
  const home = await visitor.request('/');
  assert.equal((await visitor.request('/reveal', { _csrf: home.csrf, token: expired })).status, 400);
  const fakeAdmin = first.client(new Map([['santa_admin', 's%3Av1.fake.not-a-signature']]));
  assert.match((await fakeAdmin.request('/admin')).text, /name="password"/u);
});

test('oversized bodies are rejected and missing pages have safe error views', async t => {
  const f = await fixture(t);
  const browser = f.client();
  const oversized = await browser.request('/admin/login', { password: 'x'.repeat(140000) });
  assert.equal(oversized.status, 400);
  assert.match(oversized.text, /too large or malformed/u);
  assert.doesNotMatch(oversized.text, /ReferenceError|node_modules/u);
  const missing = await browser.request('/missing');
  assert.equal(missing.status, 404);
  assert.match(missing.text, /Esta página no existe/u);
  for (const file of ['/assets/app.js', '/assets/styles.css', '/assets/favicon.svg']) {
    assert.equal((await browser.request(file)).status, 200);
  }
});
