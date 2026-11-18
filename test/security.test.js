import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtemp, rm } from 'node:fs/promises';
import { createHash, createHmac, hkdfSync } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { createApp } from '../src/app.js';
import { loadConfig } from '../src/config.js';
import { createDatabase, PIN_LOCK_SECONDS, PIN_MAX_ATTEMPTS } from '../src/database.js';
import { createAssignments, parseParticipants } from '../src/matching.js';
import { ADMIN_TTL, ASSIGNMENT_TTL, createTokenService } from '../src/tokens.js';
import { MAX_WISH_LENGTH } from '../src/wishes.js';

const env = {
  ADMIN_PASSWORD: 'a-long-test-password-only',
  SESSION_SECRET: 'a-test-only-secret-with-at-least-32-bytes-of-material',
  PARTICIPANTS: 'Alice,Bob,Charlie,Dave', DATABASE_PATH: './data/wishes.sqlite',
};
const fileConnections = new Map();

async function temporaryDatabase(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'santa-db-'));
  const filename = path.join(directory, 'test.sqlite');
  t.after(async () => {
    for (const close of fileConnections.get(filename) || []) await close();
    fileConnections.delete(filename);
    const relative = path.relative(tmpdir(), directory);
    assert.ok(relative.startsWith('santa-db-') && !relative.includes(path.sep));
    await rm(directory, { recursive: true, force: true });
  });
  return filename;
}

async function fixture(t, { filename = ':memory:', overrides = {}, clock } = {}) {
  const config = { ...loadConfig({ ...env, ...overrides }) };
  const database = createDatabase(filename, config.sessionSecret, clock ? { now: clock } : {});
  const app = createApp(config, { database });
  const server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = `http://127.0.0.1:${server.address().port}`;
  if (!config.production) config.origin = address;
  let closed = false;
  async function close() {
    if (closed) return;
    await new Promise(resolve => { server.close(resolve); server.closeAllConnections(); });
    app.locals.closeDatabase();
    closed = true;
  }
  if (filename !== ':memory:') {
    const connections = fileConnections.get(filename) || [];
    connections.push(close);
    fileConnections.set(filename, connections);
  }
  t.after(close);
  function client(initial = new Map()) {
    const cookies = new Map(initial);
    async function request(url, fields, headers = {}) {
      const response = await fetch(`${address}${url}`, {
        method: fields === undefined ? 'GET' : 'POST', redirect: 'manual',
        headers: { Cookie: [...cookies].map(([key, value]) => `${key}=${value}`).join('; '),
          ...(fields === undefined ? {} : { Origin: config.origin }), ...headers },
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
      return { status: response.status, headers: response.headers, text,
        csrf: text.match(/name="_csrf" value="([a-f0-9]+)"/u)?.[1] };
    }
    return { request, cookies };
  }
  return { config, database, client, close };
}

async function login(admin, headers = {}) {
  const page = await admin.request('/admin', undefined, headers);
  assert.equal((await admin.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, headers)).status, 303);
  return admin.request('/admin', undefined, headers);
}
async function generate(admin, participants = 'Alice,Bob,Charlie,Dave') {
  const dashboard = await admin.request('/admin');
  const result = await admin.request('/admin/generate', { _csrf: dashboard.csrf, participants });
  assert.equal(result.status, 303);
  return admin.request(result.headers.get('location'));
}
const getLinks = page => [...page.text.matchAll(/id="exchange-link" type="text" value="(https?:[^" ]+#token=e2\.[A-Za-z0-9_-]+)"/gu)].map(match => match[1]);
async function redeem(browser, invitation, name = 'Alice') {
  const page = await browser.request('/');
  const response = await browser.request('/reveal', { _csrf: page.csrf, token: invitation });
  let challenge = response;
  if (response.text.includes('id="choose-participant-form"')) {
    const token = invitation.startsWith('http') ? new URL(invitation).hash.slice(7) : invitation;
    challenge = await browser.request('/exchange/join', { _csrf: response.csrf, token, name });
  }
  return completePin(browser, challenge, name);
}
async function completePin(browser, challenge, name, pin = '0426') {
  assert.equal(challenge.status, 200);
  assert.match(challenge.text, /id="pin-form"/u);
  assert.doesNotMatch(challenge.text, /class="recipient"/u);
  const token = challenge.text.match(/name="token" value="([^"]+)"/u)[1];
  const mode = challenge.text.match(/name="mode" value="([^"]+)"/u)[1];
  const unlocked = await browser.request('/exchange/unlock', { _csrf: challenge.csrf, token, name, pin, confirmation: pin, mode });
  assert.equal(unlocked.status, 303);
  return browser.request('/reveal');
}
function legacyCookie(token, secret) {
  const signature = createHmac('sha256', secret).update(token).digest('base64').replace(/=+$/u, '');
  return encodeURIComponent(`s:${token}.${signature}`);
}

test('configuration validates secrets and supports DATABASE_PATH, the old path setting, and Railway volumes', () => {
  assert.throws(() => loadConfig({}), /ADMIN_PASSWORD/);
  assert.throws(() => loadConfig({ ...env, SESSION_SECRET: 'short' }), /SESSION_SECRET/);
  assert.throws(() => loadConfig({ ...env, PORT: 'bad' }), /PORT/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production' }), /APP_URL/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production', APP_URL: 'http://example.com' }), /HTTPS/);
  assert.throws(() => loadConfig({ ...env, APP_URL: 'https://example.com/path' }), /path/);
  assert.throws(() => loadConfig({ ...env, APP_URL: 'https://user:pass@example.com' }), /credentials/);
  assert.throws(() => loadConfig({ ...env, TRUST_PROXY: 'true' }), /TRUST_PROXY/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production', APP_URL: 'https://santa.example', DATABASE_PATH: '' }), /persistent/);
  assert.throws(() => loadConfig({ ...env, NODE_ENV: 'production', APP_URL: 'https://santa.example', DATABASE_PATH: ':memory:' }), /persistent/);
  assert.equal(loadConfig({ ...env, DATABASE_PATH: '', WISHLIST_DB_PATH: './old.sqlite' }).databasePath, path.resolve('old.sqlite'));
  assert.equal(loadConfig({ ...env, DATABASE_PATH: '', RAILWAY_VOLUME_MOUNT_PATH: './volume' }).databasePath, path.resolve('volume/wishes.sqlite'));
  assert.equal(loadConfig({ ...env, NODE_ENV: 'production', RAILWAY_PUBLIC_DOMAIN: 'santa.up.railway.app' }).origin, 'https://santa.up.railway.app');
});

test('participants validate Unicode, duplicates, controls, and roster size', () => {
  assert.deepEqual(parseParticipants(' Alice, Bob\r\nChloé\nDave, '), ['Alice', 'Bob', 'Chloé', 'Dave']);
  for (const input of ['', 'Alice', 'Alice,alice', 'Éva,E\u0301va', 'Bob,Ｂｏｂ', `Alice,${'x'.repeat(81)}`, 'Alice,Bob\u202E', Array.from({ length: 101 }, (_, i) => `Person ${i}`).join(',')]) {
    assert.throws(() => parseParticipants(input));
  }
});

test('fair matching gives and receives exactly once without self matches', () => {
  for (const size of [2, 3, 4, 10, 100]) {
    const names = Array.from({ length: size }, (_, i) => `Person ${i}`);
    for (let n = 0; n < 100; n++) {
      const assignments = createAssignments(names);
      assert.deepEqual(assignments.map(a => a.giver), names);
      assert.deepEqual(assignments.map(a => a.recipient).sort(), [...names].sort());
      assert.ok(assignments.every(a => a.giver !== a.recipient));
    }
  }
});

test('SQLite persists draws, invitation links, wishes, and both session types across a full restart', async t => {
  const filename = await temporaryDatabase(t);
  const first = await fixture(t, { filename });
  const admin = first.client();
  await login(admin);
  const generated = await generate(admin);
  const links = getLinks(generated);
  assert.equal(links.length, 1);
  const participants = first.database.getDraw().participants.map(person => ({ giver: person.name, recipient: person.recipient_name }));
  assert.ok(participants.every(person => person.giver !== person.recipient));
  assert.equal(new Set(participants.map(person => person.recipient)).size, 4);
  const participant = first.client();
  const reveal = await redeem(participant, links[0]);
  assert.match(reveal.text, /TE TOCA REGALARLE A/u);
  await participant.request('/wishes', { _csrf: reveal.csrf, wishes: 'Café y libros' });
  const adminCookies = new Map(admin.cookies);
  const participantCookies = new Map(participant.cookies);
  await first.close();
  const second = await fixture(t, { filename });
  const dashboard = await second.client(adminCookies).request('/admin');
  assert.equal(dashboard.status, 200);
  // Origin may change, but the saved credential and assignment do not.
  assert.deepEqual(getLinks(dashboard).map(url => new URL(url).hash), links.map(url => new URL(url).hash));
  const remembered = await second.client(participantCookies).request('/reveal');
  assert.match(remembered.text, new RegExp(`class="recipient">${participants[0].recipient}<`));
  assert.match(remembered.text, /Café y libros/u);
  assert.match(remembered.text, /<html lang="es">/u);
});

test('refreshing and switching saved exchanges retains links and never generates a new draw', async t => {
  const f = await fixture(t);
  const admin = f.client();
  await login(admin);
  const oldPage = await generate(admin, 'Alice,Bob');
  const oldLinks = getLinks(oldPage);
  const oldId = f.database.getDraw().id;
  await generate(admin, 'Carla,Diego,Eva');
  assert.equal(f.database.listDraws().length, 2);
  assert.equal(getLinks(await admin.request('/admin')).length, 1);
  for (let n = 0; n < 3; n++) assert.deepEqual(getLinks(await admin.request(`/admin?draw=${oldId}`)), oldLinks);
  assert.equal(f.database.listDraws().length, 2);
  assert.equal((await admin.request('/admin?draw=unknown')).status, 404);
  const dashboard = await admin.request('/admin');
  assert.equal((await admin.request('/admin/generate', { _csrf: dashboard.csrf, participants: 'Alice,Alice' })).status, 400);
  assert.equal(f.database.listDraws().length, 2);
});

test('SQLite sessions expire, renew participant access, and reject revoked or wrong-role tokens', () => {
  let now = 10000000;
  const database = createDatabase(':memory:', env.SESSION_SECRET, { now: () => now });
  try {
    const drawId = database.createDraw(['Alice', 'Bob']);
    const sharedToken = database.getDraw(drawId).sharedToken;
    const person = database.chooseParticipant(sharedToken, 'Alice');
    const participant = database.createParticipantSession(person);
    const admin = database.createAdminSession('fingerprint');
    assert.ok(database.hasAdminSession(admin, 'fingerprint'));
    assert.equal(database.hasAdminSession(participant, 'fingerprint'), false);
    assert.equal(database.readParticipantSession(admin), null);
    now += ADMIN_TTL;
    assert.equal(database.hasAdminSession(admin, 'fingerprint'), false);
    now += ASSIGNMENT_TTL - ADMIN_TTL - 1;
    assert.ok(database.readParticipantSession(participant, { renew: true }));
    now += 2;
    assert.equal(database.findExchange(sharedToken), null);
    assert.ok(database.readParticipantSession(participant));
    database.deleteSession(participant);
    assert.equal(database.readParticipantSession(participant), null);
  } finally { database.close(); }
});

test('login/logout and forget revoke database sessions, including replay of old cookies', async t => {
  const f = await fixture(t);
  const admin = f.client();
  await login(admin);
  const links = getLinks(await generate(admin, 'Alice,Bob'));
  const oldAdmin = new Map(admin.cookies);
  const dashboard = await admin.request('/admin');
  await admin.request('/admin/logout', { _csrf: dashboard.csrf });
  assert.match((await f.client(oldAdmin).request('/admin')).text, /name="password"/u);
  const person = f.client();
  const reveal = await redeem(person, links[0]);
  const oldPerson = new Map(person.cookies);
  await person.request('/forget', { _csrf: reveal.csrf });
  assert.doesNotMatch((await f.client(oldPerson).request('/')).text, /class="recipient"/u);
  await redeem(person, links[0]);
});

test('CSRF, cross-origin requests, password checks, and opaque cookie tampering fail closed', async t => {
  const f = await fixture(t);
  const browser = f.client();
  assert.equal((await browser.request('/admin/generate', { participants: 'Alice,Bob' })).status, 303);
  const page = await browser.request('/admin');
  assert.equal((await browser.request('/admin/login', { password: env.ADMIN_PASSWORD })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { Origin: 'null' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: env.ADMIN_PASSWORD }, { 'Sec-Fetch-Site': 'cross-site' })).status, 403);
  assert.equal((await browser.request('/admin/login', { _csrf: page.csrf, password: 'wrong' })).status, 401);
  const dashboard = await login(browser);
  assert.equal((await browser.request('/admin/generate', { _csrf: dashboard.csrf, participants: 'Alice,Bob' }, { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' })).status, 303);
  const forged = f.client(new Map([['santa_participant', 's%3As2.fake.bad-signature']]));
  assert.equal((await forged.request('/wishes/recipient')).status, 401);
  assert.doesNotMatch((await forged.request('/')).text, /class="recipient"/u);
});

test('opaque invitation tampering does not replace a current assignment', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const invitation = f.database.getDraw(id).sharedToken;
  const browser = f.client();
  const page = await redeem(browser, invitation);
  const saved = browser.cookies.get('santa_participant');
  assert.equal((await browser.request('/reveal', { _csrf: page.csrf, token: `${invitation}x` })).status, 400);
  assert.equal(browser.cookies.get('santa_participant'), saved);
  const cookie = page.headers.getSetCookie().find(value => value.startsWith('santa_participant='));
  assert.match(cookie, /Max-Age=5184000/u);
  assert.match(cookie, /HttpOnly/u);
  assert.match(cookie, /SameSite=Lax/u);
  assert.doesNotMatch(cookie, /Alice|Bob/u);
});

test('wishes follow the chosen name and wish form fields cannot change the current selection', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const sharedToken = f.database.getDraw(id).sharedToken;
  const alice = f.client(); const bob = f.client();
  const a = await redeem(alice, sharedToken, 'Alice');
  const b = await redeem(bob, sharedToken, 'Bob');
  const text = '<script>alert(1)</script>\n</textarea><img src=x onerror=alert(1)>';
  assert.equal((await bob.request('/wishes', { _csrf: b.csrf, wishes: text, giver: 'Alice' })).status, 303);
  assert.equal(JSON.parse((await alice.request('/wishes/recipient')).text).text, text);
  assert.equal(JSON.parse((await bob.request('/wishes/recipient')).text).text, '');
  const view = await alice.request('/reveal');
  assert.match(view.text, /&lt;script&gt;/u);
  assert.doesNotMatch(view.text, /<script>alert|<img src=x/u);
  assert.equal((await bob.request('/wishes', { _csrf: b.csrf, wishes: 'x'.repeat(MAX_WISH_LENGTH + 1) })).status, 400);
  assert.equal(JSON.parse((await alice.request('/wishes/recipient')).text).text, text);
  assert.equal((await bob.request('/wishes', { wishes: 'No CSRF' })).status, 403);
  await bob.request('/wishes', { _csrf: b.csrf, wishes: '' });
  assert.equal(JSON.parse((await alice.request('/wishes/recipient')).text).text, '');
  await alice.request('/wishes', { _csrf: a.csrf, wishes: '贈'.repeat(MAX_WISH_LENGTH) });
  assert.equal(JSON.parse((await bob.request('/wishes/recipient')).text).text.length, MAX_WISH_LENGTH);
});

test('legacy invitations, participant cookies, admin cookies, and saved wishes migrate into SQLite', async t => {
  const filename = await temporaryDatabase(t);
  const legacy = createTokenService(env.SESSION_SECRET);
  const drawId = 'old-draw'; const text = 'Mis deseos anteriores';
  const key = createHmac('sha256', Buffer.from(hkdfSync('sha256', env.SESSION_SECRET, 'secret-santa/v1', 'wish-lookup', 32)))
    .update(JSON.stringify([drawId, 'Alice'])).digest('hex');
  const old = new DatabaseSync(filename);
  old.exec('CREATE TABLE wishes (entry_key TEXT PRIMARY KEY, encrypted_text TEXT NOT NULL, expires_at INTEGER NOT NULL) STRICT');
  old.prepare('INSERT INTO wishes VALUES (?, ?, ?)').run(key, legacy.seal('wishlist', { key, text }, ASSIGNMENT_TTL), Math.floor(Date.now() / 1000) + ASSIGNMENT_TTL);
  old.close();
  const f = await fixture(t, { filename });
  const token = legacy.seal('invitation', { giver: 'Alice', recipient: 'Bob', drawId }, ASSIGNMENT_TTL);
  const alice = f.client();
  assert.match((await redeem(alice, token)).text, /Mis deseos anteriores/u);
  const oldBob = legacy.seal('assignment', { giver: 'Bob', recipient: 'Alice', drawId }, ASSIGNMENT_TTL);
  const bob = f.client(new Map([['santa_assignment', legacyCookie(oldBob, legacy.cookieSecret)]]));
  const bobChallenge = await bob.request('/reveal');
  assert.match((await completePin(bob, bobChallenge, 'Bob')).text, /Mis deseos anteriores/u);
  assert.equal(bob.cookies.has('santa_assignment'), false);
  assert.ok(bob.cookies.has('santa_participant'));
  const fingerprint = createHash('sha256').update(env.ADMIN_PASSWORD).digest('hex');
  const oldAdmin = legacy.seal('admin', { fingerprint }, ADMIN_TTL);
  const admin = f.client(new Map([['santa_admin', legacyCookie(oldAdmin, legacy.cookieSecret)]]));
  const dashboard = await admin.request('/admin');
  assert.equal(getLinks(dashboard).length, 1);
  assert.match(decodeURIComponent(admin.cookies.get('santa_admin')), /^s:s2\./u);
  await alice.request('/wishes', { _csrf: (await alice.request('/')).csrf, wishes: '' });
  await redeem(alice, token);
  assert.equal(f.database.getWishes(drawId, 'Alice').text, '');
});

test('legacy token encryption still rejects expiry, tampering, and purpose confusion', () => {
  let now = 10000000;
  const tokens = createTokenService(env.SESSION_SECRET, () => now);
  const token = tokens.seal('invitation', { giver: 'Alice', recipient: 'Bob', drawId: 'old' }, ASSIGNMENT_TTL);
  assert.ok(tokens.open('invitation', token));
  assert.equal(tokens.open('admin', token), null);
  assert.equal(tokens.open('invitation', `${token}x`), null);
  now += ASSIGNMENT_TTL;
  assert.equal(tokens.open('invitation', token), null);
});

test('production cookies are Secure and host-only; HTTPS and media CSP remain enabled', async t => {
  const f = await fixture(t, { overrides: { NODE_ENV: 'production', APP_URL: 'https://santa.example' } });
  const browser = f.client();
  assert.equal((await browser.request('/health')).status, 200);
  assert.equal((await browser.request('/admin')).status, 308);
  const headers = { 'X-Forwarded-Proto': 'https' };
  const dashboard = await login(browser, headers);
  assert.match(dashboard.headers.get('content-security-policy'), /media-src 'self'/u);
  assert.equal(dashboard.headers.get('cache-control'), 'no-store');
  assert.equal(dashboard.headers.get('referrer-policy'), 'no-referrer');
  assert.ok(dashboard.headers.get('strict-transport-security'));
  assert.ok(browser.cookies.has('__Host-santa_admin'));
  const cookies = dashboard.headers.getSetCookie();
  assert.ok(cookies.every(value => value.includes('Secure') && value.includes('HttpOnly') && !value.includes('Domain=')));
});

test('password changes invalidate saved admin sessions', async t => {
  const filename = await temporaryDatabase(t);
  const f = await fixture(t, { filename });
  const admin = f.client(); await login(admin);
  const cookies = new Map(admin.cookies); await f.close();
  const second = await fixture(t, { filename, overrides: { ADMIN_PASSWORD: 'a-different-long-password' } });
  assert.match((await second.client(cookies).request('/admin')).text, /name="password"/u);
});

test('oversized requests, HTML in names, and missing routes have safe output', async t => {
  const f = await fixture(t);
  const browser = f.client();
  const oversized = await browser.request('/admin/login', { password: 'x'.repeat(140000) });
  assert.equal(oversized.status, 400);
  assert.doesNotMatch(oversized.text, /ReferenceError|node_modules/u);
  const admin = f.client(); await login(admin);
  const generated = await generate(admin, '<img src=x onerror=alert(1)>,Bob');
  assert.match(generated.text, /&lt;img/u);
  assert.doesNotMatch(generated.text, /<img src=x/u);
  const missing = await browser.request('/missing');
  assert.equal(missing.status, 404); assert.match(missing.text, /Esta página no existe/u);
  for (const file of ['/assets/app.js', '/assets/styles.css', '/assets/feliz-navidad-santa.mp4']) assert.equal((await browser.request(file)).status, 200);
});

test('one shared link lets everyone select a saved name without exposing pairings in the picker', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob', 'Carla']);
  const draw = f.database.getDraw(id);
  const pairings = draw.participants.map(person => [person.name, person.recipient_name]);
  assert.ok(draw.participants.every(person => person.invitation_token === null));
  for (const person of draw.participants) {
    const browser = f.client();
    const page = await browser.request('/');
    const picker = await browser.request('/reveal', { _csrf: page.csrf, token: draw.sharedToken });
    assert.equal(picker.status, 200);
    assert.match(picker.text, /¿Quién <em>eres/u);
    assert.doesNotMatch(picker.text, /class="recipient"|recipient_name|invitation_token/u);
    assert.equal(browser.cookies.has('santa_participant'), false);
    const selected = await browser.request('/exchange/join', { _csrf: picker.csrf, token: draw.sharedToken, name: person.name });
    assert.equal(selected.status, 200);
    const reveal = await completePin(browser, selected, person.name);
    assert.match(reveal.text, new RegExp(`class="recipient">${person.recipient_name}<`));
  }
  assert.deepEqual(f.database.getDraw(id).participants.map(person => [person.name, person.recipient_name]), pairings);
});

test('shared-link selection rejects missing tokens, unknown names, cross-draw names, and CSRF', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  f.database.createDraw(['Carla', 'Diego']);
  const sharedToken = f.database.getDraw(id).sharedToken;
  const browser = f.client();
  const page = await browser.request('/');
  assert.equal((await browser.request('/exchange/join', { token: sharedToken, name: 'Alice' })).status, 403);
  assert.equal((await browser.request('/exchange/join', { _csrf: page.csrf, name: 'Alice' })).status, 400);
  for (const name of ['Unknown', 'Carla', '', "' OR 1=1 --"]) {
    const result = await browser.request('/exchange/join', { _csrf: page.csrf, token: sharedToken, name });
    assert.equal(result.status, 400);
    assert.equal(browser.cookies.has('santa_participant'), false);
  }
  assert.equal((await browser.request('/exchange/join', { _csrf: page.csrf, token: sharedToken, name: 'Alice' }, { Origin: 'https://evil.example' })).status, 403);
});

test('choosing another name rotates CSRF and revokes the previous browser session', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const token = f.database.getDraw(id).sharedToken;
  const browser = f.client();
  const alice = await redeem(browser, token, 'Alice');
  const aliceCookies = new Map(browser.cookies);
  const bob = await redeem(browser, token, 'Bob');
  assert.match(bob.text, /Hola, <em>Bob/u);
  assert.equal((await f.client(aliceCookies).request('/wishes/recipient')).status, 401);
  assert.equal((await browser.request('/wishes', { _csrf: alice.csrf, wishes: 'Old tab edit' })).status, 403);
  assert.equal(f.database.getWishes(id, 'Bob').text, '');
  assert.equal((await browser.request('/wishes', { _csrf: bob.csrf, wishes: 'Bob’s new wishes' })).status, 303);
});

test('previous SQLite draws receive stable shared links without losing assignments or old individual links', async t => {
  const filename = await temporaryDatabase(t);
  const initial = createDatabase(filename, env.SESSION_SECRET);
  const id = initial.createDraw(['Alice', 'Bob']);
  const original = initial.getDraw(id).participants.map(person => [person.name, person.recipient_name]);
  initial.setWishes(id, 'Alice', 'Mis deseos guardados');
  initial.close();
  // Reproduce the preceding database schema, before shared links existed.
  const old = new DatabaseSync(filename);
  old.exec('DROP INDEX draw_shared_token; ALTER TABLE draws DROP COLUMN shared_token; ALTER TABLE draws DROP COLUMN shared_expires_at;');
  const oldToken = `i2.${'A'.repeat(43)}`;
  old.prepare('UPDATE participants SET invitation_token = ?, invitation_expires_at = ? WHERE draw_id = ? AND name = ?')
    .run(oldToken, Math.floor(Date.now() / 1000) + ASSIGNMENT_TTL, id, 'Alice');
  old.close();
  const first = await fixture(t, { filename });
  const migrated = first.database.getDraw(id);
  assert.match(migrated.sharedToken, /^e2\./u);
  assert.deepEqual(migrated.participants.map(person => [person.name, person.recipient_name]), original);
  assert.equal(first.database.getWishes(id, 'Alice').text, 'Mis deseos guardados');
  assert.ok(first.database.findInvitation(oldToken));
  await redeem(first.client(), oldToken);
  await first.close();
  const second = await fixture(t, { filename });
  assert.equal(second.database.getDraw(id).sharedToken, migrated.sharedToken);
  await redeem(second.client(), migrated.sharedToken, 'Bob');
});

async function pinChallenge(browser, token, name = 'Alice') {
  const page = await browser.request('/');
  return browser.request('/exchange/join', { _csrf: page.csrf, token, name });
}

test('PIN setup validates four digits and confirmation; later visits require the saved PIN', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const token = f.database.getDraw(id).sharedToken;
  const browser = f.client();
  const challenge = await pinChallenge(browser, token);
  assert.match(challenge.text, /Crea tu PIN/u);
  assert.equal(browser.cookies.has('santa_participant'), false);
  const submit = fields => browser.request('/exchange/unlock', { _csrf: challenge.csrf, token, name: 'Alice', mode: 'setup', ...fields });
  assert.equal((await submit({ pin: '0123', confirmation: '0123', _csrf: '' })).status, 403);
  for (const pin of ['123', '12345', '12ab', '１２３４', ' 123', '']) {
    assert.equal((await submit({ pin, confirmation: pin })).status, 400);
    assert.equal(f.database.getPinState(id, 'Alice').setupRequired, true);
  }
  assert.equal((await submit({ pin: '0123', confirmation: '9876' })).status, 400);
  assert.equal((await submit({ pin: '0123', confirmation: '0123' })).status, 303);
  const row = f.database.getDraw(id).participants.find(person => person.name === 'Alice');
  assert.match(row.pin_hash, /^[a-f0-9]{64}$/u);
  assert.match(row.pin_salt, /^[a-f0-9]{32}$/u);
  assert.notEqual(row.pin_hash, '0123');
  assert.match((await browser.request('/reveal')).text, /class="recipient">Bob</u);
  const stranger = f.client();
  const loginPage = await pinChallenge(stranger, token);
  assert.match(loginPage.text, /Ingresa tu PIN/u);
  assert.doesNotMatch(loginPage.text, /name="confirmation"|class="recipient"/u);
  const attempt = fields => stranger.request('/exchange/unlock', { _csrf: loginPage.csrf, token, name: 'Alice', mode: 'login', ...fields });
  const wrong = await attempt({ pin: '9876' });
  assert.equal(wrong.status, 401);
  assert.doesNotMatch(wrong.text, /value="9876"|class="recipient"/u);
  assert.equal((await stranger.request('/wishes/recipient')).status, 401);
  assert.equal((await attempt({ pin: '9999', confirmation: '9999', mode: 'setup' })).status, 409);
  assert.equal((await attempt({ pin: '0123' })).status, 303);
  assert.equal(f.database.getDraw(id).participants.find(person => person.name === 'Alice').pin_hash, row.pin_hash);
});

test('five wrong PIN attempts lock the name for 15 minutes, including across restarts', async t => {
  const filename = await temporaryDatabase(t);
  let now = Math.floor(Date.now() / 1000);
  const first = await fixture(t, { filename, clock: () => now });
  const id = first.database.createDraw(['Alice', 'Bob']);
  const token = first.database.getDraw(id).sharedToken;
  assert.equal((await first.database.unlockParticipant({ token, name: 'Alice', pin: '0123', confirmation: '0123', mode: 'setup' })).ok, true);
  const browser = first.client();
  const page = await pinChallenge(browser, token);
  for (let n = 1; n <= PIN_MAX_ATTEMPTS; n++) {
    const wrong = await browser.request('/exchange/unlock', { _csrf: page.csrf, token, name: 'Alice', pin: '9999', mode: 'login' });
    assert.equal(wrong.status, n === PIN_MAX_ATTEMPTS ? 429 : 401);
    if (n === PIN_MAX_ATTEMPTS) assert.equal(wrong.headers.get('retry-after'), String(PIN_LOCK_SECONDS));
  }
  await first.close();
  const second = await fixture(t, { filename, clock: () => now });
  const correct = () => second.database.unlockParticipant({ token, name: 'Alice', pin: '0123', mode: 'login' });
  assert.equal((await correct()).status, 429);
  now += PIN_LOCK_SECONDS;
  assert.equal((await correct()).ok, true);
  assert.equal(second.database.getPinState(id, 'Alice').retryAfter, 0);
});

test('concurrent first-time claims cannot overwrite the winning PIN', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const token = f.database.getDraw(id).sharedToken;
  const pins = ['1111', '2222'];
  const results = await Promise.all(pins.map(pin => f.database.unlockParticipant({ token, name: 'Alice', pin, confirmation: pin, mode: 'setup' })));
  assert.equal(results.filter(result => result.ok).length, 1);
  assert.equal(results.filter(result => result.status === 409).length, 1);
  const winner = pins[results.findIndex(result => result.ok)];
  assert.equal((await f.database.unlockParticipant({ token, name: 'Alice', pin: winner, mode: 'login' })).ok, true);
});

test('admin PIN reset revokes participant sessions and lets the owner set a new PIN', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const token = f.database.getDraw(id).sharedToken;
  const alice = f.client(); const bob = f.client();
  const alicePage = await redeem(alice, token, 'Alice');
  await redeem(bob, token, 'Bob');
  await alice.request('/wishes', { _csrf: alicePage.csrf, wishes: 'Libros' });
  const guest = f.client();
  assert.equal((await guest.request('/admin/reset-pin', { drawId: id, name: 'Alice' })).status, 303);
  const admin = f.client(); const dashboard = await login(admin);
  assert.equal((await admin.request('/admin/reset-pin', { drawId: id, name: 'Alice' })).status, 403);
  assert.equal((await admin.request('/admin/reset-pin', { _csrf: dashboard.csrf, drawId: id, name: 'Alice' })).status, 303);
  assert.equal((await alice.request('/wishes/recipient')).status, 401);
  assert.equal((await bob.request('/wishes/recipient')).status, 200);
  assert.equal(f.database.getWishes(id, 'Alice').text, 'Libros');
  const challenge = await pinChallenge(alice, token, 'Alice');
  assert.match(challenge.text, /Crea tu PIN/u);
  await completePin(alice, challenge, 'Alice', '5678');
  assert.equal((await f.database.unlockParticipant({ token, name: 'Alice', pin: '0426', mode: 'login' })).status, 401);
});

test('pre-PIN browser sessions and personal links cannot bypass setup or verification', async t => {
  const f = await fixture(t);
  const id = f.database.createDraw(['Alice', 'Bob']);
  const token = f.database.getDraw(id).sharedToken;
  const identity = f.database.chooseParticipant(token, 'Alice');
  const oldSession = f.database.createParticipantSession(identity);
  const browser = f.client(new Map([['santa_participant', legacyCookie(oldSession, env.SESSION_SECRET)]]));
  const gate = await browser.request('/reveal');
  assert.match(gate.text, /id="pin-form"/u);
  assert.doesNotMatch(gate.text, /class="recipient"/u);
  assert.equal((await browser.request('/wishes/recipient')).status, 401);
  assert.equal((await browser.request('/wishes', { _csrf: gate.csrf, wishes: 'Cannot save yet' })).status, 303);
  assert.equal(f.database.getWishes(id, 'Alice').text, '');
  await completePin(browser, gate, 'Alice');
  const legacy = createTokenService(env.SESSION_SECRET).seal('invitation', identity, ASSIGNMENT_TTL);
  const attacker = f.client();
  const page = await attacker.request('/');
  const oldLinkGate = await attacker.request('/reveal', { _csrf: page.csrf, token: legacy });
  assert.match(oldLinkGate.text, /Ingresa tu PIN/u);
  assert.doesNotMatch(oldLinkGate.text, /class="recipient"/u);
  assert.equal((await attacker.request('/wishes/recipient')).status, 401);
});
