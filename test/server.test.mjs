import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { join } from 'node:path';
import test from 'node:test';
import { readConfig } from '../src/config.mjs';
import { createPasswordHash, parsePasswordHash } from '../src/password.mjs';
import { createLilauth } from '../src/server.mjs';
import { readLimited } from '../src/upstream.mjs';

const password = 'a test-only password <&>';
const username = 'operator';
const hashText = await createPasswordHash(Buffer.from(password));
const origin = 'https://lilauth.example.test';
const token = (char) => char.repeat(64);
const listLeak = token('e');
const wrongOrigin = 'https://wrong.example.test';

async function listen(t, server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

async function fakeBackend(t, board) {
  const path = board ? '/api/auth/agents' : '/v1/auth/agents';
  const managementToken = token(board ? 'a' : 'b');
  const newToken = token(board ? 'c' : 'd');
  const entries = new Map((board ? [
    { name: 'board-dashboard', kind: 'admin' },
    { name: 'other-admin', kind: 'admin' },
    { name: 'owner', kind: 'person' },
    { name: 'old', kind: 'agent' },
    { name: '<img src=x onerror=alert(1)>', kind: 'agent' },
  ] : [
    { name: 'vault-dashboard', permissions: ['auth:manage'] },
    { name: 'other-manager', permissions: ['auth:manage', 'private:read'] },
    { name: 'old', permissions: ['private:read'] },
  ]).map((entry) => [entry.name, entry]));
  const fake = { managementToken, newToken, entries, calls: [] };
  const server = createServer(async (req, res) => {
    const method = req.method;
    const body = method === 'POST' ? JSON.parse(await readLimited(req, 2048)) : undefined;
    fake.calls.push({ method, path: req.url, body, auth: req.headers.authorization });
    if (req.headers.authorization !== `Bearer ${managementToken}`) {
      res.writeHead(403).end();
    } else if (!board && method === 'GET' && req.url === '/v1/auth/vaults') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ vaults: fake.badVaultList ? ['private', 'private'] : ['private', 'public'] }));
    } else if (method === 'GET' && req.url === path && fake.redirectList) {
      res.writeHead(302, { Location: '/redirect-trap' }).end(listLeak);
    } else if (method === 'GET' && req.url === path) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ agents: [...entries.values()].map((entry) => ({ ...entry, token: listLeak })) }));
    } else if (method === 'POST' && req.url === path) {
      if (fake.mintGate) await fake.mintGate;
      if (fake.failMint) return res.writeHead(500).end(`<script>${listLeak}${managementToken}</script>`);
      entries.set(body.name, body);
      const reply = fake.malformedMint ? { ...body, permissions: ['auth:manage'] } : body;
      res.writeHead(201, { 'Content-Type': 'application/json' }).end(JSON.stringify({ ...reply, token: newToken }));
    } else if (method === 'DELETE' && req.url.startsWith(`${path}/`)) {
      entries.delete(decodeURIComponent(req.url.slice(path.length + 1)));
      res.writeHead(fake.failDelete ? 404 : 204).end();
    } else {
      res.writeHead(404).end();
    }
  });
  fake.origin = await listen(t, server);
  fake.writes = () => fake.calls.filter((call) => call.method !== 'GET');
  return fake;
}

async function setup(t) {
  const [board, vault] = await Promise.all([fakeBackend(t, true), fakeBackend(t, false)]);
  const app = await listen(t, createLilauth({ username, passwordHash: parsePasswordHash(hashText),
    publicOrigin: origin, insecure: false, backends: {
      lilboard: { origin: board.origin, token: board.managementToken },
      lilvault: { origin: vault.origin, token: vault.managementToken },
    } }));
  const get = (cookie) => fetch(app, { headers: cookie && { Cookie: cookie } });
  const post = (path, data, headers) => fetch(`${app}${path}`, {
    method: 'POST', headers: { Origin: origin, ...headers }, body: new URLSearchParams(data), redirect: 'manual',
  });
  async function signIn() {
    const res = await post('/login', { username, password });
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), '/');
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const cookieHeader = res.headers.get('set-cookie');
    assert.match(cookieHeader, /^__Host-lilauth=[a-f0-9]{64}; Path=\/; HttpOnly; SameSite=Strict; Max-Age=28800; Secure$/);
    const cookie = cookieHeader.split(';')[0];
    const dashboard = await (await get(cookie)).text();
    const csrf = dashboard.match(/name="csrf" value="([a-f0-9]{64})"/)[1];
    return { cookie, csrf, dashboard, post: (path, data, headers) => post(path, { csrf, ...data }, { Cookie: cookie, ...headers }) };
  }
  return { board, vault, get, post, signIn };
}

test('local login, protected form routes, CSRF, and logout', async (t) => {
  const app = await setup(t);
  const anonymous = await app.get();
  const signInPage = await anonymous.text();
  assert.match(signInPage, /Sign in to Lilauth/);
  const stylesheet = signInPage.match(/<style>([\s\S]*?)<\/style>/)?.[1];
  assert(stylesheet?.includes('--lil-paper'));
  const digest = createHash('sha256').update(stylesheet).digest('base64');
  assert(anonymous.headers.get('content-security-policy').includes(`style-src 'sha256-${digest}'`));
  assert.equal(anonymous.headers.get('cache-control'), 'no-store');
  assert.equal(anonymous.headers.get('referrer-policy'), 'strict-origin');
  assert.equal((await app.post('/login', { username, password }, { Origin: wrongOrigin })).status, 403);
  const badLogin = await app.post('/login', { username, password: 'bad<&password>' });
  assert.equal(badLogin.status, 401);
  assert.doesNotMatch(await badLogin.text(), /bad&lt;&amp;password&gt;|bad<&password>/);
  assert.equal((await app.post('/mint', { target: 'lilboard', name: 'new' })).status, 401);
  assert.deepEqual(app.board.calls, []);
  const session = await app.signIn();
  assert.match(session.dashboard, /all-board access/);
  assert(session.dashboard.indexOf('Agent name <input') < session.dashboard.indexOf('Backend <select'));
  assert.match(session.dashboard, /<fieldset data-vault-grants>/);
  assert.match(session.dashboard, /name="grant:private"/);
  assert.match(session.dashboard, /name="grant:public"/);
  assert.match(session.dashboard, /private:read/);
  assert.match(session.dashboard, /auth:manage/);
  assert.match(session.dashboard, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.doesNotMatch(session.dashboard, /<img|[a-f0-9]{64}<\/code>/);
  assert.ok(!session.dashboard.includes(listLeak));
  const count = app.board.calls.length;
  assert.equal((await app.post('/mint', { target: 'lilboard', name: 'new' }, { Cookie: session.cookie })).status, 403);
  assert.equal((await session.post('/revoke', { csrf: 'bad', target: 'lilboard', name: 'old' })).status, 403);
  for (const origin of [wrongOrigin, 'null']) {
    const rejected = await session.post('/mint', { target: 'lilboard', name: 'new' }, { Origin: origin });
    assert.equal(rejected.status, 403);
    assert.match(await rejected.text(), /Request origin rejected/);
  }
  assert.equal((await session.post('/logout', { csrf: 'bad' })).status, 403);
  assert.equal(app.board.calls.length, count);
  const logout = await session.post('/logout', {});
  assert.equal(logout.status, 303);
  assert.match(logout.headers.get('set-cookie'), /Max-Age=0; Secure$/);
  assert.equal((await session.post('/mint', { target: 'lilboard', name: 'new' })).status, 401);
  assert.match(await (await app.get(session.cookie)).text(), /Sign in to Lilauth/);
});

test('per-vault selectors stay server-rendered and submit validated grants', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  const response = await app.get(session.cookie);
  const html = await response.text();
  const styles = html.match(/<style>([\s\S]*?)<\/style>/)?.[1];
  assert(styles);
  const digest = createHash('sha256').update(styles).digest('base64');
  assert(response.headers.get('content-security-policy').includes(`style-src 'sha256-${digest}'`));
  assert(!response.headers.get('content-security-policy').includes('script-src'));
  assert(!html.includes('<script'));
  assert.match(styles, /option:is\(\[value="lilvault"\], \[value="both"\]\):checked/);
  const minted = await session.post('/mint', {
    target: 'lilvault', name: 'chosen', 'grant:private': 'read', 'grant:public': 'read-write',
  });
  assert.equal(minted.status, 201);
  assert.deepEqual(app.vault.writes()[0].body.permissions, ['private:read', 'public:read-write']);
  const rejected = await session.post('/mint', { target: 'lilvault', name: 'bad', 'grant:private': 'auth:manage' });
  assert.equal(rejected.status, 400);
  assert.equal(app.vault.writes().length, 1);
  const board = await session.post('/mint', { target: 'lilboard', name: 'board-only', 'grant:private': 'read' });
  assert.equal(board.status, 201);
  assert.equal(app.vault.writes().length, 1);
  app.vault.badVaultList = true;
  const unavailable = await (await app.get(session.cookie)).text();
  assert.match(unavailable, /value="lilvault" disabled/);
  assert.match(unavailable, /Vaults unavailable/);
});

test('sessions expire without relying on the browser cookie expiry', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  const later = Date.now() + 8 * 60 * 60 * 1000;
  t.mock.method(Date, 'now', () => later);
  assert.match(await (await app.get(session.cookie)).text(), /Sign in to Lilauth/);
  assert.equal((await session.post('/revoke', { target: 'lilboard', name: 'old' })).status, 401);
  assert.deepEqual(app.board.writes(), []);
});

test('login attempts are throttled even with varying forwarding headers', async (t) => {
  const app = await setup(t);
  for (let i = 0; i < 5; i++) {
    assert.equal((await app.post('/login', { username, password: 'bad' }, { 'X-Forwarded-For': `192.0.2.${i}` })).status, 401);
  }
  const throttled = await app.post('/login', { username, password }, { 'X-Forwarded-For': '192.0.2.200' });
  assert.equal(throttled.status, 429);
  assert.equal(throttled.headers.get('retry-after'), '60');
  assert.equal(throttled.headers.get('set-cookie'), null);
});

test('privileged or malformed mint requests never reach either backend', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  const count = app.board.calls.length + app.vault.calls.length;
  for (const data of [
    { target: 'lilboard', name: 'new', kind: 'admin' },
    { target: 'lilboard', name: 'new', kind: 'person' },
    { target: 'both', name: 'new', permissions: 'private:read\nauth:manage' },
    { target: 'lilvault', name: 'new', permissions: 'private:read\nprivate:read-write' },
    { target: 'lilboard', name: 'new', permissions: 'auth:manage' },
    { target: 'lilvault', name: 'new', permissions: 'private:*' },
    { target: 'lilboard', name: 'other-admin ' },
    { target: 'lilboard' },
    { target: 'http://example.test', name: 'new' },
  ]) assert.equal((await session.post('/mint', data)).status, 400);
  assert.equal(app.board.calls.length + app.vault.calls.length, count);
});

test('dual mint returns tokens only on success; duplicate mint sends no upstream POST', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  const fields = { target: 'both', name: 'new', permissions: 'private:read\npublic:read-write' };
  const minted = await session.post('/mint', fields);
  assert.equal(minted.status, 201);
  assert.equal(minted.headers.get('cache-control'), 'no-store');
  const html = await minted.text();
  assert.ok(html.includes(app.board.newToken) && html.includes(app.vault.newToken));
  assert.ok(!html.includes(app.board.managementToken) && !html.includes(app.vault.managementToken));
  assert.deepEqual(app.board.writes(), [{ method: 'POST', path: '/api/auth/agents',
    auth: `Bearer ${app.board.managementToken}`, body: { name: 'new', kind: 'agent' } }]);
  assert.deepEqual(app.vault.writes(), [{ method: 'POST', path: '/v1/auth/agents',
    auth: `Bearer ${app.vault.managementToken}`, body: { name: 'new', permissions: ['private:read', 'public:read-write'] } }]);
  const duplicate = await session.post('/mint', fields);
  assert.equal(duplicate.status, 409);
  const later = (await duplicate.text()) + (await (await app.get(session.cookie)).text());
  for (const value of [listLeak, app.board.newToken, app.vault.newToken, app.board.managementToken, app.vault.managementToken]) {
    assert.ok(!later.includes(value));
  }
  assert.equal(app.board.writes().length + app.vault.writes().length, 2);
});

test('revocation is limited to confirmed non-management agent credentials', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  for (const name of ['board-dashboard', 'other-admin', 'owner', 'nonexistent']) {
    assert.equal((await session.post('/revoke', { target: 'lilboard', name })).status, 409);
  }
  for (const name of ['vault-dashboard', 'other-manager', 'nonexistent']) {
    assert.equal((await session.post('/revoke', { target: 'lilvault', name })).status, 409);
  }
  app.vault.entries.set('broken', { name: 'broken' });
  assert.equal((await session.post('/revoke', { target: 'lilvault', name: 'broken' })).status, 502);
  assert.deepEqual(app.board.writes(), []);
  assert.deepEqual(app.vault.writes(), []);
  app.vault.entries.delete('broken');
  for (const target of ['lilboard', 'lilvault']) {
    assert.equal((await session.post('/revoke', { target, name: 'old' })).status, 200);
  }
  assert.equal(app.board.writes()[0].path, '/api/auth/agents/old');
  assert.equal(app.vault.writes()[0].path, '/v1/auth/agents/old');
  assert.equal(app.board.writes()[0].method, 'DELETE');
  assert.equal(app.vault.writes()[0].method, 'DELETE');
});

test('an ambiguous write pauses only that backend; partial mint preserves success', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  app.vault.failMint = true;
  const fields = { target: 'both', name: 'new', permissions: 'private:read' };
  const partial = await session.post('/mint', fields);
  assert.equal(partial.status, 200);
  const html = await partial.text();
  assert.match(html, /outcome unknown; writes paused/);
  assert.ok(html.includes(app.board.newToken));
  assert.ok(!html.includes(listLeak) && !html.includes(app.vault.newToken) && !html.includes(app.vault.managementToken));
  const vaultCalls = app.vault.calls.length;
  const paused = await session.post('/revoke', { target: 'lilvault', name: 'old' });
  assert.equal(paused.status, 503);
  assert.equal(app.vault.calls.length, vaultCalls);
  const dashboard = await (await app.get(session.cookie)).text();
  assert.match(dashboard, /outcome unknown; writes paused/);
  assert.match(dashboard, /private:read/);
  assert.equal(app.vault.calls.length, vaultCalls + 2);
  assert.equal((await session.post('/revoke', { target: 'lilboard', name: 'old' })).status, 200);
});

test('preflight redirects are not followed and do not pause writes', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  app.vault.redirectList = true;
  const fields = { target: 'lilvault', name: 'old' };
  const rejected = await session.post('/revoke', fields);
  assert.equal(rejected.status, 502);
  assert.match(await rejected.text(), /no change was submitted/);
  assert.ok(!app.vault.calls.some((call) => call.path === '/redirect-trap'));
  assert.deepEqual(app.vault.writes(), []);
  app.vault.redirectList = false;
  assert.equal((await session.post('/revoke', fields)).status, 200);
});

test('malformed mint success does not disclose the token and pauses writes', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  app.vault.malformedMint = true;
  const fields = { target: 'lilvault', name: 'new', permissions: 'private:read' };
  const unknown = await session.post('/mint', fields);
  assert.equal(unknown.status, 502);
  assert.ok(!(await unknown.text()).includes(app.vault.newToken));
  assert.equal((await session.post('/mint', { ...fields, name: 'another' })).status, 503);
  assert.equal(app.vault.writes().length, 1);
});

test('lilvault DELETE can fail after removing the in-memory key and pauses writes', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  app.vault.failDelete = true;
  const fields = { target: 'lilvault', name: 'old' };
  const unknown = await session.post('/revoke', fields);
  assert.equal(unknown.status, 502);
  assert.match(await unknown.text(), /outcome unknown; writes paused/);
  assert.ok(!app.vault.entries.has('old'));
  assert.equal((await session.post('/mint', { ...fields, permissions: 'private:read' })).status, 503);
  assert.equal(app.vault.writes().length, 1);
});

test('overlapping changes to one backend cannot both pass the unused-name check', async (t) => {
  const app = await setup(t);
  const session = await app.signIn();
  let release;
  app.board.mintGate = new Promise((resolve) => { release = resolve; });
  const fields = { target: 'lilboard', name: 'overlap' };
  const first = session.post('/mint', fields);
  try {
    for (let i = 0; i < 100 && !app.board.writes().length; i++) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal(app.board.writes().length, 1);
    assert.equal((await session.post('/mint', fields)).status, 409);
  } finally {
    release();
  }
  assert.equal((await first).status, 201);
  assert.equal(app.board.writes().length, 1);
});

test('startup config validates hash, secret files, origins, and loopback exception', (t) => {
  const dir = mkdtempSync(join(process.cwd(), '.test-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const hashFile = join(dir, 'admin.hash');
  const tokenFile = join(dir, 'board.token');
  writeFileSync(hashFile, hashText, { mode: 0o600 });
  writeFileSync(tokenFile, token('a'), { mode: 0o600 });
  const env = { LILCO_AUTH_MODE: 'local', LILCO_ADMIN_USERNAME: username, LILCO_ADMIN_PASSWORD_HASH_FILE: hashFile,
    LILCO_PUBLIC_ORIGIN: origin, LILCO_LILBOARD_ORIGIN: 'https://board.example.test',
    LILCO_LILBOARD_MANAGEMENT_TOKEN_FILE: tokenFile };
  assert.equal(readConfig(env).insecure, false);
  assert.deepEqual(Object.keys(readConfig(env).backends), ['lilboard']);
  assert.equal(readConfig({ ...env, LILCO_INSECURE_LOOPBACK: '1', LILCO_PUBLIC_ORIGIN: 'http://127.0.0.1:3000' }).insecure, true);
  for (const settings of [
    { LILCO_AUTH_MODE: 'oidc' },
    { LILCO_ADMIN_USERNAME: undefined },
    { LILCO_ADMIN_PASSWORD_HASH_FILE: tokenFile },
    { LILCO_LILBOARD_MANAGEMENT_TOKEN_FILE: hashFile },
    { LILCO_LILBOARD_ORIGIN: 'https://user:private@board.example.test' },
    { LILCO_LILBOARD_ORIGIN: undefined },
    { LILCO_LILBOARD_ORIGIN: undefined, LILCO_LILBOARD_MANAGEMENT_TOKEN_FILE: undefined },
    { LILCO_LILVAULT_ORIGIN: 'https://vault.example.test', LILCO_LILVAULT_MANAGEMENT_TOKEN_FILE: tokenFile },
    { LILCO_PUBLIC_ORIGIN: 'http://127.0.0.1:3000' },
    { LILCO_INSECURE_LOOPBACK: '1', LILCO_PUBLIC_ORIGIN: 'http://127.0.0.1:3000', LILCO_LISTEN_HOST: '0.0.0.0' },
  ]) assert.throws(() => readConfig({ ...env, ...settings }), /^Error: Invalid or missing /);

  const oidc = { ...env, LILCO_AUTH_MODE: 'oidc', LILCO_ADMIN_PASSWORD_HASH_FILE: undefined,
    LILCO_OIDC_ISSUER_URL: 'https://idp.example.test/application/o/lilauth/',
    LILCO_OIDC_CLIENT_ID: 'testclient', LILCO_OIDC_CLIENT_SECRET_FILE: tokenFile, LILCO_OIDC_ADMIN_GROUP: 'lilauth-admins' };
  assert.equal(readConfig(oidc).oidc.group, 'lilauth-admins');
  for (const settings of [
    { LILCO_OIDC_ADMIN_GROUP: '' },
    { LILCO_OIDC_CLIENT_SECRET_FILE: undefined, LILCO_OIDC_CLIENT_SECRET: 'not-read' },
    { LILCO_OIDC_ISSUER_URL: 'http://idp.example.test/' },
    { LILCO_OIDC_ISSUER_URL: 'https://user:password@idp.example.test/' },
    { LILCO_OIDC_ISSUER_URL: 'https://idp.example.test/?query=yes' },
    { LILCO_INSECURE_LOOPBACK: '1', LILCO_PUBLIC_ORIGIN: 'http://127.0.0.1:3000' },
  ]) assert.throws(() => readConfig({ ...oidc, ...settings }), /^Error: Invalid or missing /);
});
