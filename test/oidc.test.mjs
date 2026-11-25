import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { once } from 'node:events';
import test from 'node:test';
import { createLilauth } from '../src/server.mjs';

const publicOrigin = 'https://lilauth.example.test';
const providerOrigin = 'https://idp.example.test';
const issuer = new URL('/application/o/lilauth/', providerOrigin);
const clientId = 'lilauth-oidc-client';
const clientSecret = 'fake-client-secret-for-tests';
const group = 'lilauth-admins';
const key = generateKeyPairSync('rsa', { modulusLength: 2048 });
const wrongKey = generateKeyPairSync('rsa', { modulusLength: 2048 });

function jwt(claims, privateKey) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const payload = `${encode({ alg: 'RS256', kid: 'test' })}.${encode(claims)}`;
  return `${payload}.${sign('RSA-SHA256', Buffer.from(payload), privateKey).toString('base64url')}`;
}

async function setup(t, { claims = {}, untrustedSignature = false } = {}) {
  let authorization;
  let exchanges = 0;
  const config = { publicOrigin, backends: {}, oidc: { issuer, clientId, clientSecret, group } };
  const oidcFetch = async (url, init) => {
    if (String(url) === new URL('.well-known/openid-configuration', issuer).href) {
      return Response.json({
        issuer: issuer.href,
        authorization_endpoint: `${providerOrigin}/authorize`,
        token_endpoint: `${providerOrigin}/token`,
        jwks_uri: `${providerOrigin}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        code_challenge_methods_supported: ['S256'],
      });
    }
    if (String(url) === `${providerOrigin}/jwks`) {
      return Response.json({ keys: [{ ...key.publicKey.export({ format: 'jwk' }), kid: 'test', alg: 'RS256' }] });
    }
    assert.equal(String(url), `${providerOrigin}/token`);
    exchanges++;
    assert.equal(init.method, 'POST');
    const basic = new Headers(init.headers).get('authorization');
    assert.match(basic, /^Basic /);
    assert.deepEqual(Buffer.from(basic.slice(6), 'base64').toString().split(':').map(decodeURIComponent), [clientId, clientSecret]);
    const form = new URLSearchParams(init.body);
    assert.equal(form.get('redirect_uri'), `${publicOrigin}/auth/oidc/callback`);
    assert.equal(form.get('code'), 'test-authorization-code');
    assert.equal(createHash('sha256').update(form.get('code_verifier')).digest('base64url'), authorization.searchParams.get('code_challenge'));
    const now = Math.floor(Date.now() / 1000);
    return Response.json({
      access_token: 'synthetic', token_type: 'Bearer',
      id_token: jwt({
        iss: issuer.href, sub: 'test-subject', aud: clientId, iat: now, exp: now + 300,
        nonce: authorization.searchParams.get('nonce'), groups: [group], ...claims,
      }, untrustedSignature ? wrongKey.privateKey : key.privateKey),
    });
  };
  const server = createLilauth(config, { oidcFetch });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const request = (path, options) => fetch(`http://127.0.0.1:${server.address().port}${path}`, { redirect: 'manual', ...options });
  const start = await request('/auth/oidc/start');
  assert.equal(start.status, 303, await start.text());
  authorization = new URL(start.headers.get('location'));
  const cookie = start.headers.get('set-cookie');
  assert.match(cookie, /^__Host-lilauth-oidc=.*HttpOnly; SameSite=Lax; Max-Age=300; Secure$/);
  const callback = (state = authorization.searchParams.get('state'), headers = { Cookie: cookie.split(';')[0] }) =>
    request(`/auth/oidc/callback?${new URLSearchParams({ code: 'test-authorization-code', state })}`, { headers });
  return { authorization, request, callback, exchanges: () => exchanges };
}

test('OIDC only offers SSO, validates PKCE and issues an admin session once', async (t) => {
  const idp = await setup(t);
  const params = idp.authorization.searchParams;
  assert.equal(idp.authorization.origin, providerOrigin);
  assert.equal(params.get('response_type'), 'code');
  assert.equal(params.get('scope'), 'openid profile');
  assert.equal(params.get('redirect_uri'), `${publicOrigin}/auth/oidc/callback`);
  assert.equal(params.get('code_challenge_method'), 'S256');
  for (const name of ['state', 'nonce', 'code_challenge']) assert.match(params.get(name), /^[\w-]{43}$/);
  const home = await (await idp.request('/')).text();
  assert.match(home, /Sign in with SSO/);
  assert.doesNotMatch(home, /name="password"/);
  assert.equal((await idp.request('/login', { method: 'POST' })).status, 404);
  const response = await idp.callback();
  assert.equal(response.status, 303, await response.text());
  assert.equal(response.headers.get('location'), '/');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
  const cookies = response.headers.getSetCookie();
  assert.match(cookies[0], /__Host-lilauth-oidc=; .*Max-Age=0/);
  assert.match(cookies[1], /^__Host-lilauth=[a-f0-9]{64}; Path=\/; HttpOnly; SameSite=Lax; Max-Age=28800; Secure$/);
  const session = cookies[1].split(';')[0];
  const dashboard = await idp.request('/', { headers: { Cookie: session } });
  assert.equal(dashboard.headers.get('referrer-policy'), 'strict-origin');
  assert.match(await dashboard.text(), /Sign out/);
  assert.equal((await idp.request('/mint', { method: 'POST', headers: { Cookie: session, Origin: publicOrigin }, body: new URLSearchParams({ csrf: 'wrong' }) })).status, 403);
  assert.equal((await idp.callback()).status, 400);
  assert.equal(idp.exchanges(), 1);
});

test('OIDC callback requires both the browser cookie and matching state', async (t) => {
  const idp = await setup(t);
  assert.equal((await idp.callback(undefined, {})).status, 400);
  assert.equal((await idp.callback('wrong-state')).status, 400);
  assert.equal(idp.exchanges(), 0);
});

for (const [label, options, status] of [
  ['a different group', { claims: { groups: ['different-group'] } }, 403],
  ['a non-list groups claim', { claims: { groups: group } }, 403],
  ['wrong issuer', { claims: { iss: `${providerOrigin}/elsewhere` } }, 400],
  ['wrong audience', { claims: { aud: 'another-app' } }, 400],
  ['wrong nonce', { claims: { nonce: 'wrong-nonce' } }, 400],
  ['untrusted signature', { untrustedSignature: true }, 400],
]) {
  test(`OIDC refuses ${label}`, async (t) => {
    const idp = await setup(t, options);
    const response = await idp.callback();
    assert.equal(response.status, status);
    assert.doesNotMatch(response.headers.get('set-cookie') ?? '', /__Host-lilauth=/);
    assert.equal(response.headers.get('cache-control'), 'no-store');
  });
}
