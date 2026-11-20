import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { actionResult, dashboard, login, page } from './html.mjs';
import { lilboard } from './lilboard.mjs';
import { lilvault, parseVaultGrants } from './lilvault.mjs';
import { verifyPassword } from './password.mjs';
import { identifier, readLimited } from './upstream.mjs';

const sessionSeconds = 8 * 60 * 60;
const sessionLimit = 32;
const randomId = () => randomBytes(32).toString('hex');

function respond(res, status, html, headers) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    'Referrer-Policy': 'same-origin',
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  res.end(html);
}

async function readForm(req, allowedFields) {
  if (!/^application\/x-www-form-urlencoded(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '')) {
    throw new Error('invalid content type');
  }
  if (Number(req.headers['content-length']) > 8192) throw new Error('form too large');
  const form = new URLSearchParams((await readLimited(req.iterator({ destroyOnReturn: false }), 8192)).toString('utf8'));
  const values = Object.create(null);
  for (const [key, value] of form) {
    if (!allowedFields.includes(key) || Object.hasOwn(values, key)) throw new Error('unexpected form field');
    values[key] = value;
  }
  return values;
}

function matchesCsrf(candidate, expected) {
  return /^[a-f0-9]{64}$/.test(candidate) && timingSafeEqual(Buffer.from(candidate), Buffer.from(expected));
}

export function createLilauth(config) {
  const backends = new Map();
  if (config.backends.lilboard) backends.set('lilboard', lilboard(config.backends.lilboard));
  if (config.backends.lilvault) backends.set('lilvault', lilvault(config.backends.lilvault));
  const sessions = new Map();
  const cookieName = config.insecure ? 'lilauth-dev' : '__Host-lilauth';
  const cookie = (id, maxAge) => `${cookieName}=${id}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${config.insecure ? '' : '; Secure'}`;
  let loginFailures = 0;
  let loginResetAt = 0;
  let verifying = false;

  async function handle(req, res) {
    const now = Date.now();
    for (const [id, session] of sessions) if (session.expiresAt <= now) sessions.delete(id);
    const id = (req.headers.cookie ?? '').match(new RegExp(`(?:^|;\\s*)${cookieName}=([a-f0-9]{64})(?:;|$)`))?.[1];
    const session = sessions.get(id);
    if (req.method === 'GET' && req.url === '/') {
      if (!session) return respond(res, 200, login());
      const views = await Promise.all([...backends.values()].map(async ({ label, list, writeWarning }) => {
        const entries = await list().catch(() => undefined);
        return { label, entries, warning: writeWarning() };
      }));
      return respond(res, 200, dashboard(session.csrf, views));
    }

    if (req.method !== 'POST' || !['/login', '/logout', '/mint', '/revoke'].includes(req.url)) {
      return respond(res, 404, page('Not found', '<p><a href="/">Return to Lilauth</a></p>'));
    }
    if (req.headers.origin !== config.publicOrigin) return respond(res, 403, page('Request origin rejected', ''));
    if (req.url !== '/login' && !session) return respond(res, 401, login('Sign in to continue.'));

    let form;
    try {
      const fields = req.url === '/login' ? ['username', 'password'] : req.url === '/logout' ? ['csrf'] :
        ['csrf', 'target', 'name', ...(req.url === '/mint' ? ['permissions'] : [])];
      form = await readForm(req, fields);
    } catch {
      return respond(res, 400, page('Invalid form', '<p><a href="/">Return to Lilauth</a></p>'));
    }

    if (req.url === '/login') {
      if (session) return respond(res, 303, '', { Location: '/' });
      const attemptTime = Date.now();
      if (attemptTime >= loginResetAt) {
        loginFailures = 0;
        loginResetAt = attemptTime + 60_000;
      }
      if (verifying || loginFailures >= 5) {
        return respond(res, 429, login('Too many sign-in attempts. Try again shortly.'), { 'Retry-After': '60' });
      }
      verifying = true;
      try {
        const valid = await verifyPassword(Buffer.from(form.password ?? ''), config.passwordHash);
        if (!valid || form.username !== config.username) {
          loginFailures++;
          return respond(res, 401, login('Invalid username or password.'));
        }
        loginFailures = 0;
        if (sessions.size === sessionLimit) sessions.delete(sessions.keys().next().value);
        const newId = randomId();
        sessions.set(newId, { csrf: randomId(), expiresAt: Date.now() + sessionSeconds * 1000 });
        return respond(res, 303, '', { Location: '/', 'Set-Cookie': cookie(newId, sessionSeconds) });
      } finally {
        verifying = false;
      }
    }

    if (sessions.get(id) !== session || session.expiresAt <= Date.now()) {
      return respond(res, 401, login('Sign in to continue.'));
    }
    if (!matchesCsrf(form.csrf, session.csrf)) return respond(res, 403, page('Invalid CSRF token', ''));
    if (req.url === '/logout') {
      sessions.delete(id);
      return respond(res, 303, '', { Location: '/', 'Set-Cookie': cookie('', 0) });
    }

    const create = req.url === '/mint';
    const targets = create && form.target === 'both' && backends.size === 2 ? [...backends.keys()] : [form.target];
    if (typeof form.name !== 'string' || !identifier.test(form.name) || targets.some((target) => !backends.has(target))) {
      return respond(res, 400, page('Invalid target or agent name', '<p><a href="/">Return to Lilauth</a></p>'));
    }
    let permissions;
    if (create) {
      const input = form.permissions ?? '';
      try {
        if (targets.includes('lilvault')) permissions = parseVaultGrants(input);
        else if (input.trim()) throw new Error('unexpected grants');
      } catch {
        return respond(res, 400, page('Invalid grants', '<p>Use only distinct existing vaults with read or read-write access.</p><p><a href="/">Return to Lilauth</a></p>'));
      }
    }
    const results = await Promise.all(targets.map(async (label) => ({
      label, ...await backends.get(label).mutate(form.name, create, permissions),
    })));
    const status = results.every((result) => result.status === results[0].status) ? results[0].status : 200;
    return respond(res, status, actionResult(create, form.name, results));
  }

  return createServer({ headersTimeout: 10_000, requestTimeout: 15_000, connectionsCheckingInterval: 1000 }, (req, res) => {
    handle(req, res).catch(() => respond(res, 500, page('Request failed', '<p><a href="/">Return to Lilauth</a></p>')));
  });
}
