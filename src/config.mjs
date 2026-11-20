import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { isIP } from 'node:net';
import { parsePasswordHash } from './password.mjs';

export const tokenPattern = /^[0-9a-f]{64}$/i;
const loopback = new Set(['127.0.0.1', '::1']);

function requireSetting(valid, setting) {
  if (!valid) throw new Error(`Invalid or missing ${setting}.`);
}

function origin(value, setting) {
  let url;
  try { url = new URL(value); } catch { requireSetting(false, setting); }
  requireSetting(['http:', 'https:'].includes(url.protocol) &&
    (value === url.origin || value === `${url.origin}/`), setting);
  return url;
}

function secretFile(env, setting, parse) {
  let fd;
  try {
    fd = openSync(env[setting], constants.O_RDONLY | constants.O_NONBLOCK);
    if (!fstatSync(fd).isFile()) throw new Error();
    const buffer = Buffer.alloc(1025);
    const size = readSync(fd, buffer);
    if (size === buffer.length) throw new Error();
    return parse(buffer.subarray(0, size).toString('utf8').trim());
  } catch {
    requireSetting(false, setting);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export function readConfig(env) {
  requireSetting(env.LILCO_AUTH_MODE === 'local', 'LILCO_AUTH_MODE (only local is supported)');
  const username = env.LILCO_ADMIN_USERNAME;
  requireSetting(typeof username === 'string' && /^[A-Za-z0-9_.@-]{1,80}$/.test(username), 'LILCO_ADMIN_USERNAME');
  const passwordHash = secretFile(env, 'LILCO_ADMIN_PASSWORD_HASH_FILE', parsePasswordHash);
  const host = env.LILCO_LISTEN_HOST ?? '127.0.0.1';
  requireSetting(isIP(host), 'LILCO_LISTEN_HOST (an IP address)');
  const portValue = env.LILCO_PORT ?? '3000';
  const port = Number(portValue);
  requireSetting(/^[1-9]\d{0,4}$/.test(portValue) && port <= 65535, 'LILCO_PORT');
  const publicUrl = origin(env.LILCO_PUBLIC_ORIGIN, 'LILCO_PUBLIC_ORIGIN (an HTTP(S) origin)');
  const insecure = env.LILCO_INSECURE_LOOPBACK === '1';
  requireSetting(env.LILCO_INSECURE_LOOPBACK === undefined || insecure, 'LILCO_INSECURE_LOOPBACK');
  if (insecure) {
    requireSetting(loopback.has(host) && publicUrl.protocol === 'http:' &&
      publicUrl.hostname.replace(/^\[|\]$/g, '') === host && Number(publicUrl.port || '80') === port,
      'LILCO_INSECURE_LOOPBACK (matching HTTP loopback origin and listen address required)');
  } else {
    requireSetting(publicUrl.protocol === 'https:', 'LILCO_PUBLIC_ORIGIN (HTTPS required)');
  }

  const backends = {};
  for (const name of ['lilboard', 'lilvault']) {
    const originSetting = `LILCO_${name.toUpperCase()}_ORIGIN`;
    const tokenSetting = `LILCO_${name.toUpperCase()}_MANAGEMENT_TOKEN_FILE`;
    if (env[originSetting] === undefined && env[tokenSetting] === undefined) continue;
    const base = origin(env[originSetting], originSetting).origin;
    const token = secretFile(env, tokenSetting, (value) => {
      if (!tokenPattern.test(value)) throw new Error();
      return value;
    });
    backends[name] = { origin: base, token };
  }
  requireSetting(Object.keys(backends).length > 0, 'upstream configuration (configure at least one backend)');
  requireSetting(!backends.lilboard || !backends.lilvault ||
    backends.lilboard.token.toLowerCase() !== backends.lilvault.token.toLowerCase(),
    'upstream tokens (use distinct management tokens)');
  return { username, passwordHash, host, port, publicOrigin: publicUrl.origin, insecure, backends };
}
