import { argon2, randomBytes, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const derive = promisify(argon2);
const profile = '$argon2id$v=19$m=65536,t=3,p=1$';
export const maxPasswordBytes = 1024;

const encode = (bytes) => bytes.toString('base64').replace(/=+$/, '');
const hash = (message, nonce) => derive('argon2id', {
  message, nonce, parallelism: 1, memory: 65536, passes: 3, tagLength: 32,
});

export function parsePasswordHash(value) {
  if (!value.startsWith(profile)) throw new Error('invalid Argon2id profile');
  const parts = value.slice(profile.length).split('$');
  if (parts.length !== 2 || !/^[A-Za-z0-9+/]{22}$/.test(parts[0]) ||
      !/^[A-Za-z0-9+/]{43}$/.test(parts[1])) throw new Error('invalid Argon2id hash');
  const [salt, digest] = parts.map((part) => Buffer.from(part, 'base64'));
  if (encode(salt) !== parts[0] || encode(digest) !== parts[1]) throw new Error('invalid Argon2id encoding');
  return { salt, digest };
}

export async function createPasswordHash(password) {
  if (password.length < 12 || password.length > maxPasswordBytes) throw new Error('invalid password length');
  const salt = randomBytes(16);
  return `${profile}${encode(salt)}$${encode(await hash(password, salt))}`;
}

export async function verifyPassword(password, { salt, digest }) {
  if (password.length === 0 || password.length > maxPasswordBytes) return false;
  return timingSafeEqual(await hash(password, salt), digest);
}
