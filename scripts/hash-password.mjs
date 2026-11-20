import { createPasswordHash, maxPasswordBytes } from '../src/password.mjs';
import { readLimited } from '../src/upstream.mjs';

try {
  if (process.stdin.isTTY) throw new Error();
  console.log(await createPasswordHash(await readLimited(process.stdin, maxPasswordBytes)));
} catch {
  console.error('Supply 12–1024 bytes of password via stdin, without a trailing newline (see README).');
  process.exitCode = 1;
}
