export const identifier = /^[A-Za-z0-9_-]{1,64}$/;

export async function readLimited(stream, limit) {
  const chunks = [];
  let size = 0;
  for await (const chunk of stream) {
    size += chunk.length;
    if (size > limit) throw new Error('body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

class UpstreamRejected extends Error {}

export function managedAgents({ origin, token }, { label, path, decode, mintBody, mintToken, rejectsWrite }) {
  async function request(method, suffix, expected, body) {
    const response = await fetch(`${origin}${path}${suffix}`, {
      method,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body && { 'Content-Type': 'application/json' }),
      },
      body: body && JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    });
    if (response.status !== expected) {
      await response.body?.cancel();
      if ([401, 403].includes(response.status) || rejectsWrite(method, response.status)) {
        throw new UpstreamRejected();
      }
      throw new Error('unexpected upstream status');
    }
    if (expected !== 204) return JSON.parse(await readLimited(response.body, 512 * 1024));
  }

  async function list() {
    const { agents } = await request('GET', '', 200);
    if (!Array.isArray(agents)) throw new Error('invalid credential list');
    const entries = agents.map(decode);
    if (new Set(entries.map(({ name }) => name)).size !== entries.length) {
      throw new Error('ambiguous credential list');
    }
    return entries;
  }

  const unknownOutcome = 'Upstream outcome unknown; writes paused. Operator review required.';
  let busy = false;
  let paused = false;
  async function mutate(name, create, permissions) {
    if (paused) return { status: 503, message: unknownOutcome };
    if (busy) return { status: 409, message: 'Another change is in progress. Try again after it finishes.' };
    busy = true;
    let submitted = false;
    try {
      // These upstreams offer no conditional mutation. Lilauth must be the exclusive writer.
      const entry = (await list()).find((agent) => agent.name === name);
      if (create && entry) return { status: 409, message: 'That name already exists; no credential was replaced.' };
      if (!create && !entry?.revocable) return { status: 409, message: 'No revocable agent credential with that name was found.' };
      submitted = true;
      if (create) {
        const result = await request('POST', '', 201, mintBody(name, permissions));
        return { status: 201, token: mintToken(result, name, permissions) };
      }
      await request('DELETE', `/${encodeURIComponent(name)}`, 204);
      return { status: 200, message: 'Credential revoked.' };
    } catch (error) {
      if (!submitted) return { status: 502, message: 'Could not verify the credential list; no change was submitted.' };
      if (error instanceof UpstreamRejected) return { status: 502, message: 'Upstream rejected the change.' };
      // A lost response does not mean the upstream handler stopped.
      paused = true;
      return { status: 502, message: unknownOutcome };
    } finally {
      busy = false;
    }
  }

  return { label, list, mutate, writeWarning: () => paused ? unknownOutcome : '' };
}
