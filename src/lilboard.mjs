import { tokenPattern } from './config.mjs';
import { identifier, managedAgents } from './upstream.mjs';

export function lilboard(config) {
  return managedAgents(config, {
    label: 'lilboard',
    path: '/api/auth/agents',
    rejectsWrite: (method, status) => status === 400 || (method === 'DELETE' && status === 404),
    decode({ name, kind }) {
      if (typeof name !== 'string' || !name || !['agent', 'person', 'admin'].includes(kind)) {
        throw new Error('invalid board actor');
      }
      return {
        name,
        grants: `${kind}: all-board access${kind === 'admin' ? ' and credential management' : ''}`,
        revocable: kind === 'agent' && identifier.test(name),
      };
    },
    mintBody: (name) => ({ name, kind: 'agent' }),
    mintToken(result, name) {
      if (result.name !== name || result.kind !== 'agent' ||
          typeof result.token !== 'string' || !tokenPattern.test(result.token)) throw new Error('invalid mint reply');
      return result.token;
    },
  });
}
