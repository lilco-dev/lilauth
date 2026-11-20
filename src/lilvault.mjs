import { tokenPattern } from './config.mjs';
import { identifier, managedAgents } from './upstream.mjs';

const vaultGrant = /^[A-Za-z0-9_-]{1,64}:(?:read|read-write)$/;

function validateGrants(permissions, allowManagement) {
  if (!Array.isArray(permissions) || !permissions.length) throw new Error('missing vault grants');
  const vaults = new Set();
  for (const grant of permissions) {
    if (typeof grant !== 'string' || !(vaultGrant.test(grant) || (allowManagement && grant === 'auth:manage'))) {
      throw new Error('invalid vault grant');
    }
    const key = grant === 'auth:manage' ? grant : grant.split(':')[0];
    if (vaults.has(key)) throw new Error('ambiguous vault grants');
    vaults.add(key);
  }
  return permissions;
}

export function parseVaultGrants(input) {
  return validateGrants(input.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), false);
}

export function lilvault(config) {
  return managedAgents(config, {
    label: 'lilvault',
    path: '/v1/auth/agents',
    // DELETE can fail while removing key files after revoking the in-memory credential.
    rejectsWrite: (method, status) => status === 409 || (method === 'POST' && status === 400),
    decode({ name, permissions }) {
      if (typeof name !== 'string' || !identifier.test(name)) throw new Error('invalid vault agent');
      const grants = validateGrants(permissions, true);
      return { name, grants: grants.join(', '), revocable: !grants.includes('auth:manage') };
    },
    mintBody: (name, permissions) => ({ name, permissions }),
    mintToken(result, name, permissions) {
      if (result.name !== name || typeof result.token !== 'string' || !tokenPattern.test(result.token) ||
          !Array.isArray(result.permissions) || result.permissions.length !== permissions.length ||
          !permissions.every((grant, i) => result.permissions[i] === grant)) throw new Error('invalid mint reply');
      return result.token;
    },
  });
}
