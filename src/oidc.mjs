import * as oidc from 'openid-client';

export const oidcStartPath = '/auth/oidc/start';
export const oidcCallbackPath = '/auth/oidc/callback';

export function createOidc({ issuer, clientId, clientSecret, group }, publicOrigin, fetchImpl) {
  let discovery;
  function provider() {
    discovery ??= oidc.discovery(issuer, clientId, { id_token_signed_response_alg: 'RS256' },
      oidc.ClientSecretBasic(clientSecret), {
        execute: [oidc.enableNonRepudiationChecks],
        timeout: 5,
        [oidc.customFetch]: fetchImpl,
      }).catch((error) => {
      discovery = undefined;
      throw error;
    });
    return discovery;
  }
  return {
    async start() {
      const config = await provider();
      const state = oidc.randomState();
      const nonce = oidc.randomNonce();
      const pkceCodeVerifier = oidc.randomPKCECodeVerifier();
      const url = oidc.buildAuthorizationUrl(config, {
        redirect_uri: new URL(oidcCallbackPath, publicOrigin).href,
        scope: 'openid profile',
        code_challenge: await oidc.calculatePKCECodeChallenge(pkceCodeVerifier),
        code_challenge_method: 'S256',
        state,
        nonce,
      });
      return { url: url.href, state, nonce, pkceCodeVerifier };
    },
    async authorized(callback, { state, nonce, pkceCodeVerifier }) {
      const result = await oidc.authorizationCodeGrant(await provider(), callback, {
        expectedState: state,
        expectedNonce: nonce,
        pkceCodeVerifier,
      });
      const groups = result.claims()?.groups;
      return Array.isArray(groups) && groups.every((name) => typeof name === 'string') && groups.includes(group);
    },
  };
}
