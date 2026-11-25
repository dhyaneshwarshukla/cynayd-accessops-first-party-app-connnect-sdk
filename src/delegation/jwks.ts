import { publicRsaKey } from './profile';
import { correlation, FirstPartyAuthError, httpsUrl, object, readJson, send, Transport } from './transport';

/** The caller pins One's JWKS URL in server configuration. JWT headers cannot select the URL. */
export function oneSigningKeys(jwksUri: string, transport: Transport = {}) {
  const endpoint = httpsUrl(jwksUri);
  if (endpoint.search) throw new Error('The One JWKS URI cannot contain a query');
  return async (kid: string) => {
    const requestId = correlation();
    const payload = await readJson(await send(transport, endpoint.href, { method: 'GET' }, requestId), requestId);
    if (!Array.isArray(payload.keys)) throw new FirstPartyAuthError(503, 'JWKS_PROFILE_MISMATCH', requestId, 'RETRY');
    const matches = payload.keys.map(object).filter(key => key.kid === kid);
    if (matches.length === 0) return null;
    if (matches.length !== 1 || (matches[0].alg && matches[0].alg !== 'RS256') ||
        (matches[0].use && matches[0].use !== 'sig')) {
      throw new FirstPartyAuthError(503, 'JWKS_PROFILE_MISMATCH', requestId, 'RETRY');
    }
    try { return publicRsaKey(matches[0]); }
    catch { throw new FirstPartyAuthError(503, 'JWKS_PROFILE_MISMATCH', requestId, 'RETRY'); }
  };
}
