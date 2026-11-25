import { KeyObject } from 'crypto';
import {
  DelegatedClaims, DelegationError, decodeHeader, requireValue, verifyDpop, verifyJwt,
} from './profile';

export interface ResourceVerification {
  issuer: string; audience: string;
  /** Resolve kid only from a configured trusted JWKS origin, never from JWT URLs. */
  signingKey(kid: string): Promise<KeyObject | string | null>;
  /** Authenticated private_key_jwt + DPoP request to One's introspection endpoint; no positive cache. */
  introspect(token: string): Promise<Record<string, unknown>>;
  /** Atomic, shared replay storage. No process-local fallback. */
  consumeProof(keyThumbprint: string, jti: string, expiresAt: number): Promise<boolean>;
}

/** Consumer adapter supplied for the Drive team. Mount only after Drive supplies
 * canonical/local identity mapping and preserves its per-operation resource ACLs. */
export async function verifyDelegatedResourceRequest(input: {
  authorization: string; proof: string; method: string; publicUrl: string; requiredScope: string;
}, config: ResourceVerification): Promise<DelegatedClaims> {
  requireValue(input.authorization.startsWith('DPoP ') && !input.authorization.slice(5).includes(' '), 'invalid_token', 401);
  const token = input.authorization.slice(5);
  let header;
  try { header = decodeHeader(token); }
  catch { throw new DelegationError('invalid_token', 401); }
  requireValue(header.typ === 'at+jwt' && header.alg === 'RS256' && typeof header.kid === 'string', 'invalid_token', 401);
  const key = await config.signingKey(header.kid);
  requireValue(key, 'invalid_token', 401);
  let claims: DelegatedClaims;
  try { claims = verifyJwt(token, key, config.issuer, config.audience) as DelegatedClaims; }
  catch { throw new DelegationError('invalid_token', 401); }
  requireValue(claims.type === 'one_delegated_access' && claims.mode === 'DELEGATED' &&
    typeof claims.sub === 'string' && typeof claims.organization_id === 'string' &&
    typeof claims.client_id === 'string' && claims.act?.sub === claims.client_id && typeof claims.azp === 'string' &&
    typeof claims.source_installation_id === 'string' && typeof claims.target_installation_id === 'string' &&
    Number.isInteger(claims.source_epoch) && Number.isInteger(claims.target_epoch) &&
    Number.isInteger(claims.grant_revision) && Number.isInteger(claims.client_revision) &&
    typeof claims.jti === 'string' && claims.nbf === claims.iat && claims.exp! - claims.iat! <= 300,
    'invalid_token', 401);
  requireValue(typeof claims.scope === 'string' && claims.scope.split(' ').includes(input.requiredScope), 'insufficient_scope', 403);
  const url = new URL(input.publicUrl);
  requireValue(url.protocol === 'https:' && !url.username && !url.password, 'invalid_request');
  url.search = ''; url.hash = '';
  let proof;
  try { proof = verifyDpop(input.proof, url.href, input.method.toUpperCase(), token); }
  catch { throw new DelegationError('invalid_dpop_proof', 401); }
  requireValue(claims.cnf?.jkt === proof.jkt && await config.consumeProof(proof.jkt, proof.jti, proof.expiresAt),
    'invalid_dpop_proof', 401);
  const current = await config.introspect(token);
  requireValue(current.active === true && current.jti === claims.jti && current.sub === claims.sub &&
    current.organization_id === claims.organization_id && current.client_id === claims.client_id &&
    current.grant_revision === claims.grant_revision && current.scope === claims.scope,
    'invalid_token', 401);
  return claims;
}

/** The Drive HTTP adapter must apply these headers as well as the status/body.
 * Token-endpoint invalid_dpop_proof remains its separate OAuth 400 response. */
export function resourceAuthenticationError(error: unknown): {
  status: number; headers: Record<string, string>; body: { error: string };
} {
  if (error instanceof DelegationError && ['invalid_token', 'invalid_dpop_proof'].includes(error.error)) {
    return { status: 401, headers: { 'WWW-Authenticate': 'DPoP error="invalid_token"' }, body: { error: error.error } };
  }
  if (error instanceof DelegationError && error.error === 'insufficient_scope') {
    return { status: 403, headers: { 'WWW-Authenticate': 'DPoP error="insufficient_scope"' }, body: { error: error.error } };
  }
  return { status: 503, headers: {}, body: { error: 'temporarily_unavailable' } };
}
