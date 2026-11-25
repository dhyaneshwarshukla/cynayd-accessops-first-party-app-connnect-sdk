import { createHash, createPublicKey, KeyObject } from 'crypto';
import jwt, { JwtPayload } from 'jsonwebtoken';

export const EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
export const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
export const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
export class DelegationError extends Error {
  constructor(public readonly error: string, public readonly status = 400) { super(error); }
}
export function requireValue(condition: unknown, code: string, status = 400): asserts condition {
  if (!condition) throw new DelegationError(code, status);
}
export function digest(value: string): string {
  return createHash('sha256').update(value).digest('base64url');
}
export function httpsEndpoint(value: string): string {
  const url = new URL(value);
  requireValue(url.protocol === 'https:' && !url.username && !url.password && !url.hash && !url.search,
    'server_configuration', 503);
  return url.href;
}
export interface DelegationConfig {
  issuer: string; tokenEndpoint: string; introspectionEndpoint: string; jwksUri: string;
}
export function readDelegationConfig(): DelegationConfig {
  try {
    requireValue(process.env.ONE_DELEGATION_ENABLED === 'true', 'temporarily_unavailable', 503);
    const issuer = httpsEndpoint(process.env.ONE_DELEGATION_ISSUER || '');
    const tokenEndpoint = httpsEndpoint(process.env.ONE_DELEGATION_TOKEN_ENDPOINT || '');
    const introspectionEndpoint = httpsEndpoint(process.env.ONE_DELEGATION_INTROSPECTION_ENDPOINT || '');
    const jwksUri = httpsEndpoint(process.env.ONE_DELEGATION_JWKS_URI || '');
    requireValue([tokenEndpoint, introspectionEndpoint, jwksUri].every(v => new URL(v).origin === new URL(issuer).origin),
      'server_configuration', 503);
    return { issuer, tokenEndpoint, introspectionEndpoint, jwksUri };
  } catch (error) {
    if (error instanceof DelegationError) throw error;
    throw new DelegationError('server_configuration', 503);
  }
}
export function publicRsaKey(jwk: Record<string, unknown>): KeyObject {
  requireValue(jwk.kty === 'RSA' && typeof jwk.n === 'string' && typeof jwk.e === 'string' &&
    !['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(k => k in jwk), 'invalid_client', 401);
  let key: KeyObject;
  try { key = createPublicKey({ key: jwk as any, format: 'jwk' }); }
  catch { throw new DelegationError('invalid_client', 401); }
  requireValue((key.asymmetricKeyDetails?.modulusLength || 0) >= 2048, 'invalid_client', 401);
  return key;
}
export function verifyJwt(token: string, key: KeyObject | string, issuer: string, audience: string): JwtPayload {
  try {
    const result = jwt.verify(token, key, { algorithms: ['RS256'], issuer, audience, clockTolerance: 0 });
    requireValue(typeof result === 'object' && result !== null && result.aud === audience && result.iss === issuer,
      'invalid_grant');
    requireValue(Number.isInteger(result.exp) && Number.isInteger(result.iat) && result.iat! <= Math.floor(Date.now() / 1000) + 5,
      'invalid_grant');
    return result;
  } catch { throw new DelegationError('invalid_grant'); }
}
export function decodeHeader(token: string): jwt.JwtHeader {
  requireValue(typeof token === 'string' && token.length <= 32768, 'invalid_request');
  const decoded = jwt.decode(token, { complete: true });
  requireValue(decoded?.header && !decoded.header.crit && !(decoded.header as any).jku && !(decoded.header as any).x5u,
    'invalid_request');
  return decoded.header;
}
export interface Proof { jkt: string; jti: string; expiresAt: number }
export function verifyDpop(proof: string, endpoint: string, method = 'POST', accessToken?: string): Proof {
  try {
    const header = decodeHeader(proof) as jwt.JwtHeader & { jwk?: Record<string, unknown> };
    const jwk = header.jwk;
    requireValue(header.typ === 'dpop+jwt' && header.alg === 'ES256' && jwk?.kty === 'EC' && jwk.crv === 'P-256' &&
      typeof jwk.x === 'string' && typeof jwk.y === 'string' &&
      !['d', 'p', 'q', 'k'].some(k => k in jwk), 'invalid_dpop_proof');
    const key = createPublicKey({ key: jwk as any, format: 'jwk' });
    const payload = jwt.verify(proof, key, { algorithms: ['ES256'] }) as JwtPayload;
    const now = Math.floor(Date.now() / 1000);
    requireValue(payload.htm === method && payload.htu === endpoint && Number.isInteger(payload.iat) &&
      Math.abs(now - payload.iat!) <= 30 && typeof payload.jti === 'string' &&
      /^[A-Za-z0-9_-]{16,128}$/.test(payload.jti), 'invalid_dpop_proof');
    requireValue(accessToken ? payload.ath === digest(accessToken) : payload.ath === undefined, 'invalid_dpop_proof');
    return { jkt: digest(JSON.stringify({ crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y })),
      jti: payload.jti, expiresAt: now + 65 };
  } catch { throw new DelegationError('invalid_dpop_proof'); }
}

export interface LaunchSessionBinding {
  reference: string; sessionId: string; originalIat: number; expiresAt: number;
}
export interface SubjectClaims extends JwtPayload {
  type: 'one_delegation_subject'; id: string; sub: string; organizationId: string;
  appSlug: string; installedAppId: string; launchAccessEpoch: number;
  launchJti: string; sessionBinding: LaunchSessionBinding;
}
export interface DelegatedClaims extends JwtPayload {
  type: 'one_delegated_access'; sub: string; organization_id: string; client_id: string;
  azp: string; act: { sub: string }; mode: 'DELEGATED'; scope: string;
  source_installation_id: string; target_installation_id: string;
  source_epoch: number; target_epoch: number; grant_id: string; grant_revision: number;
  client_revision: number; credential_kid: string; resource_revision: number;
  cnf: { jkt: string }; subject: SubjectClaims;
}
