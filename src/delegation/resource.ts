import { KeyObject } from 'node:crypto';
import { DelegationClient } from './client';
import type { DelegatedClaims } from './profile';
import { resourceAuthenticationError, verifyDelegatedResourceRequest } from './resource-verifier';
import { correlation, FirstPartyAuthError, httpsUrl } from './transport';


export interface ReplayStore {
  /** Insert only if absent, atomically across all resource instances. Expiry is Unix seconds. */
  consume(thumbprint: string, proofId: string, expiresAt: number): Promise<boolean>;
}

export interface ResourceIdentity {
  userId: string;
  organizationId: string;
  installedAppId: string;
}

export interface ResourceOptions<Context> {
  issuer: string;
  audience: string;
  publicOrigin: string;
  signingKey(kid: string): Promise<KeyObject | string | null>;
  delegation: DelegationClient;
  replay: ReplayStore;
  /** Resolve verified canonical identity into the local tenant and check the operation's resource ACL. */
  authorize(identity: ResourceIdentity, context: Context): Promise<boolean>;
}

export class DelegatedResource<Context> {
  private readonly options: ResourceOptions<Context>;
  private readonly origin: string;

  constructor(options: ResourceOptions<Context>) {
    const origin = httpsUrl(options.publicOrigin);
    if (origin.pathname !== '/' || origin.search || !options.audience) throw new Error('Invalid resource configuration');
    httpsUrl(options.issuer);
    this.origin = origin.origin;
    this.options = { ...options };
  }

  async authorize(input: {
    authorization: string; proof: string; method: string; path: string; requiredScope: string; requestId?: string;
  }, context: Context): Promise<ResourceIdentity> {
    const requestId = correlation(input.requestId);
    const options = this.options;
    const publicUrl = new URL(input.path, this.origin);
    if (!input.path.startsWith('/') || publicUrl.origin !== this.origin ||
        !/^[a-z][a-z0-9_.:-]{1,127}$/.test(input.requiredScope)) {
      throw new FirstPartyAuthError(400, 'INVALID_RESOURCE_REQUEST', requestId, 'INVESTIGATE');
    }
    let claims: DelegatedClaims;
    try {
      claims = await verifyDelegatedResourceRequest({ ...input, publicUrl: publicUrl.href }, {
        issuer: options.issuer, audience: options.audience,
        signingKey: kid => options.signingKey(kid),
        introspect: token => options.delegation.introspect(token, options.audience, requestId),
        consumeProof: (jkt, jti, expiresAt) => options.replay.consume(jkt, jti, expiresAt),
      });
    } catch (error) {
      if (error instanceof FirstPartyAuthError && (error.status === 429 || error.status === 503)) throw error;
      const result = resourceAuthenticationError(error);
      throw new FirstPartyAuthError(result.status, result.body.error, requestId,
        result.status === 503 ? 'RETRY' : result.status === 403 ? 'ACCESS_DENIED' : 'INVESTIGATE');
    }
    const identity = { userId: claims.sub, organizationId: claims.organization_id, installedAppId: claims.target_installation_id };
    let allowed: boolean;
    try { allowed = await options.authorize(identity, context); }
    catch { throw new FirstPartyAuthError(503, 'RESOURCE_AUTHORITY_UNAVAILABLE', requestId, 'RETRY'); }
    if (allowed !== true) throw new FirstPartyAuthError(403, 'RESOURCE_ACCESS_DENIED', requestId, 'ACCESS_DENIED');
    return identity;
  }
}

export function authErrorResponse(error: FirstPartyAuthError) {
  const headers: Record<string, string> = { 'X-Request-Id': error.requestId, 'Cache-Control': 'no-store' };
  if (error.retryAfter) headers['Retry-After'] = error.retryAfter;
  if (error.code === 'invalid_token' || error.code === 'invalid_dpop_proof') {
    if (error.status === 401) headers['WWW-Authenticate'] = 'DPoP error="invalid_token"';
  }
  if (error.status === 403 && error.code === 'insufficient_scope') headers['WWW-Authenticate'] = 'DPoP error="insufficient_scope"';
  return { status: error.status, headers, body: { code: error.code, nextAction: error.nextAction, requestId: error.requestId } };
}
