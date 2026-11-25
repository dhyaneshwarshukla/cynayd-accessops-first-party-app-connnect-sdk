import { ACCESS_TOKEN_TYPE, ASSERTION_TYPE, EXCHANGE_GRANT, digest } from './profile';
import { DelegationSigner } from './signer';
import type { VerifiedSession } from './session';
import { correlation, FirstPartyAuthError, httpsUrl, readJson, send, Transport } from './transport';

export interface RegisteredOperation {
  /** Exact registry audience and scopes. Configuration is owned by the backend. */
  audience: string;
  scopes: readonly string[];
  method: string;
  /** Fixed public origin, with no pathname. */
  origin: string;
  /** Whether this operation is allowed on the supplied public URL. Check the route and parameters here. */
  allowsUrl(url: URL): boolean;
}

export interface DelegationClientOptions extends Transport {
  signer: DelegationSigner;
  tokenEndpoint: string;
  introspectionEndpoint: string;
  launchEvaluationEndpoint: string;
}

interface TargetToken { value: string; expiresAt: number }

export class DelegationClient {
  private readonly pending = new Map<string, Promise<TargetToken>>();
  private readonly options: DelegationClientOptions;

  constructor(options: DelegationClientOptions) {
    const endpoints = [options.tokenEndpoint, options.introspectionEndpoint, options.launchEvaluationEndpoint].map(httpsUrl);
    if (endpoints.some(url => url.search || url.origin !== endpoints[0].origin)) {
      throw new Error('One endpoints must have a common trusted origin and no query');
    }
    this.options = { ...options };
  }

  private async form(endpoint: string, fields: Record<string, string>, requestId: string) {
    const { signer } = this.options;
    return readJson(await send(this.options, endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: signer.proof('POST', endpoint) },
      body: new URLSearchParams({
        ...fields, client_id: signer.clientId, client_assertion_type: ASSERTION_TYPE,
        client_assertion: signer.assertion(endpoint),
      }),
    }, requestId), requestId);
  }

  evaluateLaunch(subject: string, requestId?: string) {
    return this.form(this.options.launchEvaluationEndpoint, {
      subject_token: subject, subject_token_type: ACCESS_TOKEN_TYPE,
    }, correlation(requestId));
  }

  introspect(token: string, audience: string, requestId?: string) {
    return this.form(this.options.introspectionEndpoint, { token, audience }, correlation(requestId));
  }

  private async exchange(subject: string, audience: string, scope: string, requestId: string): Promise<TargetToken> {
    const started = Date.now();
    const result = await this.form(this.options.tokenEndpoint, {
      grant_type: EXCHANGE_GRANT, subject_token_type: ACCESS_TOKEN_TYPE, requested_token_type: ACCESS_TOKEN_TYPE,
      subject_token: subject, audience, scope,
    }, requestId);
    if (result.token_type !== 'DPoP' || result.issued_token_type !== ACCESS_TOKEN_TYPE ||
        typeof result.access_token !== 'string' || !result.access_token || /\s/.test(result.access_token) ||
        typeof result.expires_in !== 'number' || !Number.isInteger(result.expires_in) ||
        result.expires_in <= 0 || result.expires_in > 300 ||
        typeof result.scope !== 'string' || result.scope.split(' ').sort().join(' ') !== scope) {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    return { value: result.access_token, expiresAt: started + result.expires_in * 1000 };
  }

  /** Authorization stays inside the backend. The caller forwards only sanitized target results. */
  async call(binding: VerifiedSession, operation: RegisteredOperation,
    publicUrl: string, init: Omit<RequestInit, 'method'> = {}, suppliedRequestId?: string): Promise<Response> {
    const requestId = correlation(suppliedRequestId);
    if (!binding.subject || !binding.sessionId || !Number.isFinite(binding.expiresAt) || binding.expiresAt <= Date.now()) {
      throw new FirstPartyAuthError(401, 'SOURCE_SESSION_EXPIRED', requestId, 'REAUTHENTICATE');
    }
    let url;
    try { url = httpsUrl(publicUrl); }
    catch { throw new FirstPartyAuthError(400, 'INVALID_RESOURCE_URL', requestId, 'INVESTIGATE'); }
    if (url.origin !== operation.origin || !operation.allowsUrl(new URL(url))) {
      throw new FirstPartyAuthError(400, 'INVALID_RESOURCE_URL', requestId, 'INVESTIGATE');
    }
    const scopes = [...new Set(operation.scopes)].sort();
    if (!operation.audience || !scopes.length || scopes.length > 32 ||
        scopes.some(scope => !/^[a-z][a-z0-9_.:-]{1,127}$/.test(scope))) {
      throw new FirstPartyAuthError(400, 'INVALID_OPERATION_REGISTRATION', requestId, 'INVESTIGATE');
    }
    const scope = scopes.join(' ');
    const key = digest(JSON.stringify([binding.sessionId, binding.subject, operation.audience, scope]));
    let pending = this.pending.get(key);
    if (!pending) {
      pending = this.exchange(binding.subject, operation.audience, scope, requestId).finally(() => this.pending.delete(key));
      this.pending.set(key, pending);
    }
    const token = await pending;
    if (Math.min(binding.expiresAt, token.expiresAt) <= Date.now()) {
      throw new FirstPartyAuthError(401, 'DELEGATION_CREDENTIAL_EXPIRED', requestId,
        binding.expiresAt <= Date.now() ? 'REAUTHENTICATE' : 'RETRY');
    }
    const headers = new Headers(init.headers);
    const headerNames: string[] = [];
    headers.forEach((_value, name) => headerNames.push(name));
    for (const name of headerNames) {
      if (['cookie', 'host', 'forwarded', 'proxy-authorization'].includes(name) || name.startsWith('x-forwarded-')) {
        headers.delete(name);
      }
    }
    headers.set('Authorization', `DPoP ${token.value}`);
    headers.set('DPoP', this.options.signer.proof(operation.method, url.href, token.value));
    return send(this.options, url.href, { ...init, headers, method: operation.method }, requestId);
  }
}
