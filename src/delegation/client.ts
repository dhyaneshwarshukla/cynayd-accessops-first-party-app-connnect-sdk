import { randomBytes } from 'crypto';
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
  sessionStatusEndpoint?: string;
  activityEndpoint?: string;
  boundLaunchInitiationEndpoint?: string;
  boundLaunchRedemptionEndpoint?: string;
}

export type ActivityOperation = 'message.send' | 'document.edit' | 'presentation.edit' | 'spreadsheet.edit' |
  'mail.compose' | 'mail.send' | 'file.interact' | 'record.edit';

export interface CentralSessionStatus {
  state: 'ACTIVE';
  reason: 'SESSION_VALID';
  nextAction: 'NONE';
  revision: string | null;
  accessEpoch: number;
  centralExpiresAt: string;
  subjectExpiresAt: string;
  lastActivityAt: string | null;
  idleExpiresAt: string | null;
}

interface TargetToken { value: string; expiresAt: number }

export class DelegationClient {
  private readonly pending = new Map<string, Promise<TargetToken>>();
  private readonly options: DelegationClientOptions;

  constructor(options: DelegationClientOptions) {
    const endpoints = [options.tokenEndpoint, options.introspectionEndpoint, options.launchEvaluationEndpoint,
      options.sessionStatusEndpoint ?? options.launchEvaluationEndpoint,
      options.activityEndpoint ?? options.launchEvaluationEndpoint,
      options.boundLaunchInitiationEndpoint ?? options.launchEvaluationEndpoint,
      options.boundLaunchRedemptionEndpoint ?? options.launchEvaluationEndpoint].map(httpsUrl);
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

  /** Keep the verifier in a one-time host session transaction. */
  async initiateBoundLaunch(callback: string, suppliedRequestId?: string) {
    const requestId = correlation(suppliedRequestId);
    const endpoint = this.options.boundLaunchInitiationEndpoint;
    if (!endpoint) throw new FirstPartyAuthError(503, 'BOUND_LAUNCH_NOT_CONFIGURED', requestId, 'INVESTIGATE');
    const verifier = randomBytes(32).toString('base64url');
    const state = randomBytes(32).toString('base64url');
    const result = await this.form(endpoint, { callback, challenge: digest(verifier), state }, requestId);
    if (typeof result.request !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(result.request) ||
        typeof result.expires_in !== 'number' || !Number.isSafeInteger(result.expires_in) ||
        result.expires_in <= 0 || result.expires_in > 120) {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    return { request: result.request, state, verifier, expiresIn: result.expires_in };
  }

  /** The host must atomically consume the initiating browser's stored transaction first. */
  async redeemBoundLaunch(input: { request: string; verifier: string; expectedState: string; state: string; code: string },
    suppliedRequestId?: string) {
    const requestId = correlation(suppliedRequestId);
    const endpoint = this.options.boundLaunchRedemptionEndpoint;
    if (!endpoint) throw new FirstPartyAuthError(503, 'BOUND_LAUNCH_NOT_CONFIGURED', requestId, 'INVESTIGATE');
    if (!/^[A-Za-z0-9_-]{43}$/.test(input.state) || input.state !== input.expectedState) {
      throw new FirstPartyAuthError(401, 'SOURCE_BINDING_INVALID', requestId, 'REAUTHENTICATE');
    }
    const result = await this.form(endpoint, { request: input.request, code: input.code, verifier: input.verifier }, requestId);
    if (typeof result.subject_token !== 'string' || !result.subject_token) {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    return { subject: result.subject_token };
  }

  evaluateLaunch(subject: string, requestId?: string) {
    return this.form(this.options.launchEvaluationEndpoint, {
      subject_token: subject, subject_token_type: ACCESS_TOKEN_TYPE,
    }, correlation(requestId));
  }

  /** One read-only, confidential status request. Keep the verified subject server-side. */
  async sessionStatus(binding: VerifiedSession, suppliedRequestId?: string): Promise<CentralSessionStatus> {
    const requestId = correlation(suppliedRequestId);
    const endpoint = this.options.sessionStatusEndpoint;
    if (!endpoint) throw new FirstPartyAuthError(503, 'SESSION_STATUS_NOT_CONFIGURED', requestId, 'INVESTIGATE');
    if (!binding.subject) throw new FirstPartyAuthError(401, 'SOURCE_BINDING_INVALID', requestId, 'REAUTHENTICATE');
    const result = await this.form(endpoint, {
      subject_token: binding.subject, subject_token_type: ACCESS_TOKEN_TYPE,
    }, requestId);
    if (result.state !== 'ACTIVE' || result.reason !== 'SESSION_VALID' || result.nextAction !== 'NONE' ||
        result.accessEpoch !== binding.accessEpoch ||
        (result.revision !== null && (typeof result.revision !== 'string' || !result.revision)) ||
        (result.lastActivityAt !== null && (typeof result.lastActivityAt !== 'string' || !Number.isFinite(Date.parse(result.lastActivityAt)))) ||
        (result.idleExpiresAt !== null && (typeof result.idleExpiresAt !== 'string' || !Number.isFinite(Date.parse(result.idleExpiresAt)))) ||
        typeof result.centralExpiresAt !== 'string' || typeof result.subjectExpiresAt !== 'string' ||
        !(Date.parse(result.centralExpiresAt) > Date.now()) || !(Date.parse(result.subjectExpiresAt) > Date.now())) {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    return { state: 'ACTIVE', reason: 'SESSION_VALID', nextAction: 'NONE', revision: result.revision,
      accessEpoch: binding.accessEpoch, centralExpiresAt: result.centralExpiresAt, subjectExpiresAt: result.subjectExpiresAt,
      lastActivityAt: result.lastActivityAt, idleExpiresAt: result.idleExpiresAt };
  }

  /** Use only after a policy-qualified interactive command has been accepted by the application backend. */
  async reportActivity(binding: VerifiedSession, operation: ActivityOperation, eventId: string, suppliedRequestId?: string) {
    const requestId = correlation(suppliedRequestId);
    const endpoint = this.options.activityEndpoint;
    if (!endpoint) throw new FirstPartyAuthError(503, 'ACTIVITY_NOT_CONFIGURED', requestId, 'INVESTIGATE');
    if (!binding.subject || binding.expiresAt <= Date.now()) {
      throw new FirstPartyAuthError(401, 'SOURCE_SESSION_EXPIRED', requestId, 'REAUTHENTICATE');
    }
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(eventId)) {
      throw new FirstPartyAuthError(400, 'INVALID_ACTIVITY_EVENT', requestId, 'INVESTIGATE');
    }
    const result = await this.form(endpoint, {
      subject_token: binding.subject, subject_token_type: ACCESS_TOKEN_TYPE, operation, event_id: eventId,
    }, requestId);
    if (result.accepted !== true || typeof result.updated !== 'boolean' ||
        (result.authenticationIdleUpdated !== undefined &&
          (typeof result.authenticationIdleUpdated !== 'boolean' || (result.authenticationIdleUpdated && !result.updated)))) {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    return { accepted: true as const, updated: result.updated,
      ...(result.authenticationIdleUpdated !== undefined ? { authenticationIdleUpdated: result.authenticationIdleUpdated } : {}) };
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
