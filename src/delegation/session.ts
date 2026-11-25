import { KeyObject } from 'node:crypto';
import { decodeHeader, SubjectClaims, verifyJwt } from './profile';
import { DelegationClient } from './client';
import { correlation, FirstPartyAuthError, httpsUrl, object, readJson, send, Transport } from './transport';

export interface SessionIdentity {
  userId: string;
  organizationId: string;
  installedAppId: string;
}

export interface SourceEvidence {
  centralSessionId: string;
  launchReference: string;
  launchTokenExpiresAt: number;
  portalBindingExpiresAt: number;
  subjectExpiresAt: number;
  apiTokenExpiresAt: number;
}

export interface VerifiedSession extends SessionIdentity {
  sessionId: string;
  appSlug: string;
  accessEpoch: number;
  subject: string;
  apiToken: string;
  expiresAt: number;
  sourceEvidence?: SourceEvidence;
}

/** Use protected server-side storage. Writes and invalidation must use the host session revision. */
export interface CredentialStore {
  load(sessionId: string): Promise<{ revision: string; credentials: VerifiedSession } | undefined>;
  replaceIfCurrent(sessionId: string, expectedRevision: string, credentials: VerifiedSession): Promise<boolean>;
  removeIfCurrent(sessionId: string, expectedRevision: string): Promise<boolean>;
}

export interface LaunchState {
  sessionId: string;
  revision: string;
  expected: SessionIdentity;
}

/** Consume the state atomically, matching the current authenticated browser session or verified launch transaction. */
export interface LaunchStateStore {
  consume(state: string): Promise<LaunchState | undefined>;
}

export interface BoundLaunchState extends LaunchState {
  request: string;
  verifier: string;
  centralSessionId: string;
  accessEpoch: number;
}

/** Consume only a transaction bound to the initiating authenticated host browser. */
export interface BoundLaunchStateStore {
  consume(state: string): Promise<BoundLaunchState | undefined>;
}

export interface BoundDelegationBinding extends SessionIdentity {
  sessionId: string;
  centralSessionId: string;
  appSlug: string;
  accessEpoch: number;
  subject: string;
  expiresAt: number;
}

export interface BoundDelegationStore {
  /** Update delegation evidence only, conditional on an existing authenticated host session. */
  replaceIfCurrent(sessionId: string, revision: string, binding: BoundDelegationBinding): Promise<boolean>;
}

export interface OneSessionOptions extends Transport {
  issuer: string;
  identityOrigin: string;
  appSlug: string;
  /** Resolve from One's configured, trusted JWKS. Unknown KID returns null. */
  signingKey(kid: string): Promise<KeyObject | string | null>;
  delegation: DelegationClient;
  /** Use the stored evidence deadlines after completing a verified One code launch. */
  useEvidenceDeadlines?: boolean;
}

function reauthenticate(requestId: string, code = 'SOURCE_BINDING_INVALID'): never {
  throw new FirstPartyAuthError(401, code, requestId, 'REAUTHENTICATE');
}

function timestamp(value: unknown): number {
  return typeof value === 'string' ? Date.parse(value) : NaN;
}

export class OneApplicationSession {
  private readonly origin: string;
  private readonly options: OneSessionOptions;
  readonly launchUrl: string;

  constructor(options: OneSessionOptions) {
    const origin = httpsUrl(options.identityOrigin);
    const issuer = httpsUrl(options.issuer);
    if (origin.origin !== issuer.origin || origin.pathname !== '/' || origin.search || issuer.search ||
        !/^[a-z][a-z0-9-]{1,127}$/.test(options.appSlug)) throw new Error('Invalid One source configuration');
    this.origin = origin.origin;
    this.options = { ...options };
    this.launchUrl = new URL(`/api/sso/launch/${options.appSlug}`, this.origin).href;
  }

  private async post(path: string, fields: Record<string, unknown>, requestId: string) {
    return readJson(await send(this.options, new URL(path, this.origin).href, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(fields),
    }, requestId), requestId);
  }

  /** Browser callback adapter must supply server-verified state and a code from the registered return flow. */
  async redeem(input: { code: string; state: string }, states: LaunchStateStore, suppliedRequestId?: string) {
    const requestId = correlation(suppliedRequestId);
    if (!input.code || !input.state) reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    let state;
    try { state = await states.consume(input.state); }
    catch { throw new FirstPartyAuthError(503, 'LAUNCH_STATE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!state) reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    const result = await this.post('/api/sso/redeem-code', {
      code: input.code, appSlug: this.options.appSlug,
    }, requestId);
    if (result.success !== true || typeof result.ssoToken !== 'string') {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    const credentials = await this.validate(result.ssoToken, state.sessionId, state.expected, requestId);
    return { credentials, expectedRevision: state.revision };
  }

  async completeCodeLaunch(input: { code: string; state: string }, states: LaunchStateStore, store: CredentialStore,
    suppliedRequestId?: string): Promise<VerifiedSession> {
    const requestId = correlation(suppliedRequestId);
    const { credentials, expectedRevision } = await this.redeem(input, states, requestId);
    let stored;
    try { stored = await store.replaceIfCurrent(credentials.sessionId, expectedRevision, credentials); }
    catch { throw new FirstPartyAuthError(503, 'CREDENTIAL_STORE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!stored) {
      reauthenticate(requestId, 'SOURCE_SESSION_CHANGED');
    }
    return credentials;
  }

  async completeBoundLaunch(input: { code: string; request: string; state: string }, states: BoundLaunchStateStore,
    store: BoundDelegationStore, suppliedRequestId?: string): Promise<BoundDelegationBinding> {
    const requestId = correlation(suppliedRequestId);
    const opaque = /^[A-Za-z0-9_-]{43}$/;
    if (![input.code, input.request, input.state].every(value => opaque.test(value))) {
      reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    }
    let state;
    try { state = await states.consume(input.state); }
    catch { throw new FirstPartyAuthError(503, 'LAUNCH_STATE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!state || state.request !== input.request || !state.sessionId || !state.revision ||
        !state.centralSessionId || !Number.isSafeInteger(state.accessEpoch) || state.accessEpoch < 1) {
      reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    }
    const { subject } = await this.options.delegation.redeemBoundLaunch({
      ...input, verifier: state.verifier, expectedState: input.state,
    }, requestId);
    const claims = await this.verifySubject(subject, state.expected, requestId);
    if (claims.sessionBinding.sessionId !== state.centralSessionId || claims.launchAccessEpoch !== state.accessEpoch) {
      reauthenticate(requestId, 'SOURCE_BINDING_CHANGED');
    }
    const binding = { ...state.expected, sessionId: state.sessionId, centralSessionId: state.centralSessionId,
      appSlug: this.options.appSlug, accessEpoch: state.accessEpoch, subject,
      expiresAt: Math.min(claims.exp!, claims.sessionBinding.expiresAt) * 1000 };
    if (binding.expiresAt <= Date.now()) reauthenticate(requestId, 'SOURCE_SESSION_EXPIRED');
    let stored;
    try { stored = await store.replaceIfCurrent(binding.sessionId, state.revision, binding); }
    catch { throw new FirstPartyAuthError(503, 'CREDENTIAL_STORE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!stored) reauthenticate(requestId, 'SOURCE_SESSION_CHANGED');
    return binding;
  }

  private async verifySubject(subject: string, expected: SessionIdentity, requestId: string): Promise<SubjectClaims> {
    let header;
    try { header = decodeHeader(subject); } catch { reauthenticate(requestId); }
    if (header.typ !== 'at+jwt' || header.alg !== 'RS256' || !header.kid) reauthenticate(requestId);
    let signingKey;
    try { signingKey = await this.options.signingKey(header.kid); }
    catch { throw new FirstPartyAuthError(503, 'SIGNING_KEYS_UNAVAILABLE', requestId, 'RETRY'); }
    if (!signingKey) reauthenticate(requestId);
    let claims: SubjectClaims;
    try { claims = verifyJwt(subject, signingKey, this.options.issuer, this.options.appSlug) as SubjectClaims; }
    catch { reauthenticate(requestId); }
    if (claims.type !== 'one_delegation_subject' || claims.appSlug !== this.options.appSlug ||
        claims.sub !== expected.userId || claims.id !== expected.userId || claims.organizationId !== expected.organizationId ||
        claims.installedAppId !== expected.installedAppId || !Number.isSafeInteger(claims.launchAccessEpoch) ||
        claims.launchAccessEpoch < 1 || !claims.sessionBinding?.sessionId ||
        !claims.sessionBinding.reference || claims.launchJti !== claims.sessionBinding.reference ||
        !Number.isSafeInteger(claims.sessionBinding.originalIat) || !Number.isSafeInteger(claims.sessionBinding.expiresAt)) {
      reauthenticate(requestId);
    }
    return claims;
  }

  /** Use only One credentials held by the backend, or a credential from a verified registered launch callback. */
  async validate(token: string, sessionId: string, expected: SessionIdentity, suppliedRequestId?: string): Promise<VerifiedSession> {
    const requestId = correlation(suppliedRequestId);
    if (!token || !sessionId || !expected.userId || !expected.organizationId || !expected.installedAppId) reauthenticate(requestId);
    let result;
    try {
      result = await this.post('/api/sso/validate', {
        token, appSlug: this.options.appSlug, includeDelegationSubject: true,
      }, requestId);
    } catch (error) {
      if (error instanceof FirstPartyAuthError && error.status === 401 && error.nextAction === 'INVESTIGATE') {
        throw new FirstPartyAuthError(401, error.code, error.requestId, 'REAUTHENTICATE', error.upstreamError);
      }
      throw error;
    }
    if (result.valid !== true || typeof result.delegationSubjectToken !== 'string' || typeof result.apiToken !== 'string' || !result.apiToken) {
      throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', requestId, 'INVESTIGATE');
    }
    const subject = result.delegationSubjectToken;
    const claims = await this.verifySubject(subject, expected, requestId);
    const info = object(result.sessionInfo);
    const sourceEvidence = {
      centralSessionId: claims.sessionBinding.sessionId,
      launchReference: claims.sessionBinding.reference,
      launchTokenExpiresAt: timestamp(info.expiresAt),
      portalBindingExpiresAt: Math.min(claims.sessionBinding.expiresAt * 1000, timestamp(info.delegationSourceSessionExpiresAt)),
      subjectExpiresAt: claims.exp! * 1000,
      apiTokenExpiresAt: timestamp(info.apiTokenExpiresAt),
    };
    const evidenceExpiresAt = Math.min(sourceEvidence.subjectExpiresAt, sourceEvidence.portalBindingExpiresAt,
      sourceEvidence.apiTokenExpiresAt, timestamp(info.delegationCredentialExpiresAt));
    const expiresAt = this.options.useEvidenceDeadlines ? evidenceExpiresAt :
      Math.min(evidenceExpiresAt, sourceEvidence.launchTokenExpiresAt);
    if (!Number.isFinite(expiresAt) || !Number.isFinite(sourceEvidence.launchTokenExpiresAt) ||
        expiresAt <= Date.now() || info.delegationRenewalMode !== 'INTERACTIVE_RECONNECT') {
      reauthenticate(requestId, 'SOURCE_SESSION_EXPIRED');
    }
    return { ...expected, sessionId, appSlug: this.options.appSlug, accessEpoch: claims.launchAccessEpoch,
      subject, apiToken: result.apiToken, expiresAt, sourceEvidence };
  }

  /** Recheck source access through the same canonical AccessOps pipeline used by the exchange. */
  async assertActive(session: VerifiedSession, suppliedRequestId?: string): Promise<void> {
    const requestId = correlation(suppliedRequestId);
    if (session.appSlug !== this.options.appSlug || session.expiresAt <= Date.now()) reauthenticate(requestId, 'SOURCE_SESSION_EXPIRED');
    let result;
    try {
      result = await this.options.delegation.evaluateLaunch(session.subject, requestId);
    } catch (error) {
      if (error instanceof FirstPartyAuthError && error.upstreamError === 'invalid_grant') {
        throw new FirstPartyAuthError(error.status, error.code, error.requestId, 'REAUTHENTICATE', error.upstreamError);
      }
      throw error;
    }
    if (result.decision !== 'ALLOW' || result.availability !== 'AVAILABLE' || result.applicationKey !== session.appSlug ||
        result.userId !== session.userId || result.organizationId !== session.organizationId ||
        result.installedAppId !== session.installedAppId || result.launchAccessEpoch !== session.accessEpoch) {
      throw new FirstPartyAuthError(503, 'SOURCE_ACCESS_RESPONSE_MISMATCH', requestId, 'INVESTIGATE');
    }
  }
}
