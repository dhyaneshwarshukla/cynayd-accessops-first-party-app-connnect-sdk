import { KeyObject, randomUUID } from 'node:crypto';
import { decodeHeader, SubjectClaims, verifyJwt } from './profile';
import { DelegationClient, type SourceCapability } from './client';
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
  renewal?: boolean | 'optional';
  centralSessionId: string;
  accessEpoch: number;
}

/** Initial entry learns the identity and installation from confidential redemption. */
export interface InitialBoundLaunchState extends Pick<BoundLaunchState, 'sessionId' | 'revision' | 'request' | 'verifier' | 'renewal'> {
  initial: true;
  expected?: Pick<SessionIdentity, 'organizationId' | 'installedAppId'>;
}

/** Consume only a transaction bound to the initiating host browser. */
export interface BoundLaunchStateStore {
  consume(state: string): Promise<BoundLaunchState | InitialBoundLaunchState | undefined>;
}

export interface BoundDelegationBinding extends SessionIdentity {
  sessionId: string;
  centralSessionId: string;
  appSlug: string;
  accessEpoch: number;
  subject: string;
  expiresAt: number;
  capability?: SourceCapability;
  /** Durable attempt marker. A marked generation is never retried. */
  renewalAttempt?: string;
}

export interface RenewableDelegationStore extends BoundDelegationStore {
  load(sessionId: string): Promise<{ revision: string; binding: BoundDelegationBinding } | undefined>;
}

export interface SourceRenewalCoordinator {
  /** Cross-instance exclusive lease. Return undefined without calling work when another instance owns it. */
  runExclusive<T>(sessionId: string, work: () => Promise<T>): Promise<T | undefined>;
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
    if (![input.code, input.request, input.state].every(value => typeof value === 'string' && opaque.test(value))) {
      reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    }
    let state;
    try { state = await states.consume(input.state); }
    catch { throw new FirstPartyAuthError(503, 'LAUNCH_STATE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!state || state.request !== input.request || !state.sessionId || !state.revision ||
        (state.expected && (!state.expected.organizationId || !state.expected.installedAppId))) {
      reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    }
    const existing = 'centralSessionId' in state ? state : undefined;
    if (existing && (!existing.expected?.userId || !existing.centralSessionId ||
        !Number.isSafeInteger(existing.accessEpoch) || existing.accessEpoch < 1)) {
      reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    }
    if (!existing && (!('initial' in state) || state.initial !== true)) reauthenticate(requestId, 'LAUNCH_STATE_INVALID');
    const { subject, capability } = await this.options.delegation.redeemBoundLaunch({
      ...input, verifier: state.verifier, expectedState: input.state, renewal:state.renewal,
    }, requestId);
    const claims = await this.verifySubject(subject, state.expected, requestId);
    if (existing && (claims.sessionBinding.sessionId !== existing.centralSessionId || claims.launchAccessEpoch !== existing.accessEpoch)) {
      reauthenticate(requestId, 'SOURCE_BINDING_CHANGED');
    }
    const binding = { userId: claims.sub, organizationId: claims.organizationId, installedAppId: claims.installedAppId,
      sessionId: state.sessionId, centralSessionId: claims.sessionBinding.sessionId,
      appSlug: this.options.appSlug, accessEpoch: claims.launchAccessEpoch, subject,
      expiresAt: Math.min(claims.exp!, claims.sessionBinding.expiresAt) * 1000, ...(capability ? {capability} : {}) };
    if (binding.expiresAt <= Date.now()) reauthenticate(requestId, 'SOURCE_SESSION_EXPIRED');
    let stored;
    try { stored = await store.replaceIfCurrent(binding.sessionId, state.revision, binding); }
    catch { throw new FirstPartyAuthError(503, 'CREDENTIAL_STORE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!stored) reauthenticate(requestId, 'SOURCE_SESSION_CHANGED');
    return binding;
  }

  /** Validate a host snapshot before a protected operation, optionally rotating eligible evidence. */
  async activeBoundSession(binding: BoundDelegationBinding, store: RenewableDelegationStore,
    coordinator?: SourceRenewalCoordinator, suppliedRequestId?: string): Promise<BoundDelegationBinding> {
    const requestId = correlation(suppliedRequestId);
    if (!binding.sessionId || binding.appSlug !== this.options.appSlug) {
      reauthenticate(requestId, 'SOURCE_BINDING_INVALID');
    }
    const leadMs = 30_000;
    const current = coordinator && (binding.capability || binding.renewalAttempt) &&
      binding.expiresAt - Date.now() <= leadMs
      ? await this.renewBoundSession(binding.sessionId, store, coordinator, leadMs, requestId)
      : binding;
    if (current.userId !== binding.userId || current.organizationId !== binding.organizationId ||
        current.installedAppId !== binding.installedAppId || current.centralSessionId !== binding.centralSessionId ||
        current.accessEpoch !== binding.accessEpoch) {
      reauthenticate(requestId, 'SOURCE_BINDING_CHANGED');
    }
    await this.options.delegation.sessionStatus(current, requestId);
    let latest;
    try { latest = await store.load(binding.sessionId); }
    catch { throw new FirstPartyAuthError(503, 'CREDENTIAL_STORE_UNAVAILABLE', requestId, 'RETRY'); }
    if (!latest) reauthenticate(requestId, 'SOURCE_SESSION_CHANGED');
    if (latest.binding.subject !== current.subject || latest.binding.renewalAttempt !== current.renewalAttempt) {
      throw new FirstPartyAuthError(503, 'SOURCE_SESSION_ADVANCED', requestId, 'RETRY');
    }
    return current;
  }

  async renewBoundSession(sessionId: string, store: RenewableDelegationStore, coordinator: SourceRenewalCoordinator,
    leadMs = 30_000, suppliedRequestId?: string): Promise<BoundDelegationBinding> {
    const requestId = correlation(suppliedRequestId);
    if (!Number.isSafeInteger(leadMs) || leadMs < 0) throw new RangeError('Invalid renewal lead time');
    const load = async () => {
      let current;
      try { current = await store.load(sessionId); }
      catch { throw new FirstPartyAuthError(503,'CREDENTIAL_STORE_UNAVAILABLE',requestId,'RETRY'); }
      if (!current || current.binding.sessionId !== sessionId || current.binding.appSlug !== this.options.appSlug) {
        reauthenticate(requestId,'SOURCE_SESSION_CHANGED');
      }
      return current;
    };
    const current = await load();
    if (current.binding.expiresAt - Date.now() > leadMs) return current.binding;
    const renewed = await coordinator.runExclusive(sessionId, async () => {
      const { binding, revision } = await load();
      if (binding.expiresAt - Date.now() > leadMs) return binding;
      if (binding.renewalAttempt) {
        throw new FirstPartyAuthError(409,'SOURCE_RENEWAL_RECOVERY_REQUIRED',requestId,'REAUTHENTICATE');
      }
      if (!binding.capability) throw new FirstPartyAuthError(401,'SOURCE_CAPABILITY_REQUIRED',requestId,'REAUTHENTICATE');
      const { capability, ...evidence } = binding;
      const renewalAttempt = randomUUID();
      let claimedRevision: string | undefined;
      try {
        if (!await store.replaceIfCurrent(sessionId,revision,{ ...evidence,renewalAttempt })) {
          reauthenticate(requestId,'SOURCE_SESSION_CHANGED');
        }
        const claimed = await load();
        if (claimed.binding.renewalAttempt !== renewalAttempt || claimed.revision === revision) {
          reauthenticate(requestId,'SOURCE_SESSION_CHANGED');
        }
        claimedRevision = claimed.revision;
        const next = await this.options.delegation.renewSource(capability,requestId);
        const claims = await this.verifySubject(next.subject,binding,requestId);
        if (claims.sessionBinding.sessionId !== binding.centralSessionId || claims.launchAccessEpoch !== binding.accessEpoch) {
          reauthenticate(requestId,'SOURCE_BINDING_CHANGED');
        }
        const expiresAt = Math.min(claims.exp!,claims.sessionBinding.expiresAt) * 1000;
        if (expiresAt <= Math.max(Date.now(),binding.expiresAt) || expiresAt > next.capability.expiresAt) {
          throw new FirstPartyAuthError(409,'SOURCE_RENEWAL_NOT_ADVANCED',requestId,'REAUTHENTICATE');
        }
        const replacement = { ...evidence,subject:next.subject,expiresAt,capability:next.capability };
        if (!await store.replaceIfCurrent(sessionId,claimed.revision,replacement)) reauthenticate(requestId,'SOURCE_SESSION_CHANGED');
        return replacement;
      } catch (error) {
        if (claimedRevision && error instanceof FirstPartyAuthError && error.code === 'source_renewal_locked_unspent') {
          let restored = false;
          try { restored = await store.replaceIfCurrent(sessionId, claimedRevision, binding); }
          catch { /* Preserve the attempt marker for verified recovery. */ }
          if (restored) throw error;
          throw new FirstPartyAuthError(409,'SOURCE_RENEWAL_RECOVERY_REQUIRED',requestId,'REAUTHENTICATE');
        }
        if (error instanceof FirstPartyAuthError &&
            (error.code === 'SOURCE_SESSION_CHANGED' || ['UNLOCK','REAUTHENTICATE','ACCESS_DENIED'].includes(error.nextAction))) {
          throw error;
        }
        // A response or storage failure may have spent the old capability.
        // Never retry it automatically or replay the surrounding operation.
        throw new FirstPartyAuthError(409,'SOURCE_RENEWAL_RECOVERY_REQUIRED',requestId,'REAUTHENTICATE');
      }
    });
    if (renewed) return renewed;
    const after = await load();
    if (after.revision !== current.revision && !after.binding.renewalAttempt && after.binding.expiresAt > Date.now()) return after.binding;
    throw new FirstPartyAuthError(503,'SOURCE_RENEWAL_IN_PROGRESS',requestId,'RETRY');
  }

  private async verifySubject(subject: string, expected: (Pick<SessionIdentity, 'organizationId' | 'installedAppId'> &
    Partial<Pick<SessionIdentity, 'userId'>>) | undefined, requestId: string): Promise<SubjectClaims> {
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
        typeof claims.sub !== 'string' || !claims.sub || claims.id !== claims.sub ||
        typeof claims.organizationId !== 'string' || !claims.organizationId ||
        typeof claims.installedAppId !== 'string' || !claims.installedAppId ||
        (expected && ((expected.userId !== undefined && claims.sub !== expected.userId) ||
          claims.organizationId !== expected.organizationId || claims.installedAppId !== expected.installedAppId)) ||
        !Number.isSafeInteger(claims.launchAccessEpoch) ||
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
