import { createHash, randomBytes } from 'node:crypto';
import { SessionEventMonitor, type SessionEvent } from './delegation/lifecycle';
import { correlation, FirstPartyAuthError, httpsUrl, type RecoveryAction } from './delegation/transport';
import type { DelegationClient } from './delegation/client';
import type {
  BoundDelegationBinding, BoundLaunchState, InitialBoundLaunchState, OneApplicationSession,
  RenewableDelegationStore, SourceRenewalCoordinator,
} from './delegation/session';

const opaque = /^[A-Za-z0-9_-]{43}$/;

export interface PendingHostLaunch {
  request: string;
  state: string;
  verifier: string;
  expiresAt: number;
  returnTo: string;
  priorCookieId?: string;
  prior?: { id: string; revision: string; expected: BoundLaunchState['expected']; centralSessionId: string; accessEpoch: number };
}

export interface HostSessionStore extends RenewableDelegationStore {
  createLaunch(id: string, pending: PendingHostLaunch): Promise<void>;
  /** Atomically validate, consume and advance the launch revision. */
  consumeLaunch(id: string, match: Pick<PendingHostLaunch, 'state' | 'request'> & { priorId?: string }):
    Promise<{ revision: string; pending: PendingHostLaunch } | undefined>;
  /** Atomically activate the new ID and retire the prior ID at its captured revision. */
  activate(id: string, revision: string, binding: BoundDelegationBinding,
    prior?: { id: string; revision: string }): Promise<boolean>;
  /** Delete both records in a single operation. */
  remove(ids: readonly string[]): Promise<void>;
}

export interface HostSessionOptions {
  appOrigin: string;
  onePortalOrigin: string;
  callback: string;
  cookieLabel: string;
  store: HostSessionStore;
  delegation: DelegationClient;
  session: OneApplicationSession;
  renewal?: SourceRenewalCoordinator;
  expectedInstallation?: Pick<BoundDelegationBinding, 'organizationId' | 'installedAppId'>;
  /** An application route allowlist. Auth routes and external redirects should be excluded. */
  allowsReturn(url: URL): boolean;
}

function hostError(status: number, code: string, action: RecoveryAction) {
  return new FirstPartyAuthError(status, code, correlation(), action);
}

export function hostErrorResponse(error: unknown) {
  if (!(error instanceof FirstPartyAuthError)) {
    return { status: 503, body: { code: 'HOST_SESSION_UNAVAILABLE', nextAction: 'RETRY' } };
  }
  const reconnect = error.upstreamError === 'invalid_grant' || [
    'SOURCE_SESSION_EXPIRED', 'SOURCE_CAPABILITY_REQUIRED', 'SOURCE_RENEWAL_RECOVERY_REQUIRED',
    'SOURCE_RENEWAL_NOT_ADVANCED', 'SOURCE_SESSION_CHANGED', 'access_epoch_stale',
  ].includes(error.code);
  return {
    status: reconnect ? 401 : error.status,
    body: { code: error.code, nextAction: reconnect ? 'RECONNECT' : error.nextAction, requestId: error.requestId },
    retryAfter: error.retryAfter,
  };
}

function exactOrigin(value: string) {
  const url = httpsUrl(value);
  if (url.origin !== value) throw new Error('Use an exact HTTPS origin');
  return value;
}

export class FirstPartyHost {
  readonly sessionCookie: string;
  readonly launchCookie: string;
  private readonly monitor: SessionEventMonitor;

  constructor(private readonly options: HostSessionOptions) {
    exactOrigin(options.appOrigin);
    exactOrigin(options.onePortalOrigin);
    const callback = httpsUrl(options.callback);
    if (callback.origin !== options.appOrigin || callback.search || callback.href !== options.callback ||
      !/^[a-z0-9_-]{1,48}$/.test(options.cookieLabel)) throw new Error('Invalid host registration configuration');
    this.sessionCookie = '__Host-' + options.cookieLabel + '-one';
    this.launchCookie = this.sessionCookie + '-launch';
    this.monitor = new SessionEventMonitor(options.delegation);
  }

  assertCallbackPath(path: string) {
    if (new URL(this.options.callback).pathname !== path) throw new Error('Registered callback does not match the host route');
  }

  assertOrigin(origin: string | null | undefined) {
    if (origin !== this.options.appOrigin) throw hostError(403, 'HOST_ORIGIN_DENIED', 'ACCESS_DENIED');
  }

  private cookie(header: string | undefined, name: string) {
    const values = (header ?? '').split(';').map(value => value.trim())
      .filter(value => value.startsWith(name + '=')).map(value => value.slice(name.length + 1));
    if (values.length === 0) return undefined;
    if (values.length === 1 && opaque.test(values[0])) return values[0];
    throw hostError(401, 'HOST_COOKIE_INVALID', 'REAUTHENTICATE');
  }

  private returnPath(value: unknown) {
    if (typeof value !== 'string' || value.length > 2048 || !value.startsWith('/') ||
      value.startsWith('//') || /[\\\u0000-\u0020\u007f]/.test(value)) return '/';
    const url = new URL(value, this.options.appOrigin);
    if (url.origin !== this.options.appOrigin || url.pathname.startsWith('//') || !this.options.allowsReturn(url)) return '/';
    return url.pathname + url.search;
  }

  async start(origin: string | undefined, cookies: string | undefined, returnTo: unknown) {
    this.assertOrigin(origin);
    const priorId = this.cookie(cookies, this.sessionCookie);
    const prior = priorId ? await this.options.store.load(priorId) : undefined;
    const oldLaunch = this.cookie(cookies, this.launchCookie);
    const launch = await this.options.delegation.initiateBoundLaunch(this.options.callback);
    if (oldLaunch && oldLaunch !== priorId) await this.options.store.remove([oldLaunch]);
    const id = randomBytes(32).toString('base64url');
    const binding = prior?.binding;
    await this.options.store.createLaunch(id, {
      request: launch.request, verifier: launch.verifier, state: launch.state,
      expiresAt: Date.now() + launch.expiresIn * 1000, returnTo: this.returnPath(returnTo),
      priorCookieId: priorId,
      prior: prior && priorId && binding ? {
        id: priorId, revision: prior.revision, centralSessionId: binding.centralSessionId, accessEpoch: binding.accessEpoch,
        expected: { userId: binding.userId, organizationId: binding.organizationId, installedAppId: binding.installedAppId },
      } : undefined,
    });
    const authorizationUrl = new URL('/apps/bound-launch', this.options.onePortalOrigin);
    authorizationUrl.searchParams.set('request', launch.request);
    return { id, authorizationUrl: authorizationUrl.href, expiresIn: launch.expiresIn };
  }

  async callback(cookies: string | undefined, input: { request: string; code: string; state: string }) {
    const id = this.cookie(cookies, this.launchCookie);
    const priorId = this.cookie(cookies, this.sessionCookie);
    if (!id || [input.request, input.code, input.state].some(value => typeof value !== 'string' || !opaque.test(value))) {
      throw hostError(401, 'LAUNCH_STATE_INVALID', 'REAUTHENTICATE');
    }
    const claim = await this.options.store.consumeLaunch(id, { request: input.request, state: input.state, priorId });
    if (!claim) throw hostError(401, 'LAUNCH_STATE_INVALID', 'REAUTHENTICATE');
    const { pending, revision } = claim;
    const { prior } = pending;
    const base = { request: pending.request, verifier: pending.verifier, sessionId: id, revision,
      renewal: this.options.renewal ? 'optional' as const : undefined };
    const state: InitialBoundLaunchState | BoundLaunchState = prior ? {
      ...base, expected: prior.expected, centralSessionId: prior.centralSessionId, accessEpoch: prior.accessEpoch,
    } : { ...base, initial: true, expected: this.options.expectedInstallation };
    let validationError: unknown;
    try {
      await this.options.session.completeBoundLaunch(input, { consume: async () => state }, {
        replaceIfCurrent: async (sessionId, expectedRevision, binding) => {
          try { await this.options.delegation.sessionStatus(binding); }
          catch (error) { validationError = error; throw error; }
          return this.options.store.activate(sessionId, expectedRevision, binding, prior);
        },
      });
    } catch (error) {
      throw validationError ?? error;
    }
    if (prior) this.monitor.logout(prior.id);
    return { id, landing: new URL(this.returnPath(pending.returnTo), this.options.appOrigin).href };
  }

  private async stored(cookies: string | undefined) {
    const id = this.cookie(cookies, this.sessionCookie);
    if (!id) throw hostError(401, 'HOST_SESSION_REQUIRED', 'REAUTHENTICATE');
    const record = await this.options.store.load(id);
    if (!record || record.binding.sessionId !== id) throw hostError(401, 'HOST_SESSION_REQUIRED', 'REAUTHENTICATE');
    return record.binding;
  }

  /** Use for every protected operation, then enforce the application's resource permissions. */
  async authenticate(cookies: string | undefined) {
    return this.options.session.activeBoundSession(await this.stored(cookies), this.options.store, this.options.renewal);
  }

  async status(cookies: string | undefined) {
    const { userId, organizationId, installedAppId } = await this.authenticate(cookies);
    return { userId, tenantId: organizationId, installedAppId, email: null };
  }

  async screenActivity(origin: string | undefined, cookies: string | undefined, operation: unknown, eventId: unknown) {
    this.assertOrigin(origin);
    if ((operation !== 'screen.interaction' && operation !== 'screen.view' && operation !== 'screen.view.end') ||
      typeof eventId !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(eventId)) {
      throw hostError(400, 'SCREEN_ACTIVITY_INVALID', 'INVESTIGATE');
    }
    return this.options.delegation.reportScreenInteraction(await this.stored(cookies), eventId, operation);
  }

  async unlockBinding(origin: string | undefined, cookies: string | undefined) {
    this.assertOrigin(origin);
    const binding = await this.stored(cookies);
    return { binding: createHash('sha256').update('one-embedded-unlock:' + binding.centralSessionId).digest('base64url') };
  }

  async events(cookies: string | undefined) {
    const { sessionId } = await this.stored(cookies);
    return (emit: (event: SessionEvent) => void) =>
      this.monitor.subscribe(sessionId, async () => (await this.options.store.load(sessionId))?.binding, emit);
  }

  async logout(origin: string | undefined, cookies: string | undefined) {
    this.assertOrigin(origin);
    const ids = [this.cookie(cookies, this.sessionCookie), this.cookie(cookies, this.launchCookie)]
      .filter((id): id is string => Boolean(id));
    await this.options.store.remove(ids);
    for (const id of ids) this.monitor.logout(id);
  }
}
