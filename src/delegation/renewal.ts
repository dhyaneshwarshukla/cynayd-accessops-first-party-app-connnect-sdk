import { CredentialStore, LaunchStateStore, OneApplicationSession, VerifiedSession } from './session';
import { correlation, FirstPartyAuthError, httpsUrl } from './transport';

export type SourceRecoveryStatus = 'ACTIVE' | 'RENEWAL_DUE' | 'EXPIRED';

export function sourceRecoveryStatus(session: VerifiedSession, leadMs = 60_000, now = Date.now()): SourceRecoveryStatus {
  if (!Number.isFinite(leadMs) || leadMs < 0) throw new RangeError('Invalid renewal lead time');
  if (session.expiresAt <= now) return 'EXPIRED';
  return session.expiresAt - now <= leadMs ? 'RENEWAL_DUE' : 'ACTIVE';
}

/** Build a top-level browser destination from operator-configured URLs only. */
export function oneResumeUrl(config: { portalOrigin: string; appSlug: string; callbackUrl: string }): string {
  const portal = httpsUrl(config.portalOrigin);
  const callback = httpsUrl(config.callbackUrl);
  if (portal.pathname !== '/' || portal.search || callback.search || callback.pathname === '/' ||
      !/^[a-z][a-z0-9-]{1,127}$/.test(config.appSlug)) {
    throw new Error('Invalid One resume configuration');
  }
  const resume = new URL('/apps/resume', portal);
  resume.searchParams.set('appSlug', config.appSlug);
  resume.searchParams.set('mode', 'renew');
  resume.searchParams.set('returnUrl', callback.href);
  return resume.href;
}

/**
 * Complete a browser resume against the existing host session. State must come from a
 * browser-bound, atomically consumed transaction. Store replacements must advance the
 * revision atomically, and host logout must invalidate that same revision.
 */
export async function completeSourceRenewal(
  one: OneApplicationSession,
  input: { code: string; state: string },
  states: LaunchStateStore,
  store: CredentialStore,
  suppliedRequestId?: string,
): Promise<VerifiedSession> {
  const requestId = correlation(suppliedRequestId);
  const { credentials, expectedRevision } = await one.redeem(input, states, requestId);
  const storeUnavailable = () => new FirstPartyAuthError(503, 'CREDENTIAL_STORE_UNAVAILABLE', requestId, 'RETRY');
  const changed = () => new FirstPartyAuthError(401, 'SOURCE_SESSION_CHANGED', requestId, 'REAUTHENTICATE');
  const current = await store.load(credentials.sessionId).catch(() => { throw storeUnavailable(); });
  if (!current || current.revision !== expectedRevision) throw changed();
  const previous = current.credentials;
  const evidence = credentials.sourceEvidence;
  if (!previous.sourceEvidence || !evidence ||
      previous.sourceEvidence.centralSessionId !== evidence.centralSessionId ||
      previous.sessionId !== credentials.sessionId || previous.userId !== credentials.userId ||
      previous.organizationId !== credentials.organizationId || previous.appSlug !== credentials.appSlug ||
      previous.installedAppId !== credentials.installedAppId || previous.accessEpoch !== credentials.accessEpoch) {
    throw new FirstPartyAuthError(401, 'SOURCE_BINDING_CHANGED', requestId, 'REAUTHENTICATE');
  }
  await one.assertActive(credentials, requestId);
  if (previous.sourceEvidence.launchReference === evidence.launchReference ||
      credentials.expiresAt <= previous.expiresAt) {
    throw new FirstPartyAuthError(409, 'SOURCE_RENEWAL_NOT_ADVANCED', requestId, 'RETRY');
  }
  const replaced = await store.replaceIfCurrent(credentials.sessionId, expectedRevision, credentials)
    .catch(() => { throw storeUnavailable(); });
  if (!replaced) throw changed();
  return credentials;
}
