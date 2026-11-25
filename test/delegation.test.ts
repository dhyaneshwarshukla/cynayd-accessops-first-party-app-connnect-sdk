import { randomUUID } from 'node:crypto';
import * as sdk from '../src';

const { mockServices } = require('../examples/mock-services.cjs');

async function fixture() {
  const services = mockServices(sdk);
  const binding: sdk.VerifiedSession = await services.session.validate('launch-credential', 'local-session', services.expected);
  const call = (target = 'drive') => {
    const operation = services.operations[target];
    return services.client.call(binding, operation, operation.origin + (target === 'drive' ? '/files' : '/events'));
  };
  return { ...services, binding, call };
}

test('same verified One session can access both targets, with scope and sender constraint', async () => {
  const { call, session, binding } = await fixture();
  await session.assertActive(binding);
  expect((await call()).status).toBe(201);
  expect((await call('calendar')).status).toBe(201);
});

test('coalesces concurrent exchange while creating fresh resource proofs', async () => {
  const { call, status } = await fixture();
  const responses = await Promise.all([call(), call(), call()]);
  expect(responses.map(result => result.status)).toEqual([201, 201, 201]);
  expect(status.tokenCalls).toBe(1);
  expect(new Set(status.proofs).size).toBe(3);
  expect((await call()).status).toBe(201);
  expect(status.tokenCalls).toBe(2);
});

test.each([['organizationId', 'other-tenant'], ['installedAppId', 'other-install'], ['userId', 'other-user']])(
  'rejects rebound %s before storing credentials', async (field, value) => {
    const { session, expected } = mockServices(sdk);
    await expect(session.validate('launch-credential', 'local-session', { ...expected, [field]: value }))
      .rejects.toMatchObject({ status: 401, nextAction: 'REAUTHENTICATE' });
  },
);

test('consumes launch state and rejects a callback after the session revision changes', async () => {
  const { session, expected } = mockServices(sdk);
  const consume = jest.fn().mockResolvedValueOnce({ sessionId: 'local', revision: 'prior', expected }).mockResolvedValue(undefined);
  const replaceIfCurrent = jest.fn().mockResolvedValue(false);
  const store: sdk.CredentialStore = { load: jest.fn(), replaceIfCurrent, removeIfCurrent: jest.fn() };
  const input = { code: 'one-code', state: 'one-state' };
  await expect(session.completeCodeLaunch(input, { consume }, store)).rejects.toMatchObject({ code: 'SOURCE_SESSION_CHANGED' });
  await expect(session.completeCodeLaunch(input, { consume }, store)).rejects.toMatchObject({ code: 'LAUNCH_STATE_INVALID' });
  expect(replaceIfCurrent).toHaveBeenCalledTimes(1);
});

test('preserves the verified evidence rejection and source expiry guidance', async () => {
  const { session, expected, status, call, binding } = await fixture();
  await expect(session.validate('attributes-only', 'local', expected))
    .rejects.toMatchObject({ status: 403, code: 'VERIFIED_FEDERATION_EVIDENCE_REQUIRED', nextAction: 'REAUTHENTICATE' });
  status.expires = true;
  await expect(session.validate('source-api', 'local', expected))
    .rejects.toMatchObject({ status: 401, code: 'TOKEN_EXPIRED', nextAction: 'REAUTHENTICATE' });
  binding.expiresAt = Date.now() - 1;
  await expect(call()).rejects.toMatchObject({ status: 401, code: 'SOURCE_SESSION_EXPIRED' });
});

test('denies unauthorized app access and preserves 403, 429 and 503', async () => {
  const { call, status, operations, binding, client } = await fixture();
  status.allowed = false;
  await expect(call()).rejects.toMatchObject({ status: 403, code: 'access_denied', nextAction: 'ACCESS_DENIED' });
  status.allowed = true;
  status.resourceError = 429;
  const requestId = randomUUID();
  await expect(client.call(binding, operations.drive, operations.drive.origin + '/files', {}, requestId))
    .rejects.toMatchObject({ status: 429, code: 'RATE_LIMIT_EXCEEDED', retryAfter: '2', requestId });
  status.resourceError = 0;
  status.available = false;
  await expect(call()).rejects.toMatchObject({ status: 503, code: 'temporarily_unavailable', nextAction: 'RETRY' });
});

test('denies resource ACL failures after successful central exchange', async () => {
  const { call, status } = await fixture();
  status.acl = false;
  const response = await call();
  expect(response.status).toBe(403);
  await expect(response.json()).resolves.toMatchObject({ code: 'RESOURCE_ACCESS_DENIED' });
});

test('live resource introspection sees revocation after issuance', async () => {
  const { call, status } = await fixture();
  status.beforeTarget = () => { status.active = false; };
  const response = await call();
  expect(response.status).toBe(401);
  expect(response.headers.get('WWW-Authenticate')).toBe('DPoP error="invalid_token"');
});

test.each([['wrongTargetAudience', 401], ['wrongScope', 403], ['expiredTarget', 401], ['replayAvailable', 503]])(
  'rejects unsafe resource case %s', async (name, http) => {
    const { call, status } = await fixture();
    status[name] = name !== 'replayAvailable';
    expect((await call()).status).toBe(http);
  },
);

test('rejects a replayed resource proof across concurrent operations', async () => {
  const { call, status } = await fixture();
  let proof: string | null;
  status.beforeTarget = (headers: Headers) => {
    if (!proof) proof = headers.get('DPoP');
    else headers.set('DPoP', proof);
  };
  const responses = await Promise.all([call(), call()]);
  expect(responses.map(response => response.status).sort()).toEqual([201, 401]);
});

test('rejects malformed proof and fails closed when resource authority is unavailable or limited', async () => {
  const { call, status } = await fixture();
  status.beforeTarget = (headers: Headers) => headers.set('DPoP', 'bad');
  expect((await call()).status).toBe(401);
  status.beforeTarget = () => { status.available = false; };
  expect((await call()).status).toBe(503);
  status.available = true;
  status.beforeTarget = () => { status.resourceError = 429; };
  const response = await call();
  expect(response.status).toBe(429);
  expect(response.headers.get('Retry-After')).toBe('2');
});

test('never sends tokens to unapproved origins or routes', async () => {
  const { client, binding, operations, status } = await fixture();
  await expect(client.call(binding, operations.drive, 'https://other.example.test/files'))
    .rejects.toMatchObject({ code: 'INVALID_RESOURCE_URL' });
  await expect(client.call(binding, operations.drive, operations.drive.origin + '/events'))
    .rejects.toMatchObject({ code: 'INVALID_RESOURCE_URL' });
  expect(status.tokenCalls).toBe(0);
});

async function renewalFixture() {
  const { evidenceSession: one, expected, status, client, operations } = mockServices(sdk);
  const initial = await one.validate('launch-credential', 'local-session', expected);
  let current: Awaited<ReturnType<sdk.CredentialStore['load']>> = { revision: 'old', credentials: initial };
  const store: sdk.CredentialStore = {
    load: async () => current,
    replaceIfCurrent: jest.fn(async (_id, expectedRevision, credentials) => {
      if (!current || current.revision !== expectedRevision) return false;
      current = { revision: 'new', credentials };
      return true;
    }),
    removeIfCurrent: async (_id, expectedRevision) => {
      if (!current || current.revision !== expectedRevision) return false;
      current = undefined;
      return true;
    },
  };
  const states = { consume: jest.fn().mockResolvedValueOnce({ sessionId: initial.sessionId, revision: 'old', expected }) };
  const complete = () => sdk.completeSourceRenewal(one, { code: 'one-code', state: 'one-state' }, states, store);
  status.recovery = { duration: 1200, launchDuration: 300 };
  return { one, expected, status, initial, store, complete, client, operations };
}

test('renews same central session using live AccessOps, then performs delegated Drive operation', async () => {
  const { complete, initial, store, client, operations } = await renewalFixture();
  const renewed = await complete();
  expect(renewed.sourceEvidence?.centralSessionId).toBe(initial.sourceEvidence?.centralSessionId);
  expect(renewed.expiresAt).toBeGreaterThan(initial.expiresAt);
  expect(renewed.sourceEvidence?.launchTokenExpiresAt).toBeLessThan(renewed.expiresAt);
  expect((await store.load(initial.sessionId))?.revision).toBe('new');
  expect((await client.call(renewed, operations.drive, operations.drive.origin + '/files')).status).toBe(201);
});

test.each([
  ['new central session', { sessionId: 'different-session' }, 'SOURCE_BINDING_CHANGED'],
  ['same provenance', { reference: 'fixture-launch' }, 'SOURCE_RENEWAL_NOT_ADVANCED'],
  ['same deadline', { duration: 600 }, 'SOURCE_RENEWAL_NOT_ADVANCED'],
])('rejects renewal with %s', async (_case, patch, code) => {
  const { complete, status, store } = await renewalFixture();
  Object.assign(status.recovery, patch);
  await expect(complete()).rejects.toMatchObject({ code });
  expect(store.replaceIfCurrent).not.toHaveBeenCalled();
});

test.each([
  ['active', false, 'REAUTHENTICATE'],
  ['allowed', false, 'ACCESS_DENIED'],
  ['available', false, 'RETRY'],
])('does not commit renewal when One reports %s=%s', async (field, value, nextAction) => {
  const { complete, status, store } = await renewalFixture();
  status[field] = value;
  await expect(complete()).rejects.toMatchObject({ nextAction });
  expect(store.replaceIfCurrent).not.toHaveBeenCalled();
});

test('host logout prevents a concurrent callback from restoring credentials', async () => {
  const { complete, initial, store } = await renewalFixture();
  const callback = complete();
  await store.removeIfCurrent(initial.sessionId, 'old');
  await expect(callback).rejects.toMatchObject({ code: 'SOURCE_SESSION_CHANGED' });
  expect(await store.load(initial.sessionId)).toBeUndefined();
});

test('only one concurrent callback can finish a browser transaction', async () => {
  const { complete, store } = await renewalFixture();
  const callbacks = await Promise.allSettled([complete(), complete()]);
  expect(callbacks.filter(result => result.status === 'fulfilled')).toHaveLength(1);
  expect(store.replaceIfCurrent).toHaveBeenCalledTimes(1);
});

test('proactively signals deadlines without sending background activity', async () => {
  const { initial } = await renewalFixture();
  expect(sdk.sourceRecoveryStatus(initial, 60_000, initial.expiresAt - 60_001)).toBe('ACTIVE');
  expect(sdk.sourceRecoveryStatus(initial, 60_000, initial.expiresAt - 60_000)).toBe('RENEWAL_DUE');
  expect(sdk.sourceRecoveryStatus(initial, 60_000, initial.expiresAt)).toBe('EXPIRED');
  const url = new URL(sdk.oneResumeUrl({ portalOrigin: 'https://one.example', appSlug: 'cynayd-connect',
    callbackUrl: 'https://connect.example/one-drive-return' }));
  expect(url.pathname).toBe('/apps/resume');
  expect(url.searchParams.get('returnUrl')).toBe('https://connect.example/one-drive-return');
  expect(() => sdk.oneResumeUrl({ portalOrigin: 'https://one.example', appSlug: 'cynayd-connect',
    callbackUrl: 'https://connect.example/one-drive-return?code=existing' })).toThrow();
});

test('simulates twelve hours with rotating source evidence and repeated target exchanges', async () => {
  const clock = jest.spyOn(Date, 'now');
  const base = Date.now();
  clock.mockReturnValue(base);
  try {
    const { evidenceSession: one, expected, status, client, operations } = mockServices(sdk);
    let current = { revision: '0', credentials: await one.validate('launch-credential', 'local', expected) };
    const store: sdk.CredentialStore = {
      load: async () => current,
      replaceIfCurrent: async (_id, revision, credentials) => {
        if (revision !== current.revision) return false;
        current = { revision: String(Number(revision) + 1), credentials };
        return true;
      },
      removeIfCurrent: async () => false,
    };
    for (let minute = 5; minute <= 720; minute += 5) {
      clock.mockReturnValue(base + minute * 60_000);
      if (minute % 10 === 0) {
        expect(sdk.sourceRecoveryStatus(current.credentials)).toBe('EXPIRED');
        status.recovery = { code: 'code-' + minute, reference: 'launch-' + minute, duration: (minute + 10) * 60 };
        await sdk.completeSourceRenewal(one, { code: status.recovery.code, state: 'fixture-state' }, {
          consume: async () => ({ sessionId: 'local', revision: current.revision, expected }),
        }, store);
      }
      const operation = minute % 10 === 0 ? operations.drive : operations.calendar;
      const path = operation === operations.drive ? '/files' : '/events';
      expect((await client.call(current.credentials, operation, operation.origin + path)).status).toBe(201);
      if ([60, 240, 480, 720].includes(minute)) {
        expect(current.revision).toBe(String(minute / 10));
        expect(status.tokenCalls).toBe(minute / 5);
      }
    }
  } finally {
    clock.mockRestore();
  }
});

test('validates a session without exchanging a target token and preserves lock recovery', async () => {
  const { client, binding, status } = await fixture();
  expect(await client.sessionStatus(binding)).toMatchObject({
    state: 'ACTIVE', accessEpoch: binding.accessEpoch, revision: 'fixture-revision',
  });
  expect(status.tokenCalls).toBe(0);
  status.locked = true;
  await expect(client.sessionStatus(binding)).rejects.toMatchObject({ code: 'session_locked', nextAction: 'UNLOCK' });
});

test('direct backend enforcement refuses to execute the application operation while locked', async () => {
  const { client, binding, status } = await fixture();
  const operation = jest.fn(async () => 'authorized');
  status.locked = true;
  await expect(sdk.withCentralSession(client, binding, operation)).rejects.toMatchObject({ nextAction: 'UNLOCK' });
  expect(operation).not.toHaveBeenCalled();
  status.locked = false;
  await expect(sdk.withCentralSession(client, binding, operation)).resolves.toBe('authorized');
});

test('two event relay subscribers share one status request and treat lock and logout as hints', async () => {
  const { client, binding, status } = await fixture();
  status.locked = true;
  const wrapped = { sessionStatus: jest.fn((session: sdk.VerifiedSession) => client.sessionStatus(session)) };
  const monitor = new sdk.SessionEventMonitor(wrapped);
  const notifications: sdk.SessionEvent[][] = [[], []];
  let lockSeen!: () => void;
  const locked = new Promise<void>(resolve => { lockSeen = resolve; });
  const close = monitor.subscribe('host-operation-session', async () => binding, event => notifications[0].push(event));
  const closeOther = monitor.subscribe('host-operation-session', async () => binding, event => {
    notifications[1].push(event);
    if (event.type === 'SESSION_LOCKED') lockSeen();
  });
  await locked;
  expect(wrapped.sessionStatus).toHaveBeenCalledTimes(1);
  monitor.logout('host-operation-session');
  expect(notifications.map(events => events.map(event => event.type))).toEqual([
    ['SESSION_LOCKED', 'SESSION_LOGOUT'], ['SESSION_LOCKED', 'SESSION_LOGOUT'],
  ]);
  expect(sdk.encodeSessionEvent(notifications[0][0])).toBe('event: session\ndata: {"type":"SESSION_LOCKED"}\n\n');
  close();
  closeOther();
});

test('reports qualified activity through confidential client auth and preserves duplicate semantics', async () => {
  const { client, binding, status } = await fixture();
  const event = randomUUID();
  await expect(client.reportActivity(binding, 'message.send', event)).resolves.toEqual({ accepted: true, updated: true });
  await expect(client.reportActivity(binding, 'message.send', event)).resolves.toEqual({ accepted: true, updated: false });
  await expect(client.reportActivity(binding, 'message.send', 'short')).rejects.toMatchObject({ code: 'INVALID_ACTIVITY_EVENT' });
  status.locked = true;
  await expect(client.reportActivity(binding, 'message.send', randomUUID())).rejects.toMatchObject({ nextAction: 'UNLOCK' });
});

test('reports whether One advanced authentication idle time on its qualified path', async () => {
  const { client, binding, status } = await fixture();
  status.authenticationIdle = true;
  const event = randomUUID();
  await expect(client.reportActivity(binding, 'message.send', event)).resolves.toEqual({
    accepted: true, updated: true, authenticationIdleUpdated: true,
  });
  await expect(client.reportActivity(binding, 'message.send', event)).resolves.toEqual({
    accepted: true, updated: false, authenticationIdleUpdated: false,
  });
});

test('initiates bound launch with a server-held verifier and redeems only after state matches', async () => {
  const { client } = await fixture();
  const pending = await client.initiateBoundLaunch('https://connect.example.test/return');
  expect(pending.expiresIn).toBe(120);
  const input = { ...pending, expectedState: pending.state, code: 'fixture-code' };
  await expect(client.redeemBoundLaunch({ ...input, state: 'mismatched' })).rejects.toMatchObject({
    code: 'SOURCE_BINDING_INVALID',
  });
  await expect(client.redeemBoundLaunch(input)).resolves.toMatchObject({ subject: expect.any(String) });
  await expect(client.redeemBoundLaunch(input)).rejects.toMatchObject({ code: 'invalid_grant' });
});

test('bound callback cannot replace evidence after host logout or mismatched revision', async () => {
  const { client, session, expected } = await fixture();
  const pending = await client.initiateBoundLaunch('https://connect.example.test/return');
  const states = { consume: jest.fn().mockResolvedValue({
    ...pending, expected, sessionId: 'host-session', revision: 'before-logout',
    centralSessionId: 'one-session', accessEpoch: 5,
  }) };
  const store = { replaceIfCurrent: jest.fn().mockResolvedValue(false) };
  await expect(session.completeBoundLaunch({
    request: pending.request, state: pending.state, code: pending.request,
  }, states, store)).rejects.toMatchObject({ code: 'SOURCE_SESSION_CHANGED' });
  expect(store.replaceIfCurrent).toHaveBeenCalledWith('host-session', 'before-logout', expect.any(Object));
});
