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
