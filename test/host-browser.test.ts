import { createHostSessionBrowser } from '../src/browser';

const callback = 'https://one.example.test/apps/bound-launch?request=' + 'a'.repeat(43);
const browser = () => createHostSessionBrowser({
  basePath: '/api/auth/one', oneOrigin: () => 'https://one.example.test', storageKey: 'test-launch',
});
const respond = (status: number, body: object) => new Response(JSON.stringify(body), { status });

afterEach(() => jest.restoreAllMocks());

it.each([
  [401, { code: 'HOST_SESSION_REQUIRED' }, 'unbound'],
  [404, {}, 'unavailable'],
  [403, {}, 'denied'],
  [403, { nextAction: 'UNLOCK' }, 'locked'],
  [401, { code: 'session_revoked', nextAction: 'REAUTHENTICATE' }, 'sign-in'],
  [409, { nextAction: 'RECONNECT' }, 'recovery'],
  [503, { nextAction: 'RETRY' }, 'retry'],
  [200, { nextAction: 'RECONNECT' }, 'unavailable'],
])('classifies host status %s %j as %s', async (status, body, state) => {
  jest.spyOn(globalThis, 'fetch').mockResolvedValue(respond(status, body));
  await expect(browser().status()).resolves.toEqual({ state });
});

it('deduplicates concurrent launch and suppresses another automatic redirect', async () => {
  const fetch = jest.spyOn(globalThis, 'fetch').mockResolvedValue(respond(200, { authorizationUrl: callback }));
  const location = { replace: jest.fn() };
  Object.defineProperty(globalThis, 'window', { value: { location }, configurable: true });
  try {
    const host = browser();
    await expect(Promise.all([host.launch(true, '/w/sample'), host.launch(true, '/w/sample')])).resolves.toEqual([true, true]);
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledWith('/api/auth/one/start', expect.objectContaining({ body: '{"returnTo":"/w/sample"}' }));
    expect(location.replace).toHaveBeenCalledWith(callback);
    await expect(host.launch(true, '/w/sample')).resolves.toBe(false);
    fetch.mockResolvedValue(respond(200, { authorizationUrl: callback.replace('one.example.test', 'other.example.test') }));
    await expect(host.launch(false, '/w/sample')).rejects.toThrow('Invalid One launch URL');
    expect(location.replace).toHaveBeenCalledTimes(1);
  } finally {
    Reflect.deleteProperty(globalThis, 'window');
  }
});
