/** Same-origin sync hints only. Fetch authoritative state through the application backend. */
export function observeSessionChanges(onChange: () => void, channelName = 'cynayd-session-v1') {
  const channel = typeof BroadcastChannel === 'undefined' ? undefined : new BroadcastChannel(channelName);
  const onMessage = (event: MessageEvent) => { if (event.data === 'session-changed') onChange(); };
  const onVisible = () => { if (document.visibilityState === 'visible') onChange(); };
  channel?.addEventListener('message', onMessage);
  window.addEventListener('online', onVisible);
  document.addEventListener('visibilitychange', onVisible);
  return {
    invalidate() { channel?.postMessage('session-changed'); onChange(); },
    close() {
      channel?.close();
      window.removeEventListener('online', onVisible);
      document.removeEventListener('visibilitychange', onVisible);
    },
  };
}

/** Listen on the product's authenticated SSE relay. Data is an invalidation hint only. */
export function observeSessionEventStream(path: string, onChange: () => void): () => void {
  const url = new URL(path, window.location.origin);
  if (url.origin !== window.location.origin || url.username || url.password || url.search || url.hash) {
    throw new Error('Use the configured same-origin session event relay');
  }
  const stream = new EventSource(url.href);
  stream.addEventListener('session', onChange);
  stream.addEventListener('open', onChange);
  return () => stream.close();
}

export type HostSessionStatus =
  | { state: 'active'; userId: string; tenantId: string; installedAppId: string; email: string | null }
  | { state: 'unbound' | 'locked' | 'recovery' | 'sign-in' | 'denied' | 'retry' | 'unavailable' };

/** Listen for explicit input in the focused document. The host and One validate each report. */
export function observeScreenInteraction(report: () => void) {
  const events = ['pointerdown', 'keydown', 'wheel', 'touchmove'] as const;
  let last = -Infinity;
  const listener = (event: Event) => {
    if (!event.isTrusted || !document.hasFocus() || document.visibilityState !== 'visible' ||
        (event instanceof KeyboardEvent && event.repeat)) return;
    const now = performance.now();
    if (now - last < 30_000) return;
    last = now;
    report();
  };
  for (const event of events) document.addEventListener(event, listener, { capture: true, passive: true });
  return () => {
    for (const event of events) document.removeEventListener(event, listener, true);
  };
}

/** Lease changes are driven by input and visibility transitions. No heartbeat is sent. */
export function observeScreenViewing(
  report: (operation: 'screen.interaction' | 'screen.view' | 'screen.view.end', eventId: string) => Promise<boolean>,
  isViewing: () => boolean,
) {
  let current: string | undefined;
  let pending = Promise.resolve();
  let generation = 0;
  function end() {
    generation++;
    pending = pending.then(async () => {
      if (!current) return;
      const ended = current;
      current = undefined;
      await report('screen.view.end', ended);
    }).catch(() => {});
  }
  const close = observeScreenInteraction(() => {
    const observed = generation;
    pending = pending.then(async () => {
      if (observed !== generation || !document.hasFocus() || document.visibilityState !== 'visible') return;
      const event = crypto.randomUUID();
      if (!isViewing()) await report('screen.interaction', event);
      else if (await report('screen.view', event)) current = event;
    }).catch(() => {});
  });
  const onVisibility = () => { if (document.visibilityState !== 'visible') end(); };
  window.addEventListener('blur', end);
  window.addEventListener('pagehide', end);
  document.addEventListener('visibilitychange', onVisibility);
  return () => {
    close();
    window.removeEventListener('blur', end);
    window.removeEventListener('pagehide', end);
    document.removeEventListener('visibilitychange', onVisibility);
    end();
  };
}

export interface HostSessionBrowserOptions {
  /** Same-origin host route prefix, for example /api/auth/one. */
  basePath: string;
  oneOrigin: () => string;
  storageKey: string;
  /** Transitional host response code for a missing cookie. */
  missingCookieCode?: string;
}

/** Same-origin browser transport for a confidential first-party host. */
export function createHostSessionBrowser(options: HostSessionBrowserOptions) {
  if (!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(options.basePath)) {
    throw new Error('Invalid host session route');
  }
  const { basePath, storageKey, missingCookieCode = 'HOST_SESSION_REQUIRED' } = options;
  let launchInProgress: Promise<boolean> | undefined;
  let lastAttempt = 0;

  function clearLaunchAttempt() {
    lastAttempt = 0;
    try { sessionStorage.removeItem(storageKey); } catch { /* Storage can be disabled. */ }
  }

  function suppressAutomaticLaunch() {
    lastAttempt = Date.now();
    try { sessionStorage.setItem(storageKey, String(lastAttempt)); } catch { /* Storage can be disabled. */ }
  }

  function launchAttemptTime() {
    try { return Math.max(Number(sessionStorage.getItem(storageKey)) || 0, lastAttempt); }
    catch { return lastAttempt; }
  }

  async function status(): Promise<HostSessionStatus> {
    try {
      const response = await fetch(basePath + '/session', { cache: 'no-store', redirect: 'error' });
      const body = await response.json();
      if (!body || typeof body !== 'object') return { state: 'unavailable' };
      if (response.ok) {
        const { userId, tenantId, installedAppId, email } = body;
        if ([userId, tenantId, installedAppId].every(id => typeof id === 'string' && id)) {
          return { state: 'active', userId, tenantId, installedAppId, email: typeof email === 'string' ? email : null };
        }
        return { state: 'unavailable' };
      }
      if (response.status === 401 && body.code === missingCookieCode) {
        return { state: 'unbound' };
      }
      if (body.nextAction === 'UNLOCK') return { state: 'locked' };
      if (body.nextAction === 'ACCESS_DENIED') return { state: 'denied' };
      if (body.nextAction === 'RETRY') return { state: 'retry' };
      if (['session_expired', 'session_revoked', 'step_up_required'].includes(body.code)) return { state: 'sign-in' };
      if (body.nextAction === 'RECONNECT' || body.nextAction === 'REAUTHENTICATE') return { state: 'recovery' };
      if (response.status === 403) return { state: 'denied' };
    } catch { /* Report availability through the status contract. */ }
    return { state: 'unavailable' };
  }

  async function logout() {
    const response = await fetch(basePath + '/logout', { method: 'POST', redirect: 'error' });
    if (!response.ok) throw new Error('Could not close the application session');
    suppressAutomaticLaunch();
  }

  function launch(automatic: boolean, returnTo = window.location.pathname + window.location.search): Promise<boolean> {
    if (launchInProgress) return launchInProgress;
    if (automatic && Date.now() - launchAttemptTime() < 120_000) return Promise.resolve(false);
    suppressAutomaticLaunch();
    launchInProgress = (async () => {
      const response = await fetch(basePath + '/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ returnTo }),
        redirect: 'error',
      });
      if (!response.ok) throw new Error('Could not start the application session');
      const destination = new URL((await response.json()).authorizationUrl);
      if (destination.protocol !== 'https:' || destination.origin !== new URL(options.oneOrigin()).origin ||
          destination.pathname !== '/apps/bound-launch' || destination.searchParams.size !== 1 ||
          !/^[A-Za-z0-9_-]{43}$/.test(destination.searchParams.get('request') ?? '') ||
          destination.username || destination.password || destination.hash) {
        throw new Error('Invalid One launch URL');
      }
      window.location.replace(destination.href);
      return true;
    })().finally(() => { launchInProgress = undefined; });
    return launchInProgress;
  }

  async function reportScreenInteraction(operation = 'screen.interaction', eventId: string = crypto.randomUUID()) {
    const response = await fetch(basePath + '/screen-activity', {
      method: 'POST', redirect: 'error', keepalive: operation === 'screen.view.end',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ operation, eventId }),
    });
    if (!response.ok) throw new Error('Could not report screen activity');
    return (await response.json()).viewing === true;
  }

  async function unlockFrameUrl() {
    const response = await fetch(basePath + '/unlock-binding', { method: 'POST', redirect: 'error', cache: 'no-store' });
    if (!response.ok) throw new Error('Cannot verify this application session');
    const { binding } = await response.json();
    if (typeof binding !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(binding)) throw new Error('Invalid session binding');
    const url = new URL('/workspace-unlock', options.oneOrigin());
    if (url.protocol !== 'https:' || url.username || url.password) throw new Error('Invalid One origin');
    url.hash = binding;
    return url;
  }

  return { status, logout, launch, reportScreenInteraction, unlockFrameUrl, clearLaunchAttempt, suppressAutomaticLaunch };
}
