import {
  createHostSessionBrowser, mountCentralUnlock, observeScreenViewing, observeSessionChanges, observeSessionEventStream,
} from '@cynayd/accessops-first-party-app-connnect-sdk/browser';

const basePath = '/api/auth/one';
const result = await fetch('/reference-config', { redirect: 'error', cache: 'no-store' });
if (!result.ok) throw new Error('Could not load application configuration');
const { onePortalOrigin } = await result.json();
const host = createHostSessionBrowser({
  basePath, oneOrigin: () => onePortalOrigin, storageKey: 'reference-launch', rememberLogout: true,
});
const status = document.getElementById('status');
const connect = document.getElementById('connect');
const logout = document.getElementById('logout');
let cleanup;
let current;
let reconcileRunning = false;
let pending = false;

async function reconcile() {
  pending = true;
  if (reconcileRunning) return;
  reconcileRunning = true;
  try {
    while (pending) {
      pending = false;
      const next = await host.status();
      connect.hidden = !['unbound', 'sign-in', 'recovery'].includes(next.state);
      logout.hidden = ['unbound', 'unavailable'].includes(next.state);
      status.textContent = {
        active: 'Your CYNAYD session is active.',
        unbound: 'Connect your CYNAYD session.',
        locked: 'Your CYNAYD session is locked.',
        recovery: 'Reconnect your CYNAYD session.',
        'sign-in': 'Sign in to One to continue.',
        denied: 'Your account cannot access this application.',
        retry: 'One could not verify your session. Try again shortly.',
        unavailable: 'Your session status is unavailable.',
      }[next.state];
      if (current !== next.state) {
        cleanup?.();
        cleanup = undefined;
        if (next.state === 'active') {
          host.clearLaunchAttempt();
          cleanup = observeScreenViewing(async (operation, id) => {
            try { return await host.reportScreenInteraction(operation, id); }
            catch { void reconcile(); return false; }
          }, () => false);
        }
        current = next.state;
      }
      if (next.state === 'locked' && !cleanup) {
        try {
          cleanup = mountCentralUnlock(document.getElementById('unlock'), await host.unlockFrameUrl(), sync.invalidate);
        } catch { status.textContent = 'The One unlock screen is unavailable.'; }
      }
      if (next.state === 'unbound' || next.state === 'recovery') {
        void host.launch(true).catch(() => { status.textContent = 'Could not connect to One.'; });
      }
    }
  } finally { reconcileRunning = false; }
}

const sync = observeSessionChanges(() => { void reconcile(); }, 'reference-session');
const closeEvents = observeSessionEventStream(basePath + '/events', sync.invalidate);
const timer = window.setInterval(() => {
  if (document.visibilityState === 'visible') void reconcile();
}, 30_000);
window.addEventListener('pagehide', event => {
  cleanup?.();
  cleanup = undefined;
  current = undefined;
  if (!event.persisted) {
    sync.close();
    closeEvents();
    window.clearInterval(timer);
  }
});
window.addEventListener('pageshow', event => {
  if (event.persisted) void reconcile();
});
document.getElementById('check').onclick = () => { void reconcile(); };
connect.onclick = () => {
  void (async () => {
    if (current === 'sign-in') await host.logout();
    await host.launch(false);
  })().catch(() => { status.textContent = 'Could not connect to One.'; });
};
logout.onclick = () => {
  void host.logout().then(sync.invalidate).catch(() => { status.textContent = 'Could not end the application session.'; });
};
void reconcile();
