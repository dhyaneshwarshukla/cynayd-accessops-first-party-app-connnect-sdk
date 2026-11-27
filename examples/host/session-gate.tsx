'use client';

import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  createHostSessionBrowser, mountCentralUnlock, observeScreenViewing, observeSessionChanges,
  observeSessionEventStream, type HostSessionStatus,
} from '@cynayd/accessops-first-party-app-connnect-sdk/browser';

const basePath = '/api/auth/one';
const host = createHostSessionBrowser({
  basePath, storageKey: 'first-party-launch', rememberLogout: true, oneOrigin: () => process.env.NEXT_PUBLIC_ONE_PORTAL_ORIGIN!,
});

type Active = Extract<HostSessionStatus, { state: 'active' }>;
const identity = (session: Active) => JSON.stringify([session.tenantId, session.userId, session.installedAppId]);

export function SessionGate({ children, eventsEnabled = true }: { children: ReactNode; eventsEnabled?: boolean }) {
  const [status, setStatus] = useState<HostSessionStatus>();
  const [error, setError] = useState('');
  const original = useRef<string | undefined>(undefined);
  const mount = useRef<HTMLDivElement>(null);
  const refresh = useRef<() => void>(() => undefined);
  const invalidate = useRef<() => void>(() => undefined);

  useEffect(() => {
    let disposed = false;
    let running = false;
    let requested = false;
    async function reconcile() {
      requested = true;
      if (running || disposed) return;
      running = true;
      try {
        while (requested && !disposed) {
          requested = false;
          const next = await host.status();
          if (disposed) return;
          if (next.state === 'active') {
            const current = identity(next);
            if (original.current && original.current !== current) {
              setStatus({ state: 'denied' });
              continue;
            }
            original.current = current;
            host.clearLaunchAttempt();
          }
          setStatus(next);
          if (next.state === 'unbound' || next.state === 'recovery') {
            void host.launch(true).catch(() => { if (!disposed) setError('Could not connect to One.'); });
          }
        }
      } finally { running = false; }
    }
    refresh.current = () => { void reconcile(); };
    const sync = observeSessionChanges(refresh.current);
    invalidate.current = sync.invalidate;
    const close = eventsEnabled ? observeSessionEventStream(basePath + '/events', sync.invalidate) : () => undefined;
    // Passive fallback also supports FastAPI hosts without a relay.
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') refresh.current();
    }, 30_000);
    refresh.current();
    return () => {
      disposed = true;
      close();
      sync.close();
      window.clearInterval(timer);
    };
  }, [eventsEnabled]);

  useEffect(() => {
    if (status?.state !== 'active') return;
    return observeScreenViewing(async (operation, eventId) => {
      try { return await host.reportScreenInteraction(operation, eventId); }
      catch { refresh.current(); return false; }
    }, () => false); // Supply a predicate for approved viewing routes.
  }, [status?.state]);

  useEffect(() => {
    if (status?.state !== 'locked') return;
    let disposed = false;
    let cleanup: (() => void) | undefined;
    void host.unlockFrameUrl().then(url => {
      if (!disposed && mount.current) cleanup = mountCentralUnlock(mount.current, url, () => invalidate.current());
    }).catch(() => { if (!disposed) setError('Could not open the One unlock screen.'); });
    return () => { disposed = true; cleanup?.(); };
  }, [status?.state]);

  return <>
    <div hidden={status?.state !== 'active'}>{original.current && children}</div>
    <div ref={mount} />
    {status?.state !== 'active' && <section aria-live="polite">
      <p>{status?.state === 'locked' ? 'Your CYNAYD session is locked.' : 'Check your CYNAYD session to continue.'}</p>
      {error && <p role="alert">{error}</p>}
      {status?.state === 'denied' && <p>This account cannot continue in this workspace.</p>}
      <button onClick={() => refresh.current()}>Check session</button>
      {status && ['unbound', 'sign-in', 'recovery'].includes(status.state) &&
        <button onClick={() => {
          void (async () => {
            if (status.state === 'sign-in') await host.logout();
            await host.launch(false);
          })().catch(() => setError('Could not connect to One.'));
        }}>Continue to One</button>}
    </section>}
  </>;
}
