import { DelegationClient, CentralSessionStatus } from './client';
import type { VerifiedSession, BoundDelegationBinding } from './session';

type LifecycleBinding = VerifiedSession | BoundDelegationBinding;
import { FirstPartyAuthError } from './transport';
import { sourceRecoveryStatus } from './renewal';

/** Call after authenticating the host session, and compose with the application's operation ACL. */
export async function withCentralSession<T>(
  client: DelegationClient, binding: LifecycleBinding,
  operation: (state: CentralSessionStatus) => Promise<T>, requestId?: string,
): Promise<T> {
  return operation(await client.sessionStatus(binding, requestId));
}

export type SessionEventType = 'SESSION_LOCKED' | 'SESSION_UNLOCKED' | 'SESSION_EXPIRED' |
  'SESSION_REVOKED' | 'SESSION_LOGOUT' | 'SESSION_ACCESS_DENIED' | 'CREDENTIAL_RENEWAL_REQUIRED';

export interface SessionEvent {
  type: SessionEventType;
  /** Opaque, scoped to the central session. Treat every event as an invalidation hint. */
  revision?: string;
}
type Listener = (event: SessionEvent) => void;

interface Monitor {
  listeners: Set<Listener>;
  load: () => Promise<LifecycleBinding | undefined>;
  timer?: ReturnType<typeof setTimeout>;
  last?: SessionEventType;
  lock: boolean;
}

/** Share one instance per backend process. Relays only hints to an already authenticated host session. */
export class SessionEventMonitor {
  private readonly active = new Map<string, Monitor>();
  constructor(private readonly client: Pick<DelegationClient, 'sessionStatus'>, private readonly intervalMs = 60_000) {
    if (!Number.isSafeInteger(intervalMs) || intervalMs < 30_000 || intervalMs > 300_000) {
      throw new RangeError('Invalid session event monitoring interval');
    }
  }

  subscribe(key: string, load: Monitor['load'], listener: Listener): () => void {
    const current = this.active.get(key);
    const monitor = current ?? { listeners: new Set<Listener>(), load, lock: false };
    monitor.listeners.add(listener);
    if (!current) {
      this.active.set(key, monitor);
      void this.check(key, monitor);
    }
    return () => {
      monitor.listeners.delete(listener);
      if (!monitor.listeners.size && this.active.get(key) === monitor) this.stop(key, monitor);
    };
  }

  logout(key: string) {
    const monitor = this.active.get(key);
    if (monitor) {
      this.emit(monitor, { type: 'SESSION_LOGOUT' });
      this.stop(key, monitor);
    }
  }

  private stop(key: string, monitor: Monitor) {
    clearTimeout(monitor.timer);
    this.active.delete(key);
  }

  private emit(monitor: Monitor, event: SessionEvent) {
    if (monitor.last === event.type) return;
    monitor.last = event.type;
    for (const listener of monitor.listeners) {
      try { listener(event); } catch { /* A disconnected relay cannot disrupt other subscriptions. */ }
    }
  }

  private async refreshState(key: string, monitor: Monitor, binding: LifecycleBinding) {
    const state = await this.client.sessionStatus(binding);
    if (this.active.get(key) !== monitor) return;
    if (monitor.lock) this.emit(monitor, { type: 'SESSION_UNLOCKED', revision: state.revision ?? undefined });
    monitor.lock = false;
    if (sourceRecoveryStatus(binding) !== 'ACTIVE') this.emit(monitor, { type: 'CREDENTIAL_RENEWAL_REQUIRED' });
    else monitor.last = undefined;
  }

  private async check(key: string, monitor: Monitor) {
    try {
      const binding = await monitor.load();
      if (this.active.get(key) !== monitor) return;
      if (!binding) { this.logout(key); return; }
      if ((('sourceEvidence' in binding ? binding.sourceEvidence?.subjectExpiresAt : undefined) ?? binding.expiresAt) <= Date.now()) {
        this.emit(monitor, { type: 'CREDENTIAL_RENEWAL_REQUIRED' });
      } else {
        await this.refreshState(key, monitor, binding);
      }
    } catch (error) {
      if (this.active.get(key) !== monitor) return;
      if (error instanceof FirstPartyAuthError) {
        if (error.code === 'session_locked') {
          monitor.lock = true;
          this.emit(monitor, { type: 'SESSION_LOCKED' });
        } else if (error.code === 'session_revoked' || error.code === 'session_expired') {
          this.emit(monitor, { type: error.code === 'session_revoked' ? 'SESSION_REVOKED' : 'SESSION_EXPIRED' });
          this.stop(key, monitor);
          return;
        } else if (error.nextAction === 'ACCESS_DENIED') {
          this.emit(monitor, { type: 'SESSION_ACCESS_DENIED' });
        } else if (error.nextAction === 'REAUTHENTICATE' || error.upstreamError === 'invalid_grant') {
          this.emit(monitor, { type: 'CREDENTIAL_RENEWAL_REQUIRED' });
        }
      }
    }
    if (this.active.get(key) !== monitor) return;
    monitor.timer = setTimeout(() => void this.check(key, monitor), this.intervalMs + Math.floor(Math.random() * 5_000));
    monitor.timer.unref?.();
  }
}

/** Format for the product's authenticated SSE connection. Never include credential or identity data. */
export function encodeSessionEvent(event: SessionEvent): string {
  return `event: session\ndata: ${JSON.stringify({ type: event.type, revision: event.revision })}\n\n`;
}
