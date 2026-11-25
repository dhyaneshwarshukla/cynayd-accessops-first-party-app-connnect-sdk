import { randomUUID } from 'node:crypto';

export type RecoveryAction = 'REAUTHENTICATE' | 'ACCESS_DENIED' | 'RETRY' | 'INVESTIGATE';

export class FirstPartyAuthError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    public readonly requestId: string,
    public readonly nextAction: RecoveryAction,
    public readonly upstreamError?: string,
    public readonly retryAfter?: string,
  ) {
    super(code);
    this.name = 'FirstPartyAuthError';
  }
}

export interface Transport {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export function httpsUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw new Error('A trusted HTTPS URL is required');
  }
  return url;
}

export function object(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return {};
}

function validRequestId(value: unknown): value is string {
  return typeof value === 'string' &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(value);
}

export function correlation(value?: string): string {
  return validRequestId(value) ? value : randomUUID();
}

function identifier(value: unknown): string | undefined {
  return typeof value === 'string' && /^[a-z][a-z0-9_]{1,95}$/i.test(value) ? value : undefined;
}

function wireError(response: Response, body: Record<string, unknown>, requestId: string) {
  const upstreamError = identifier(body.error);
  const code = identifier(body.code) ?? upstreamError ?? 'UPSTREAM_AUTH_ERROR';
  const retryAfter = response.headers.get('Retry-After') ?? undefined;
  let action: RecoveryAction = 'INVESTIGATE';
  if (response.status === 429 || response.status === 503 || body.nextAction === 'RETRY') action = 'RETRY';
  else if (code === 'ACCESS_DENIED' || code === 'access_denied' || body.nextAction === 'ACCESS_DENIED') action = 'ACCESS_DENIED';
  else if (body.nextAction === 'REAUTHENTICATE' || body.nextAction === 'RECONNECT' ||
      ['VERIFIED_FEDERATION_EVIDENCE_REQUIRED', 'TOKEN_EXPIRED', 'AUTH_TOKEN_EPOCH', 'SESSION_EXPIRED',
        'ACCESS_EPOCH_STALE', 'access_epoch_stale'].includes(code)) action = 'REAUTHENTICATE';
  return new FirstPartyAuthError(response.status, code, requestId, action, upstreamError, retryAfter);
}

export async function send(transport: Transport, url: string, init: RequestInit, requestId: string): Promise<Response> {
  const headers = new Headers(init.headers);
  headers.set('X-Request-Id', requestId);
  try {
    return await (transport.fetch ?? fetch)(url, {
      ...init, headers, redirect: 'error', cache: 'no-store',
      signal: init.signal ?? AbortSignal.timeout(transport.timeoutMs ?? 10000),
    });
  } catch {
    throw new FirstPartyAuthError(503, 'UPSTREAM_UNAVAILABLE', requestId, 'RETRY');
  }
}

export async function readJson(response: Response, requestId: string): Promise<Record<string, unknown>> {
  const body = object(await response.json().catch(() => undefined));
  const reported = response.headers.get('X-Request-Id') ?? body.request_id;
  const id = validRequestId(reported) ? reported : requestId;
  if (!response.ok) throw wireError(response, body, id);
  if (!Object.keys(body).length) throw new FirstPartyAuthError(503, 'UPSTREAM_PROFILE_MISMATCH', id, 'INVESTIGATE');
  return body;
}
