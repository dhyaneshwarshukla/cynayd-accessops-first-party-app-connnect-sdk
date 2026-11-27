import { encodeSessionEvent } from './delegation/lifecycle';
import { FirstPartyHost, hostErrorResponse } from './host';

const headers = { 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' };
const cookie = (name: string, value: string, age?: number) =>
  `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax${age === undefined ? '' : '; Max-Age=' + age}`;
const json = (body: unknown, status = 200, extra?: HeadersInit) => new Response(JSON.stringify(body), {
  status, headers: { ...headers, 'Content-Type': 'application/json', ...extra },
});
const invalid = () => json({ code: 'HOST_REQUEST_INVALID' }, 400);

async function requestObject(request: Request) {
  if (!request.body) return undefined;
  const reader = request.body.getReader();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  let body = '';
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > 4096) {
        void reader.cancel().catch(() => undefined);
        return undefined;
      }
      body += decoder.decode(value, { stream: true });
    }
    const parsed: unknown = JSON.parse(body + decoder.decode());
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed as Record<string, unknown>;
  } catch { /* Report the same error for malformed or interrupted input. */ }
  finally { reader.releaseLock(); }
  return undefined;
}

export function createHostHttpHandler(host: FirstPartyHost, basePath: string) {
  if (!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(basePath)) throw new Error('Invalid host route prefix');
  host.assertCallbackPath(basePath + '/callback');

  return async function handle(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const endpoint = url.pathname.slice(basePath.length);
    if (!url.pathname.startsWith(basePath + '/')) return json({ code: 'NOT_FOUND' }, 404);
    const origin = request.headers.get('Origin') ?? undefined;
    const cookies = request.headers.get('Cookie') ?? undefined;
    try {
      if (request.method === 'POST') {
        host.assertOrigin(origin);
        switch (endpoint) {
          case '/start': {
            const body = await requestObject(request);
            if (!body) return invalid();
            const launch = await host.start(origin, cookies, body.returnTo);
            return json({ authorizationUrl: launch.authorizationUrl }, 200, {
              'Set-Cookie': cookie(host.launchCookie, launch.id, launch.expiresIn),
            });
          }
          case '/unlock-binding':
            return json(await host.unlockBinding(origin, cookies));
          case '/screen-activity': {
            const body = await requestObject(request);
            if (!body) return invalid();
            return json(await host.screenActivity(origin, cookies, body.operation, body.eventId));
          }
          case '/logout': {
            await host.logout(origin, cookies);
            const responseHeaders = new Headers(headers);
            responseHeaders.append('Set-Cookie', cookie(host.sessionCookie, '', 0));
            responseHeaders.append('Set-Cookie', cookie(host.launchCookie, '', 0));
            return new Response(null, { status: 204, headers: responseHeaders });
          }
        }
      }
      if (request.method === 'GET') {
        switch (endpoint) {
          case '/callback': {
            const fields = ['request', 'code', 'state'] as const;
            if (fields.some(field => url.searchParams.getAll(field).length !== 1)) return invalid();
            const { id, landing } = await host.callback(cookies, {
              request: url.searchParams.get('request')!, code: url.searchParams.get('code')!, state: url.searchParams.get('state')!,
            });
            const responseHeaders = new Headers({ ...headers, Location: landing });
            responseHeaders.append('Set-Cookie', cookie(host.sessionCookie, id));
            responseHeaders.append('Set-Cookie', cookie(host.launchCookie, '', 0));
            return new Response(null, { status: 303, headers: responseHeaders });
          }
          case '/session':
            return json(await host.status(cookies));
          case '/events': {
            const subscribe = await host.events(cookies);
            const encoder = new TextEncoder();
            let unsubscribe: (() => void) | undefined;
            let detach: (() => void) | undefined;
            const stream = new ReadableStream<Uint8Array>({
              start(controller) {
                if (request.signal.aborted) { controller.close(); return; }
                const stop = () => {
                  unsubscribe?.();
                  detach?.();
                  controller.close();
                };
                request.signal.addEventListener('abort', stop, { once: true });
                detach = () => request.signal.removeEventListener('abort', stop);
                controller.enqueue(encoder.encode(': connected\n\n'));
                unsubscribe = subscribe(event => {
                  if ((controller.desiredSize ?? 0) > 0) controller.enqueue(encoder.encode(encodeSessionEvent(event)));
                });
              },
              cancel() { unsubscribe?.(); detach?.(); },
            }, { highWaterMark: 2 });
            return new Response(stream, { headers: {
              ...headers, 'Content-Type': 'text/event-stream', 'X-Accel-Buffering': 'no',
            } });
          }
        }
      }
      return json({ code: 'NOT_FOUND' }, 404);
    } catch (error) {
      const response = hostErrorResponse(error);
      return json(response.body, response.status, response.retryAfter ? { 'Retry-After': response.retryAfter } : undefined);
    }
  };
}
