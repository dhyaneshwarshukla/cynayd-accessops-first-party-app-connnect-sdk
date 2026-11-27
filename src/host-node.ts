import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';

type Handler = (request: Request) => Promise<Response>;

/** Use before JSON body middleware. Supports Node HTTP and Express-based NestJS. */
export function createNodeHostHandler(handle: Handler, appOrigin: string) {
  return async (request: IncomingMessage, response: ServerResponse) => {
    const abort = new AbortController();
    const close = () => abort.abort();
    response.once('close', close);
    try {
      const path = 'originalUrl' in request ? request.originalUrl : request.url;
      if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.includes('\\')) {
        response.writeHead(400).end();
        return;
      }
      const headers = new Headers();
      for (let index = 0; index < request.rawHeaders.length; index += 2) {
        const name = request.rawHeaders[index];
        const value = request.rawHeaders[index + 1];
        if (name.toLowerCase() === 'cookie' && headers.has(name)) {
          headers.set(name, headers.get(name) + '; ' + value);
        } else {
          headers.append(name, value);
        }
      }
      const chunks: Buffer[] = [];
      if (request.method === 'POST') {
        let size = 0;
        for await (const chunk of request.iterator({ destroyOnReturn: false })) {
          const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          size += bytes.length;
          if (size > 4096) {
            response.writeHead(413, { Connection: 'close', 'Cache-Control': 'no-store' }).end();
            return;
          }
          chunks.push(bytes);
        }
      }
      const result = await handle(new Request(new URL(path, appOrigin), {
        method: request.method, headers, signal: abort.signal,
        body: chunks.length ? Buffer.concat(chunks) : undefined,
      }));
      result.headers.forEach((value, name) => {
        if (name !== 'set-cookie') response.setHeader(name, value);
      });
      const cookies = typeof result.headers.getSetCookie === 'function'
        ? result.headers.getSetCookie() : result.headers.get('set-cookie')?.split(', ');
      if (cookies?.length) response.setHeader('Set-Cookie', cookies);
      response.writeHead(result.status).flushHeaders();
      if (!result.body) response.end();
      else await pipeline(Readable.fromWeb(result.body as import("node:stream/web").ReadableStream), response, { signal: abort.signal });
    } catch {
      if (!response.headersSent && !abort.signal.aborted) response.writeHead(503, { 'Cache-Control': 'no-store' }).end();
      else if (!response.destroyed) response.destroy();
    } finally {
      response.off('close', close);
    }
  };
}
