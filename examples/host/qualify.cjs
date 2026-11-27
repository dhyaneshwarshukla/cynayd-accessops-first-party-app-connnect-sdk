// Local qualification. The authority is the SDK fixture and PostgreSQL is disposable.
const assert = require('node:assert/strict');
const { once } = require('node:events');
const { randomBytes } = require('node:crypto');
const { readFileSync } = require('node:fs');
const express = require('express');
const { createServer } = require('node:http');
const { Pool } = require('pg');
const sdk = require('@cynayd/accessops-first-party-app-connnect-sdk');
const { mockServices } = require('../mock-services.cjs');

async function main() {
  if (!process.env.SDK_TEST_DATABASE_URL) throw new Error('Supply an isolated PostgreSQL test database');
  const pool = new Pool({ connectionString: process.env.SDK_TEST_DATABASE_URL });
  const connection = await pool.connect();
  let server, nestApp;
  try {
    const sql = readFileSync(__dirname + '/schema.sql', 'utf8').replaceAll('CREATE TABLE', 'CREATE TEMP TABLE');
    await connection.query(sql);
    const store = new sdk.PostgresHostSessionStore({
      query: (text, values) => connection.query(text, values),
      async transaction(work) {
        await connection.query('BEGIN');
        try {
          const result = await work(connection);
          await connection.query('COMMIT');
          return result;
        } catch (error) {
          await connection.query('ROLLBACK');
          throw error;
        }
      },
    }, randomBytes(32), 3600);
    const authority = mockServices(sdk);
    const origin = 'https://app.example.test';
    const base = '/api/auth/one';
    const host = new sdk.FirstPartyHost({
      appOrigin: origin, onePortalOrigin: 'https://one.example.test', cookieLabel: 'fixture',
      callback: origin + base + '/callback', store, delegation: authority.client, session: authority.session,
      allowsReturn: url => url.pathname === '/' || url.pathname === '/workspace',
    });
    const start = authority.client.initiateBoundLaunch.bind(authority.client);
    let pending;
    authority.client.initiateBoundLaunch = async callback => (pending = await start(callback));
    const handler = sdk.createNodeHostHandler(sdk.createHostHttpHandler(host, base), origin);
    const framework = process.env.SDK_TEST_FRAMEWORK || 'express';
    if (framework === 'nest') {
      const { Module } = require('@nestjs/common');
      const { NestFactory } = require('@nestjs/core');
      class EmptyModule {}
      Module({})(EmptyModule);
      nestApp = await NestFactory.create(EmptyModule, { logger: false, abortOnError: false });
      nestApp.use(base, handler);
      await nestApp.listen(0, '127.0.0.1');
      server = nestApp.getHttpServer();
    } else {
      if (framework === 'node') server = createServer(handler).listen(0, '127.0.0.1');
      else {
        const app = express();
        app.use(base, handler);
        server = app.listen(0, '127.0.0.1');
      }
      await once(server, 'listening');
    }
    const endpoint = 'http://127.0.0.1:' + server.address().port + base;
    const post = (path, body, cookies, acceptedOrigin = origin) => fetch(endpoint + path, {
      method: 'POST', headers: { Origin: acceptedOrigin, ...(cookies ? { Cookie: cookies } : {}) },
      body: body && JSON.stringify(body),
    });
    const firstCookie = response => response.headers.getSetCookie()[0].split(';')[0];
    const begin = async (returnTo, cookies) => {
      const result = await post('/start', { returnTo }, cookies);
      assert.equal(result.status, 200);
      assert.match(result.headers.get('set-cookie'), /Secure; HttpOnly; SameSite=Lax/);
      assert.match((await result.json()).authorizationUrl, /^https:\/\/one\.example\.test\/apps\/bound-launch\?/);
      const callback = new URLSearchParams({ request: pending.request, state: pending.state, code: 'x'.repeat(43) });
      return {
        cookie: firstCookie(result),
        complete: cookie => fetch(endpoint + '/callback?' + callback, { headers: { Cookie: cookie }, redirect: 'manual' }),
      };
    };
    assert.equal((await post('/start', {}, undefined, 'https://elsewhere.example.test')).status, 403);
    const initial = await begin('/workspace?draft=one');
    const launched = await initial.complete(initial.cookie);
    assert.equal(launched.status, 303);
    assert.equal(launched.headers.get('location'), origin + '/workspace?draft=one');
    assert.equal((await initial.complete(initial.cookie)).status, 401);
    const old = firstCookie(launched);
    const current = cookie => fetch(endpoint + '/session', { headers: { Cookie: cookie } });
    assert.equal((await (await current(old)).json()).tenantId, 'tenant-test');
    authority.status.locked = true;
    assert.equal((await (await current(old)).json()).nextAction, 'UNLOCK');
    assert.match((await (await post('/unlock-binding', undefined, old)).json()).binding, /^[\w-]{43}$/);
    authority.status.locked = false;
    const recovery = await begin('//elsewhere.example.test', old);
    assert.equal((await recovery.complete(recovery.cookie)).status, 401);
    const replaced = await recovery.complete(old + '; ' + recovery.cookie);
    assert.equal(replaced.status, 303);
    assert.equal(replaced.headers.get('location'), origin + '/');
    assert.equal((await current(old)).status, 401);
    const fresh = firstCookie(replaced);
    authority.status.allowed = false;
    assert.equal((await (await current(fresh)).json()).nextAction, 'ACCESS_DENIED');
    authority.status.allowed = true;
    assert.equal((await post('/logout', undefined, fresh)).status, 204);
    assert.equal((await current(fresh)).status, 401);
    const replay = new sdk.PostgresProofReplayStore(connection);
    const replays = await Promise.all([1, 2].map(() => replay.consume('test-jkt', 'test-proof', Date.now() / 1000 + 60)));
    assert.deepEqual(replays.sort(), [false, true]);
    console.log(framework + ' host, PostgreSQL, bound launch, live status, lock, recovery, logout and replay contract passed');
  } finally {
    if (server) server.closeAllConnections();
    if (nestApp) await nestApp.close();
    else if (server) server.close();
    connection.release();
    await pool.end();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
