/* In-process qualification fixtures only. These URLs are intercepted by mock fetch. */
const { createHash, generateKeyPairSync, randomBytes, randomUUID } = require('node:crypto');
const jwt = require('jsonwebtoken');

const one = 'https://one.example.test';
const drive = 'https://drive.example.test';
const calendar = 'https://calendar.example.test';
const start = Math.floor(Date.now() / 1000);
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });

function mockServices(sdk) {
  const issuer = one + '/';
  const endpoints = {
    tokenEndpoint: one + '/api/v1/delegations/token',
    introspectionEndpoint: one + '/api/v1/delegations/introspect',
    launchEvaluationEndpoint: one + '/api/v1/delegations/launch-evaluate',
    sessionStatusEndpoint: one + '/api/v1/delegations/session-status',
    activityEndpoint: one + '/api/v1/delegations/activity',
    boundLaunchInitiationEndpoint: one + '/api/v1/delegations/bound-launch-initiate',
    boundLaunchRedemptionEndpoint: one + '/api/v1/delegations/bound-launch-redeem',
  };
  const expected = { userId: 'person-test', organizationId: 'tenant-test', installedAppId: 'connect-install-test' };
  const status = { active: true, allowed: true, acl: true, available: true, replayAvailable: true, expires: false,
    expiredTarget: false, wrongTargetAudience: false, wrongScope: false, tokenCalls: 0, proofs: [], resourceError: 0, recovery: null, locked: false };
  const operations = {
    drive: { audience: 'drive-fixture', scopes: ['drive:write'], method: 'POST', origin: drive, allowsUrl: u => u.pathname === '/files' },
    calendar: { audience: 'calendar-fixture', scopes: ['calendar:write'], method: 'POST', origin: calendar,
      allowsUrl: u => u.pathname === '/events' },
  };
  const seen = new Set();
  const serviceProofs = new Set();
  const keys = id => new sdk.DelegationSigner({ clientId: id, credentialKid: 'fixture-key',
    clientPrivateKey: privateKey, proofPrivateKey: generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey });
  const sign = (claims, audience, expiresIn) => jwt.sign(claims, privateKey, {
    algorithm: 'RS256', keyid: 'fixture-key', header: { alg: 'RS256', typ: 'at+jwt' }, issuer, audience, expiresIn,
  });
  const makeSubject = (reference, centralSessionId, expiry) => sign({ type: 'one_delegation_subject', sub: expected.userId, id: expected.userId,
    organizationId: expected.organizationId, appSlug: 'cynayd-connect', installedAppId: expected.installedAppId,
    launchAccessEpoch: 5, launchJti: reference,
    sessionBinding: { reference, sessionId: centralSessionId, originalIat: start, expiresAt: expiry },
  }, 'cynayd-connect', expiry - Math.floor(Date.now() / 1000));
  const subject = makeSubject('fixture-launch', 'one-session', start + 600);
  const subjects = new Set([subject]);
  const redeemedCodes = new Set();
  const activityEvents = new Set();
  const boundLaunches = new Map();

  function proofIsValid(proof, method, url, token, thumbprint) {
    const head = jwt.decode(proof, { complete: true })?.header;
    const { kty, crv, x, y } = head?.jwk || {};
    const hash = value => createHash('sha256').update(value).digest('base64url');
    const claims = jwt.verify(proof, { key: { kty, crv, x, y }, format: 'jwk' }, { algorithms: ['ES256'] });
    if (head.typ !== 'dpop+jwt' || hash(JSON.stringify({ crv, kty, x, y })) !== thumbprint ||
        claims.htm !== method || claims.htu !== url || claims.ath !== (token ? hash(token) : undefined) ||
        Math.abs(Math.floor(Date.now() / 1000) - claims.iat) > 30 || serviceProofs.has(claims.jti)) return false;
    serviceProofs.add(claims.jti);
    return true;
  }

  async function fetchMock(url, init) {
    const headers = new Headers(init.headers);
    const response = (body, code = 200, extra = {}) => new Response(JSON.stringify(body), {
      status: code, headers: { 'X-Request-Id': headers.get('X-Request-Id'), 'Content-Type': 'application/json', ...extra },
    });
    if (url === one + '/api/sso/redeem-code') {
      const code = JSON.parse(init.body).code;
      if (redeemedCodes.has(code) || code !== (status.recovery?.code ?? 'one-code')) {
        return response({ code: 'LAUNCH_INVALID' }, 401);
      }
      redeemedCodes.add(code);
      return response({ success: true, ssoToken: 'launch-credential' });
    }
    if (url === one + '/api/sso/validate') {
      const body = JSON.parse(init.body);
      if (body.token !== 'launch-credential' && body.token !== 'source-api') {
        return response({ code: 'VERIFIED_FEDERATION_EVIDENCE_REQUIRED', nextAction: 'REAUTHENTICATE' }, 403);
      }
      if (status.expires) return response({ code: 'TOKEN_EXPIRED' }, 401);
      if (body.appSlug !== 'cynayd-connect' || body.includeDelegationSubject !== true) return response({ error: 'invalid_request' }, 400);
      const recovery = status.recovery;
      const deadline = start + (recovery?.duration ?? 600);
      const expiry = new Date(deadline * 1000).toISOString();
      const launchExpiry = new Date((start + (recovery?.launchDuration ?? 600)) * 1000).toISOString();
      const newSubject = recovery ? makeSubject(recovery.reference ?? 'renewed-launch', recovery.sessionId ?? 'one-session', deadline) : subject;
      subjects.add(newSubject);
      return response({ valid: true, apiToken: 'source-api', delegationSubjectToken: newSubject,
        sessionInfo: { expiresAt: launchExpiry, apiTokenExpiresAt: expiry, delegationSourceSessionExpiresAt: expiry,
          delegationCredentialExpiresAt: expiry, delegationRenewalMode: 'INTERACTIVE_RECONNECT' } });
    }
    if (Object.values(endpoints).includes(url)) {
      const body = init.body;
      const id = body.get('client_id');
      const assertion = jwt.verify(body.get('client_assertion'), publicKey, { audience: url, issuer: id, subject: id, algorithms: ['RS256'] });
      if (serviceProofs.has(assertion.jti) || !proofIsValid(headers.get('DPoP'), 'POST', url, undefined, assertion.cnf.jkt)) {
        return response({ error: 'invalid_client' }, 401);
      }
      serviceProofs.add(assertion.jti);
      if (status.resourceError === 429) return response({ error: 'rate_limit_exceeded', code: 'RATE_LIMIT_EXCEEDED' }, 429, { 'Retry-After': '2' });
      if (!status.available) return response({ error: 'temporarily_unavailable' }, 503);
      if (url === endpoints.introspectionEndpoint) {
        const token = jwt.decode(body.get('token'));
        if (!status.active || !status.allowed || id !== token.aud + '-resource' || body.get('audience') !== token.aud) {
          return response({ active: false });
        }
        return response({ ...token, active: true });
      }
      if (url === endpoints.boundLaunchInitiationEndpoint) {
        const request = randomBytes(32).toString('base64url');
        boundLaunches.set(request, body.get('challenge'));
        return response({ request, expires_in: 120 });
      }
      if (url === endpoints.boundLaunchRedemptionEndpoint) {
        const request = body.get('request');
        const expected = boundLaunches.get(request);
        const challenge = createHash('sha256').update(body.get('verifier')).digest('base64url');
        if (expected !== challenge) return response({ error: 'invalid_grant' }, 400);
        boundLaunches.delete(request);
        return response({ subject_token: subject });
      }
      if (!status.active || !subjects.has(body.get('subject_token')) || id !== 'connect-fixture') return response({ error: 'invalid_grant' }, 400);
      if (!status.allowed) return response({ error: 'access_denied' }, 403);
      if (status.locked) return response({ error: 'session_locked' }, 403);
      if (url === endpoints.activityEndpoint) {
        if (body.get('operation') !== 'message.send') return response({ error: 'activity_not_eligible' }, 403);
        const id = body.get('event_id');
        const updated = !activityEvents.has(id);
        activityEvents.add(id);
        return response({ accepted: true, updated, ...(status.authenticationIdle ? { authenticationIdleUpdated: updated } : {}) });
      }
      if (url === endpoints.sessionStatusEndpoint) {
        const now = Date.now();
        return response({ state: 'ACTIVE', reason: 'SESSION_VALID', nextAction: 'NONE', accessEpoch: 5,
          centralExpiresAt: new Date(now + 600_000).toISOString(), subjectExpiresAt: new Date(now + 60_000).toISOString(),
          idleExpiresAt: new Date(now + 300_000).toISOString(), lastActivityAt: new Date(now - 24_000).toISOString(),
          revision: 'fixture-revision' });
      }
      if (url === endpoints.launchEvaluationEndpoint) {
        return response({ decision: 'ALLOW', availability: 'AVAILABLE', applicationKey: 'cynayd-connect', ...expected, launchAccessEpoch: 5 });
      }
      status.tokenCalls++;
      const audience = body.get('audience');
      const operation = Object.values(operations).find(op => op.audience === audience);
      if (!operation) return response({ error: 'invalid_target' }, 400);
      const scope = body.get('scope');
      if (scope !== operation.scopes.join(' ')) return response({ error: 'invalid_scope' }, 400);
      const now = Math.floor(Date.now() / 1000);
      const accessToken = sign({ sub: expected.userId, organization_id: expected.organizationId, client_id: id,
        azp: 'cynayd-connect', act: { sub: id }, mode: 'DELEGATED', type: 'one_delegated_access',
        scope: status.wrongScope ? 'unrelated:read' : scope, source_installation_id: expected.installedAppId,
        target_installation_id: audience + '-install', source_epoch: 5, target_epoch: 3, grant_revision: 1,
        client_revision: 1, jti: randomUUID(), cnf: assertion.cnf, nbf: status.expiredTarget ? now - 120 : now,
        iat: status.expiredTarget ? now - 120 : now,
      }, status.wrongTargetAudience ? 'wrong-fixture' : audience, 60);
      return response({ access_token: accessToken, token_type: 'DPoP', expires_in: 60,
        issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', scope });
    }
    const operation = Object.values(operations).find(op => new URL(url).origin === op.origin);
    if (!operation || !operation.allowsUrl(new URL(url))) throw new Error('Unexpected fixture request');
    status.proofs.push(headers.get('DPoP'));
    if (status.beforeTarget) status.beforeTarget(headers);
    try {
      await resources[operation.audience].authorize({
        authorization: headers.get('Authorization'), proof: headers.get('DPoP'), path: new URL(url).pathname,
        requestId: headers.get('X-Request-Id'), method: init.method, requiredScope: operation.scopes[0],
      }, { tenant: expected.organizationId });
      return response({ saved: true }, 201);
    } catch (error) {
      const result = sdk.authErrorResponse(error);
      return response(result.body, result.status, result.headers);
    }
  }

  const options = { ...endpoints, fetch: fetchMock };
  const client = new sdk.DelegationClient({ ...options, signer: keys('connect-fixture') });
  const signingKey = async kid => kid === 'fixture-key' ? publicKey : null;
  const resources = {};
  for (const op of Object.values(operations)) {
    resources[op.audience] = new sdk.DelegatedResource({
      issuer, audience: op.audience, publicOrigin: op.origin, signingKey,
      delegation: new sdk.DelegationClient({ ...options, signer: keys(op.audience + '-resource') }),
      replay: { async consume(jkt, jti) {
        if (!status.replayAvailable) throw new Error('fixture replay store unavailable');
        const key = jkt + ':' + jti;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      } },
      async authorize(identity, context) {
        return status.acl && identity.userId === expected.userId && identity.organizationId === context.tenant &&
          identity.installedAppId === op.audience + '-install';
      },
    });
  }
  const session = new sdk.OneApplicationSession({ issuer, identityOrigin: one, appSlug: 'cynayd-connect',
    signingKey, delegation: client, fetch: fetchMock });
  return { session, expected, client, operations, status,
    evidenceSession: new sdk.OneApplicationSession({ issuer, identityOrigin: one, appSlug: 'cynayd-connect',
      signingKey, delegation: client, fetch: fetchMock, useEvidenceDeadlines: true }) };
}

module.exports = { mockServices };
