const { createHash, createPublicKey } = require('node:crypto');

const fail = message => { throw new Error(message); };
const matches = (value, pattern) => typeof value === 'string' && pattern.test(value);
const id = value => matches(value, /^[A-Za-z0-9_.:-]{1,160}$/);
const scope = value => matches(value, /^[a-z][a-z0-9_.:-]{1,127}$/);
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const date = value => matches(value, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/) && Number.isFinite(Date.parse(value));
const thumbprint = value => matches(value, /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/);
const unique = (values, predicate, min = 0, max = 32) =>
  Array.isArray(values) && values.length >= min && values.length <= max &&
  new Set(values).size === values.length && values.every(predicate);

function shape(value, checks, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).length !== Object.keys(checks).length) fail('Invalid ' + label);
  for (const [key, check] of Object.entries(checks)) {
    if (!Object.hasOwn(value, key) || !check(value[key])) fail('Invalid ' + label + '.' + key);
  }
}
function exactUrl(value) {
  if (typeof value !== 'string') return false;
  const url = URL.canParse(value) && new URL(value);
  return url && url.protocol === 'https:' && !url.username && !url.password &&
    !value.includes('?') && !value.includes('#') && url.href === value;
}
function assertion(value) {
  shape(value, {
    kid: id, notBefore: date, notAfter: date,
    publicJwk: jwk => {
      shape(jwk, { kty: x => x === 'RSA', n: x => matches(x, /^[\w-]{342,2731}$/),
        e: x => matches(x, /^[\w-]{2,12}$/) }, 'public RSA JWK');
      const key = createPublicKey({ key: jwk, format: 'jwk' });
      const exported = key.export({ format: 'jwk' });
      return key.asymmetricKeyDetails.modulusLength >= 2048 && exported.n === jwk.n && exported.e === jwk.e;
    },
  }, 'assertion');
  return Date.parse(value.notAfter) > Date.parse(value.notBefore);
}
const installationShape = { organizationId: id, installationId: id };
const grantShape = { organizationId: id, audience: id, targetInstallationId: id,
  scopes: x => unique(x, scope, 1), validUntil: date };
const grantIdentity = grant => JSON.stringify([grant.organizationId, grant.audience]);
function validate(request) {
  shape(request, {
    version: x => x === 1, appSlug: id, clientId: id,
    mode: x => ['create', 'reuse'].includes(x), assertion,
    profile: profile => {
      shape(profile, { callback: exactUrl, landing: exactUrl, proofThumbprints: x => unique(x, thumbprint, 1, 8) }, 'profile');
      return new URL(profile.callback).origin === new URL(profile.landing).origin;
    },
    client: client => {
      if (request.mode === 'reuse') return client === null;
      shape(client, { audiences: x => unique(x, id), scopes: x => unique(x, scope) }, 'client');
      return Boolean(client.audiences.length) === Boolean(client.scopes.length);
    },
    installations: x => Array.isArray(x) && x.length >= 1 && x.length <= 32,
    grants: x => Array.isArray(x) && x.length <= 32,
  }, 'request');

  for (const item of request.installations) shape(item, installationShape, 'installation');
  for (const item of request.grants) shape(item, grantShape, 'grant');
  if (new Set(request.installations.map(x => x.organizationId)).size !== request.installations.length ||
      new Set(request.grants.map(grantIdentity)).size !== request.grants.length) fail('Duplicate installation or grant');
  for (const grant of request.grants) {
    if (!request.installations.some(item => item.organizationId === grant.organizationId)) fail('Grant has no source installation');
    if (request.client && (!request.client.audiences.includes(grant.audience) ||
        !grant.scopes.every(value => request.client.scopes.includes(value)))) fail('Grant exceeds requested client permissions');
  }
  return request;
}
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}
const encode = value => JSON.stringify(canonical(value), null, 2) + '\n';
module.exports = { validate, encode, digest, grantIdentity };
