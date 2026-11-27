const { validate, encode, grantIdentity } = require('./request.cjs');

const same = (left, right) => encode(left) === encode(right);
const contains = (available, required) => required.every(value => available.includes(value));
const current = (value, now) => Date.parse(value.notBefore) <= now && now < Date.parse(value.notAfter);

function validInventory(inventory) {
  const list = (items, key, check) => Array.isArray(items) && items.every(item =>
    item && check(item) && typeof key(item) === 'string') && new Set(items.map(key)).size === items.length;
  const strings = items => Array.isArray(items) && items.every(item => typeof item === 'string');
  return list(inventory.clients, x => x.clientId, x => typeof x.appSlug === 'string' &&
    typeof x.active === 'boolean' && strings(x.audiences) && strings(x.scopes) &&
    list(x.keys, k => k.kid, k => typeof k.active === 'boolean' && k.publicJwk?.kty === 'RSA' &&
      typeof k.publicJwk.n === 'string' && typeof k.publicJwk.e === 'string' &&
      Number.isFinite(Date.parse(k.notBefore)) && Number.isFinite(Date.parse(k.notAfter))) &&
    (x.profile === null || (x.profile && (x.profile.state === 'disabled' ||
      (x.profile.state === 'approved' && typeof x.profile.callback === 'string' &&
        typeof x.profile.landing === 'string' && strings(x.profile.proofThumbprints)))))) &&
    list(inventory.installations, x => JSON.stringify([x.organizationId, x.installationId]), x =>
      typeof x.appSlug === 'string' && typeof x.organizationId === 'string' &&
      typeof x.installationId === 'string' && typeof x.active === 'boolean') &&
    list(inventory.resources, x => x.audience, x =>
      typeof x.appSlug === 'string' && typeof x.active === 'boolean' && strings(x.scopes)) &&
    list(inventory.grants, x => JSON.stringify([x.clientId, grantIdentity(x)]), x =>
      typeof x.clientId === 'string' && typeof x.organizationId === 'string' && typeof x.audience === 'string' &&
      typeof x.active === 'boolean' && typeof x.sourceInstallationId === 'string' &&
      typeof x.targetInstallationId === 'string' && strings(x.scopes) && Number.isFinite(Date.parse(x.validUntil))) &&
    strings(inventory.frameOrigins);
}

function reconcile(request, inventory, now = Date.now()) {
  validate(request);
  const findings = [];
  const operations = [];
  function report(code, remediation, operation) {
    findings.push({ code, remediation, repairable: Boolean(operation) });
    if (operation) operations.push(operation);
  }
  const { appSlug, clientId, assertion, profile } = request;
  const origin = new URL(profile.callback).origin;
  if (inventory?.contract !== 'one-registration-v1' || inventory.appSlug !== appSlug ||
      inventory.requestedClientId !== clientId || !(now - Date.parse(inventory.observedAt) >= 0) ||
      now - Date.parse(inventory.observedAt) > 300_000 ||
      !validInventory(inventory)) {
    report('UNSUPPORTED_CENTRAL_CONTRACT', 'Obtain current One CLI and AccessOps operator evidence for this app and client. Refresh within five minutes.');
    return { findings, operations };
  }

  const client = inventory.clients.find(item => item.clientId === clientId);
  const competing = inventory.clients.some(item => item.clientId !== clientId &&
    item.appSlug === appSlug && (item.profile?.state === 'approved' || request.mode === 'create'));
  const approvedProfile = { state: 'approved', ...profile };
  if (competing || (client && (client.appSlug !== appSlug || client.active !== true))) {
    report('CLIENT_CONFLICT', 'Have the One operator resolve existing app/client ownership and active profile before planning a change.');
  }
  if (!client) {
    report('MISSING_CONFIDENTIAL_CLIENT', 'Confirm the existing client identity, or review a new launch-only client with the One operator.',
      request.mode === 'create' && { kind: 'client', clientId, appSlug, ...request.client });
  } else if (request.client && (!contains(client.audiences, request.client.audiences) ||
      !contains(client.scopes, request.client.scopes))) {
    report('CLIENT_PERMISSION_CONFLICT', 'Use a separately approved One change for client permission changes. Preserve existing permissions.');
  }

  const key = client?.keys.find(item => item.kid === assertion.kid);
  if (!key || key.active !== true || !same(key.publicJwk, assertion.publicJwk) || !current(key, now) ||
      Date.parse(key.notBefore) !== Date.parse(assertion.notBefore) ||
      Date.parse(key.notAfter) !== Date.parse(assertion.notAfter)) {
    report('INVALID_ASSERTION_KEY_BINDING', 'Verify the host RSA public key, KID and validity window. Use a new approved KID for rotation.',
      !key && (client || request.mode === 'create') && current(assertion, now) &&
      { kind: 'key', clientId, ...assertion });
  }

  if (!client?.profile) {
    report('MISSING_LAUNCH_PROFILE', 'Publish the reviewed first-party profile with the exact HTTPS callback and proof binding.',
      { kind: 'first-party-client', clientId, profile: approvedProfile });
  } else {
    const saved = client.profile;
    if (saved.state !== 'approved') report('PROFILE_DISABLED', 'Have the One operator explicitly review re-enabling the disabled profile.');
    if (saved.callback !== profile.callback || saved.landing !== profile.landing) {
      report('UNREGISTERED_CALLBACK', 'Review the exact callback and landing with the One operator before replacing an existing profile.');
    }
    if (!contains(saved.proofThumbprints || [], profile.proofThumbprints)) {
      report('INVALID_PROOF_KEY_BINDING', 'Review proof rotation in One and preserve existing thumbprints through the cutover.');
    }
  }
  if (!inventory.frameOrigins.includes(origin)) {
    report('UNAPPROVED_ORIGIN', 'Verify the exact app origin against the registry-enabled One frame-origins endpoint after publication.');
    // Frame publication is verified after the profile is applied.
    findings[findings.length - 1].advisory = !client?.profile;
  }

  for (const required of request.installations) {
    if (!inventory.installations.some(item => item.active === true && item.appSlug === appSlug && same(
      { organizationId: item.organizationId, installationId: item.installationId }, required))) {
      report('MISSING_INSTALLATION', 'Verify the active AccessOps installation ' + required.installationId + ' for ' + required.organizationId + '.');
    }
  }
  for (const grant of request.grants) {
    const sourceInstallationId = request.installations.find(item => item.organizationId === grant.organizationId).installationId;
    const existing = inventory.grants.find(item => item.clientId === clientId && grantIdentity(item) === grantIdentity(grant));
    if (existing && existing.active === true && existing.sourceInstallationId === sourceInstallationId &&
        existing.targetInstallationId === grant.targetInstallationId && contains(existing.scopes, grant.scopes) &&
        Date.parse(existing.validUntil) >= Date.parse(grant.validUntil) && Date.parse(existing.validUntil) > now) continue;
    const resource = inventory.resources.find(item => item.audience === grant.audience && item.active === true);
    const target = resource && inventory.installations.some(item => item.active === true && item.appSlug === resource.appSlug &&
      item.organizationId === grant.organizationId && item.installationId === grant.targetInstallationId);
    const allowlist = client || request.client;
    const allowed = allowlist && contains(allowlist.audiences, [grant.audience]) && contains(allowlist.scopes, grant.scopes);
    report('MISSING_DELEGATION_GRANT', 'Verify the approved resource, tenant installations, exact scopes and expiry for ' +
      grant.audience + '. Review existing grant changes separately.',
      !existing && allowed && target && contains(resource.scopes, grant.scopes) && Date.parse(grant.validUntil) > now &&
      { kind: 'grant', clientId, sourceInstallationId, ...grant });
  }
  return { findings, operations };
}

module.exports = { reconcile };
