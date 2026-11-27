const { test } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { generateKeyPairSync } = require('node:crypto');
const { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { validate } = require('../../tooling/registration/request.cjs');
const { reconcile } = require('../../tooling/registration/reconcile.cjs');
const tool = resolve(__dirname, '../../tooling/registration/register.cjs');
const publicJwk = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
const now = Date.now();
const at = offset => new Date(now + offset).toISOString();
const request = {
  version: 1, appSlug: 'example', clientId: 'example-client', mode: 'create',
  client: { audiences: [], scopes: [] },
  assertion: { kid: 'key-1', publicJwk, notBefore: at(-1000), notAfter: at(60000) },
  profile: {
    callback: 'https://app.example.test/api/auth/one/callback',
    landing: 'https://app.example.test/',
    proofThumbprints: ['A'.repeat(43)],
  },
  installations: [{ organizationId: 'example-org', installationId: 'example-installation' }],
  grants: [],
};
const inventory = {
  contract: 'one-registration-v1', observedAt: at(-1000), appSlug: request.appSlug,
  requestedClientId: request.clientId, clients: [], grants: [], resources: [], frameOrigins: [],
  installations: request.installations.map(item => ({ ...item, appSlug: request.appSlug, active: true })),
};
const existingClient = {
  clientId: request.clientId, appSlug: request.appSlug, active: true,
  audiences: ['existing-resource'], scopes: ['resource:read'],
  keys: [{ ...request.assertion, active: true }], profile: { ...request.profile, state: 'approved' },
};

test('rejects private JWK fields, wildcard scopes and callback aliasing', () => {
  for (const modify of [
    item => { item.assertion.publicJwk.d = 'private'; },
    item => { item.client = { audiences: ['resource'], scopes: ['resource:*'] }; },
    item => { item.profile.callback += '?'; },
  ]) {
    const item = structuredClone(request);
    modify(item);
    assert.throws(() => validate(item));
  }
});

test('plans new registration in order and skips existing records with unrelated permissions', () => {
  assert.deepEqual(reconcile(request, inventory, now).operations.map(item => item.kind),
    ['client', 'key', 'first-party-client']);
  const reuse = { ...request, mode: 'reuse', client: null };
  assert.deepEqual(reconcile(reuse, { ...inventory, clients: [existingClient],
    frameOrigins: ['https://app.example.test'] }, now), { findings: [], operations: [] });
  const withoutProfile = { ...existingClient, profile: null };
  assert.deepEqual(reconcile(reuse, { ...inventory, clients: [withoutProfile] }, now)
    .operations.map(item => item.kind), ['first-party-client']);
});

test('reports conflicts, expired evidence, wrong proof and missing installations', () => {
  const result = reconcile(request, { ...inventory, clients: [{ ...existingClient,
    profile: { ...existingClient.profile, proofThumbprints: ['E'.repeat(43)] } }], installations: [] }, now);
  assert.ok(result.findings.some(item => item.code === 'INVALID_PROOF_KEY_BINDING' && !item.repairable));
  assert.ok(result.findings.some(item => item.code === 'MISSING_INSTALLATION' && !item.repairable));
  assert.equal(reconcile(request, inventory, now + 600_000).findings[0].code, 'UNSUPPORTED_CENTRAL_CONTRACT');
  const other = { ...existingClient, clientId: 'other-client' };
  assert.ok(reconcile(request, { ...inventory, clients: [other] }, now).findings.some(item =>
    item.code === 'CLIENT_CONFLICT' && !item.repairable));
});

test('Git handoff pins reviewed bytes, verifies the plan and records per-operation receipts', () => {
  const root = mkdtempSync(join(tmpdir(), 'registration-test-'));
  try {
    const repo = join(root, 'handoff');
    const one = join(root, 'one');
    mkdirSync(repo);
    mkdirSync(join(one, 'node_modules/.bin'), { recursive: true });
    writeFileSync(join(one, 'node_modules/.bin/ts-node'), `#!/usr/bin/env node
const [,,flag,script,file,change,mode] = process.argv;
const applied = mode === '--apply';
if ((process.env.ONE_DELEGATION_ALLOW_OPERATOR_CHANGES === 'true') !== applied) process.exit(2);
const {kind} = JSON.parse(require('fs').readFileSync(file));
console.log(JSON.stringify({kind, applied, schemaValid: !applied}));
`, { mode: 0o700 });
    const git = (...args) => execFileSync('git', ['-C', repo, ...args], { encoding: 'utf8' }).trim();
    const run = (...args) => spawnSync(process.execPath, [tool, ...args], { encoding: 'utf8' });
    const draft = join(root, 'draft.json');
    const snapshot = join(root, 'inventory.json');
    const receipt = join(root, 'receipt.jsonl');
    writeFileSync(draft, JSON.stringify(request));
    writeFileSync(snapshot, JSON.stringify(inventory));
    git('init', '-q');
    const dir = 'registrations/development/example/change-123';
    const packaged = run('package', draft, join(repo, dir));
    assert.equal(packaged.status, 0, packaged.stderr);
    const digest = packaged.stdout.trim();
    git('add', dir);
    git('-c', 'user.email=example@example.test', '-c', 'user.name=Example', 'commit', '-qm', 'Request registration');
    const prefix = [repo, git('rev-parse', 'HEAD'), dir + '/request.json'];
    const review = run('review', ...prefix, digest, snapshot, one, 'change-123');
    assert.equal(review.status, 0, review.stderr);
    const approvedPlan = JSON.parse(review.stdout).planSha256;
    const badDigest = run('review', ...prefix, '0'.repeat(64), snapshot, one, 'change-123');
    assert.match(badDigest.stderr, /differs from the reviewed digest/);
    const badPlan = run('apply', ...prefix, digest, snapshot, one, 'change-123', '0'.repeat(64), receipt);
    assert.match(badPlan.stderr, /fresh plan differs/);
    const applied = run('apply', ...prefix, digest, snapshot, one, 'change-123', approvedPlan, receipt);
    assert.equal(applied.status, 0, applied.stderr);
    const entries = readFileSync(receipt, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(entries.slice(1, -1).map(item => item.kind), ['client', 'key', 'first-party-client']);
    assert.equal(entries.at(-1).complete, true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('adds only missing grants with verified targets and preserves broader active grants', () => {
  const grant = {
    organizationId: 'example-org', audience: 'existing-resource', targetInstallationId: 'target-installation',
    scopes: ['resource:read'], validUntil: at(30000),
  };
  const reuse = { ...request, mode: 'reuse', client: null, grants: [grant] };
  const snapshot = {
    ...inventory, clients: [existingClient], frameOrigins: ['https://app.example.test'],
    installations: [...inventory.installations, { appSlug: 'target', organizationId: 'example-org',
      installationId: 'target-installation', active: true }],
    resources: [{ audience: 'existing-resource', appSlug: 'target', scopes: ['resource:read'], active: true }],
  };
  assert.equal(reconcile(reuse, snapshot, now).operations[0].kind, 'grant');
  const existing = { ...grant, clientId: request.clientId, sourceInstallationId: 'example-installation',
    scopes: ['resource:read', 'resource:write'], active: true, validUntil: at(60000) };
  assert.deepEqual(reconcile(reuse, { ...snapshot, grants: [existing] }, now), { findings: [], operations: [] });
  const conflict = reconcile(reuse, { ...snapshot, grants: [{ ...existing, active: false }] }, now);
  assert.equal(conflict.findings[0].code, 'MISSING_DELEGATION_GRANT');
  assert.deepEqual(conflict.operations, []);
});
