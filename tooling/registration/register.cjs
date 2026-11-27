#!/usr/bin/env node
const { execFileSync } = require('node:child_process');
const { mkdtempSync, readFileSync, mkdirSync, writeFileSync, rmSync, appendFileSync } = require('node:fs');
const { resolve, join } = require('node:path');
const { tmpdir } = require('node:os');
const { validate, encode, digest } = require('./request.cjs');
const { reconcile } = require('./reconcile.cjs');

const read = path => JSON.parse(readFileSync(path, 'utf8'));
const write = (path, content) => writeFileSync(path, content, { flag: 'wx', mode: 0o600 });
const hash = value => /^[a-f0-9]{64}$/.test(value || '');
const need = (condition, message) => { if (!condition) throw new Error(message); };
const git = (repo, ...args) => execFileSync('git', ['--no-replace-objects', '-C', repo, ...args], { maxBuffer: 256 * 1024 });

function retrieve(repo, commit, path, expected) {
  need(/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(commit), 'Pin the full Git commit ID.');
  need(/^registrations\/(?:[a-z0-9][a-z0-9_-]*\/){3}request\.json$/.test(path), 'Use registrations/<environment>/<app>/<request-id>/request.json.');
  need(hash(expected), 'Supply the reviewed SHA-256 digest.');
  need(git(repo, 'cat-file', '-t', commit).toString().trim() === 'commit', 'Expected a Git commit.');
  const bytes = git(repo, 'show', commit + ':' + path);
  need(digest(bytes) === expected, 'Request SHA-256 differs from the reviewed digest.');
  const request = validate(JSON.parse(bytes));
  need(encode(request) === bytes.toString('utf8'), 'Request bytes are not in canonical form. Repackage and review.');
  return request;
}

function invokeOne(root, changeId, operations, mode, record) {
  const temp = mkdtempSync(join(tmpdir(), 'cynayd-registration-'));
  const env = { ...process.env };
  delete env.ONE_DELEGATION_ALLOW_OPERATOR_CHANGES;
  if (mode === '--apply') env.ONE_DELEGATION_ALLOW_OPERATOR_CHANGES = 'true';
  try {
    operations.forEach((operation, index) => {
      const entry = join(temp, index + '.json');
      write(entry, encode(operation));
      const raw = execFileSync(resolve(root, 'node_modules/.bin/ts-node'),
        ['--files', 'scripts/delegation-register.ts', entry, changeId, mode],
        { cwd: root, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
      const receipt = JSON.parse(raw.trim());
      need(receipt.kind === operation.kind && (mode === '--check'
        ? receipt.schemaValid === true && receipt.applied === false : receipt.applied === true),
      'Unexpected One CLI receipt. Refresh inventory before retrying.');
      record({ index, kind: operation.kind, operationSha256: digest(encode(operation)),
        ...(mode === '--check' ? { schemaValid: true } : {}), applied: receipt.applied });
    });
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

function main([command, ...args]) {
  if (command === 'generate' && args.length === 7) {
    const [draft, rsa, proof, kid, notBefore, notAfter, output] = args;
    const metadata = read(draft);
    need(!Object.hasOwn(metadata, 'assertion') && !Object.hasOwn(metadata.profile, 'proofThumbprints'),
      'The generation template must omit assertion and proofThumbprints.');
    const publicKeyTool = resolve(__dirname, '../../examples/registration/public-key.cjs');
    const publicKey = (...parameters) => execFileSync(process.execPath, [publicKeyTool, ...parameters],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
    const { kind, clientId, ...assertion } = JSON.parse(publicKey('key', rsa, metadata.clientId, kid, notBefore, notAfter));
    const proofThumbprints = [publicKey('proof', proof)];
    write(output, encode(validate({ ...metadata, assertion, profile: { ...metadata.profile, proofThumbprints } })));
    return;
  }
  if (command === 'package' && args.length === 2) {
    const [draft, dir] = args;
    const bytes = encode(validate(read(draft)));
    mkdirSync(dir, { recursive: true });
    write(join(dir, 'request.json'), bytes);
    write(join(dir, 'request.sha256'), digest(bytes) + '  request.json\n');
    console.log(digest(bytes));
    return;
  }
  if (command === 'validate' && args.length === 1) {
    validate(read(args[0]));
    console.log('Valid public registration request');
    return;
  }
  if (['preflight', 'review', 'apply'].includes(command) && args.length ===
      ({ preflight: 5, review: 7, apply: 9 })[command]) {
    const [repo, commit, path, expected, inventory, oneRoot, changeId, approvedPlan, receiptFile] = args;
    const request = retrieve(repo, commit, path, expected);
    const result = reconcile(request, read(inventory));
    if (command === 'preflight') {
      console.log(encode({ ready: result.findings.length === 0, findings: result.findings }));
      process.exitCode = result.findings.length ? 1 : 0;
      return;
    }
    const blockers = result.findings.filter(item => !item.repairable && !item.advisory);
    need(!blockers.length, encode({ blockers }));
    need(/^[A-Za-z0-9_.:-]{8,160}$/.test(changeId), 'Supply the existing One change reference.');
    const planSha256 = digest(encode({ commit, path, requestSha256: expected, changeId, operations: result.operations }));
    const checks = [];
    if (command === 'apply') need(hash(approvedPlan) && planSha256 === approvedPlan,
      'The fresh plan differs from the approved plan. Review the remaining operations before retrying.');
    invokeOne(oneRoot, changeId, result.operations, '--check', receipt => checks.push(receipt));
    if (command === 'review') {
      console.log(encode({ planSha256, ...result, checks }));
      return;
    }
    write(receiptFile, JSON.stringify({ commit, path, requestSha256: expected, planSha256, changeId,
      appSlug: request.appSlug, startedAt: new Date().toISOString() }) + '\n');
    const record = entry => appendFileSync(receiptFile, JSON.stringify(entry) + '\n');
    invokeOne(oneRoot, changeId, result.operations, '--apply', record);
    record({ complete: true, finishedAt: new Date().toISOString() });
    return;
  }
  throw new Error('See docs/registration-workflow.md for generate, package, validate, preflight, review and apply commands.');
}

try { main(process.argv.slice(2)); }
catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
