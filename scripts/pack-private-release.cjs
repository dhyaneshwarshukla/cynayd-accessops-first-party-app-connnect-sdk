const { createHash } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const manifest = require(path.join(root, 'package.json'));
const version = process.argv[2];
const output = path.resolve(process.argv[3] ?? 'release');

if (manifest.name !== '@cynayd/accessops-first-party-app-connnect-sdk' || !/^\d+\.\d+\.\d+$/.test(version) ||
    manifest.version !== version || manifest.private !== true) {
  throw new Error('Release requires the exact private SDK manifest and a matching stable package version');
}

const staging = fs.mkdtempSync(path.join(os.tmpdir(), 'cynayd-sdk-release-'));
try {
  execFileSync('npm', ['run', 'build'], { cwd: root, stdio: 'inherit' });
  for (const entry of manifest.files) fs.cpSync(path.join(root, entry), path.join(staging, entry), { recursive: true });
  const releaseManifest = { ...manifest, publishConfig: { registry: 'https://registry.npmjs.org/', access: 'restricted' } };
  delete releaseManifest.private;
  delete releaseManifest.scripts;
  fs.writeFileSync(path.join(staging, 'package.json'), JSON.stringify(releaseManifest, null, 2) + '\n');
  fs.mkdirSync(output, { recursive: true });
  const json = execFileSync('npm', ['pack', '--ignore-scripts', '--pack-destination', output, '--json'],
    { cwd: staging, encoding: 'utf8' });
  const [result] = JSON.parse(json);
  const checksum = createHash('sha256').update(fs.readFileSync(path.join(output, result.filename))).digest('hex');
  fs.writeFileSync(path.join(output, 'SHA256SUMS'), `${checksum}  ${result.filename}\n`);
  fs.writeFileSync(path.join(output, 'npm-pack.json'), json);
  console.log(`Prepared restricted package ${result.name}@${result.version} (SHA-256 ${checksum})`);
} finally {
  fs.rmSync(staging, { recursive: true, force: true });
}
