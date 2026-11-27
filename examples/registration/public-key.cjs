const { createHash, createPublicKey } = require('node:crypto');
const { readFileSync } = require('node:fs');

function readPublic(path) {
  const pem = readFileSync(path, 'utf8').trim();
  if (!/^-----BEGIN PUBLIC KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END PUBLIC KEY-----$/.test(pem)) {
    throw new Error('Supply an exported SPKI public PEM');
  }
  return createPublicKey(pem);
}

function main() {
  const [mode, publicPath, clientId, kid, notBefore, notAfter, ...extra] = process.argv.slice(2);
  if (extra.length) throw new Error('Unexpected arguments');
  if (mode === 'proof' && publicPath && !clientId) {
    const { kty, crv, x, y } = readPublic(publicPath).export({ format: 'jwk' });
    if (kty !== 'EC' || crv !== 'P-256') throw new Error('Expected a P-256 proof key');
    const thumbprint = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest('base64url');
    console.log(thumbprint);
    return;
  }
  if (mode === 'key' && publicPath && clientId && kid && notBefore && notAfter) {
    const key = readPublic(publicPath);
    const { kty, n, e } = key.export({ format: 'jwk' });
    if (kty !== 'RSA' || key.asymmetricKeyDetails.modulusLength < 2048) throw new Error('Expected RSA 2048+');
    console.log(JSON.stringify({ kind: 'key', clientId, kid, publicJwk: { kty, n, e }, notBefore, notAfter }, null, 2));
    return;
  }
  throw new Error('Usage: public-key.cjs proof PUBLIC_PEM | key PUBLIC_PEM CLIENT_ID KID NOT_BEFORE NOT_AFTER');
}
try { main(); }
catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
