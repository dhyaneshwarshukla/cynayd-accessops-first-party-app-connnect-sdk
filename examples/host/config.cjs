const { readFileSync } = require('node:fs');
const { Pool } = require('pg');
const {
  DelegationClient, DelegationSigner, FirstPartyHost, OneApplicationSession, PostgresHostSessionStore,
  createHostHttpHandler, createNodeHostHandler, oneSigningKeys,
} = require('@cynayd/accessops-first-party-app-connnect-sdk');

const required = name => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error('Missing ' + name);
  return value;
};
const appOrigin = required('APP_ORIGIN');
const basePath = '/api/auth/one';
const tokenEndpoint = required('ONE_TOKEN_ENDPOINT');
const endpoint = name => new URL(name, tokenEndpoint).href;
const issuer = required('ONE_ISSUER');
const jwks = required('ONE_JWKS_URL');
if (new URL(jwks).origin !== new URL(issuer).origin) throw new Error('Untrusted One signing keys');

const delegation = new DelegationClient({
  tokenEndpoint,
  introspectionEndpoint: endpoint('introspect'),
  launchEvaluationEndpoint: endpoint('launch-evaluate'),
  sessionStatusEndpoint: endpoint('session-status'),
  activityEndpoint: endpoint('activity'),
  boundLaunchInitiationEndpoint: endpoint('bound-launch-initiate'),
  boundLaunchRedemptionEndpoint: endpoint('bound-launch-redeem'),
  sourceRenewalEndpoint: endpoint('source-renewal'),
  signer: new DelegationSigner({
    clientId: required('ONE_CLIENT_ID'),
    credentialKid: required('ONE_ASSERTION_KID'),
    clientPrivateKey: readFileSync(required('ONE_ASSERTION_KEY_FILE'), 'utf8'),
    proofPrivateKey: readFileSync(required('ONE_PROOF_KEY_FILE'), 'utf8'),
  }),
});
const session = new OneApplicationSession({
  issuer, identityOrigin: new URL(issuer).origin, appSlug: required('ONE_APP_SLUG'),
  signingKey: oneSigningKeys(jwks), delegation,
});
const pool = new Pool({ connectionString: required('HOST_DATABASE_URL') });
const encodedKey = required('HOST_SEAL_KEY');
const key = Buffer.from(encodedKey, 'base64url');
if (key.toString('base64url') !== encodedKey) throw new Error('Use a canonical base64url host seal key');
const store = new PostgresHostSessionStore({
  query: (sql, values) => pool.query(sql, values),
  async transaction(work) {
    const connection = await pool.connect();
    try {
      await connection.query('BEGIN');
      const result = await work(connection);
      await connection.query('COMMIT');
      connection.release();
      return result;
    } catch (error) {
      try { await connection.query('ROLLBACK'); connection.release(); }
      catch { connection.release(true); }
      throw error;
    }
  },
}, key, 28800);

const host = new FirstPartyHost({
  appOrigin, callback: required('ONE_EXACT_CALLBACK'), cookieLabel: required('ONE_COOKIE_LABEL'),
  onePortalOrigin: required('ONE_PORTAL_ORIGIN'), delegation, session, store,
  renewal: process.env.ONE_APPROVED_RENEWAL === 'true' ? store : undefined,
  allowsReturn: url => url.pathname === '/' && !url.search,
});

const handle = createHostHttpHandler(host, basePath);
module.exports = { host, delegation, basePath, handle, nodeHandler: createNodeHostHandler(handle, appOrigin) };
