// Adapted from One Identity delegation/client.ts. See docs/architecture.md.
import { createPrivateKey, createPublicKey, KeyObject, randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { digest } from './profile';
import { httpsUrl } from './transport';

export interface DelegationKeys {
  clientId: string;
  credentialKid: string;
  clientPrivateKey: string | KeyObject;
  proofPrivateKey: string | KeyObject;
}

export class DelegationSigner {
  readonly clientId: string;
  readonly thumbprint: string;
  private readonly credentialKid: string;
  private readonly clientKey: KeyObject;
  private readonly proofKey: KeyObject;
  private readonly proofJwk: Record<string, unknown>;

  constructor(keys: DelegationKeys) {
    this.clientId = keys.clientId;
    this.credentialKid = keys.credentialKid;
    const clientKey = typeof keys.clientPrivateKey === 'string' ? createPrivateKey(keys.clientPrivateKey) : keys.clientPrivateKey;
    const proofKey = typeof keys.proofPrivateKey === 'string' ? createPrivateKey(keys.proofPrivateKey) : keys.proofPrivateKey;
    if (!this.clientId || !this.credentialKid || clientKey.type !== 'private' || clientKey.asymmetricKeyType !== 'rsa' ||
        (clientKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048) {
      throw new Error('A registered client ID, KID and RSA private key of at least 2048 bits are required');
    }
    if (proofKey.type !== 'private' || proofKey.asymmetricKeyType !== 'ec' ||
        proofKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw new Error('A P-256 private proof key is required');
    this.clientKey = clientKey;
    this.proofKey = proofKey;
    const { x, y } = createPublicKey(proofKey).export({ format: 'jwk' });
    this.proofJwk = { crv: 'P-256', kty: 'EC', x, y };
    this.thumbprint = digest(JSON.stringify(this.proofJwk));
  }

  assertion(endpoint: string): string {
    if (httpsUrl(endpoint).search) throw new Error('An assertion endpoint cannot contain a query');
    const now = Math.floor(Date.now() / 1000);
    return jwt.sign({
      iss: this.clientId, sub: this.clientId, aud: endpoint, iat: now, exp: now + 30,
      jti: randomUUID(), cnf: { jkt: this.thumbprint },
    }, this.clientKey, { algorithm: 'RS256', keyid: this.credentialKid });
  }

  proof(method: string, url: string, token?: string): string {
    const target = httpsUrl(url);
    target.search = '';
    return jwt.sign({
      htm: method.toUpperCase(), htu: target.href, iat: Math.floor(Date.now() / 1000),
      jti: randomUUID(), ...(token ? { ath: digest(token) } : {}),
    }, this.proofKey, { algorithm: 'ES256', header: { alg: 'ES256', typ: 'dpop+jwt', jwk: this.proofJwk } as jwt.JwtHeader });
  }
}
