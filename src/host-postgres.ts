import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import type { HostSessionStore, PendingHostLaunch } from './host';
import type { BoundDelegationBinding, SourceRenewalCoordinator } from './delegation/session';

export interface HostPostgresConnection {
  query<Row>(sql: string, values: unknown[]): Promise<{ rows: Row[]; rowCount: number | null }>;
}

export interface HostPostgres extends HostPostgresConnection {
  /** Use a single pinned connection. Roll back on any thrown error. */
  transaction<T>(work: (connection: HostPostgresConnection) => Promise<T>): Promise<T>;
}

type Payload = { pending: PendingHostLaunch } | { claimed: true } | { binding: BoundDelegationBinding };
type Row = { revision: string; sealed_payload: string };
class ActivationLost extends Error {}

export class PostgresHostSessionStore implements HostSessionStore, SourceRenewalCoordinator {
  private readonly sealKey: Buffer;

  constructor(private readonly db: HostPostgres, key: Uint8Array, private readonly hostTtlSeconds: number) {
    if (key.length !== 32 || !Number.isSafeInteger(hostTtlSeconds) || hostTtlSeconds <= 0 || hostTtlSeconds > 86_400) {
      throw new Error('Invalid host seal key or host retention');
    }
    this.sealKey = Buffer.from(key);
  }

  private hash(id: string) {
    return createHash('sha256').update(id).digest('hex');
  }

  private aad(hash: string, revision: string) {
    return Buffer.from('cynayd-sdk-host-v1:' + hash + ':' + revision);
  }

  private seal(hash: string, revision: string, value: Payload) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.sealKey, iv);
    cipher.setAAD(this.aad(hash, revision));
    const bytes = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), bytes]).toString('base64url');
  }

  private async read(id: string) {
    const hash = this.hash(id);
    const { rows: [row] } = await this.db.query<Row>(
      'SELECT revision, sealed_payload FROM cynayd_host_sessions WHERE id_hash=$1 AND expires_at>clock_timestamp()', [hash],
    );
    if (!row) return undefined;
    const bytes = Buffer.from(row.sealed_payload, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', this.sealKey, bytes.subarray(0, 12));
    decipher.setAAD(this.aad(hash, row.revision));
    decipher.setAuthTag(bytes.subarray(12, 28));
    const payload: Payload = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]).toString());
    return { revision: row.revision, payload };
  }

  private async update(connection: HostPostgresConnection, id: string, expected: string, payload: Payload, ttl?: number) {
    const hash = this.hash(id);
    const revision = randomUUID();
    const result = await connection.query(
      `UPDATE cynayd_host_sessions SET revision=$3, sealed_payload=$4,
        expires_at=COALESCE(clock_timestamp() + make_interval(secs => $5::double precision), expires_at)
        WHERE id_hash=$1 AND revision=$2 AND expires_at>clock_timestamp()`,
      [hash, expected, revision, this.seal(hash, revision, payload), ttl ?? null],
    );
    return result.rowCount === 1 ? revision : undefined;
  }

  async createLaunch(id: string, pending: PendingHostLaunch) {
    const hash = this.hash(id);
    const revision = randomUUID();
    await this.db.query(
      'INSERT INTO cynayd_host_sessions (id_hash, revision, sealed_payload, expires_at) VALUES ($1,$2,$3,$4)',
      [hash, revision, this.seal(hash, revision, { pending }), new Date(pending.expiresAt)],
    );
  }

  async consumeLaunch(id: string, match: Pick<PendingHostLaunch, 'request' | 'state'> & { priorId?: string }) {
    const row = await this.read(id);
    if (!row || !('pending' in row.payload)) return undefined;
    const { pending } = row.payload;
    if (pending.state !== match.state || pending.request !== match.request || pending.priorCookieId !== match.priorId ||
        pending.expiresAt <= Date.now()) return undefined;
    const revision = await this.update(this.db, id, row.revision, { claimed: true });
    return revision ? { revision, pending } : undefined;
  }

  async activate(id: string, revision: string, binding: BoundDelegationBinding, prior?: { id: string; revision: string }) {
    if (binding.sessionId !== id || prior?.id === id) return false;
    const current = await this.read(id);
    if (current?.revision !== revision || !('claimed' in current.payload)) return false;
    try {
      return await this.db.transaction(async connection => {
        if (prior) {
          const result = await connection.query(
            'DELETE FROM cynayd_host_sessions WHERE id_hash=$1 AND revision=$2 AND expires_at>clock_timestamp()',
            [this.hash(prior.id), prior.revision],
          );
          if (result.rowCount !== 1) return false;
        }
        if (!await this.update(connection, id, revision, { binding }, this.hostTtlSeconds)) throw new ActivationLost();
        return true;
      });
    } catch (error) {
      if (error instanceof ActivationLost) return false;
      throw error;
    }
  }

  async load(id: string) {
    const row = await this.read(id);
    if (!row || !('binding' in row.payload)) return undefined;
    return { revision: row.revision, binding: row.payload.binding };
  }

  async replaceIfCurrent(id: string, revision: string, binding: BoundDelegationBinding) {
    const record = await this.load(id);
    if (binding.sessionId !== id || record?.revision !== revision) return false;
    return Boolean(await this.update(this.db, id, revision, { binding }));
  }

  async remove(ids: readonly string[]) {
    await this.db.query('DELETE FROM cynayd_host_sessions WHERE id_hash=ANY($1::text[])', [ids.map(id => this.hash(id))]);
  }

  async runExclusive<T>(id: string, work: () => Promise<T>) {
    const hash = this.hash(id);
    const owner = randomUUID();
    const claimed = await this.db.query(
      `UPDATE cynayd_host_sessions SET lease_owner=$2, lease_until=clock_timestamp()+interval '35 seconds'
        WHERE id_hash=$1 AND expires_at>clock_timestamp() AND (lease_until IS NULL OR lease_until<=clock_timestamp())`,
      [hash, owner],
    );
    if (claimed.rowCount !== 1) return undefined;
    try {
      return await work();
    } finally {
      await this.db.query('UPDATE cynayd_host_sessions SET lease_owner=NULL, lease_until=NULL WHERE id_hash=$1 AND lease_owner=$2',
        [hash, owner]).catch(() => undefined);
    }
  }
}

/** The resource verifier supplies the validated proof expiry in Unix seconds. */
export class PostgresProofReplayStore {
  constructor(private readonly db: HostPostgresConnection) {}

  async consume(thumbprint: string, proofId: string, expiresAt: number) {
    const result = await this.db.query(
      `INSERT INTO cynayd_dpop_replays (thumbprint, proof_id, expires_at)
        VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING`,
      [thumbprint, proofId, expiresAt],
    );
    return result.rowCount === 1;
  }
}
