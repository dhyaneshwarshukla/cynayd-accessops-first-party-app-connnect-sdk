"""Async psycopg host store. Use an application-owned pool and schema."""

from dataclasses import asdict
from hashlib import sha256
import json
from secrets import token_bytes
from uuid import uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .client import Capability
from .session import Credentials
from .subject import SubjectIdentity


class _ActivationLost(Exception):
    pass


class PostgresHostStore:
    def __init__(self, pool, key: bytes, ttl_seconds: int = 28800):
        if len(key) != 32 or type(ttl_seconds) is not int or not 0 < ttl_seconds <= 86400:
            raise ValueError("Invalid host seal key or retention")
        self.pool, self.aead, self.ttl = pool, AESGCM(key), ttl_seconds

    @staticmethod
    def _hash(token):
        return sha256(token.encode()).hexdigest()

    @staticmethod
    def _aad(key, revision):
        return f"cynayd-python-host-v1:{key}:{revision}".encode()

    def _seal(self, key, revision, value):
        nonce = token_bytes(12)
        encrypted = self.aead.encrypt(nonce, json.dumps(value).encode(), self._aad(key, revision))
        return (nonce + encrypted).hex()

    def _open(self, key, revision, sealed):
        raw = bytes.fromhex(sealed.decode("ascii") if isinstance(sealed, bytes) else sealed)
        return json.loads(self.aead.decrypt(raw[:12], raw[12:], self._aad(key, revision)))

    async def _read(self, conn, key, *, lock=False):
        result = await conn.execute(
            "SELECT revision, sealed_payload, lease_until IS NOT NULL,"
            " coalesce(lease_until > clock_timestamp(), false) FROM cynayd_host_sessions"
            " WHERE id_hash=%s AND expires_at>clock_timestamp()" + (" FOR UPDATE" if lock else ""), (key,),
        )
        row = await result.fetchone()
        if row:
            revision, sealed, claimed, in_progress = row
            return revision, self._open(key, revision, sealed), claimed, in_progress
        return None

    async def _write(self, conn, key, expected, payload, *, ttl=None, claim_seconds=None, require_claim=False):
        revision = uuid4()
        result = await conn.execute(
            "UPDATE cynayd_host_sessions SET revision=%s, sealed_payload=%s,"
            " expires_at=coalesce(clock_timestamp()+make_interval(secs=>%s), expires_at),"
            " lease_until=clock_timestamp()+make_interval(secs=>%s)"
            " WHERE id_hash=%s AND revision=%s AND expires_at>clock_timestamp()"
            + (" AND lease_until IS NOT NULL" if require_claim else ""),
            (revision, self._seal(key, revision, payload), ttl, claim_seconds, key, expected),
        )
        return revision if result.rowcount == 1 else None

    async def create_launch(self, token, pending, seconds):
        key, revision = self._hash(token), uuid4()
        async with self.pool.connection() as conn:
            await conn.execute(
                "INSERT INTO cynayd_host_sessions (id_hash,revision,sealed_payload,expires_at)"
                " VALUES (%s,%s,%s,clock_timestamp()+make_interval(secs=>%s))",
                (key, revision, self._seal(key, revision, {"pending": pending}), seconds),
            )

    async def consume_launch(self, token, *, request, state, prior_id):
        key = self._hash(token)
        async with self.pool.connection() as conn:
            row = await self._read(conn, key, lock=True)
            pending = row and row[1].get("pending")
            if not pending or (pending["request"], pending["state"], pending["prior_id"]) != (request, state, prior_id):
                return None
            revision = await self._write(conn, key, row[0], {"claimed": True})
            return (revision, pending) if revision else None

    async def activate(self, token, revision, credentials, prior):
        try:
            async with self.pool.connection() as conn:
                async with conn.transaction():
                    key = self._hash(token)
                    current = await self._read(conn, key)
                    if not current or current[0] != revision or current[1].get("claimed") is not True:
                        return False
                    if prior:
                        deleted = await conn.execute(
                            "DELETE FROM cynayd_host_sessions WHERE id_hash=%s AND revision=%s"
                            " AND expires_at>clock_timestamp()", (self._hash(prior[0]), prior[1]),
                        )
                        if deleted.rowcount != 1:
                            return False
                    if not await self._write(conn, key, revision, {"credentials": asdict(credentials)}, ttl=self.ttl):
                        raise _ActivationLost()
            return True
        except _ActivationLost:
            return False

    async def read(self, token):
        async with self.pool.connection() as conn:
            row = await self._read(conn, self._hash(token))
        payload = row and row[1].get("credentials")
        if not payload:
            return None
        capability = Capability(**payload["capability"]) if payload["capability"] else None
        return str(row[0]), Credentials(SubjectIdentity(**payload["identity"]), payload["subject"], capability)

    async def claim(self, token, revision, generation):
        key = self._hash(token)
        async with self.pool.connection() as conn:
            row = await self._read(conn, key, lock=True)
            if not row or str(row[0]) != revision:
                return "changed", None
            if row[2]:
                return ("in_progress" if row[3] else "recovery_required"), None
            capability = row[1].get("credentials", {}).get("capability")
            if not capability or capability["generation"] != generation:
                return "changed", None
            claimed = await self._write(conn, key, row[0], row[1], claim_seconds=35)
            return ("claimed", str(claimed)) if claimed else ("changed", None)

    async def replace(self, token, revision, credentials):
        async with self.pool.connection() as conn:
            return bool(await self._write(conn, self._hash(token), revision, {"credentials": asdict(credentials)},
                                          require_claim=True))

    async def remove(self, tokens):
        async with self.pool.connection() as conn:
            await conn.execute("DELETE FROM cynayd_host_sessions WHERE id_hash=ANY(%s)",
                               ([self._hash(token) for token in tokens],))


class PostgresProofReplayStore:
    def __init__(self, pool):
        self.pool = pool

    async def consume(self, thumbprint, proof_id, expires_at):
        async with self.pool.connection() as conn:
            result = await conn.execute(
                "INSERT INTO cynayd_dpop_replays (thumbprint,proof_id,expires_at)"
                " VALUES (%s,%s,to_timestamp(%s)) ON CONFLICT DO NOTHING",
                (thumbprint, proof_id, expires_at),
            )
            return result.rowcount == 1
