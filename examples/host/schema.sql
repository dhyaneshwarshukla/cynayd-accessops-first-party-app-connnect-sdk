CREATE TABLE cynayd_host_sessions (
  id_hash text PRIMARY KEY,
  revision uuid NOT NULL,
  sealed_payload text NOT NULL,
  expires_at timestamptz NOT NULL,
  lease_owner uuid,
  lease_until timestamptz
);
CREATE INDEX cynayd_host_sessions_expiry ON cynayd_host_sessions (expires_at);

CREATE TABLE cynayd_dpop_replays (
  thumbprint text NOT NULL,
  proof_id text NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (thumbprint, proof_id)
);
CREATE INDEX cynayd_dpop_replays_expiry ON cynayd_dpop_replays (expires_at);
