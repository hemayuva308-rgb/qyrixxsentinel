-- QYRIX SENTINEL - shared rate-limit counters (v1.4). PostgreSQL is already a required, health-checked dependency of a
-- durable deployment, so it is used as the shared counter store instead of adding Redis. Buckets are SHA-256 hashes of
-- the logical key (no raw IP addresses, e-mail addresses or key ids are stored). Not tenant-scoped (by design: login
-- and pre-authentication limits exist before a tenant is known).
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket       char(64)    NOT NULL,
  window_start bigint      NOT NULL,            -- epoch seconds, aligned to the window
  count        integer     NOT NULL,
  expires_at   timestamptz NOT NULL,
  PRIMARY KEY (bucket, window_start)
);
CREATE INDEX IF NOT EXISTS rate_limits_expiry ON rate_limits (expires_at);
GRANT SELECT, INSERT, DELETE ON rate_limits TO qyrix_app;
GRANT UPDATE (count) ON rate_limits TO qyrix_app;
