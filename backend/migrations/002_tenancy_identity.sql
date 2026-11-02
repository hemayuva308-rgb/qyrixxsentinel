-- QYRIX SENTINEL - tenancy, identity, sessions, row-level security, least-privilege application role.
-- Applied once, in a transaction, by the migration runner (connection owner).

CREATE TABLE IF NOT EXISTS tenants (
  id               text        PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{2,39}$'),
  name             text        NOT NULL,
  approved_domains text[],                       -- NULL => no outbound HTTP destinations (deny all) for non-default tenants
  created_at       timestamptz NOT NULL DEFAULT now(),
  disabled_at      timestamptz
);
INSERT INTO tenants (id, name) VALUES ('default', 'Default tenant') ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS api_keys (
  id           text        PRIMARY KEY,
  tenant_id    text        NOT NULL REFERENCES tenants(id),
  role         text        NOT NULL CHECK (role IN ('owner','admin','security_reviewer','approver','auditor','integrator','agent')),
  name         text        NOT NULL,
  key_hash     char(64)    NOT NULL UNIQUE,      -- SHA-256 of the key; the key itself is never stored
  created_by   text        NOT NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz,
  revoked_at   timestamptz,
  last_used_at timestamptz
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash      char(64)    PRIMARY KEY,          -- SHA-256 of the opaque session token
  tenant_id    text        NOT NULL REFERENCES tenants(id),
  role         text        NOT NULL,
  cred_id      text        NOT NULL,             -- api key id or env credential name
  cred_fp      char(16),                         -- fingerprint of an env credential (rotation invalidates sessions)
  created_at   timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz
);

-- Tenant column on every data table (existing rows belong to the default tenant).
ALTER TABLE provenance_steps ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id);
ALTER TABLE approvals        ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id);
ALTER TABLE gate_evaluations ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id);
ALTER TABLE grants           ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id);
ALTER TABLE proof_records    ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id);
ALTER TABLE proof_anchors    ADD COLUMN IF NOT EXISTS tenant_id text NOT NULL DEFAULT 'default' REFERENCES tenants(id);

-- One hash chain per tenant.
ALTER TABLE proof_records DROP CONSTRAINT IF EXISTS proof_records_pkey;
ALTER TABLE proof_records ADD PRIMARY KEY (tenant_id, n);
ALTER TABLE proof_records DROP CONSTRAINT IF EXISTS proof_records_hash_key;
ALTER TABLE proof_records ADD CONSTRAINT proof_records_tenant_hash_key UNIQUE (tenant_id, hash);

CREATE INDEX IF NOT EXISTS provenance_steps_tenant_seq ON provenance_steps (tenant_id, seq);
CREATE INDEX IF NOT EXISTS approvals_tenant ON approvals (tenant_id);
CREATE INDEX IF NOT EXISTS gate_evaluations_tenant ON gate_evaluations (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS grants_tenant ON grants (tenant_id);
CREATE INDEX IF NOT EXISTS sessions_cred ON sessions (cred_id);

-- Append-only evidence: only the table owner (never the application role) may delete, and only during a guarded reset.
CREATE OR REPLACE FUNCTION qyrix_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_user <> 'qyrix_app' AND current_setting('qyrix.allow_reset', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'append-only table %', TG_TABLE_NAME;
END $$;

-- Least-privilege application role used for every tenant-scoped transaction (SET LOCAL ROLE qyrix_app).
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_app') THEN
    CREATE ROLE qyrix_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
END $$;
DO $$ BEGIN EXECUTE format('GRANT qyrix_app TO %I', current_user); END $$;
GRANT USAGE ON SCHEMA public TO qyrix_app;
GRANT SELECT, INSERT          ON provenance_steps, proof_records, proof_anchors TO qyrix_app;
GRANT SELECT, INSERT, UPDATE  ON approvals, gate_evaluations, grants TO qyrix_app;
GRANT USAGE, SELECT ON SEQUENCE provenance_steps_seq_seq TO qyrix_app;
-- no DELETE, no TRUNCATE, no access to tenants/api_keys/sessions for the application role

-- Row-level security: a row is visible / writable only when its tenant equals the transaction's qyrix.tenant_id.
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['provenance_steps','approvals','gate_evaluations','grants','proof_records','proof_anchors'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''qyrix.tenant_id'', true)) '
                   'WITH CHECK (tenant_id = current_setting(''qyrix.tenant_id'', true))', t);
  END LOOP;
END $$;
