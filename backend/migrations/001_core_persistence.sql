-- QYRIX SENTINEL - core persistence (single tenant). Applied by app/persistence.py inside a transaction.
-- Follows docs/DATABASE_DESIGN.md §2 minus tenancy (org_id) which is NOT implemented.

CREATE TABLE IF NOT EXISTS provenance_steps (
  id              uuid PRIMARY KEY,
  source          text        NOT NULL,
  declared_label  text        NOT NULL CHECK (declared_label IN ('TRUSTED','UNTRUSTED','UNVERIFIED')),
  effective_label text        NOT NULL CHECK (effective_label IN ('TRUSTED','UNTRUSTED','UNVERIFIED')),
  text_redacted   text        NOT NULL DEFAULT '',
  parents         text[]      NOT NULL DEFAULT '{}',
  unknown_parents text[]      NOT NULL DEFAULT '{}',
  created_at      timestamptz NOT NULL,
  seq             bigserial   UNIQUE
);

CREATE TABLE IF NOT EXISTS approvals (
  id           text        PRIMARY KEY,
  status       text        NOT NULL CHECK (status IN ('pending','approved','denied')),
  used         boolean     NOT NULL DEFAULT false,
  digest       char(64)    NOT NULL,
  scope        jsonb       NOT NULL,
  requested_by text        NOT NULL,
  decided_by   text,
  created_at   timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS gate_evaluations (
  id                uuid        PRIMARY KEY,
  verdict           text        NOT NULL CHECK (verdict IN ('ALLOW','BLOCK')),
  rule_ids          text[]      NOT NULL,
  params            jsonb       NOT NULL,      -- ALLOW implies no secret-pattern data (R2/R12); see SECURITY_DESIGN
  params_digest     char(64)    NOT NULL,
  hop               integer     NOT NULL DEFAULT 0,
  host              text,
  redirect_location text,
  created_at        timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS grants (
  id                 text        PRIMARY KEY,
  gate_evaluation_id uuid        NOT NULL UNIQUE REFERENCES gate_evaluations(id),
  params_digest      char(64)    NOT NULL,
  approval_id        text        REFERENCES approvals(id),
  created_at         timestamptz NOT NULL,
  expires_at         timestamptz NOT NULL,
  used_at            timestamptz,
  revoked_at         timestamptz,
  revoked_by         text
);

-- Mirror of the hash chain (source of truth stays the fsync'd JSONL file); used to detect truncation/rewrites at startup.
CREATE TABLE IF NOT EXISTS proof_records (
  n                  bigint      PRIMARY KEY,
  hash               char(64)    NOT NULL UNIQUE,
  prev               char(64)    NOT NULL,
  kind               text        NOT NULL,
  verdict            text        NOT NULL,
  gate_evaluation_id uuid,
  recorded_at        timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS proof_anchors (
  id          uuid        PRIMARY KEY,
  n           bigint      NOT NULL,
  head_hash   char(64)    NOT NULL,
  method      text        NOT NULL,
  tsa_url     text        NOT NULL,
  token_b64   text        NOT NULL,
  gen_time    text,
  serial      text,
  created_at  timestamptz NOT NULL
);

-- Append-only: proof rows and anchors can never be updated or deleted (except TRUNCATE by the demo reset).
CREATE OR REPLACE FUNCTION qyrix_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'append-only table %', TG_TABLE_NAME; END $$;
DROP TRIGGER IF EXISTS proof_records_append_only ON proof_records;
CREATE TRIGGER proof_records_append_only BEFORE UPDATE OR DELETE ON proof_records FOR EACH ROW EXECUTE FUNCTION qyrix_append_only();
DROP TRIGGER IF EXISTS proof_anchors_append_only ON proof_anchors;
CREATE TRIGGER proof_anchors_append_only BEFORE UPDATE OR DELETE ON proof_anchors FOR EACH ROW EXECUTE FUNCTION qyrix_append_only();
