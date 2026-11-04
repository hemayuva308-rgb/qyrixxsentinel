-- QYRIX OBSERVER - O003: canary reconciliations (Phase C4 minimal, design §11, §12). ADDITIVE; observer-db only.
-- * One new append-only, versioned table; nothing in O001/O002 is altered.
-- * ENFORCEMENT_VERIFIED is deliberately NOT an allowed value: it needs a C5 coverage attestation. Allowing it is a
--   future migration, so no C4 code path - correct or buggy - can store it.
-- * A definite result (BYPASS / UNAUTHORIZED) must rest on observer-originated evidence (E3).
-- * Late data never edits a row: a new version supersedes the previous one.
-- * observer_runtime: SELECT + INSERT only; RLS by tenant; append-only even for the owner.

CREATE TABLE reconciliations (
  recon_id       uuid PRIMARY KEY,
  run_id         uuid NOT NULL REFERENCES canary_runs(run_id),
  tenant_id      text NOT NULL,
  version        integer NOT NULL CHECK (version >= 1),
  supersedes     uuid REFERENCES reconciliations(recon_id),
  scope          text NOT NULL DEFAULT 'canary' CHECK (scope = 'canary'),
  result         text NOT NULL CHECK (result IN ('BYPASS_DETECTED', 'UNAUTHORIZED_EXECUTION', 'INCONCLUSIVE')),
  reasons        text[] NOT NULL,
  evidence_level text NOT NULL CHECK (evidence_level IN ('E3', 'none')),
  facts          jsonb NOT NULL,
  decided_at     timestamptz NOT NULL,
  ledger_n       bigint NOT NULL,
  ledger_hash    char(64) NOT NULL,
  UNIQUE (run_id, version),
  CHECK ((version = 1) = (supersedes IS NULL)),
  CHECK (result = 'INCONCLUSIVE' OR (evidence_level = 'E3' AND cardinality(reasons) = 0)),
  CHECK (result <> 'INCONCLUSIVE' OR cardinality(reasons) > 0)
);
CREATE INDEX reconciliations_tenant_time ON reconciliations (tenant_id, decided_at);

CREATE TRIGGER reconciliations_append_only BEFORE UPDATE OR DELETE ON reconciliations
  FOR EACH ROW EXECUTE FUNCTION observer_append_only();
CREATE TRIGGER reconciliations_no_truncate BEFORE TRUNCATE ON reconciliations
  FOR EACH STATEMENT EXECUTE FUNCTION observer_append_only();
ALTER TABLE reconciliations ENABLE ROW LEVEL SECURITY;
ALTER TABLE reconciliations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reconciliations TO observer_runtime
  USING (tenant_id = observer_tenant()) WITH CHECK (tenant_id = observer_tenant());

REVOKE ALL ON reconciliations FROM PUBLIC;
GRANT SELECT, INSERT ON reconciliations TO observer_runtime;
