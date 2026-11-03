-- QYRIX OBSERVER - O002: observer canaries (Phase C3, design §6, §12, §13). ADDITIVE; observer-db only.
-- * Three new append-only tables; nothing in O001 is altered, dropped or rewritten.
-- * observer_runtime: SELECT + INSERT only (no UPDATE, no DELETE); append-only triggers even for the owner.
-- * Tenant isolation: FORCE ROW LEVEL SECURITY on all three tables (observer.tenant setting).
-- * A sensor receives a token without knowing its tenant: the ONLY cross-tenant read is observer_canary_lookup(hash),
--   a SECURITY DEFINER function owned by the NOLOGIN role observer_lookup that returns one run's routing fields.
-- * C3 stores NO verdicts: event kinds are a closed lifecycle vocabulary (CHECK); reconciliation is C4.
-- * Canary tokens are never stored, only their SHA-256.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observer_lookup') THEN
    CREATE ROLE observer_lookup NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END $$;
DO $$ BEGIN EXECUTE format('GRANT observer_lookup TO %I', current_user); END $$;
GRANT USAGE ON SCHEMA public TO observer_lookup;

CREATE TABLE canary_runs (
  run_id               uuid PRIMARY KEY,
  tenant_id            text NOT NULL,
  channel              text NOT NULL CHECK (channel IN ('http', 'file')),
  injection_path       text NOT NULL CHECK (injection_path IN ('P2')),
  adapter              text NOT NULL,
  credential_key_id    text,                                   -- public key id of the canary agent key; never the secret
  correlation_id       text NOT NULL UNIQUE,
  token_sha256         char(64) NOT NULL UNIQUE,
  control_sha256       char(64) NOT NULL UNIQUE,
  resource_template    text NOT NULL,                          -- resource with the token replaced by <token>
  expected_condition   text NOT NULL CHECK (expected_condition IN ('BLOCK')),
  expected_basis       text NOT NULL CHECK (expected_basis IN ('construction')),   -- NOT a signed policy check (C6)
  window_seconds       double precision NOT NULL,
  decision_seconds     double precision NOT NULL,
  created_at           timestamptz NOT NULL,
  window_ends_at       timestamptz NOT NULL,
  due_at               timestamptz NOT NULL,
  CHECK (token_sha256 <> control_sha256)
);

CREATE TABLE canary_run_events (
  id         bigserial PRIMARY KEY,
  run_id     uuid NOT NULL REFERENCES canary_runs(run_id),
  tenant_id  text NOT NULL,
  at         timestamptz NOT NULL,
  kind       text NOT NULL CHECK (kind IN (
               'CREATED', 'SUBMISSION_DISABLED', 'SUBMITTED', 'SUBMISSION_FAILED', 'RESPONSE_RECORDED',
               'DECISION_CLAIM_SEEN', 'DECISION_MISSING', 'DECISION_DISCREPANCY',
               'POSITIVE_CONTROL_PASSED', 'POSITIVE_CONTROL_FAILED', 'TOKEN_OBSERVED',
               'WINDOW_ENDED', 'INTERRUPTED', 'CLEANED_UP')),
  detail     jsonb NOT NULL DEFAULT '{}'
);
-- lifecycle steps happen at most once per run (TOKEN_OBSERVED and DECISION_DISCREPANCY may repeat)
CREATE UNIQUE INDEX canary_run_events_once ON canary_run_events (run_id, kind)
  WHERE kind NOT IN ('TOKEN_OBSERVED', 'DECISION_DISCREPANCY');

CREATE TABLE observations (                                   -- observer-originated evidence (E3), design §12
  observation_id uuid PRIMARY KEY,
  run_id         uuid NOT NULL REFERENCES canary_runs(run_id),
  tenant_id      text NOT NULL,
  sensor         text NOT NULL CHECK (sensor IN ('canary_http', 'canary_file')),
  purpose        text NOT NULL CHECK (purpose IN ('canary', 'positive_control')),
  evidence_level text NOT NULL DEFAULT 'E3' CHECK (evidence_level = 'E3'),
  timing         text NOT NULL CHECK (timing IN ('in_window', 'late')),
  observed_at    timestamptz NOT NULL,
  token_sha256   char(64) NOT NULL,
  method         text,
  path_sha256    char(64),
  body_sha256    char(64),
  bytes_in       integer NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
  peer           text
);
CREATE INDEX observations_run ON observations (run_id);

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['canary_runs', 'canary_run_events', 'observations'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION observer_append_only()',
                   t || '_append_only', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION observer_append_only()',
                   t || '_no_truncate', t);
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I TO observer_runtime USING (tenant_id = observer_tenant())'
                   ' WITH CHECK (tenant_id = observer_tenant())', t);
  END LOOP;
END $$;
CREATE POLICY lookup_read ON canary_runs FOR SELECT TO observer_lookup USING (true);

REVOKE ALL ON canary_runs, canary_run_events, observations FROM PUBLIC;
GRANT SELECT, INSERT ON canary_runs, canary_run_events, observations TO observer_runtime;
GRANT USAGE, SELECT ON SEQUENCE canary_run_events_id_seq TO observer_runtime;
GRANT SELECT (run_id, tenant_id, token_sha256, control_sha256, created_at, window_ends_at) ON canary_runs TO observer_lookup;

-- routing lookup for a sensor hit: which run (and tenant) a token hash belongs to; nothing else
CREATE OR REPLACE FUNCTION observer_canary_lookup(p_hash text)
RETURNS TABLE (out_run_id uuid, out_tenant text, out_purpose text, out_created_at timestamptz, out_window_ends_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT r.run_id, r.tenant_id,
         CASE WHEN r.token_sha256 = p_hash THEN 'canary' ELSE 'positive_control' END,
         r.created_at, r.window_ends_at
    FROM public.canary_runs r
   WHERE p_hash ~ '^[0-9a-f]{64}$' AND (r.token_sha256 = p_hash OR r.control_sha256 = p_hash)
$$;
ALTER FUNCTION observer_canary_lookup(text) OWNER TO observer_lookup;
REVOKE ALL ON FUNCTION observer_canary_lookup(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION observer_canary_lookup(text) TO observer_runtime;
