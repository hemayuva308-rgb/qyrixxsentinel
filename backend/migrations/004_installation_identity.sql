-- QYRIX SENTINEL - installation identity for silent data-loss detection (v1.4).
-- The installation id lives in THREE independent places: this table, the signed state witness (separate volume,
-- HMAC key in a separate secret) and, optionally, the deployment configuration (QYRIX_EXPECTED_INSTALL_ID).
-- Losing or replacing any one of them is detected by comparing it with the others (app/integrity.py).

CREATE TABLE IF NOT EXISTS installation (
  id          smallint    PRIMARY KEY CHECK (id = 1),          -- exactly one row
  install_id  uuid        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE OR REPLACE TRIGGER installation_append_only BEFORE UPDATE OR DELETE ON installation
  FOR EACH ROW EXECUTE FUNCTION qyrix_append_only();
GRANT SELECT, INSERT ON installation TO qyrix_app;            -- insert once (PK), never update/delete

-- Census across tenants without exposing any tenant's rows: only counts leave this function.
DROP POLICY IF EXISTS census ON proof_records;
CREATE POLICY census ON proof_records FOR SELECT TO qyrix_auth USING (true);
GRANT SELECT (tenant_id) ON proof_records TO qyrix_auth;
CREATE OR REPLACE FUNCTION qyrix_proof_census() RETURNS TABLE (tenants bigint, records bigint)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT count(DISTINCT tenant_id), count(*) FROM public.proof_records
$$;
ALTER FUNCTION qyrix_proof_census() OWNER TO qyrix_auth;
REVOKE ALL ON FUNCTION qyrix_proof_census() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qyrix_proof_census() TO qyrix_app;
