-- QYRIX OBSERVER - O004: egress evidence + coverage attestations (Phase C5, design §7, §11, §13). observer-db only.
-- * Two new append-only tables (SELECT/INSERT only for the runtime; triggers even for the owner).
-- * egress_observations / coverage_attestations are infrastructure evidence without a tenant (a tunnel is attributed to
--   a tenant only through signed claims); they are never exposed through a tenant read API, so no tenant RLS.
-- * reconciliations: the result CHECK is WIDENED (no row changes) to admit ENFORCEMENT_VERIFIED, and a NEW constraint
--   requires every VERIFIED row to carry E3 evidence, no reasons and a coverage attestation id. Rows written by O003
--   all satisfy both constraints. This is the only non-CREATE statement and it removes no data.

CREATE TABLE egress_observations (
  observation_id uuid PRIMARY KEY,
  sensor         text NOT NULL CHECK (sensor IN ('egress_proxy', 'dns', 'sink')),
  kind           text NOT NULL CHECK (kind IN ('tunnel_open', 'tunnel_close', 'http_request', 'refused', 'dns_query', 'sink_hit')),
  evidence_level text NOT NULL DEFAULT 'E3' CHECK (evidence_level = 'E3'),
  tunnel_id      uuid,
  observed_at    timestamptz NOT NULL,
  closed_at      timestamptz,
  peer           text,
  host           text,
  sni            text,
  dest_ip        text,
  dest_port      integer,
  execution_id   uuid,
  method         text,
  path_sha256    char(64),
  qname          text,
  qtype          integer,
  token_sha256   char(64),
  bytes_in       bigint NOT NULL DEFAULT 0,
  bytes_out      bigint NOT NULL DEFAULT 0,
  reason         text
);
-- one tunnel / request per execution id (design §7.5 EXECUTION_ID_REUSE), enforced by the database
CREATE UNIQUE INDEX egress_execution_once ON egress_observations (execution_id)
  WHERE kind IN ('tunnel_open', 'http_request') AND execution_id IS NOT NULL;
CREATE INDEX egress_time ON egress_observations (observed_at);
CREATE INDEX egress_token ON egress_observations (token_sha256) WHERE token_sha256 IS NOT NULL;
CREATE INDEX egress_qname ON egress_observations (qname) WHERE qname IS NOT NULL;

CREATE TABLE coverage_attestations (
  attestation_id  uuid PRIMARY KEY,
  channel         text NOT NULL CHECK (channel IN ('http')),
  container_id    text NOT NULL,
  image           text,
  attestor_key_id text NOT NULL,
  attested_at     timestamptz NOT NULL,
  valid_until     timestamptz NOT NULL,
  received_at     timestamptz NOT NULL,
  attestor_checks jsonb NOT NULL,
  observer_checks jsonb NOT NULL,
  valid           boolean NOT NULL,
  reasons         text[] NOT NULL,
  doc             jsonb NOT NULL,
  CHECK (valid_until > attested_at AND valid_until <= attested_at + interval '1 hour'),
  CHECK (valid = (cardinality(reasons) = 0))
);
CREATE INDEX coverage_time ON coverage_attestations (attested_at);

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['egress_observations', 'coverage_attestations'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION observer_append_only()',
                   t || '_append_only', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION observer_append_only()',
                   t || '_no_truncate', t);
  END LOOP;
END $$;
REVOKE ALL ON egress_observations, coverage_attestations FROM PUBLIC;
GRANT SELECT, INSERT ON egress_observations, coverage_attestations TO observer_runtime;

ALTER TABLE reconciliations DROP CONSTRAINT reconciliations_result_check;
ALTER TABLE reconciliations ADD CONSTRAINT reconciliations_result_check
  CHECK (result IN ('ENFORCEMENT_VERIFIED', 'BYPASS_DETECTED', 'UNAUTHORIZED_EXECUTION', 'INCONCLUSIVE'));
ALTER TABLE reconciliations ADD CONSTRAINT reconciliations_verified_needs_coverage
  CHECK (result <> 'ENFORCEMENT_VERIFIED'
         OR (evidence_level = 'E3' AND cardinality(reasons) = 0 AND (facts->'coverage'->>'attestation_id') IS NOT NULL));
