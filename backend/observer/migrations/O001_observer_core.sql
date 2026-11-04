-- QYRIX OBSERVER - O001: observer database core (Phase C1, design §13). Separate cluster/container (observer-db);
-- NO table, role or credential is shared with the backend database.
--
-- Roles: the migrating account (observer_admin in deployment) owns everything; observer_runtime (LOGIN, least
-- privilege) ingests; observer_reader (NOLOGIN) may read the ledger. No role gets DELETE; evidence tables are
-- append-only by trigger, even for their owner (UPDATE / DELETE / TRUNCATE raise).
-- Tenant isolation: tenant-scoped evidence (events, producer_claims) is under FORCE ROW LEVEL SECURITY keyed on the
-- transaction-local setting observer.tenant; an unset tenant matches no row.

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observer_runtime') THEN
    CREATE ROLE observer_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observer_reader') THEN
    CREATE ROLE observer_reader NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END $$;
ALTER ROLE observer_runtime NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO observer_runtime', current_database()); END $$;
GRANT USAGE ON SCHEMA public TO observer_runtime, observer_reader;

CREATE OR REPLACE FUNCTION observer_tenant() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('observer.tenant', true), '') $$;

CREATE OR REPLACE FUNCTION observer_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'observer evidence is append-only (% on %)', TG_OP, TG_TABLE_NAME;
END $$;

-- ---------- configuration evidence ----------
CREATE TABLE key_manifests (
  manifest_version integer PRIMARY KEY,
  digest           char(64) NOT NULL,
  doc              jsonb NOT NULL,
  installed_at     timestamptz NOT NULL DEFAULT now()
);

-- ---------- producer / stream state (mutable state, not evidence) ----------
CREATE TABLE producers (
  producer_id   text PRIMARY KEY,
  current_epoch integer NOT NULL DEFAULT 1 CHECK (current_epoch >= 1),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE streams (
  producer_id          text NOT NULL REFERENCES producers(producer_id),
  epoch                integer NOT NULL CHECK (epoch >= 1),
  status               text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'quarantined', 'closed')),
  reason               text,
  last_hb_seq          bigint NOT NULL DEFAULT 0,
  last_hb_received_at  timestamptz,
  last_hb_issued_at    timestamptz,
  silent_alerted       boolean NOT NULL DEFAULT false,
  created_at           timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (producer_id, epoch)
);

-- Counters only (no event content), so not tenant-RLS'd: the operator status view spans tenants.
CREATE TABLE watermarks (
  producer_id     text NOT NULL,
  epoch           integer NOT NULL,
  tenant_id       text NOT NULL,
  contiguous_seq  bigint NOT NULL DEFAULT 0,
  max_seq         bigint NOT NULL DEFAULT 0,
  attested_seq    bigint NOT NULL DEFAULT 0,       -- highest allocated_through_seq CLAIMED by an accepted heartbeat (E0)
  gap_since       timestamptz,                     -- observer time a hole was first seen (max_seq > contiguous_seq)
  behind_since    timestamptz,                     -- observer time attested_seq first exceeded contiguous_seq (tail)
  gap_alerted     boolean NOT NULL DEFAULT false,
  behind_alerted  boolean NOT NULL DEFAULT false,
  last_proof_n    bigint,
  last_proof_head char(64),
  PRIMARY KEY (producer_id, epoch, tenant_id),
  FOREIGN KEY (producer_id, epoch) REFERENCES streams(producer_id, epoch)
);

-- ---------- evidence (append-only) ----------
CREATE TABLE events (                                -- decision / grant (seq set) and adapter_report (seq NULL, E1)
  event_id     uuid PRIMARY KEY,
  producer_id  text NOT NULL,
  epoch        integer NOT NULL,
  tenant_id    text NOT NULL,
  seq          bigint CHECK (seq IS NULL OR seq >= 1),
  type         text NOT NULL CHECK (type IN ('decision', 'grant', 'adapter_report')),
  evidence_level text NOT NULL CHECK (evidence_level IN ('E0', 'E1')),
  key_id       text NOT NULL,
  issued_at    timestamptz NOT NULL,
  received_at  timestamptz NOT NULL,
  digest       char(64) NOT NULL,
  envelope     jsonb NOT NULL,
  CHECK ((type = 'adapter_report') = (seq IS NULL)),
  CHECK ((type = 'adapter_report') = (evidence_level = 'E1')),
  UNIQUE (producer_id, epoch, tenant_id, seq)
);

CREATE TABLE heartbeats (                            -- producer-level claims (E0); one row per distinct hb_seq
  event_id     uuid PRIMARY KEY,
  producer_id  text NOT NULL,
  epoch        integer NOT NULL,
  hb_seq       bigint NOT NULL CHECK (hb_seq >= 1),
  status       text NOT NULL CHECK (status IN ('accepted', 'out_of_order', 'regression')),
  key_id       text NOT NULL,
  issued_at    timestamptz NOT NULL,
  received_at  timestamptz NOT NULL,
  digest       char(64) NOT NULL,
  envelope     jsonb NOT NULL,
  UNIQUE (producer_id, epoch, hb_seq)
);

-- Backend-reported proof heads and counters (design §9): CLAIMS, evidence level E0, labelled as such by constraint.
-- They are never observations, never raise any result's evidence level and never establish observer authenticity.
CREATE TABLE producer_claims (
  id                    bigserial PRIMARY KEY,
  tenant_id             text NOT NULL,
  producer_id           text NOT NULL,
  epoch                 integer NOT NULL,
  hb_seq                bigint NOT NULL,
  label                 text NOT NULL DEFAULT 'backend_reported_head' CHECK (label = 'backend_reported_head'),
  evidence_level        text NOT NULL DEFAULT 'E0' CHECK (evidence_level = 'E0'),
  allocated_through_seq bigint NOT NULL,
  proof_n               bigint,
  proof_head            char(64),
  received_at           timestamptz NOT NULL
);

CREATE TABLE epoch_changes (                         -- signed by the OPERATOR RECOVERY key (§5.4), never the GATE key
  event_id     uuid PRIMARY KEY,
  producer_id  text NOT NULL,
  new_epoch    integer NOT NULL,
  key_id       text NOT NULL,
  received_at  timestamptz NOT NULL,
  digest       char(64) NOT NULL,
  envelope     jsonb NOT NULL,
  UNIQUE (producer_id, new_epoch)
);

-- Observer ledger: one global hash chain; every record signed by the observer signing key (manifest).
CREATE TABLE ledger (
  n               bigint PRIMARY KEY CHECK (n >= 1),
  prev            char(64) NOT NULL,
  hash            char(64) NOT NULL UNIQUE,
  recorded_at     timestamptz NOT NULL,
  kind            text NOT NULL,
  code            text NOT NULL,
  producer_id     text,
  tenant_id       text,
  ref             text,
  detail          jsonb NOT NULL,
  observer_key_id text NOT NULL,
  sig             text NOT NULL
);

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['key_manifests', 'events', 'heartbeats', 'producer_claims', 'epoch_changes', 'ledger'] LOOP
    EXECUTE format('CREATE TRIGGER %I BEFORE UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION observer_append_only()',
                   t || '_append_only', t);
    EXECUTE format('CREATE TRIGGER %I BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION observer_append_only()',
                   t || '_no_truncate', t);
  END LOOP;
END $$;

DO $$ DECLARE t text; BEGIN
  FOREACH t IN ARRAY ARRAY['events', 'producer_claims'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I TO observer_runtime USING (tenant_id = observer_tenant())'
                   ' WITH CHECK (tenant_id = observer_tenant())', t);
  END LOOP;
END $$;

-- ---------- privileges (no DELETE anywhere; evidence: SELECT/INSERT only) ----------
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
GRANT SELECT, INSERT ON key_manifests, events, heartbeats, producer_claims, epoch_changes, ledger TO observer_runtime;
GRANT SELECT, INSERT ON producers, streams, watermarks TO observer_runtime;
GRANT UPDATE (current_epoch) ON producers TO observer_runtime;
GRANT UPDATE (status, reason, last_hb_seq, last_hb_received_at, last_hb_issued_at, silent_alerted) ON streams TO observer_runtime;
GRANT UPDATE (contiguous_seq, max_seq, attested_seq, gap_since, behind_since, gap_alerted, behind_alerted,
              last_proof_n, last_proof_head) ON watermarks TO observer_runtime;
GRANT USAGE, SELECT ON SEQUENCE producer_claims_id_seq TO observer_runtime;
GRANT EXECUTE ON FUNCTION observer_tenant() TO observer_runtime;
GRANT SELECT ON ledger TO observer_reader;
