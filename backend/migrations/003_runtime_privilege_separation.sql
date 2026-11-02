-- QYRIX SENTINEL - database privilege separation (v1.4).
--
-- Threat addressed: until v1.3 the long-running backend connected as the database owner (in Docker even a SUPERUSER
-- with BYPASSRLS) and only dropped to qyrix_app with SET LOCAL ROLE per transaction. Any code-execution or SQL-injection
-- bug could skip that switch and read/modify every tenant, delete evidence, or run OS commands (COPY ... PROGRAM).
--
-- After this migration:
--   * the backend logs in as qyrix_runtime: LOGIN, NOSUPERUSER, NOBYPASSRLS, NOCREATEROLE, NOCREATEDB, NOREPLICATION,
--     owns nothing, is a member of qyrix_app only, and verifies all of that itself at startup (fail closed);
--   * migrations and administrative tasks run under the separate privileged account (one-shot `python -m app.migrate`);
--   * RLS covers every tenant table INCLUDING api_keys and sessions; a missing/empty tenant context matches no row;
--   * cross-tenant credential lookups (by SHA-256 hash only) go through SECURITY DEFINER functions owned by the NOLOGIN
--     role qyrix_auth, which can only read/touch credential rows - it cannot enumerate them for the runtime;
--   * evidence deletion (demo reset only) is a SECURITY DEFINER function owned by NOLOGIN qyrix_maint whose EXECUTE
--     right is granted to the runtime only when the operator explicitly allows demo reset at migration time;
--   * UPDATE rights are column-scoped, so even injected SQL cannot rewrite verdicts, digests or proof records.

-- ---------- roles ----------
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_runtime') THEN
    CREATE ROLE qyrix_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION INHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_auth') THEN
    CREATE ROLE qyrix_auth NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_maint') THEN
    CREATE ROLE qyrix_maint NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
END $$;
-- re-assert attributes in case the roles pre-existed with more power
ALTER ROLE qyrix_runtime NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
ALTER ROLE qyrix_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT qyrix_app TO qyrix_runtime;
-- the (privileged) migrating account may hand objects to the NOLOGIN owner roles; the runtime never gets these
DO $$ BEGIN EXECUTE format('GRANT qyrix_auth, qyrix_maint TO %I', current_user); END $$;

-- the runtime must not be able to create objects or temp tables, nor inherit PUBLIC function rights
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
DO $$ BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO qyrix_runtime', current_database());
END $$;
GRANT USAGE ON SCHEMA public TO qyrix_app, qyrix_auth, qyrix_maint;

-- ---------- tenant context ----------
-- NULL/empty context => NULL => no row matches (fail closed). STABLE so it is evaluated once per statement.
CREATE OR REPLACE FUNCTION qyrix_tenant() RETURNS text LANGUAGE sql STABLE
  AS $$ SELECT nullif(current_setting('qyrix.tenant_id', true), '') $$;
GRANT EXECUTE ON FUNCTION qyrix_tenant() TO qyrix_app, qyrix_auth, qyrix_maint;

-- rows must always name their tenant explicitly (no silent fallback to 'default')
ALTER TABLE provenance_steps ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE approvals        ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE gate_evaluations ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE grants           ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE proof_records    ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE proof_anchors    ALTER COLUMN tenant_id DROP DEFAULT;

-- ---------- privileges (replace 002's table-wide grants with minimal, column-scoped ones) ----------
REVOKE ALL ON provenance_steps, approvals, gate_evaluations, grants, proof_records, proof_anchors,
              tenants, api_keys, sessions, schema_migrations FROM qyrix_app;
GRANT SELECT, INSERT ON provenance_steps, proof_records, proof_anchors, gate_evaluations TO qyrix_app;
GRANT UPDATE (redirect_location)                           ON gate_evaluations TO qyrix_app;
GRANT SELECT, INSERT                                       ON approvals TO qyrix_app;
GRANT UPDATE (status, used, decided_by, updated_at)        ON approvals TO qyrix_app;
GRANT SELECT, INSERT                                       ON grants TO qyrix_app;
GRANT UPDATE (used_at, revoked_at, revoked_by)             ON grants TO qyrix_app;
GRANT SELECT                                               ON schema_migrations TO qyrix_app;
-- tenants: non-secret metadata; platform operations create/disable tenants through the runtime
GRANT SELECT, INSERT                                       ON tenants TO qyrix_app;
GRANT UPDATE (disabled_at)                                 ON tenants TO qyrix_app;
-- credentials: tenant-scoped by RLS for the runtime
GRANT SELECT (id, tenant_id, role, name, created_by, created_at, expires_at, revoked_at, last_used_at), INSERT ON api_keys TO qyrix_app;
GRANT UPDATE (revoked_at)                                  ON api_keys TO qyrix_app;
GRANT SELECT (tenant_id, role, cred_id, created_at, expires_at, revoked_at), INSERT ON sessions TO qyrix_app;
GRANT UPDATE (revoked_at)                                  ON sessions TO qyrix_app;
GRANT USAGE, SELECT ON SEQUENCE provenance_steps_seq_seq   TO qyrix_app;
-- NOTE: the runtime has no SELECT on api_keys.key_hash or sessions.id_hash lookups across tenants, no DELETE, no TRUNCATE.

GRANT SELECT, UPDATE (last_used_at) ON api_keys TO qyrix_auth;
GRANT SELECT, UPDATE (last_seen_at, revoked_at) ON sessions TO qyrix_auth;
GRANT SELECT ON tenants TO qyrix_auth;

GRANT SELECT, DELETE ON provenance_steps, approvals, gate_evaluations, grants, proof_records, proof_anchors TO qyrix_maint;

-- ---------- row-level security ----------
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['provenance_steps','approvals','gate_evaluations','grants','proof_records','proof_anchors','api_keys','sessions'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I TO qyrix_app USING (tenant_id = qyrix_tenant()) WITH CHECK (tenant_id = qyrix_tenant())', t);
    EXECUTE format('DROP POLICY IF EXISTS maint_reset ON %I', t);
  END LOOP;
  FOREACH t IN ARRAY ARRAY['provenance_steps','approvals','gate_evaluations','grants','proof_records','proof_anchors'] LOOP
    EXECUTE format('CREATE POLICY maint_reset ON %I FOR ALL TO qyrix_maint USING (tenant_id = qyrix_tenant())', t);
  END LOOP;
END $$;
DROP POLICY IF EXISTS auth_lookup ON api_keys;
CREATE POLICY auth_lookup ON api_keys FOR ALL TO qyrix_auth USING (true);
DROP POLICY IF EXISTS auth_lookup ON sessions;
CREATE POLICY auth_lookup ON sessions FOR ALL TO qyrix_auth USING (true);
-- tenants: readable by the runtime (platform list) - holds no secrets; inserts must be valid ids (CHECK constraint)
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenants_read ON tenants;
CREATE POLICY tenants_read ON tenants FOR SELECT TO qyrix_app, qyrix_auth USING (true);
DROP POLICY IF EXISTS tenants_write ON tenants;
CREATE POLICY tenants_write ON tenants FOR INSERT TO qyrix_app WITH CHECK (disabled_at IS NULL);
DROP POLICY IF EXISTS tenants_disable ON tenants;
CREATE POLICY tenants_disable ON tenants FOR UPDATE TO qyrix_app USING (id <> 'default') WITH CHECK (id <> 'default');

-- ---------- append-only evidence ----------
CREATE OR REPLACE FUNCTION qyrix_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' AND current_user = 'qyrix_maint' AND current_setting('qyrix.allow_reset', true) = 'on' THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'append-only table %', TG_TABLE_NAME;
END $$;

-- ---------- credential lookups (SECURITY DEFINER, owner qyrix_auth) ----------
CREATE OR REPLACE FUNCTION qyrix_lookup_key(h text)
RETURNS TABLE (id text, tenant_id text, role text, expires_at timestamptz, revoked_at timestamptz, tenant_disabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT k.id, k.tenant_id, k.role, k.expires_at, k.revoked_at, t.disabled_at IS NOT NULL
    FROM public.api_keys k JOIN public.tenants t ON t.id = k.tenant_id
   WHERE k.key_hash = h AND length(h) = 64
$$;
CREATE OR REPLACE FUNCTION qyrix_touch_key(h text) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE public.api_keys SET last_used_at = now()
   WHERE key_hash = h AND (last_used_at IS NULL OR last_used_at < now() - interval '60 seconds')
$$;
CREATE OR REPLACE FUNCTION qyrix_lookup_session(h text)
RETURNS TABLE (tenant_id text, role text, cred_id text, cred_fp text, expires_at timestamptz, last_seen_at timestamptz,
               revoked boolean, tenant_disabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.tenant_id, s.role, s.cred_id, s.cred_fp, s.expires_at, s.last_seen_at,
         s.revoked_at IS NOT NULL OR EXISTS (SELECT 1 FROM public.api_keys k WHERE 'key:' || k.id = s.cred_id AND k.revoked_at IS NOT NULL),
         t.disabled_at IS NOT NULL
    FROM public.sessions s JOIN public.tenants t ON t.id = s.tenant_id
   WHERE s.id_hash = h AND length(h) = 64
$$;
CREATE OR REPLACE FUNCTION qyrix_touch_session(h text) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE public.sessions SET last_seen_at = now() WHERE id_hash = h
$$;
CREATE OR REPLACE FUNCTION qyrix_end_session(h text) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  UPDATE public.sessions SET revoked_at = now() WHERE id_hash = h AND revoked_at IS NULL
$$;
ALTER FUNCTION qyrix_lookup_key(text) OWNER TO qyrix_auth;
ALTER FUNCTION qyrix_touch_key(text) OWNER TO qyrix_auth;
ALTER FUNCTION qyrix_lookup_session(text) OWNER TO qyrix_auth;
ALTER FUNCTION qyrix_touch_session(text) OWNER TO qyrix_auth;
ALTER FUNCTION qyrix_end_session(text) OWNER TO qyrix_auth;
REVOKE ALL ON FUNCTION qyrix_lookup_key(text), qyrix_touch_key(text), qyrix_lookup_session(text), qyrix_touch_session(text),
                       qyrix_end_session(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qyrix_lookup_key(text), qyrix_touch_key(text), qyrix_lookup_session(text), qyrix_touch_session(text),
                          qyrix_end_session(text) TO qyrix_app;

-- ---------- demo/eval evidence reset (owner qyrix_maint; EXECUTE granted only by `app.migrate --allow-demo-reset`) ----------
CREATE OR REPLACE FUNCTION qyrix_reset_tenant_evidence(t text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF t IS NULL OR t <> current_setting('qyrix.tenant_id', true) THEN
    RAISE EXCEPTION 'reset only within the current tenant context';
  END IF;
  PERFORM set_config('qyrix.allow_reset', 'on', true);
  DELETE FROM public.grants WHERE tenant_id = t;
  DELETE FROM public.gate_evaluations WHERE tenant_id = t;
  DELETE FROM public.approvals WHERE tenant_id = t;
  DELETE FROM public.provenance_steps WHERE tenant_id = t;
  DELETE FROM public.proof_records WHERE tenant_id = t;
  DELETE FROM public.proof_anchors WHERE tenant_id = t;
  PERFORM set_config('qyrix.allow_reset', 'off', true);
END $$;
ALTER FUNCTION qyrix_reset_tenant_evidence(text) OWNER TO qyrix_maint;
REVOKE ALL ON FUNCTION qyrix_reset_tenant_evidence(text) FROM PUBLIC;
