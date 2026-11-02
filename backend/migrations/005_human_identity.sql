-- QYRIX SENTINEL - human accounts, organisation membership, invitations, TOTP MFA, recovery codes, password reset (v1.4).
-- Secrets are never stored in clear: passwords = scrypt, TOTP secrets = AES-256-GCM (key outside the DB),
-- recovery codes / invitation / reset / challenge tokens = SHA-256 of high-entropy random values.

CREATE TABLE IF NOT EXISTS users (
  id                  text        PRIMARY KEY,                       -- usr_<hex>
  email               text        NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) <= 254),
  name                text        NOT NULL DEFAULT '',
  password_hash       text        NOT NULL,
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  totp_secret_enc     bytea,                                          -- AES-GCM(nonce||ct), AAD = user id
  totp_pending_enc    bytea,                                          -- enrolment in progress
  mfa_enabled_at      timestamptz,
  last_totp_step      bigint      NOT NULL DEFAULT 0,                 -- replay protection
  failed_logins       integer     NOT NULL DEFAULT 0,
  locked_until        timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  disabled_at         timestamptz
);

CREATE TABLE IF NOT EXISTS memberships (
  tenant_id  text        NOT NULL REFERENCES tenants(id),
  user_id    text        NOT NULL REFERENCES users(id),
  role       text        NOT NULL CHECK (role IN ('owner','admin','security_reviewer','approver','auditor','integrator','agent')),
  created_by text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS invitations (
  id          text        PRIMARY KEY,
  tenant_id   text        NOT NULL REFERENCES tenants(id),
  email       text        NOT NULL CHECK (email = lower(email)),
  role        text        NOT NULL CHECK (role IN ('owner','admin','security_reviewer','approver','auditor','integrator','agent')),
  token_hash  char(64)    NOT NULL UNIQUE,
  created_by  text        NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  revoked_at  timestamptz
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  user_id    text        NOT NULL REFERENCES users(id),
  code_hash  char(64)    NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  used_at    timestamptz,
  PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE IF NOT EXISTS password_resets (
  token_hash char(64)    PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES users(id),
  created_by text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);

CREATE TABLE IF NOT EXISTS login_challenges (
  token_hash char(64)    PRIMARY KEY,
  user_id    text        NOT NULL REFERENCES users(id),
  tenant_id  text        NOT NULL REFERENCES tenants(id),
  purpose    text        NOT NULL CHECK (purpose IN ('mfa', 'enroll')),
  attempts   integer     NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_id text REFERENCES users(id);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (user_id);
CREATE INDEX IF NOT EXISTS memberships_user ON memberships (user_id);

-- ---------- privileges ----------
-- users are global (one person may belong to several organisations); the runtime needs them to authenticate.
GRANT SELECT, INSERT ON users TO qyrix_app;
GRANT UPDATE (name, password_hash, password_changed_at, totp_secret_enc, totp_pending_enc, mfa_enabled_at, last_totp_step,
              failed_logins, locked_until, disabled_at) ON users TO qyrix_app;
GRANT SELECT, INSERT, DELETE ON recovery_codes TO qyrix_app;
GRANT UPDATE (used_at) ON recovery_codes TO qyrix_app;
GRANT SELECT, INSERT ON password_resets, login_challenges TO qyrix_app;
GRANT UPDATE (used_at) ON password_resets TO qyrix_app;
GRANT UPDATE (used_at, attempts) ON login_challenges TO qyrix_app;
-- tenant-scoped (RLS)
GRANT SELECT, INSERT, DELETE ON memberships TO qyrix_app;
GRANT UPDATE (role) ON memberships TO qyrix_app;
GRANT SELECT (id, tenant_id, email, role, created_by, created_at, expires_at, accepted_at, revoked_at), INSERT ON invitations TO qyrix_app;
GRANT UPDATE (accepted_at, revoked_at) ON invitations TO qyrix_app;
GRANT SELECT (user_id) ON sessions TO qyrix_app;
GRANT SELECT (user_id) ON sessions TO qyrix_auth;
GRANT SELECT ON users, memberships TO qyrix_auth;

DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['memberships', 'invitations'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I TO qyrix_app USING (tenant_id = qyrix_tenant()) WITH CHECK (tenant_id = qyrix_tenant())', t);
  END LOOP;
END $$;
DROP POLICY IF EXISTS auth_lookup ON memberships;
CREATE POLICY auth_lookup ON memberships FOR SELECT TO qyrix_auth USING (true);
DROP POLICY IF EXISTS auth_lookup ON invitations;
CREATE POLICY auth_lookup ON invitations FOR SELECT TO qyrix_auth USING (true);
GRANT SELECT ON invitations TO qyrix_auth;

-- invitation lookup by token hash only (before the tenant is known)
CREATE OR REPLACE FUNCTION qyrix_lookup_invitation(h text)
RETURNS TABLE (id text, tenant_id text, email text, role text, expires_at timestamptz, accepted boolean, revoked boolean, tenant_disabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT i.id, i.tenant_id, i.email, i.role, i.expires_at, i.accepted_at IS NOT NULL, i.revoked_at IS NOT NULL, t.disabled_at IS NOT NULL
    FROM public.invitations i JOIN public.tenants t ON t.id = i.tenant_id
   WHERE i.token_hash = h AND length(h) = 64
$$;
ALTER FUNCTION qyrix_lookup_invitation(text) OWNER TO qyrix_auth;
REVOKE ALL ON FUNCTION qyrix_lookup_invitation(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qyrix_lookup_invitation(text) TO qyrix_app;

-- session lookup now also ends human sessions whose user was disabled or removed from the organisation
CREATE OR REPLACE FUNCTION qyrix_lookup_session(h text)
RETURNS TABLE (tenant_id text, role text, cred_id text, cred_fp text, expires_at timestamptz, last_seen_at timestamptz,
               revoked boolean, tenant_disabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT s.tenant_id, s.role, s.cred_id, s.cred_fp, s.expires_at, s.last_seen_at,
         s.revoked_at IS NOT NULL
           OR EXISTS (SELECT 1 FROM public.api_keys k WHERE 'key:' || k.id = s.cred_id AND k.revoked_at IS NOT NULL)
           OR (s.user_id IS NOT NULL AND (
                 EXISTS (SELECT 1 FROM public.users u WHERE u.id = s.user_id AND u.disabled_at IS NOT NULL)
              OR NOT EXISTS (SELECT 1 FROM public.memberships m WHERE m.user_id = s.user_id AND m.tenant_id = s.tenant_id))),
         t.disabled_at IS NOT NULL
    FROM public.sessions s JOIN public.tenants t ON t.id = s.tenant_id
   WHERE s.id_hash = h AND length(h) = 64
$$;

-- end every session of a user in every organisation (password reset / MFA reset / disable)
CREATE OR REPLACE FUNCTION qyrix_revoke_user_sessions(uid text) RETURNS integer
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  WITH r AS (UPDATE public.sessions SET revoked_at = now() WHERE user_id = uid AND revoked_at IS NULL RETURNING 1)
  SELECT count(*)::integer FROM r
$$;
ALTER FUNCTION qyrix_revoke_user_sessions(text) OWNER TO qyrix_auth;
REVOKE ALL ON FUNCTION qyrix_revoke_user_sessions(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION qyrix_revoke_user_sessions(text) TO qyrix_app;
