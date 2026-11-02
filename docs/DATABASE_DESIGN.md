# QYRIX SENTINEL — Database Design

> **Status: tenant-scoped PostgreSQL persistence is IMPLEMENTED** (`backend/migrations/001_core_persistence.sql`,
> `002_tenancy_identity.sql`, `backend/app/persistence.py`, `backend/app/identity.py`; tests in `test_persistence.py`,
> `test_tenancy.py`, `test_backup.py`). Sections 0 and 0a describe it. Section 2 is the earlier PLANNED design, kept for
> reference; where it differs, sections 0/0a are authoritative.

## 0a. Tenancy and identity (migration 002)
| Table / object | Purpose and guarantees |
|---|---|
| `tenants` | `id` (`^[a-z0-9][a-z0-9-]{2,39}$`), name, `approved_domains text[]` (NULL/empty = deny all for non-default tenants), `disabled_at`. Seeds `default`. |
| `api_keys` | `key_hash` (SHA-256, unique) — plaintext never stored; role CHECK over the 7 roles; `expires_at`, `revoked_at`, `last_used_at`. |
| `sessions` | `id_hash` (SHA-256 of `qss_…`), tenant, role, `cred_id`, `cred_fp` (env-token fingerprint ⇒ rotation kills sessions), `expires_at`, `last_seen_at`, `revoked_at`. |
| `tenant_id` columns | `NOT NULL DEFAULT 'default'` on provenance_steps, approvals, gate_evaluations, grants, proof_records (PK `(tenant_id, n)`), proof_anchors. |
| role `qyrix_app` | `NOLOGIN NOSUPERUSER NOBYPASSRLS`. SELECT/INSERT on provenance, proofs, anchors; SELECT/INSERT/UPDATE on approvals, evaluations, grants. **No DELETE; no access to tenants/api_keys/sessions.** |
| RLS policy `tenant_isolation` | `USING / WITH CHECK (tenant_id = current_setting('qyrix.tenant_id', true))`, `ENABLE` + `FORCE`. No tenant set ⇒ zero rows. |
| `qyrix_append_only()` | DELETE allowed only for a non-`qyrix_app` user with `qyrix.allow_reset = 'on'` (demo reset); UPDATE of proof rows never. |

Every data statement runs in a transaction that first does `SET LOCAL ROLE qyrix_app` and
`set_config('qyrix.tenant_id', <tenant>, true)`, **and** filters `tenant_id = <tenant>` explicitly (defence in depth: either
layer alone blocks cross-tenant rows — tested with raw SQL). Identity tables are accessed as the table owner by `PgStore`.

**Operational notes.** The application connects as the database owner and *drops* to `qyrix_app` per transaction; a
separate login role for migrations vs runtime is a recommended next step. Backups: `scripts/backup.sh` (pg_dump custom
format, DB first, then chain files, SHA-256 manifest); restores re-verify the DB proof mirror against the chain on start.

## 0. Implemented schema (single tenant)
| Table | Key fields | Lifecycle / guarantees |
|---|---|---|
| `provenance_steps` | `id uuid`, declared/effective label, redacted text, `parents[]`, `created_at`, `seq` | insert-only; reloaded (50-step window + trust index) at startup |
| `approvals` | `id`, `status pending/approved/denied`, `used`, `digest`, `scope jsonb`, `expires_at` | decided only while pending (conditional UPDATE); consumed in the grant transaction |
| `gate_evaluations` | `id uuid`, verdict, rule ids, `params jsonb`, `params_digest`, `hop`, `redirect_location` | ALLOW rows only executable if the chain holds a matching ALLOW record |
| `grants` | `id`, `gate_evaluation_id` (unique FK), `params_digest`, `expires_at`, `used_at`, `revoked_at/by` | single use via `UPDATE … WHERE used_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING` |
| `proof_records` | `n`, `hash`, `prev`, kind, verdict | append-only (trigger rejects UPDATE/DELETE); must be a prefix of the chain file |
| `proof_anchors` | `id uuid`, `n`, `head_hash`, `tsa_url`, `token_b64`, `gen_time`, `serial` | append-only (trigger) |
| `schema_migrations` | `name` | migrations applied in a transaction at startup |
`gate_evaluations.params` can only contain data that passed the Gate (secret-pattern data is always BLOCKed by R2/R12), and the
database is on an internal-only network; encryption at rest is still recommended for production.

## 1. In-memory mode (no `QYRIX_DB_HOST` / `QYRIX_DATABASE_URL`)

Connection settings (`app/persistence.py` `dsn_from_env`): `QYRIX_DB_HOST`, `QYRIX_DB_PORT` (5432), `QYRIX_DB_NAME` (qyrix), `QYRIX_DB_USER` (qyrix)
and the password **from a file** — `QYRIX_DB_PASSWORD_FILE`, default `/run/secrets/db_password` (the Docker Compose secret). PostgreSQL itself reads
the same secret via `POSTGRES_PASSWORD_FILE`. Missing, empty or `CHANGE_ME` secret ⇒ persistence down ⇒ Gate BLOCKs (R17).

| Entity | Storage | Shape | Notes |
|---|---|---|---|
| Proof record | `QYRIX_CHAIN_FILE` (JSONL, one record per line, fsync) | see API_SPECIFICATION.md "Record v2" | append-only; verified on load |
| Provenance step | `ProvenanceStore` (memory) | `{id uuid4, source, label, declared_label, text(redacted ≤500), parents[], unknown_parents[], tainted, ts}` | 50-step window + trust index (≤10,000 ids) |
| Approval | `GateContext.appr` (memory) | `{id, status, used, digest, scope, requested_by, ts, exp, expires_at, decided_by}` | lost on restart |
| Gate evaluation | `GateContext.evals` (memory, ≤5,000) | `{id uuid4, verdict, rules, params{tool,method,dest,cmd,data}, digest, hop, host, redirect_location, ts}` | `params` holds raw data in memory only, never in the proof |
| Grant | `GateContext.grants` (memory) | `{id grt_…, gate_evaluation_id, digest, used, exp, expires_at}` | evicted with its evaluation |

## 2. Target PostgreSQL schema (PLANNED)

```sql
-- tenancy & identity
CREATE TABLE organizations (id uuid PRIMARY KEY, name text NOT NULL, plan text NOT NULL DEFAULT 'free', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE users (id uuid PRIMARY KEY, email citext UNIQUE NOT NULL, password_hash text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE memberships (org_id uuid REFERENCES organizations, user_id uuid REFERENCES users,
  role text NOT NULL CHECK (role IN ('owner','admin','security_reviewer','approver','auditor','integrator')), PRIMARY KEY (org_id, user_id));
CREATE TABLE agent_identities (id uuid PRIMARY KEY, org_id uuid NOT NULL REFERENCES organizations, name text NOT NULL, key_hash text NOT NULL, revoked_at timestamptz);
CREATE TABLE api_keys (id uuid PRIMARY KEY, org_id uuid NOT NULL REFERENCES organizations, key_hash text NOT NULL, scopes text[] NOT NULL, revoked_at timestamptz);

-- provenance
CREATE TABLE provenance_steps (id uuid PRIMARY KEY, org_id uuid NOT NULL REFERENCES organizations,
  source text NOT NULL, declared_label text NOT NULL, effective_label text NOT NULL, text_redacted text, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE provenance_edges (org_id uuid NOT NULL, child_id uuid NOT NULL REFERENCES provenance_steps, parent_id uuid NOT NULL REFERENCES provenance_steps,
  PRIMARY KEY (child_id, parent_id));

-- gate / execution
CREATE TABLE approvals (id uuid PRIMARY KEY, org_id uuid NOT NULL, scope_digest char(64) NOT NULL, scope jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','approved','denied','expired')), requested_by uuid, decided_by uuid,
  expires_at timestamptz NOT NULL, consumed_by_grant uuid UNIQUE);          -- consumption = grant reference (no public CONSUMED status)
CREATE TABLE gate_evaluations (id uuid PRIMARY KEY, org_id uuid NOT NULL, agent_id uuid, verdict text NOT NULL, rule_ids text[] NOT NULL,
  params_encrypted bytea NOT NULL, params_digest char(64) NOT NULL, redirect_of uuid REFERENCES gate_evaluations, hop int NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE grants (id uuid PRIMARY KEY, org_id uuid NOT NULL, gate_evaluation_id uuid NOT NULL UNIQUE REFERENCES gate_evaluations,
  params_digest char(64) NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz);
-- atomic consume: UPDATE grants SET used_at=now() WHERE id=$1 AND org_id=$2 AND used_at IS NULL AND expires_at>now() RETURNING …;
-- approval->grant: one transaction: INSERT grant; UPDATE approvals SET consumed_by_grant=… WHERE id=… AND consumed_by_grant IS NULL; rollback on 0 rows.

-- evidence (append-only: INSERT-only role, no UPDATE/DELETE grants; trigger rejects modification)
CREATE TABLE proof_records (org_id uuid NOT NULL, n bigint NOT NULL, record jsonb NOT NULL, prev char(64) NOT NULL, hash char(64) NOT NULL,
  PRIMARY KEY (org_id, n), UNIQUE (org_id, hash));
CREATE TABLE anchors (org_id uuid NOT NULL, head_n bigint NOT NULL, head_hash char(64) NOT NULL, location text NOT NULL, anchored_at timestamptz NOT NULL);

-- metering
CREATE TABLE usage_events (id uuid PRIMARY KEY, org_id uuid NOT NULL, kind text NOT NULL, idempotency_key text NOT NULL,
  gate_evaluation_id uuid, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE (org_id, idempotency_key));
```

Tenant isolation plan: every table carries `org_id`; every query filters by the caller's org from the authenticated
principal (never from the request body); PostgreSQL row-level security as a second layer; IDOR tests per endpoint.
