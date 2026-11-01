# QYRIX SENTINEL — Database Design

> **Status: PostgreSQL is PLANNED and NOT IMPLEMENTED in this build.** Section 1 documents what persists today.
> Section 2 is the target schema for the multi-tenant phase; nothing in it exists in code yet.

## 1. Current persistence (v1.2, implemented)

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
