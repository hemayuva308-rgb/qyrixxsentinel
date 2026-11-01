# QYRIX SENTINEL — Multi-tenancy, usage metering and billing: production requirements

**Status: NOT_IMPLEMENTED (by decision).** This build is a single-tenant controlled beta. Nothing below exists in code;
this document defines what production SaaS needs so it can be built without destabilising the hackathon submission.

## 1. Hackathon readiness vs production SaaS readiness
| Capability | Hackathon build (now) | Production SaaS (required) |
|---|---|---|
| Identity | two static bearer tokens (admin, agent) | users with SSO/OIDC + MFA; per-tenant agent identities and API keys (hashed, scoped, rotatable, revocable) |
| Tenancy | one implicit tenant | organisations; every row, chain, grant and anchor scoped by `org_id` |
| Roles | admin / agent | owner, admin, security reviewer, approver, auditor, integrator, agent (plan §8) |
| Persistence | PostgreSQL, one backend process per database | PostgreSQL with HA, backups, PITR, migrations in CI; multiple stateless API replicas |
| Evidence | one hash chain per deployment; optional RFC 3161 anchoring | one chain per tenant; scheduled anchoring; per-tenant export; retention policy |
| Metering / quotas | none | server-side usage events, quotas enforced in the Gate path |
| Billing | proposed prices on the website only | payment provider integration, invoices, tax, dunning |
| Operations | Docker Compose | Kubernetes/managed containers, secrets manager, monitoring, alerting, incident runbooks, SOC 2 controls |

## 2. Architecture changes required
1. **Tenant context on every request.** Derive `org_id` from the authenticated principal only (never from the body/path).
   Thread it through `GateContext` → one context per tenant (provenance store, chain, approvals, grants, adapters, allowlist).
2. **Schema.** Add `org_id uuid NOT NULL` to every table in `migrations/` (+ composite keys `(org_id, id)`), per-tenant `proof_records (org_id, n)`;
   PostgreSQL row-level security: `USING (org_id = current_setting('qyrix.org_id')::uuid)` set per transaction.
3. **Horizontal scale.** Today the chain head lives in process memory → one writer per chain. Production: per-tenant chain append
   serialised in the database (`SELECT ... FOR UPDATE` on a chain-head row, or an advisory lock per tenant) so N API replicas can write.
4. **Per-tenant policy.** Allowlists, approval rules, redirect limits and adapters become tenant configuration with immutable versions
   (draft → publish), and every proof record references the policy version used.
5. **Per-tenant egress.** Outbound adapter traffic through an egress proxy that enforces the tenant's destination allowlist at the network layer.
6. **Secrets.** Tenant API keys hashed (argon2/scrypt), LLM/TSA credentials in a secrets manager; never in the database in clear.

## 3. Tenant isolation requirements (acceptance tests)
- Every endpoint: a principal from org A receives 404 (not 403) for any object id of org B (IDOR tests for provenance steps, approvals, evaluations, grants, anchors, exports).
- `POST /tools/execute` with a grant from another tenant → refused before any lookup leaks existence.
- Lineage may only reference steps of the same tenant; cross-tenant parent ids are treated as unknown (→ UNVERIFIED).
- Proof chains, anchors and exports are per tenant; verifying tenant A's bundle never touches tenant B's data.
- Rate limits and quotas per tenant and per agent identity; one tenant cannot exhaust another's capacity.
- Database RLS enabled and tested with a role that cannot bypass it; admin tooling uses a separate, audited role.
- Background jobs (anchoring, retention) run with an explicit tenant scope.

## 4. Usage metrics to track (server-side, idempotent)
| Metric | Definition | Billable (proposed) |
|---|---|---|
| `gate_evaluation` | one ALLOW or BLOCK decision | **yes** — the "security check" |
| `gate_block` | subset of evaluations with BLOCK | counted inside evaluations |
| `verified_execution` | `/tools/execute` that started the adapter | no (already counted at evaluation) |
| `skill_inspection` | `/inspect` call | no (rate-limited) |
| `llm_classification` | advisory classifier call that reached a provider | no, but cost-tracked |
| `proof_export` / `forensic_report` | exported bundle / generated report | proposed add-on (₹500 per verified report) |
| `anchor` | RFC 3161 anchor created | no (operational cost) |
Each event: `(org_id, agent_id, kind, gate_evaluation_id, idempotency_key, created_at)` with `UNIQUE (org_id, idempotency_key)`;
written in the same transaction as the evaluation so a retry can never double-bill. Quotas are checked **before** evaluation;
over-quota requests are refused with a clear error and **never** silently allowed (fail closed).

## 5. Billing integration requirements
- Payment provider (e.g. Stripe or Razorpay for INR) with server-side webhooks verified by signature; subscription state lives in the
  database and is read by the API — never trusted from the browser.
- Plans map to quotas (Free 1,000 / Pro 100,000 checks per month, Enterprise fair-use contract, On-premise licence) — all **proposed**.
- Invoices with GST handling, proration, failed-payment grace period and downgrade path that never disables security (BLOCK keeps working).
- No checkout UI until the above is implemented and tested; the website keeps pricing labelled "proposed".

## 6. Order of work (after the hackathon)
1. Tenant model + RLS + IDOR test suite. 2. Identity (OIDC, API keys, agent identities). 3. Per-tenant chains + multi-replica append.
4. Metering events + quotas. 5. Billing provider + webhooks. 6. Per-tenant egress proxy. 7. Ops: HA database, backups, monitoring, SOC 2 controls.
