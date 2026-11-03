# QYRIX SENTINEL — API Specification (as implemented, v1.4)

Base path: `/api/v1`. Any other path → `400 {"error":"SOLE_PATH_VIOLATION"}`.
Authentication: `Authorization: Bearer <credential>` where the credential is one of
* an operator env token (`QYRIX_ADMIN_TOKEN` → `admin@default`, `QYRIX_AGENT_TOKEN` → `agent@default`, `QYRIX_PLATFORM_TOKEN` → platform operator),
* a tenant API key `qsk_…` (stored as SHA-256 only; shown once at creation), or
* a console session `qss_…` (from `POST /auth/session`).

The tenant is ALWAYS derived from the credential; no request body or header can select a tenant.
Unauthenticated: only `GET /api/v1/health`, `GET /api/v1/ready`, `GET /`, and `/api/v1/demo/*`. `GET /api/v1/metrics` uses its own token.
`401` invalid/expired credential · `403` authenticated but not permitted · `429` rate limit or auth-failure throttle · `503` identity store,
persistence or tenant context unavailable (fail closed).

### Roles and permissions (server-side, `app/identity.py`)
| Permission | owner | admin | security_reviewer | approver | auditor | integrator | agent |
|---|---|---|---|---|---|---|---|
| `read` (status, provenance, proofs, approvals, verify, export) | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `inspect` | ✓ | ✓ | ✓ | | | | |
| `provenance.write` | ✓ | ✓ | ✓ | | | ✓ | ✓ |
| `gate.evaluate`, `tools.execute`, `approval.request` | ✓ | ✓ | | | | ✓ | ✓ |
| `approval.decide`, `grant.revoke` | ✓ | ✓ | | ✓ | | | |
| `proof.anchor`, `keys.manage`, `demo.reset` | ✓ | ✓ | | | | | |
The platform operator has **none** of these permissions. Env `admin` = role admin, env `agent` = role agent (v1.2 compatible).
Errors use FastAPI's `{"detail": "<CODE or message>"}`. All responses carry `Cache-Control: no-store`.

## Inspector
### `POST /sentinel/inspect` — `inspect` (owner, admin, security_reviewer)
Request `{"text": string ≤100000}` → `{domains[], commands[], secrets[], unapproved[], classification{label, explanation, source, provider, model, latency_ms, attempts[]}}`.
`classification` is advisory; the Gate never reads it.

## Provenance
### `POST /sentinel/provenance/step` — `provenance.write`
Request `{"source": ≤64, "label": "TRUSTED"|"UNTRUSTED"|"UNVERIFIED" (aliases: trusted, approved, untrusted, unverified; anything else ⇒ UNVERIFIED), "text": ≤5000, "parents": [uuid] ≤50}`
Response: `{id (uuid4), source, label (EFFECTIVE), declared_label, text (redacted, ≤500), parents[], unknown_parents[], tainted, ts}`.
Effective label = lowest of declared label and every parent's effective label; unknown parent ⇒ at most UNVERIFIED.
### `GET /sentinel/provenance` — `{limit: 50, steps: [...]}` (most recent 50).

## Execution Gate
### `POST /sentinel/gate/evaluate` — `gate.evaluate`
Request:
```json
{"tool":"http|file.read|…","method":"GET","dest":"…","cmd":"","data":"","lineage":["<uuid>"],
 "approval_id":null,"redirect_of":null,"approved":null}
```
`execute: true` is rejected with `400 EXECUTE_MOVED…` (execution moved to `/tools/execute`). `approved` is a client
claim that can only cause a block (R4), never an allow.

Response:
```json
{"verdict":"ALLOW|BLOCK","rules":["R…"],"blocked_dest":null,"lineage":["<uuid>:<EFFECTIVE>"],
 "latency_ms":0.4,"external_calls":0,"executed":false,"exec_status":null,"proof":{…record…},
 "gate_evaluation_id":"<uuid>","params_digest":"<sha256>","redirect_hop":0,
 "grant_id":"grt_…|null","grant_expires_at":"…|null"}
```
Rules: `R0_FAIL_CLOSED`, `R1_DEST_NOT_APPROVED`, `R2_SECRET_EXFIL`, `R3_UNTRUSTED_LINEAGE`, `R4_APPROVAL_SCOPE_MISMATCH`,
`R5_COMMAND_INJECTION`, `R6_APPROVAL_REPLAY`, `R7_APPROVAL_REQUIRED`, `R8_UNSUPPORTED_TOOL`, `R9_SSRF_BLOCKED`,
`R10_PATH_NOT_ALLOWED`, `R11_PROOF_DEGRADED`, `R12_SECRET_TO_EXTERNAL`, `R13_LINEAGE_MISSING`, `R14_APPROVAL_EXPIRED`,
`R15_REDIRECT_LIMIT`, `R16_REDIRECT_INVALID`, `R17_PERSISTENCE_UNAVAILABLE`, `R18_TASK_ID_REQUIRED` (v1.5, only with
`QYRIX_REQUIRE_TASK_ID=1`), `R19_UNTRUSTED_STATE_CHANGE` (v1.5: POST/PUT/PATCH/DELETE with tainted lineage
needs a valid human approval of the exact action, even to approved hosts), `R20_DECEPTIVE_HOSTNAME` (v1.5: invisible
characters, look-alike dots, compatibility forms, non-NFC or mixed-script labels; hosts are compared and shown as
IDNA2008 A-labels, response field `dest_host`), `LINEAGE_CYCLE_DETECTED`.

v1.5 request fields (optional): `correlation_id`, `task_id` (`^[A-Za-z0-9_.:-]{1,64}$`; caller-provided context, not a
verified identity). v1.5 response fields: `correlation_id`, `task_id`, `policy_version`. A grant is bound to the calling
credential, the `task_id` and the `policy_version` (`docs/AUTHORIZATION_BINDING.md`).

### `POST /sentinel/grants/{grant_id}/revoke` — `grant.revoke` (owner, admin, approver)
Revokes an unused grant (DB + memory) and appends a `GRANT_REVOKED` proof record. Already used/revoked/unknown ⇒ `409 GRANT_NOT_REVOCABLE`.

## Controlled execution
### `POST /tools/execute` — `tools.execute`
Body must be **exactly** `{"gate_evaluation_id": string ≤64, "grant_id": string ≤64}` plus, from v1.5, an optional
`"task_id"` that must equal the task the grant was issued for. The caller must be the credential that obtained the grant.
v1.5 refusals: `403 GRANT_AGENT_MISMATCH`, `403 GRANT_TASK_MISMATCH`, `409 GRANT_POLICY_CHANGED`, `400 TASK_ID_INVALID`.
The same binding applies to `POST /tools/redeem` (delegated execution, `docs/CONTINUOUS_ENFORCEMENT_VERIFICATION.md`).

| Condition | Status | detail |
|---|---|---|
| any other key present | 400 | `CLIENT_PARAMS_NOT_ALLOWED` (checked before any lookup) |
| ids missing / wrong type | 400 | `GATE_EVALUATION_AND_GRANT_REQUIRED` |
| invalid JSON | 400 | `INVALID_JSON` |
| unknown evaluation/grant, mismatch, or evaluation was BLOCK | 403 | `GRANT_INVALID` |
| grant already used | 409 | `GRANT_REPLAY` |
| grant expired (`QYRIX_GRANT_TTL_SECONDS`, default 120) | 409 | `GRANT_EXPIRED` |
| stored params no longer match digest | 403 | `PARAMS_DIGEST_MISMATCH` |
| proof chain degraded | 403 | `PROOF_DEGRADED` |
| grant revoked | 409 | `GRANT_REVOKED` |
| stored params no longer pass the current policy (allowlist/workspace) | 403 | `REVALIDATION_FAILED` |
| PostgreSQL unavailable (persistence mode) | 503 | `PERSISTENCE_UNAVAILABLE` |
| start record cannot be written | 503 | `PROOF_WRITE_FAILED` |

Every refusal is appended to the proof chain as `EXECUTION_REFUSED`.
Success: `{executed, tool, gate_evaluation_id, result, adapter, external_calls, proof_start, proof_result}`.
`http` result: `{status, pinned_ip, host, redirect?{location, cross_host, requires_gate:true, hop, max_hops}}`.
`file.read` result: `{bytes, content (redacted)}`.

### Redirects
A 3xx is returned, not followed. To follow, evaluate again with `dest = redirect.location` and
`redirect_of = <previous gate_evaluation_id>`; mismatched target ⇒ `R16_REDIRECT_INVALID`; hop > 5 ⇒ `R15_REDIRECT_LIMIT`.
No credentials are ever sent by the adapter, so there is nothing to strip cross-host.

## Approvals
* `POST /sentinel/approvals` — `approval.request`. `{tool, method, dest, cmd, data}` (`requested_by` is set from the principal; a body value is overwritten) → `{id, status:"pending", used:false, digest, scope{…, data_sha256}, expires_at, …}`.
* `GET /sentinel/approvals`.
* `POST /sentinel/approvals/{id}/{approve|deny}` — `approval.decide` (owner, admin, approver; agent ⇒ 403). `decided_by` = principal. Already decided ⇒ 409.
Approval ≠ execution. The agent resubmits to `gate/evaluate` with `approval_id`; consumption happens atomically with
grant creation. There is **no** public consume endpoint and no public `CONSUMED` status (the `used` flag is internal state shown read-only).

## Proof
* `GET /sentinel/proofs` → `{chain[], verify}`.
* `GET /sentinel/proofs/verify` → `{valid, status: PASS|FAIL|PARTIAL_UNANCHORED, length, head, broken_at?, anchor_status, degraded}`.
* `GET /sentinel/proofs/export` → `{format:"qyrix-proof-bundle/v2", exported_at, anchor_status, chain[], verify}`.
* `POST /sentinel/proofs/verify-bundle` (body = bundle or bare list, ≤20 MB): empty ⇒ `422 EMPTY_PROOF_BUNDLE`;
  malformed/tampered/reordered/missing ⇒ `status: FAIL`; consistent ⇒ `PARTIAL_UNANCHORED` (client-supplied anchors are ignored).
* `POST /sentinel/proofs/tamper` → simulation on a copy; real chain untouched.
* `POST /sentinel/proofs/anchor` — `proof.anchor` (owner, admin). Anchors the current head at `QYRIX_TSA_URL` (RFC 3161). Stored only after the token
  verified (imprint, nonce, signature, chain to `QYRIX_TSA_CA_FILE`). Errors: `409 ANCHOR_NOT_CONFIGURED`, `422 EMPTY_PROOF_BUNDLE`,
  `409 PROOF_DEGRADED|ANCHOR_STALE`, `503 ANCHOR_UNAVAILABLE|ANCHOR_REJECTED|ANCHOR_INVALID`. Never changes Gate decisions.
* `GET /sentinel/proofs/anchors` → `{configured, problem, can_verify, tsa_url, anchors[{id, n, head_hash, method, tsa_url, gen_time, serial, created_at}]}`.
* Verification statuses with anchors: `PASS` (verified anchor covers head), `PARTIAL_UNANCHORED` (+ `anchor_status`
  `UNANCHORED|ANCHORED_PREFIX|ANCHOR_UNVERIFIABLE`, `anchored_through`), `FAIL` (+ `ANCHOR_MISMATCH|ANCHOR_INVALID`).
  `verify-bundle` accepts anchors in the bundle but verifies their tokens only against the **server's** configured TSA CA.

Record v2 fields: `v, n, ts, kind (gate_decision|execution), gate_evaluation_id, tool, method, verdict, rule_ids,
blocked_dest (redacted), lineage, data ("[REDACTED len=N]"), ext_calls, params_digest?, result_status?, prev, hash`.
`hash = sha256(prev + canonical_json(record − hash))`.

## Operations
* `GET /sentinel/status` — health of api/gate/provenance/proof/ai, counters, `chain_status`, `anchor_status`, `anchors`,
  `persistence` (`memory|postgres|down`), recent records.
* `POST /sentinel/reset`, `POST /sentinel/benchmark` — admin **and** `QYRIX_ENABLE_DEMO_RESET=1`, else 403.
  Benchmark response: `{cases[{name,type,expected,verdict,rules,ms,ok,lineage,external_calls_delta,proof_n}], counts, metrics, verify, hypotheses}`.

## Identity and sessions
* `POST /auth/session` `{credential}` → `{session_token: "qss_…", expires_at, tenant, role}`. Platform credentials → 403; a session
  cannot mint a session; throttled like any authentication. TTL `QYRIX_SESSION_TTL_SECONDS` (8 h), idle `QYRIX_SESSION_IDLE_SECONDS` (30 min).
* `DELETE /auth/session` (bearer = the session) → revoked server-side.
* `POST /sentinel/keys` `{role, name, ttl_days?}` (`keys.manage`; role ≤ caller's grant ceiling) → key shown once.
* `GET /sentinel/keys` → metadata only (never hashes). `POST /sentinel/keys/{id}/revoke` → revokes the key and all its sessions.

## Human accounts (v1.4)
Public (throttled; uniform errors): `POST /auth/login {tenant, email, password}` → `{status: mfa_required | mfa_enrollment_required, challenge}`
(or a session only when `QYRIX_REQUIRE_MFA=0`) · `POST /auth/login/mfa {challenge, code | recovery_code}` → session ·
`POST /auth/mfa/enroll/start {challenge}` → `{secret, otpauth_uri}` once · `POST /auth/mfa/enroll/confirm {challenge, code}` → session +
10 recovery codes once · `POST /auth/password/forgot {email}` → always 202 · `POST /auth/password/reset {token, new_password}` ·
`POST /auth/invitations/accept {token, name, password}`.
Human session: `GET /auth/me`, `POST /auth/password/change {current_password, new_password, code}` (revokes all sessions),
`POST /auth/mfa/recovery-codes {code}`.
`users.manage` (owner, admin): `POST/GET /sentinel/invitations`, `POST /sentinel/invitations/{id}/revoke`, `GET /sentinel/members`,
`POST /sentinel/members/{uid}/role {role}`, `DELETE /sentinel/members/{uid}`, `POST /sentinel/members/{uid}/password-reset`
(token once), `POST /sentinel/members/{uid}/mfa-reset`. Rules: grant ceiling; admins cannot act on owners; nobody acts on
themselves here; last owner protected; role change / removal revokes sessions.
Platform: `POST /platform/tenants/{id}/invitations` (bootstrap / break-glass owner invite).
`/sentinel/gate/evaluate` now **rejects unknown fields (422)**. Readiness includes `integrity` (+ `integrity_reason`).
Client identity header `x-qyrix-client: v1|<ip|unknown>|<ts>|<hmac>` is honoured only with a valid fresh HMAC.

## Platform (platform operator only; no tenant data access)
* `POST /platform/tenants` `{id, name, approved_domains?}` — needs `QYRIX_MULTI_TENANT=1` **and** PostgreSQL (else 409
  `MULTI_TENANCY_DISABLED` / `PERSISTENCE_REQUIRED`). New tenants have an EMPTY destination allowlist (deny all) unless given.
* `GET /platform/tenants` · `POST /platform/tenants/{id}/keys` `{role, name, ttl_days}` (bootstrap key) ·
  `POST /platform/tenants/{id}/disable` (kills its keys and sessions immediately).

## Operations (monitoring)
* `GET /ready` → 200 `{ready: true, checks}` or 503: proof chain valid, Gate not degraded, persistence not down, database reachable.
* `GET /metrics` (bearer `QYRIX_METRICS_TOKEN`, ≥ 24 chars; 404 when unset) → Prometheus text: gate decisions, auth failures,
  rate limiting, sessions, persistence/tenant-context failures, per-tenant chain length / degraded / persistence / external calls.
* Security events are JSON lines on stdout (logger `qyrix.security`): `gate_decision`, `auth_failure`, `rate_limited`,
  `session_created`, `api_key_created/revoked`, `tenant_created/disabled`, `grant_revoked`, … Field names that could carry
  secrets (token, credential, data, dest, text, …) are dropped by construction.

## Public demo
* `GET /demo/scenarios`.
* `POST /demo/run` `{"scenario": "safe"|"direct"|"transformed"|"delayed"}`, extra fields ⇒ 422.
  429 when `QYRIX_DEMO_RATE_PER_MIN` (per client, default 20) or `QYRIX_DEMO_GLOBAL_RATE_PER_MIN` (default 600) is exceeded;
  404 when `QYRIX_PUBLIC_DEMO=0`. Response: `{mode:"SIMULATED_DEMO", isolated:true, notice, scenario, instruction, action,
  inspection, provenance, gate, execution, followup, proof{chain, verify}, external_calls, matched_expectation, elapsed_ms}`.

## Frontend routes (Next.js)
`POST /api/session` (login), `DELETE /api/session` (logout), `GET|POST /api/proxy/{health|sentinel/*|tools/execute}`
(cookie + `x-qs-csrf: 1` + same origin), `POST /api/demo` (public; body must be exactly `{"scenario": "safe"|"direct"|"transformed"|"delayed"}`,
anything else ⇒ 422; forwards only the id plus the client address for rate limiting).

## Divergences from the master plan's frozen specification
The supplied API Specification v1.1 / Security Design v1.2 documents were empty in the repository, so the spec items
quoted in the master plan (section 11) were implemented directly. Paths keep the existing `/api/v1/sentinel/*` prefix
for compatibility; the execution endpoint is `/api/v1/tools/execute` as specified.
