# QYRIX SENTINEL — API Specification (as implemented, v1.2)

Base path: `/api/v1`. Any other path → `400 {"error":"SOLE_PATH_VIOLATION"}`.
Authentication: `Authorization: Bearer <token>`; roles `admin` (human operator/approver) and `agent`.
Unauthenticated: only `GET /api/v1/health`, `GET /`, and `/api/v1/demo/*`.
Errors use FastAPI's `{"detail": "<CODE or message>"}`. All responses carry `Cache-Control: no-store`.

## Inspector
### `POST /sentinel/inspect` — any role
Request `{"text": string ≤100000}` → `{domains[], commands[], secrets[], unapproved[], classification{label, explanation, source, provider, model, latency_ms, attempts[]}}`.
`classification` is advisory; the Gate never reads it.

## Provenance
### `POST /sentinel/provenance/step` — any role
Request `{"source": ≤64, "label": "TRUSTED"|"UNTRUSTED"|"UNVERIFIED" (aliases: trusted, approved, untrusted, unverified; anything else ⇒ UNVERIFIED), "text": ≤5000, "parents": [uuid] ≤50}`
Response: `{id (uuid4), source, label (EFFECTIVE), declared_label, text (redacted, ≤500), parents[], unknown_parents[], tainted, ts}`.
Effective label = lowest of declared label and every parent's effective label; unknown parent ⇒ at most UNVERIFIED.
### `GET /sentinel/provenance` — `{limit: 50, steps: [...]}` (most recent 50).

## Execution Gate
### `POST /sentinel/gate/evaluate` — any role
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
`R15_REDIRECT_LIMIT`, `R16_REDIRECT_INVALID`, `LINEAGE_CYCLE_DETECTED`.

## Controlled execution
### `POST /tools/execute` — any role
Body must be **exactly** `{"gate_evaluation_id": string ≤64, "grant_id": string ≤64}`.

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
* `POST /sentinel/approvals` — any role. `{tool, method, dest, cmd, data, requested_by}` → `{id, status:"pending", used:false, digest, scope{…, data_sha256}, expires_at, …}`.
* `GET /sentinel/approvals`.
* `POST /sentinel/approvals/{id}/{approve|deny}` — **admin only** (agent ⇒ 403). Already decided ⇒ 409.
Approval ≠ execution. The agent resubmits to `gate/evaluate` with `approval_id`; consumption happens atomically with
grant creation. There is **no** public consume endpoint and no public `CONSUMED` status (the `used` flag is internal state shown read-only).

## Proof
* `GET /sentinel/proofs` → `{chain[], verify}`.
* `GET /sentinel/proofs/verify` → `{valid, status: PASS|FAIL|PARTIAL_UNANCHORED, length, head, broken_at?, anchor_status, degraded}`.
* `GET /sentinel/proofs/export` → `{format:"qyrix-proof-bundle/v2", exported_at, anchor_status, chain[], verify}`.
* `POST /sentinel/proofs/verify-bundle` (body = bundle or bare list, ≤20 MB): empty ⇒ `422 EMPTY_PROOF_BUNDLE`;
  malformed/tampered/reordered/missing ⇒ `status: FAIL`; consistent ⇒ `PARTIAL_UNANCHORED` (client-supplied anchors are ignored).
* `POST /sentinel/proofs/tamper` → simulation on a copy; real chain untouched.

Record v2 fields: `v, n, ts, kind (gate_decision|execution), gate_evaluation_id, tool, method, verdict, rule_ids,
blocked_dest (redacted), lineage, data ("[REDACTED len=N]"), ext_calls, params_digest?, result_status?, prev, hash`.
`hash = sha256(prev + canonical_json(record − hash))`.

## Operations
* `GET /sentinel/status` — health of api/gate/provenance/proof/ai, counters, `chain_status`, recent records.
* `POST /sentinel/reset`, `POST /sentinel/benchmark` — admin **and** `QYRIX_ENABLE_DEMO_RESET=1`, else 403.
  Benchmark response: `{cases[{name,type,expected,verdict,rules,ms,ok,lineage,external_calls_delta,proof_n}], counts, metrics, verify, hypotheses}`.

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
