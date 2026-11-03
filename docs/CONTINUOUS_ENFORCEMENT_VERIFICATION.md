# Continuous Enforcement Verification, universal adapters and the MCP proxy (v1.5)

A security decision only says what *should* happen. Continuous Enforcement Verification (CEV) checks what *did* happen,
using evidence that comes neither from the Gate's decision path nor from the integration that was told to enforce
the decision.

> **Independence today (v1.5): the observer runs inside the backend process.** It has its own thread and loopback
> socket and never consults the Gate, so it catches an integration (adapter) that ignores a decision. It does **not**
> protect against a compromise of the backend process itself: an attacker controlling that process controls the
> observer too. No current CEV test demonstrates otherwise. A separate observer service with its own lifecycle and
> authenticated event ingestion is planned work (Phase C).

## 1. Components (all in `backend/app/`)

| Component | File | What it does |
|---|---|---|
| Decision ledger | `gateway.py` (existing SHA-256 chain) | Every decision record now carries `correlation_id` (caller-supplied or the `gate_evaluation_id`). The id is **not** part of the parameter digest, so it never changes what a grant authorises. |
| HTTP canary observer | `cev.py` `CanaryHttpObserver` | A stdlib HTTP listener on `127.0.0.1` (own thread and socket, not FastAPI, not the Gate). Every request to `/canary/<token>` is recorded with method, time and a SHA-256 of the body. |
| File canary observer | `cev.py` `CanaryFileObserver` | One file per run in a dedicated directory; creation, modification and deletion are detected by content/metadata snapshot. **Reads are not observable** without OS hooks, so this channel claims writes and deletes only. |
| Reconciler | `cev.reconcile()` | Pure, deterministic function → `ENFORCEMENT_VERIFIED`, `BYPASS_DETECTED`, `UNAUTHORIZED_EXECUTION`, `INCONCLUSIVE`. |
| Canaries | `cev.run_canary()` | A harmless must-block action against an isolated canary resource, sent through an adapter, observed, reconciled and written to the proof chain. |
| Adapter contract + registry | `integrations.py` | One contract for every platform; each integration declares its capabilities; status is `BUILT`, `TEST_FIXTURE` or `ROADMAP`. |
| Delegated execution | `gateway.redeem_grant()`, `POST /api/v1/tools/redeem` | For integrations that execute the action themselves (MCP servers): the single-use grant is checked exactly like `/tools/execute` and consumed atomically for the exact `params_digest`. Sentinel runs no tool. |
| MCP proxy | `mcp_proxy.py` | stdio proxy: `tools/call` → Gate → grant redemption → forward. Everything else passes through. |

## 2. Reconciler rules

| Decision | Side effect observed | Telemetry proven* | Result |
|---|---|---|---|
| BLOCK | yes | any | **BYPASS_DETECTED** (critical alert) |
| BLOCK | no | yes | **ENFORCEMENT_VERIFIED** |
| BLOCK | no | no | **INCONCLUSIVE** |
| none | yes | any | **UNAUTHORIZED_EXECUTION** (critical alert) |
| none | no | any | **INCONCLUSIVE** |
| ALLOW | yes, grant consumed through Sentinel | any | **ENFORCEMENT_VERIFIED** |
| ALLOW | yes, grant not consumed | any | **UNAUTHORIZED_EXECUTION** (critical alert) |
| ALLOW | no | any | **INCONCLUSIVE** |

\* Telemetry is "proven" only when, in the same run, the observer was armed, passed a **positive control** (it had to
see a known side effect) and the observation window closed. Missing or unproven telemetry is never reported as
verified; an observed side effect always counts. The integration's own report ("I did not forward it") is shown on
the dashboard but never used.

## 3. Canaries

Must-block under the current deterministic policy:
- **http:** `POST http://127.0.0.1:<observer>/canary/<token>`, blocked by R9 (SSRF, loopback) and R13 (no lineage).
- **file:** the `file.write` tool on the canary file, blocked by R8 (not an executable tool).

The payload is synthetic (`qyrix-canary=<correlation id>`). Canary resources are isolated: the observer only listens on
loopback, and the canary directory is private. Each run writes a `cev_reconciliation` record to the hash chain with:
- the decision verdict and rules;
- the decision proof hash;
- the observed events, as digests only;
- telemetry health;
- the result and the reasons for it.

Bypass and unauthorized execution raise the immediate critical alert `enforcement_bypass_detected`. Inconclusive runs log
`enforcement_inconclusive` as a warning. The metric is `qyrix_cev_results_total{adapter,channel,result}`.

**Periodic canaries (opt-in):** `QYRIX_CEV_CANARY_INTERVAL_SECONDS` (> 0, minimum 10 s) runs the adapters in
`QYRIX_CEV_CANARY_ADAPTERS` (default `rest_api`) on both channels. Test fixtures are never scheduled.

## 4. The signature demo: same BLOCK, two integrations

`POST /api/v1/sentinel/cev/demo {"channel": "http"|"file"}` (dashboard: **Enforcement Verification → Run canary**).
The two adapters are **controlled test fixtures**, enabled only when `QYRIX_CEV_TEST_FIXTURES=1` or in demo/eval mode:

- **Honest adapter:** gets BLOCK and does nothing. The observer sees nothing, so the result is **ENFORCEMENT_VERIFIED**.
- **Deliberately broken adapter:** gets BLOCK, ignores it and touches the canary. It is hard-guarded so it can touch
  *only* canary resources. It then reports "not forwarded" (a lie). The observer records the hit, so the result is
  **BYPASS_DETECTED** and a critical alert is raised.

Afterwards the chain verifies. It contains both decisions, with their correlation ids, and both reconciliations.

Hash-chain integrity shows the records were not altered after they were written. It does **not** by itself prove an
event happened. That evidence comes from the observer. It is separate from the Gate's decision path, but still inside
the backend process; its limits are listed in section 7.

## 5. Universal adapter contract (`qyrix-adapter-contract/v1`)

1. **Evaluate:** `POST /api/v1/sentinel/gate/evaluate` with `{tool, method, dest, cmd, data, lineage, correlation_id, task_id}`.
   The grant is bound to the authenticated credential, the `task_id` and the current policy version
   (`docs/AUTHORIZATION_BINDING.md`).
2. **Enforce:**
   - On BLOCK, the integration must not perform the action.
   - On ALLOW, either Sentinel executes it (`POST /api/v1/tools/execute`), or the integration redeems the single-use
     grant (`POST /api/v1/tools/redeem` with `{gate_evaluation_id, grant_id, params_digest, correlation_id, task_id}` and the
     header `X-Qyrix-Integration`) and only then executes exactly those parameters. Same agent, same task, same policy
     version, or the call is refused.
3. **Verify:** CEV canaries through the integration, checked against the observer. The observer is separate from the
   integration and the Gate's decision path; in v1.5 it runs in the backend process.

`GET /api/v1/sentinel/integrations` lists every integration, its declared capabilities and its status:

| Status | Integrations |
|---|---|
| BUILT | `rest_api`, `mcp_proxy` |
| TEST_FIXTURE | `honest_fixture`, `broken_fixture` |
| ROADMAP | CLI, VS Code, n8n, GitHub, browser agents, Python SDK, TypeScript SDK, custom agents |

## 6. MCP proxy

```bash
cd backend
QYRIX_URL=http://127.0.0.1:8000 QYRIX_TOKEN=<agent or integrator API key> \
  python -m app.mcp_proxy --config examples/mcp_proxy.tools.json --timeout 30 -- <your MCP server command>
```
Point the MCP client at the proxy command instead of the server.

**How calls are handled:**
- **Unmapped tools are blocked** (R8).
- **Mapped tools** become `http` or `file.read` actions, with the **full arguments object** as payload. The grant
  therefore binds the exact arguments, and secret-looking arguments trigger R2/R12.
- **When a call is not forwarded:** BLOCK, an unreachable Sentinel, or a refused redemption. The client gets an MCP
  tool result with `isError: true` and `_meta.qyrix` = `{verdict, rules, correlation_id, gate_evaluation_id,
  decision_proof_hash}`.
- **Correlation id:** clients may supply one in `params._meta["qyrix/correlation_id"]`.
- **Task context:** set with `--task-id`, or per call in `params._meta["qyrix/task_id"]`. It is sent to evaluate and to
  redeem. It is caller-provided context, not a verified task identity.
- **Timeouts:** a call that times out returns JSON-RPC error `-32001`, and its late reply is dropped.

**Scope:**
- stdio transport only.
- Tested against the stdio MCP server fixture `backend/tests/fixtures/mcp_server_fixture.py`, a separate process, and
  end to end as its own process against a live Sentinel HTTP server.
- Compatibility with third-party MCP servers is **not yet tested**, so it is not claimed.

## 7. Limits (do not claim beyond these)
- **The observer is co-located.** It runs inside the backend process: separate thread and socket, independent of the
  Gate's code path but not of the host. A fully independent deployment runs it as its own service.
- **File reads are not observed.**
- **Canaries prove the enforcement path for canary resources.** They do not prove every real action of an integration
  was enforced.
- **The broken adapter is a test fixture, not a real-world integration.**
- **In-memory state does not survive a restart.** Results are read back from the proof chain, which is durable; the
  observer's in-memory hits do not persist.

## 8. Tests
- `backend/tests/test_cev.py` (32 tests):
  - the reconciler truth table, plus an exhaustive check that missing telemetry is never verified;
  - both demo channels against the full acceptance criteria;
  - observer failure, adapter crash, and rogue execution;
  - fixture gating, permissions, and the broken-fixture guard;
  - correlation ids;
  - redemption: single use, digest binding, expiry, extra fields, and 8-thread concurrent redemption.
- `backend/tests/test_mcp_proxy.py` (13 tests):
  - discovery pass-through;
  - blocked call never forwarded and never observed;
  - unmapped tool denied;
  - allowed call redeemed once with exact arguments;
  - secret-looking arguments blocked;
  - Sentinel down → fail closed;
  - refused redemption not forwarded;
  - timeout handling;
  - invalid requests;
  - a CEV canary *through the MCP proxy* = ENFORCEMENT_VERIFIED;
  - an end-to-end subprocess run.
