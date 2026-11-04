# Authorization binding: agent, task and policy version (v1.5 P1)

An ALLOW decision issues one grant. From v1.5 a grant is usable only by the **same authenticated agent**, for the
**same task context**, under the **same policy version**, for the **same action, resource and arguments**, **once**,
**before expiry**, and only **within its tenant**.

## 1. Implemented guarantees (each enforced in code and covered by tests)

| Binding | Source of truth | Enforced at | Refusal code |
|---|---|---|---|
| Tenant | the caller's tenant context, plus PostgreSQL row-level security | every lookup, and the atomic consume | `GRANT_INVALID` (invisible) |
| Evaluation ↔ grant | `gate_evaluation_id` | execute / redeem | `GRANT_INVALID` |
| **Agent** | the **authenticated credential id** of the evaluating caller (`env:agent`, `key:<id>`, `user:<id>`) | execute / redeem, in memory **and** in the atomic SQL | `GRANT_AGENT_MISMATCH` (403) |
| **Task** | `task_id` presented at evaluation; the same value (or the same absence) must be presented again | execute / redeem, memory + SQL | `GRANT_TASK_MISMATCH` (403) |
| **Policy version** | SHA-256 of the canonical policy inputs (section 3), recomputed at use time | execute / redeem, memory + SQL | `GRANT_POLICY_CHANGED` (409) |
| Action, resource, arguments | `params_digest` over tool, method, destination, command and the full payload | execute / redeem (redeem requires the caller to present it) | `PARAMS_DIGEST_MISMATCH` |
| Single use | `used` flag + `UPDATE … WHERE used_at IS NULL … RETURNING` | execute / redeem | `GRANT_REPLAY` (409) |
| Expiry | `QYRIX_GRANT_TTL_SECONDS` (default 120 s) | memory + SQL `expires_at > now()` | `GRANT_EXPIRED` (409) |
| Revocation | approver / admin revoke | memory + SQL | `GRANT_REVOKED` (409) |

**How the checks are ordered:**
- **Agent is checked first.** A foreign credential learns nothing about the grant's state: it gets
  `GRANT_AGENT_MISMATCH`, never `GRANT_REPLAY` or `GRANT_EXPIRED`.
- **Failed checks consume nothing.** A refused attempt, whether wrong agent, wrong task or tampered digest, never
  consumes the grant.

**How consumption is enforced in PostgreSQL:** the atomic consume is a single statement:
```sql
UPDATE grants SET used_at = now()
WHERE tenant_id = … AND id = … AND gate_evaluation_id = … AND params_digest = …
  AND agent_id IS NOT DISTINCT FROM … AND task_id IS NOT DISTINCT FROM …
  AND policy_version IS NOT DISTINCT FROM …
  AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now()
RETURNING id
```
So even a bug in the in-memory checks cannot consume a mismatched grant. The runtime database account can INSERT
bindings, but **cannot UPDATE** `agent_id`, `task_id` or `policy_version` (column privileges are unchanged from 003).

**Who the binding covers:**
- **API callers** (`/sentinel/gate/evaluate`, `/tools/execute`, `/tools/redeem`) are always bound to their credential.
- **In-process callers** (benchmark, public demo, CEV fixtures) evaluate and execute with no principal. Their grants
  carry `agent_id = NULL`, and an API caller can therefore never use them.

### `QYRIX_REQUIRE_TASK_ID=1` (default off)
With this setting on, an action without a valid `task_id` gets the additional rule **`R18_TASK_ID_REQUIRED`**: the
verdict is BLOCK and no grant is issued. A `task_id` that is present but malformed is rejected at input validation:
422 on evaluate, and `TASK_ID_INVALID` (400) on execute or redeem. The pattern is `^[A-Za-z0-9_.:-]{1,64}$`.

## 2. Limitations (do not claim beyond these)
- **`task_id` is caller-provided context, not a verified task identity.** Whoever holds the credential chooses the
  value, whether through the API or the MCP proxy (`--task-id`, or `params._meta["qyrix/task_id"]`). The binding
  guarantees that a grant issued for task A cannot be used for task B, or without a task. It does **not** prove that
  task A exists, was assigned to this agent, or is legitimate. Trusted task identity needs a task-issuer mechanism,
  such as signed task tokens from an orchestrator. That does not exist yet.
- **The agent is the credential, not a self-declared name.** Several agents sharing one API key are one agent to
  Sentinel. Use **one key per agent**. Sessions derived from a key share its id.
- **Policy version covers declared inputs only.** Rule *code* changes are covered only when `POLICY_ENGINE_VERSION` is
  bumped. That is a release-process rule, not automatic. TTL settings and rate limits are deliberately excluded: they
  change when a grant expires, not what is allowed.
- **Legacy grants issued before migration 007** have NULL bindings and are refused through the API. This affects at
  most the grants in flight during an upgrade, which live 120 s by default.
- **Mixed-version deployments are unsafe.** An older backend ignores the binding columns. The existing rule of **one
  backend process per database** therefore matters: never run v1.4 and v1.5 against the same database at the same time.

## 3. Policy version inputs
`policy_version = SHA-256( canonical_json(policy_inputs(ctx)) )`. Canonical JSON means sorted keys, no whitespace,
ASCII escaping, and every set sorted and normalised. Domains are lower-cased and trimmed, with duplicates and trailing
dots removed. The inputs are:

| Input | Why it matters |
|---|---|
| `engine` (`POLICY_ENGINE_VERSION`) | the version of the rule code (R0–R18, netguard classification, confinement) |
| `approved_domains` (per tenant) | which destinations may receive traffic |
| `workspace` (real path) | which files `file.read` may reach |
| `executable_tools`, `adapters` | which tools can run, and through what |
| `require_task_id` | whether task context is mandatory |
| `max_redirects`, `max_file_bytes` | execution bounds |
| `detectors` (secret, injection, command and key=value patterns with flags; TLD set) | what the Gate classifies as exfiltration or injection |

`tests/test_grant_binding.py::test_each_policy_input_change_invalidates_outstanding_grants` changes each input in turn
(12 cases) and asserts that outstanding grants are refused with `GRANT_POLICY_CHANGED` on both the execute and the
redeem path.

## 4. Migration `007_task_bound_grants.sql`
- Adds nullable columns: `grants.agent_id`, `grants.task_id` and `grants.policy_version`, plus the same three and
  `correlation_id` on `gate_evaluations`.
- No defaults and no rewrite; nothing is dropped, renamed or reset.
- Privileges are unchanged.

Verified on a real PostgreSQL 16 cluster (`tests/test_grant_binding_pg.py`):
- a database migrated to 006 and **holding legacy rows** upgrades with only 007 applied;
- a second run applies nothing;
- row counts and existing values are unchanged, and the new columns are NULL;
- the runtime account still passes the least-privilege startup check;
- the runtime account cannot UPDATE any binding column;
- the binding survives a restart and is enforced after reload;
- a legacy unbound row cannot be consumed.
