# Feature matrix: Built / Partially built / Proposed (v1.5-dev, 2026-11-03, updated after P1)

Rule: **Built** = implemented and covered by automated tests in this repository. Anything else is labelled as such.
Test counts are from the last full run, recorded in the commit that changed this file.

## Core security (v1.4, unchanged)
| Feature | Status | Evidence |
|---|---|---|
| Deterministic default-deny Execution Gate (R0–R17) | Built | `app/gateway.py`, `tests/test_sentinel.py`, `tests/test_v12_controls.py`, `tests/test_hardening.py` |
| Skill Inspector, Trust Provenance Engine | Built | `app/gateway.py`, `app/provenance.py` |
| SHA-256 hash-linked proof chain + offline verifier | Built | `app/proof.py`, `scripts/verify_proof.py` |
| RFC 3161 external timestamp anchoring | Partially built | Implemented and tested against a local TSA only; no public TSA verified |
| Meta Llama / Baseten advisory classifier | Partially built | Failure paths tested; **live provider calls not verified** |
| Single-use, expiring, digest-bound grants | Built | `tests/test_v12_controls.py`, `tests/test_persistence.py` |
| Agent-bound grants (authenticated credential) | Built (v1.5 P1) | `tests/test_grant_binding.py`, `tests/test_grant_binding_pg.py`; memory + atomic SQL |
| Task-bound grants (`task_id`) + optional `QYRIX_REQUIRE_TASK_ID` (R18) | Built (v1.5 P1) | **task_id is caller-provided context, not a verified task identity** (`docs/AUTHORIZATION_BINDING.md`) |
| Policy-version-bound grants (canonical SHA-256 of all policy inputs) | Built (v1.5 P1) | one test per policy input (12) |
| Migration 007 (additive) verified on real PostgreSQL with pre-existing data | Built (v1.5 P1) | `tests/test_grant_binding_pg.py` |
| RBAC, tenants (RLS), API keys, sessions, MFA, invitations, password reset | Built | `tests/test_identity.py`, `tests/test_tenancy.py`, `tests/test_accounts.py`, `tests/test_db_privileges.py` |
| Alerts engine, Prometheus metrics/rules | Built | `app/alerts.py`, `ops/prometheus/`, `tests/test_alerts.py` |
| Proof export | Built | `GET /api/v1/sentinel/proofs/export` |

## v1.5: Universal adapters + Continuous Enforcement Verification
| Feature | Status | Evidence |
|---|---|---|
| Universal adapter contract + capability-declaring registry | Built | `app/integrations.py`, `GET /api/v1/sentinel/integrations`, `tests/test_cev.py` |
| Correlation ids on every decision record | Built | `tests/test_cev.py::test_correlation_id_*`, `test_canary_actions_are_must_block_*` |
| Delegated execution: single-use grant redemption for integrations | Built | `POST /api/v1/tools/redeem`, replay/digest/expiry/concurrency tests |
| Execution Observer: HTTP canary (loopback listener) | Built (co-located) | `app/cev.py`; independent of the Gate's code path, not of the host |
| Execution Observer: file canary (write/delete) | Built (co-located) | File **reads are not observed** |
| Enforcement Reconciler (4 states, missing telemetry never verified) | Built | Truth-table + exhaustive tests in `tests/test_cev.py` |
| Enforcement canaries (on demand; periodic opt-in) | Built | `POST /api/v1/sentinel/cev/canary`, `QYRIX_CEV_CANARY_INTERVAL_SECONDS` |
| Honest vs broken adapter demo (controlled test fixtures) | Built | `POST /api/v1/sentinel/cev/demo`, `/enforcement` dashboard |
| Critical alert + metric on bypass / unauthorized execution | Built | `enforcement_bypass_detected`, `qyrix_cev_results_total` |
| Enforcement verification dashboard | Built | `frontend/src/app/(app)/enforcement/page.tsx` (verified in a live browser run) |
| Adapter conformance score (from the proof chain) | Built | `GET /api/v1/sentinel/cev/results`; inconclusive runs excluded, never counted as success |
| MCP proxy (stdio): tools/call interception, Gate, redemption, forward | Built | `app/mcp_proxy.py`, `tests/test_mcp_proxy.py` (fixture MCP server + end-to-end process test) |
| MCP compatibility with third-party servers | Proposed | Not yet tested; not claimed |
| Observer as a separate service / host | Proposed | |

## Still to do (master plan, in priority order)
| Feature | Status |
|---|---|
| Trusted task identity (signed task tokens from a task issuer / orchestrator) | Proposed: today task_id is caller-provided context |
| Red-team generator: schema, safety filter, dedupe, isolated runner, deterministic replay, review workflow | Built (v1.5 P2-A) | `app/redteam.py`, `tests/test_redteam.py` (44) |
| Meta Llama as red-team case author (live generation) | Partially built | Provider path tested with a mock transport only; **live generation not verified** (no credentials) |
| Template red-team corpus (40 cases, 16 categories) + report | Built (preliminary, synthetic) | `evidence/redteam/`; 37/37 attacks stopped, 0 false positives after R19/R20 |
| R19 untrusted state change (approved host is not authorization) | Built (v1.5) | `tests/test_gate_hardening.py` |
| R20 strict hostname canonicalization (IDNA2008, invisible chars, look-alike dots, mixed scripts) | Built (v1.5) | `tests/test_gate_hardening.py`; whole-script homographs not detected (shown as A-label, never match ASCII allowlist) |
| Benchmark v2: 130 synthetic cases in tiers (template / human / model), all 22 Gate rules, system checks, reproducible digest | Built (v1.5 P2-B, synthetic) | `app/benchmark_v2.py`, `evidence/benchmark-v2/`, `tests/test_benchmark_v2.py` |
| Public benchmarks (AgentDojo: MIT; InjecAgent: no licence found) | Not run | `docs/BENCHMARK_V2.md` §2 (licence review); AgentDojo needs a live LLM agent |
| Browser-based proof bundle verifier | Proposed (offline CLI verifier is built) |
| CLI, VS Code, n8n, GitHub, browser-agent integrations; Python/TypeScript SDKs | Roadmap |
| Agent registry, incident investigation UI, team reports | Proposed |
| Public demo deployment | Blocked (see deployment notes: persistent storage needs a paid plan; awaiting owner approval) |
