# Benchmark v2 report (qyrix-benchmark/2.0)

> Synthetic, isolated corpus written for this project. Results describe this corpus only and are not a measure of general or real-world security.

Generated 2026-11-03T06:28:04.437514+00:00, commit `30d9beb`, engine `gate-rules/2026-11-03.2`, isolated policy `37242fb53180f033`, digest `4e0b41e7be292180`.

## Totals (counted directly from the corpus files; each case has exactly one primary category)

| Tier | Cases | Attack cases | Attacks stopped | Safe controls | Safe controls allowed |
|---|---|---|---|---|---|
| template | 120 | 113 | 113 | 7 | 7 |
| human | 7 | 2 | 2 | 5 | 5 |
| model | 0 | 0 | 0 | 0 | 0 |
| **overall** | **127** | **115** | **115** | **12** | **12** |

Rates: attack prevention 100.0%, false negatives 0.0%, false positives 0.0% (safe controls only).

### Attacks by primary category (sums to 115)

| Category | Cases | Stopped |
|---|---|---|
| approval_misuse | 7 | 7 |
| argument_tampering | 7 | 7 |
| cross_task_grant_reuse | 7 | 7 |
| delayed_multistep | 7 | 7 |
| delegation_abuse | 5 | 5 |
| direct_injection | 6 | 6 |
| encoded_obfuscated | 7 | 7 |
| fail_closed_environment | 7 | 7 |
| gate_rule_bypass | 5 | 5 |
| indirect_injection | 7 | 7 |
| mcp_tool_manipulation | 4 | 4 |
| policy_change | 7 | 7 |
| redirect_abuse | 7 | 7 |
| ssrf_destination | 7 | 7 |
| tool_misuse | 6 | 6 |
| unauthorized_data_transfer | 7 | 7 |
| unauthorized_file_access | 3 | 3 |
| unicode_manipulation | 9 | 9 |
| **total** | **115** | **115** |

### Cross-cutting views (overlapping; do NOT sum to the total)

Views overlap and are not exhaustive: a case may belong to several views or none, so view counts do not sum to the attack total. attack_categories (one primary category per case) does.

| View | Cases | Stopped |
|---|---|---|
| prompt_injection | 27 | 27 |
| unauthorized_tool_execution | 12 | 12 |
| replay | 4 | 4 |
| cross_agent | 5 | 5 |
| cross_task | 7 | 7 |
| policy_version | 4 | 4 |
| tainted_state_change | 7 | 7 |
| unicode_hostname_deception | 9 | 9 |
| approval_misuse | 7 | 7 |
| fail_closed_environment | 7 | 7 |
| ssrf_and_destination | 7 | 7 |
| data_exfiltration | 7 | 7 |
| argument_tampering | 7 | 7 |

## System checks

- Proof tampering (modified field, deleted record, reordered records, modified hash): 4/4 detected.
- Tail truncation with a bare hash chain: **not detected** (expected and reported). Anchor coverage: truncation below an anchored record detected; after the latest anchor not covered.
- CEV (honest and broken fixtures, HTTP and file): 100.0% as expected, 0.0% INCONCLUSIVE. The CEV observer currently runs inside the backend process (own thread and loopback socket). The CEV checks show detection of a misbehaving adapter; they do NOT show protection against a compromise of the backend process itself. A separate observer service is Phase C work.
- Cross-platform consistency (direct vs MCP mapping): 25/25 identical.

## Proof-chain truncation: implementation status

| Mechanism | Status | Evidence |
|---|---|---|
| Bare SHA-256 hash chain | cannot detect removal of the newest records | this benchmark (check proof_tamper:truncated_tail) |
| State witness (HMAC high-water mark, separate volume) | implemented: app/integrity.py; durable mode only (PostgreSQL + witness configured), checked when persistence attaches (startup / recovery) -> PROOF_CHAIN_REGRESSED, Gate blocks | tests/test_integrity.py::test_partial_loss_truncated_chain_and_deleted_db_rows |
| PostgreSQL proof mirror cross-check | implemented: gateway._sync_proof_mirror; durable mode only -> PROOF_MIRROR_MISMATCH | tests/test_persistence.py::test_truncated_chain_file_vs_mirror_degrades_gate |
| RFC 3161 anchoring | implemented, optional, off by default; local TSA tested only; detects truncation below an anchored record, does not cover records after the latest anchor | tests/test_anchor.py, tests/test_truncation_status.py |

## Latency and reproducibility

Latency (ms, 635 samples): p50 0.173, p95 0.312, p99 1.132 - in-process Gate evaluation only (no network, no persistence); machine-dependent.

Digest `4e0b41e7be292180a58d0c49329568f08f154ea493473ac8010a0a464106d61e` covers benchmark configuration and corpus hashes; every case id, tier, category, decision, rule codes, enforcement and status (attacks and safe controls); proof-tamper, anchor, CEV and consistency outcomes; v1 legacy results. Identical across 5 repeats: True; across a separate run: True.

Rules observed: 22 of 22 Gate rules; not observed: none.

## Comparison

| Benchmark | Cases | Attacks stopped | Safe allowed |
|---|---|---|---|
| v1 (unchanged, isolated) | 10 | 7/7 | 3/3 |
| Phase A corpus (re-run) | 40 | 37/37 | 3/3 |
| **v2** | 127 | 115/115 | 12/12 |

Not covered: Public benchmarks (AgentDojo: MIT, needs a live LLM agent; InjecAgent: no licence found) - not run; Live model-generated cases - none (no provider credentials); Whole-script homograph detection (UTS #39 confusables) - not implemented; such hosts never match ASCII allowlists; Real egress, real persistence/PostgreSQL behaviour and multi-process races - covered by unit/integration tests, not this benchmark; Proof tail truncation - not detectable by a bare hash chain; the state witness and DB mirror detect it in durable mode only and are not exercised here (see report section 'Proof-chain truncation'); Compromise of the backend process itself - the CEV observer currently runs in that process (Phase C).
