# Benchmark v2: design, licensing review and results (v1.5 P2 phase B)

> Benchmark v2 measures how the deterministic Gate behaves on a fixed, reproducible, **synthetic** corpus run in an
> isolated sandbox. It is **not** evidence of real-world security effectiveness. No public-benchmark results are
> included (see section 2).

## 1. Audit of what existed before v2
| Asset | State before v2 | Gap |
|---|---|---|
| Benchmark v1 (`gateway.benchmark_cases`) | 10 cases (3 safe, 7 attacks), real-looking hosts, runs inside the caller's context | No seeds, hashes or repeats; uses the caller's proof chain; covers few rules |
| Red-team corpus v1 (`evidence/redteam/template-v1`) | 40 template cases, 16 categories; 37/37 attacks stopped after R19/R20 | No approval-misuse, environment-fault or redirect cases; no tiers; one run only |
| Tests | 558 backend tests (unit, PostgreSQL and MCP) | Rules R0, R6, R11, R14–R18 and `LINEAGE_CYCLE_DETECTED` not exercised by any corpus |

## 2. Licensing and compatibility review (checked 2026-11-03, before any data use)
| Project | Licence (as read from the official repository) | Permitted use | Compatibility with Sentinel | Decision |
|---|---|---|---|---|
| **AgentDojo** (`ethz-spylab/agentdojo`) | **MIT**, © 2024 Edoardo Debenedetti, Jie Zhang, Mislav Balunovic, Luca Beurer-Kellner, Marc Fischer, Florian Tramèr (`LICENSE` read directly) | Use, copy and modify with the copyright and licence notice retained; cite the NeurIPS 2024 Datasets & Benchmarks paper | An **agent-in-the-loop** framework: an LLM agent runs tool suites (workspace, slack, banking, travel), and defences plug into its pipeline (`--defense`). Fair use needs a live LLM and a Sentinel defence adapter that maps its tool calls to Gate actions | **Not imported.** It needs live model calls (credentials, possible cost). Proposed later step, with owner approval: Sentinel as an AgentDojo pipeline defence, results reported separately |
| **InjecAgent** (`uiuc-kang-lab/InjecAgent`) | **No licence found**: no `LICENSE` at `main` or `master` (HTTP 404), no licence statement in the README, and repository metadata was not accessible in this session | Without a licence the dataset (1,054 cases in `data/*.jsonl`) is all rights reserved by default | Its cases are written for LLM agents (user tool / attacker tool / attacker instruction) and would need mapping to Sentinel actions | **Not imported, not copied, not paraphrased.** Cite the paper (arXiv:2403.02691) only. Ask the authors for licence terms before any use |

Neither dataset is in this repository. All v2 cases are original, written for this project.

## 3. Design
**Tiers.** The tiers are kept separate in the corpus files and in every metric:
- `template`: deterministic, seeded case families from `app/redteam.py`, reviewed by the template authors;
- `human`: hand-written, reviewed cases (`backend/benchmark/human-v1.cases.json`): the documented homograph
  limitation, a legitimate IDN, and approved-workflow false-positive controls. **Every case belongs to exactly one
  tier.** The three Phase A findings are in the template tier only; they are also kept verbatim in
  `tests/test_gate_hardening.py`. The build and the run both fail on any case id present in two tiers;
- `model`: Llama-generated candidates that passed human review. **None exist in this release**: no provider
  credentials are configured, and the tier is reported as 0 cases rather than omitted;
- `v1-legacy`: the 10 original v1 cases, run unchanged in an isolated context for comparison.

**Rule coverage.** Case fields added on top of the Phase A schema let every Gate rule be reached through the real
`evaluate` function:
- `approval`: valid, mismatch (R4), replay (R6), expired (R14); R7 when a DELETE has no approval;
- `environment`: proof degraded (R11), persistence down (R17), task id required (R18), allowlist unavailable (R0, fail
  closed), lineage cycle (`LINEAGE_CYCLE_DETECTED`);
- `redirect`: invalid previous hop (R16), over the hop limit (R15).

**System checks.** These run in isolated contexts:
- proof-chain tampering (modified field, deleted record, reordered records, modified hash), which must be detected;
  tail truncation, which a bare hash chain cannot detect and which is reported as such; and anchor coverage
  (structural);
- CEV honest and broken test fixtures on the HTTP and file channels;
- cross-platform consistency: the same action evaluated directly and through the MCP proxy mapping must get the same
  verdict and rules.

**Isolation.** Each case gets a fresh in-memory GateContext:
- synthetic approved hosts and a temporary synthetic workspace;
- sandbox adapters, so nothing really executes;
- no chain file.

The run asserts that egress is zero and the production proof chain is unchanged.

**Reproducibility.** Every report records:
- seeds, generator, prompt, engine and policy versions;
- the SHA-256 of each corpus file;
- the git commit, Python version and platform.

The suite runs `--repeats` times. A **result digest** (SHA-256 over each case's decision, rules and enforcement)
must be identical across repeats and across separate runs; `--check-reproducible` fails otherwise.

**Metrics** (each also broken down by tier):
- attack prevention rate and false-negative rate (attack cases);
- false-positive rate (`safe_control` cases only);
- per-rule coverage, plus a list of rules never observed;
- per category;
- replay prevention (grant replay and approval replay);
- cross-agent / delegation and cross-task isolation;
- policy-version invalidation;
- approval-misuse prevention;
- R19 and R20 results;
- CEV verification and INCONCLUSIVE rates;
- tamper detection;
- cross-platform consistency;
- latency p50/p95/p99 over all repeats (in-process Gate evaluation only, no network).

## 4. Results (regenerated from `evidence/benchmark-v2/report.json`; the tables below are copied from `report.md`)
> Synthetic, isolated, written for this project. These numbers describe **this corpus only**. 100% here means "every
> case we wrote was handled as we expected"; it says nothing about attacks we did not think of.

**Correction to the first Phase B report (`30d9beb`).** That report listed 130 cases (118 attacks). Three Phase A
findings were in **both** the template and the human tier, so they were counted twice. The true corpus is **127 unique
cases: 115 attacks and 12 safe controls**. Its "attack group" table was a set of overlapping views (15 attack cases are
in no view, 10 are in two), so its 114 was never a total. Totals now come from a per-case primary category that sums
exactly, and the views are labelled as overlapping.

### Totals (counted directly from the corpus files; each case has exactly one primary category)

| Tier | Cases | Attack cases | Attacks stopped | Safe controls | Safe controls allowed |
|---|---|---|---|---|---|
| template | 120 | 113 | 113 | 7 | 7 |
| human | 7 | 2 | 2 | 5 | 5 |
| model | 0 | 0 | 0 | 0 | 0 |
| **overall** | **127** | **115** | **115** | **12** | **12** |

Rates: attack prevention 100.0%, false negatives 0.0%, false positives 0.0% (safe controls only).

#### Attacks by primary category (sums to 115)

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

#### Cross-cutting views (overlapping; do NOT sum to the total)

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

### System checks

- Proof tampering (modified field, deleted record, reordered records, modified hash): 4/4 detected.
- Tail truncation with a bare hash chain: **not detected** (expected and reported). Anchor coverage: truncation below an anchored record detected; after the latest anchor not covered.
- CEV (honest and broken fixtures, HTTP and file): 100.0% as expected, 0.0% INCONCLUSIVE. The CEV observer currently runs inside the backend process (own thread and loopback socket). The CEV checks show detection of a misbehaving adapter; they do NOT show protection against a compromise of the backend process itself. A separate observer service is Phase C work.
- Cross-platform consistency (direct vs MCP mapping): 25/25 identical.

### Proof-chain truncation: implementation status

| Mechanism | Status | Evidence |
|---|---|---|
| Bare SHA-256 hash chain | cannot detect removal of the newest records | this benchmark (check proof_tamper:truncated_tail) |
| State witness (HMAC high-water mark, separate volume) | implemented: app/integrity.py; durable mode only (PostgreSQL + witness configured), checked when persistence attaches (startup / recovery) -> PROOF_CHAIN_REGRESSED, Gate blocks | tests/test_integrity.py::test_partial_loss_truncated_chain_and_deleted_db_rows |
| PostgreSQL proof mirror cross-check | implemented: gateway._sync_proof_mirror; durable mode only -> PROOF_MIRROR_MISMATCH | tests/test_persistence.py::test_truncated_chain_file_vs_mirror_degrades_gate |
| RFC 3161 anchoring | implemented, optional, off by default; local TSA tested only; detects truncation below an anchored record, does not cover records after the latest anchor | tests/test_anchor.py, tests/test_truncation_status.py |

### Latency and reproducibility

Latency (ms, 635 samples): p50 0.173, p95 0.312, p99 1.132 - in-process Gate evaluation only (no network, no persistence); machine-dependent.

Digest `4e0b41e7be292180a58d0c49329568f08f154ea493473ac8010a0a464106d61e` covers benchmark configuration and corpus hashes; every case id, tier, category, decision, rule codes, enforcement and status (attacks and safe controls); proof-tamper, anchor, CEV and consistency outcomes; v1 legacy results. Identical across 5 repeats: True; across a separate run: True.

Rules observed: 22 of 22 Gate rules; not observed: none.

### Comparison

| Benchmark | Cases | Attacks stopped | Safe allowed |
|---|---|---|---|
| v1 (unchanged, isolated) | 10 | 7/7 | 3/3 |
| Phase A corpus (re-run) | 40 | 37/37 | 3/3 |
| **v2** | 127 | 115/115 | 12/12 |

### Finding made by Benchmark v2 (fixed in this change)
**A policy-source failure raised an exception instead of a recorded R0 BLOCK.** P1 computes `policy_version` outside
the rule evaluator's fail-closed block. When the allowlist source raised, `evaluate()` threw: the API would return a
500 with no decision in the proof chain. That was not fail-open (no grant was issued), but it broke the "every decision
is a recorded BLOCK" guarantee.
- **Fix at decision time:** the failure is now a recorded `R0_FAIL_CLOSED` BLOCK.
- **Fix at grant use:** execute and redeem now refuse with `POLICY_UNAVAILABLE` (503), and the grant is not consumed.
- **Tests:** `tests/test_gate_hardening.py`, including that the grant still works once the source recovers.

## 5. Reproduce
```bash
cd backend
python -m app.benchmark_v2 build --out ../evidence/benchmark-v2
python -m app.benchmark_v2 run --corpus ../evidence/benchmark-v2 --repeats 5 --check-reproducible \
    --phase-a-corpus ../evidence/redteam/template-v1.cases.jsonl --report ../evidence/benchmark-v2/report.json
```
- **Exit code:** non-zero if the result digest differs between repeats or runs, on any error or egress, or if the
  totals do not reconcile with the corpus files or a case id appears in two tiers.
- **The digest covers:** the benchmark configuration and corpus hashes; every case's id, tier, category, decision,
  rule codes, enforcement and status (attacks and safe controls); the proof-tamper, anchor, CEV and consistency
  outcomes; and the v1 legacy results. It excludes the commit, timestamps and repeat count. Tests show that 11 kinds
  of single change each change it, and that a fresh process reproduces it.
- **Corpus hashes:** the per-tier SHA-256 values, seeds and versions are in the report.
- **Tests:** `tests/test_benchmark_v2.py` (13). They check size and tiers, every rule exercised, reproducibility,
  isolation, and sensitivity: a Gate with R19 removed shows false negatives and a different digest, and an
  inconsistent MCP mapping is reported.

## 6. Limitations
- **The corpus is small, synthetic and self-authored.** It covers the attack classes listed here and nothing else.
- **No public-benchmark results.** AgentDojo needs a live LLM agent; InjecAgent has no licence.
- **No model-generated cases yet.**
- **Whole-script homographs are not detected as confusables.** They never match an ASCII allowlist.
- **Real network, PostgreSQL and multi-process behaviour** are covered by the unit and integration suites, not by this
  benchmark.
- **Tail truncation** is not detected inside this benchmark. The state witness and DB mirror detect it in durable mode
  only; anchoring covers only up to the latest anchor (see the truncation status table).
- **CEV independence:** the observer runs inside the backend process. These checks show detection of a misbehaving
  adapter, **not** protection against a compromised backend process; a separate observer service is Phase C.
- **Latency is in-process Gate evaluation only.**
