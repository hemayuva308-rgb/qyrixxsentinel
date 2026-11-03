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
- `human`: hand-written, reviewed cases (`benchmark/human/human-v1.cases.jsonl`), including the three Phase A
  findings verbatim and the documented homograph limitation;
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
- proof-chain tampering (modified field, deleted record, reordered records), which must be detected;
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

## 4. Results (actual run, `evidence/benchmark-v2/report.json`, commit `b2d9e48` + this change)
> Synthetic, isolated, written for this project. These numbers describe **this corpus only**. 100% here means "every
> case we wrote was handled as we expected"; it says nothing about attacks we did not think of.

| Tier | Cases | Attacks stopped | False-negative rate % | Safe controls allowed | False-positive rate % |
|---|---|---|---|---|---|
| template | 120 | 113 / 113 | 0.0 | 7 / 7 | 0.0 |
| human | 10 | 5 / 5 | 0.0 | 5 / 5 | 0.0 |
| model | 0 | 0 / 0 | n/a | 0 / 0 | n/a |
| **overall** | 130 | 118 / 118 | 0.0 | 12 / 12 | 0.0 |

The model tier is reported as 0 cases. No reviewed Llama output exists, because no credentials are configured.

| Attack group | Cases | Stopped |
|---|---|---|
| prompt_injection | 28 | 28 |
| unauthorized_tool_execution | 12 | 12 |
| replay | 4 | 4 |
| cross_agent | 5 | 5 |
| cross_task | 7 | 7 |
| policy_version | 4 | 4 |
| tainted_state_change | 8 | 8 |
| unicode_hostname_deception | 11 | 11 |
| approval_misuse | 7 | 7 |
| fail_closed_environment | 7 | 7 |
| ssrf_and_destination | 7 | 7 |
| data_exfiltration | 7 | 7 |
| argument_tampering | 7 | 7 |

| Measure | Result |
|---|---|
| Gate rules exercised | 22 of 22, including R0, R11 and R14–R20 and `LINEAGE_CYCLE_DETECTED`; not observed: none |
| Grant refusal codes exercised | GRANT_AGENT_MISMATCH, GRANT_TASK_MISMATCH, GRANT_POLICY_CHANGED, GRANT_REPLAY, PARAMS_DIGEST_MISMATCH |
| Proof tamper detection | 100.0% (modified field, deleted record, reordered records, modified hash). **Tail truncation is not detectable by the hash chain alone**; this is listed, not hidden (the state witness and anchoring address it) |
| CEV (honest and broken fixtures, HTTP + file) | 100.0% as expected, 0.0% INCONCLUSIVE |
| Cross-platform consistency (direct vs MCP mapping) | 27 / 27 pairs identical |
| Latency, in-process Gate only, 650 samples | p50 0.189 ms, p95 0.326 ms, p99 0.729 ms (machine-dependent) |
| Reproducibility | identical result digest across 5 repeats and a separate run: `582c48b807f569ec…` |
| Isolation | 0 egress; production proof chain unchanged (asserted by the run) |

### Comparison
| Benchmark | Cases | Attacks stopped | Safe allowed | False positives |
|---|---|---|---|---|
| v1 (10 plan cases, unchanged, isolated) | 10 | 7 / 7 | 3 / 3 | 0 |
| Phase A red-team corpus `template-v1` (before R19/R20) | 39 | 33 / 36 | 3 / 3 | 0 |
| Phase A corpus re-run today | 40 | 37 / 37 | 3 / 3 | 0 |
| **Benchmark v2** | **130** | **118 / 118** | **12 / 12** | **0** |

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
- **Exit code:** non-zero if the result digest differs between repeats or runs, or on any error or egress.
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
- **Latency is in-process Gate evaluation only.**
