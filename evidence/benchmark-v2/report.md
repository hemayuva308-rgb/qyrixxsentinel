# Benchmark v2 report (qyrix-benchmark/2.0)

> Synthetic, isolated corpus written for this project. Results describe this corpus only and are not a measure of general or real-world security.

Generated 2026-11-03T05:45:11.529976+00:00, commit `b2d9e48`, engine `gate-rules/2026-11-03.2`, isolated policy `37242fb53180f033`.

| Tier | Cases | Attack cases | Prevention | False negatives | Safe controls | False positives |
|---|---|---|---|---|---|---|
| template | 120 | 113 | 100.0 | 0.0 | 7 | 0.0 |
| human | 10 | 5 | 100.0 | 0.0 | 5 | 0.0 |
| model | 0 | 0 | None | None | 0 | None |
| **overall** | 130 | 118 | 100.0% | 0.0% | 12 | 0.0% |

| Group | Cases | Stopped |
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

System checks: proof tamper detection 100.0% (tail truncation not detectable by hash chain, listed); CEV pass 100.0%, INCONCLUSIVE 0.0%; cross-platform consistency 27/27.

Latency (ms, 650 samples): p50 0.189, p95 0.326, p99 0.729 - in-process Gate evaluation only (no network, no persistence); machine-dependent.

Reproducible: True across 5 repeats (digest `582c48b807f569ec`).

Rules observed: 22 of 22 Gate rules; not observed: none.

Not covered: Public benchmarks (AgentDojo: MIT, needs a live LLM agent; InjecAgent: no licence found) - not run; Live model-generated cases - none (no provider credentials); Whole-script homograph detection (UTS #39 confusables) - not implemented; such hosts never match ASCII allowlists; Real egress, real persistence/PostgreSQL behaviour and multi-process races - covered by unit/integration tests, not this benchmark; Proof tail truncation - not detectable by the hash chain alone (state witness / anchoring cover it).
