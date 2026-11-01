# SG-01 No Direct Egress

**Status: PARTIAL**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
No tool action can reach the network except through the controlled adapter after an ALLOW, a recorded proof and a valid single-use grant.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG01-T1 | blocked attack makes zero external calls | `test_sentinel.py::test_attack_blocked_with_zero_external_calls` | as expected | PASS |
| SG01-T2 | evaluation performs no DNS lookup or egress | `test_hardening.py::test_decision_without_execute_does_no_dns_and_no_egress` | as expected | PASS |
| SG01-T3 | BLOCK issues no grant | `test_v12_controls.py::test_block_issues_no_grant` | as expected | PASS |
| SG01-T4 | demo never resolves DNS or calls an LLM | `test_v12_controls.py::test_demo_never_uses_real_adapters_or_llm` | as expected | PASS |
| SG01-T5 | benchmark attacks: external_calls_delta = 0 | `evidence/benchmark-results.json` | as expected | PASS |

## Open items (not claimed)
- Egress is measured by an in-process counter, not at the network layer.
- No container egress firewall restricting the backend to adapter traffic (NOT RUN / NOT IMPLEMENTED).
