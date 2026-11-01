# SG-07 RBAC & Ownership

**Status: PARTIAL**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Every endpoint is authenticated; admin vs agent separation of duty.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG07-T1 | unauthenticated and bad tokens rejected | `test_hardening.py::test_unauthenticated_and_bad_tokens_rejected` | as expected | PASS |
| SG07-T2 | agent cannot approve/reset/benchmark | `test_hardening.py::test_agent_cannot_approve_reset_or_benchmark` | as expected | PASS |
| SG07-T3 | unset/short tokens lock everyone out | `test_hardening.py::test_unset_tokens_lock_everyone_out` | as expected | PASS |
| SG07-T4 | placeholder tokens refused | `test_placeholder_token.py` | as expected | PASS |
| SG07-T5 | execute requires auth | `test_v12_controls.py::test_execute_requires_both_ids_and_auth` | as expected | PASS |

## Open items (not claimed)
- Organisations, tenants, per-object ownership, IDOR tests and the full role set: NOT IMPLEMENTED. Do not claim multi-tenancy.
