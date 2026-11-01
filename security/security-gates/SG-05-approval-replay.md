# SG-05 Approval Replay & Atomicity

**Status: TESTED**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Approvals are exact-scope, expiring, single-use, admin-decided and consumed atomically with grant creation.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG05-T1 | approval single-use | `test_sentinel.py::test_approval_is_single_use` | as expected | PASS |
| SG05-T2 | approval bound to payload hash | `test_hardening.py::test_approval_bound_to_payload_hash` | as expected | PASS |
| SG05-T3 | approval expiry | `test_hardening.py::test_approval_expires` | as expected | PASS |
| SG05-T4 | 20 parallel resubmissions => exactly one grant | `test_v12_controls.py::test_20_parallel_resubmissions_yield_exactly_one_grant` | as expected | PASS |
| SG05-T5 | grant insertion failure rolls back approval | `test_v12_controls.py::test_grant_creation_failure_rolls_back_approval` | as expected | PASS |
| SG05-T6 | grant replay refused | `test_v12_controls.py::test_file_read_executes_through_grant_and_is_single_use` | as expected | PASS |
| SG05-T7 | no public consume endpoint | `test_v12_controls.py::test_no_public_approval_consume_endpoint` | as expected | PASS |

## Open items (not claimed)
- Approvals, evaluations and grants are in memory (lost on restart).
