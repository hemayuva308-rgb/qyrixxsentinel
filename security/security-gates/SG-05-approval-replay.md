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
| SG05-T8 | grant survives restart, executes once, replay refused after a 2nd restart | `test_persistence.py::test_records_survive_restart_and_grant_executes_once` | as expected | PASS |
| SG05-T9 | replay across two processes sharing PostgreSQL | `test_persistence.py::test_replay_across_two_processes_sharing_the_database` | as expected | PASS |
| SG05-T10 | approval consumed once across processes (R6) | `test_persistence.py::test_approval_consumed_once_across_processes` | as expected | PASS |
| SG05-T11 | expired / revoked grants refused after restart | `test_persistence.py::test_expired_and_revoked_grants_cannot_execute_after_restart` | as expected | PASS |
| SG05-T12 | real uvicorn process SIGKILLed and restarted over HTTP | `test_persistence.py::test_real_backend_process_restart_over_http` + `evidence/persistence-docker-restart.txt` | as expected | PASS |

## Open items (not claimed)
- Supported deployment: one backend process per database (a second process fails closed).
