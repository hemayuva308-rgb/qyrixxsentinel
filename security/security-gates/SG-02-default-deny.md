# SG-02 Default Deny & Schema Validation

**Status: TESTED**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Unknown tool, destination, label or lineage blocks; strict request schemas; execution rejects client parameters.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG02-T1 | unknown tool and shell blocked | `test_hardening.py::test_unknown_tool_and_shell_blocked` | as expected | PASS |
| SG02-T2 | unapproved hosts, IPs, ports, schemes blocked | `test_hardening.py::test_unapproved_public_host_and_ip_and_ports_blocked` | as expected | PASS |
| SG02-T3 | missing/unknown lineage blocks | `test_hardening.py::test_missing_or_unknown_lineage_is_not_a_taint_bypass` | as expected | PASS |
| SG02-T4 | client params rejected with 400 before lookup | `test_v12_controls.py::test_client_params_rejected_before_lookup` | as expected | PASS |
| SG02-T5 | demo accepts only fixed scenario ids | `test_v12_controls.py::test_demo_accepts_only_fixed_scenarios` | as expected | PASS |
| SG02-T6 | sole-path enforcement | `test_hardening.py::test_sole_path_is_enforced` | as expected | PASS |

## Open items (not claimed)
- Policy is code; immutable policy versions with draft/publish separation are NOT IMPLEMENTED.
