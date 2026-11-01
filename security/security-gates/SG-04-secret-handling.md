# SG-04 Secret Handling & File Jail

**Status: TESTED**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Secrets are redacted before storage, proof and AI; file access is confined to the workspace with descriptor-relative, no-symlink reads.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG04-T1 | no raw secret in proof records | `test_sentinel.py::test_raw_secret_never_stored_in_proof` | as expected | PASS |
| SG04-T2 | provenance text redacted before storage | `test_v12_controls.py::test_provenance_text_is_redacted_before_storage` | as expected | PASS |
| SG04-T3 | only redacted text sent to AI | `test_hardening.py::test_only_redacted_text_is_sent_to_ai` | as expected | PASS |
| SG04-T4 | file jail: symlinks, traversal, absolute, NUL, directories, >1 MB | `test_v12_controls.py::test_read_jailed_rejects_symlinks_traversal_and_large_files` | as expected | PASS |
| SG04-T5 | gate rejects symlink inside workspace | `test_v12_controls.py::test_confine_path_rejects_symlink_inside_workspace` | as expected | PASS |
| SG04-T6 | demo response contains no fixture secret | `test_v12_controls.py::test_demo_is_public_isolated_and_never_touches_production_chain` | as expected | PASS |

## Open items (not claimed)
- Secret pattern is broad (may over-redact words like 'token').
