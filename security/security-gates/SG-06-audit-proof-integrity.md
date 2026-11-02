# SG-06 Audit / Proof Integrity

**Status: PARTIAL**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Canonical JSON SHA-256 hash chain, durable before execution; tampering, deletion and reordering are detected.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.2.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-01 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG06-T1 | canonical v2 record hash; PARTIAL_UNANCHORED never PASS | `test_v12_controls.py::test_new_records_are_canonical_v2_and_verify_partial_unanchored` | as expected | PASS |
| SG06-T2 | bundle: empty 422, tampered/malformed/reordered/missing FAIL | `test_v12_controls.py::test_bundle_verification_outcomes` | as expected | PASS |
| SG06-T3 | proof write failure blocks | `test_hardening.py::test_proof_write_failure_fails_closed` | as expected | PASS |
| SG06-T4 | corrupted chain degrades gate to block-all | `test_hardening.py::test_corrupted_chain_degrades_gate_to_block_all` | as expected | PASS |
| SG06-T5 | offline verification of benchmark bundle | `evidence/benchmark-proof-bundle.json + scripts/verify_proof.py` | as expected | PASS |
| SG06-T6 | RFC 3161 anchor covering head ⇒ PASS; growth ⇒ PARTIAL; tamper / mismatch / forged token ⇒ FAIL | `test_anchor.py` (13 tests, real local TSA) | as expected | PASS |
| SG06-T7 | token independently verifiable with plain `openssl ts -verify` | `test_anchor.py::test_token_independently_verifiable_with_openssl` | as expected | PASS |
| SG06-T8 | append-only proof mirror (UPDATE/DELETE rejected) | `test_persistence.py::test_proof_mirror_and_anchors_are_append_only`, `evidence/persistence-docker-restart.txt` | as expected | PASS |
| SG06-T9 | truncated chain file vs DB mirror ⇒ gate degraded | `test_persistence.py::test_truncated_chain_file_vs_mirror_degrades_gate` | as expected | PASS |

## Open items (not claimed)
- Anchoring with a public/independent RFC 3161 TSA: NOT VERIFIED (blocked by the build environment's network policy). S3 Object Lock: NOT IMPLEMENTED.
- Signing key isolation and revocation: NOT IMPLEMENTED.
- Clock-anomaly DEGRADED/FAIL/recovery: NOT IMPLEMENTED.
