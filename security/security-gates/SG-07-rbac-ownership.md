# SG-07 RBAC & Ownership

**Status: PARTIAL**  (TESTED = all listed checks executed and passing; PARTIAL = listed checks pass but part of the control is missing)

## Control
Every endpoint is authenticated; a 7-role permission matrix is enforced server-side; tenants are isolated (per-tenant context + PostgreSQL RLS); the platform operator has no tenant data access.

## Evidence records
Build: branch `claude/hopeful-franklin-5ggx72`, backend v1.3.0 · Environment: Linux, Python 3.13, pytest 8, Chromium 153, Docker 29 (cloud container) ·
Owner: QYRIX SENTINEL engineering · Timestamp: 2026-11-02 (UTC) ·
Artifact: `evidence/pytest-junit.xml` (SHA-256 recorded in `docs/IMPLEMENTATION_REPORT.md`). Preconditions: `backend/tests/conftest.py`
(test tokens, temporary chain file and workspace, demo/eval mode on).

| Test ID | Action | Test / artifact | Expected vs actual | Result |
|---|---|---|---|---|
| SG07-T1 | unauthenticated and bad tokens rejected | `test_hardening.py::test_unauthenticated_and_bad_tokens_rejected` | as expected | PASS |
| SG07-T2 | agent cannot approve/reset/benchmark | `test_hardening.py::test_agent_cannot_approve_reset_or_benchmark` | as expected | PASS |
| SG07-T3 | unset/short tokens lock everyone out | `test_hardening.py::test_unset_tokens_lock_everyone_out` | as expected | PASS |
| SG07-T4 | placeholder tokens refused | `test_placeholder_token.py` | as expected | PASS |
| SG07-T5 | execute requires auth | `test_v12_controls.py::test_execute_requires_both_ids_and_auth` | as expected | PASS |
| SG07-T6 | full RBAC matrix, 7 roles × 7 operations | `test_identity.py::test_rbac_matrix` | as expected | PASS |
| SG07-T7 | key-minting privilege escalation blocked | `test_identity.py::test_privilege_escalation_via_key_creation_is_blocked` | as expected | PASS |
| SG07-T8 | platform operator has no tenant data access | `test_identity.py::test_platform_operator_has_no_tenant_data_access` | as expected | PASS |
| SG07-T9 | accountability fields from principal, not body | `test_identity.py::test_requested_by_and_decided_by_come_from_the_principal_not_the_body` | as expected | PASS |
| SG07-T10 | cross-tenant IDOR: grants, approvals, revocation, provenance, keys, proofs | `test_tenancy.py` (real PostgreSQL) | as expected | PASS |
| SG07-T11 | RLS blocks cross-tenant rows for `qyrix_app` with raw SQL | `test_tenancy.py::test_row_level_security_blocks_cross_tenant_rows_for_the_app_role` | as expected | PASS |
| SG07-T12 | sessions: logout, idle/absolute expiry, key revocation, token rotation | `test_identity.py` session tests | as expected | PASS |
| SG07-T13 | live Compose: cross-tenant execute refused, RLS in live DB | `evidence/production-hardening-v1.3.txt` §3 | as expected | PASS |

## Open items (not claimed)
- Human user accounts, invitations, SSO/SAML/OIDC and MFA: NOT IMPLEMENTED (credentials are API keys per role).
- Per-object ownership inside a tenant (e.g. "only the requester can cancel"): NOT IMPLEMENTED.
- Rate limits and auth throttles are per process; multi-replica deployments need a shared limiter.
- No external penetration test of the tenancy boundary.
