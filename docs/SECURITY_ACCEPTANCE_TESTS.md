# QYRIX SENTINEL — Security Acceptance Tests (v1.4)

A release is acceptable only if **every automated test below passes** and every **manual/environment** item is either
re-run for that release or explicitly listed as not run. Run: `cd backend && pip install -r requirements-dev.txt && python -m pytest -q`
(PostgreSQL binaries must be installed for the database tests; without them those tests SKIP and the release is NOT acceptable).

Status at commit time (2026-11-02, v1.4): **302 passed, 1 skipped** (the skipped test is the opt-in live Meta Llama call).
Live Compose E2E: 30/30 (v1.4). Evidence: `evidence/pytest-junit.xml`, `evidence/production-hardening-v1.4.txt`.

## SAT-1 Authentication
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-1.1 | Missing, malformed, oversized, unknown credentials ⇒ 401 | `test_identity.py::test_malformed_credentials_rejected`, `test_hardening.py::test_unauthenticated_and_bad_tokens_rejected` |
| SAT-1.2 | Unset / short / placeholder operator tokens lock everyone out | `test_hardening.py::test_unset_tokens_lock_everyone_out`, `test_placeholder_token.py` |
| SAT-1.3 | API keys stored as hashes only, shown once, revocable, expiring | `test_keys_are_stored_hashed_shown_once_and_revocable`, `test_expired_key_is_rejected` |
| SAT-1.4 | Brute force throttled per client and globally; spoofed client header ignored unless trusted | `test_auth_failure_throttling_blocks_brute_force`, `test_global_auth_failure_ceiling`, `test_client_header_ignored_unless_trusted` |

## SAT-2 Sessions
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-2.1 | Session exchange returns `qss_`, stores only its hash; logout revokes server-side | `test_session_lifecycle_and_logout`; live E2E "logged-out session cannot be replayed" |
| SAT-2.2 | Absolute and idle expiry enforced | `test_session_absolute_and_idle_expiry` |
| SAT-2.3 | Key revocation, operator-token rotation and tenant disable kill sessions | `test_revoking_a_key_kills_its_sessions`, `test_rotating_an_env_token_kills_its_sessions`, `test_tenancy.py::test_disabling_a_tenant_cuts_keys_and_sessions` |
| SAT-2.4 | Sessions cannot mint sessions; platform cannot open console sessions; unknown fields 422 | `test_sessions_cannot_mint_sessions_and_platform_cannot_open_one` |
| SAT-2.5 | Browser holds only an httpOnly SameSite=Strict session cookie, never the credential | live E2E (`evidence/production-hardening-v1.3.txt` §3) |

## SAT-3 Authorization
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-3.1 | 7 roles × 7 operations match the permission matrix exactly (allowed ⇒ 200, else 403) | `test_rbac_matrix` (parametrised) |
| SAT-3.2 | Agent can never approve, revoke or manage keys; integrator cannot upload for inspection | `test_agent_can_never_approve_or_revoke_or_manage_keys`, `test_integrator_inspection_upload_is_forbidden` |
| SAT-3.3 | No privilege escalation through key creation; no tenant field accepted | `test_privilege_escalation_via_key_creation_is_blocked` |
| SAT-3.4 | Platform operator has no tenant data access | `test_platform_operator_has_no_tenant_data_access`; live E2E |
| SAT-3.5 | Accountability fields come from the principal | `test_requested_by_and_decided_by_come_from_the_principal_not_the_body` |

## SAT-4 Tenant isolation (real PostgreSQL)
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-4.1 | Multi-tenancy off by default; refused without durable persistence | `test_tenant_principal_refused_when_multi_tenancy_disabled`, `test_multi_tenancy_requires_durable_persistence`, `test_tenant_context_refuses_without_database` |
| SAT-4.2 | Separate state per tenant; default admin cannot see other tenants | `test_contexts_are_separate_objects_with_separate_state`, `test_default_tenant_admin_cannot_reach_other_tenants` |
| SAT-4.3 | Cross-tenant grant execution, approval decision, grant revocation, provenance lineage, key revocation refused (IDOR) | `test_cross_tenant_grant_execution_is_refused`, `test_cross_tenant_approvals_and_revocation_are_refused`, `test_cross_tenant_provenance_lineage_is_refused`, `test_keys_are_tenant_scoped` |
| SAT-4.4 | Workspaces and destination allowlists are per tenant; new tenants deny all destinations | `test_workspaces_are_isolated`, `test_allowlists_are_per_tenant_and_default_deny` |
| SAT-4.5 | RLS hides other tenants' rows, rejects forged inserts, denies identity tables and DELETE/UPDATE for `qyrix_app` | `test_row_level_security_blocks_cross_tenant_rows_for_the_app_role`; live E2E |
| SAT-4.6 | Tenant context failures fail closed (503), duplicate/unknown tenants are clean errors | `test_unbuildable_tenant_context_fails_closed`, `test_duplicate_and_unknown_tenants_are_clean_errors` |

## SAT-5 Execution Gate and evidence (unchanged core; must stay green)
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-5.1 | Default deny, R0–R17, grant-only execution, param binding, replay refusal | `test_sentinel.py`, `test_v12_controls.py`, `test_hardening.py` |
| SAT-5.2 | SSRF, DNS rebinding, redirects, path traversal / symlinks | `test_hardening.py`, `test_v12_controls.py` |
| SAT-5.3 | Meta Llama is advisory only; failures fall back without affecting the Gate | `test_classifier.py` |
| SAT-5.4 | Proof chain tamper detection; PASS only with a verified RFC 3161 anchor on the head | `test_anchor.py`, `test_sentinel.py` |

## SAT-6 Persistence, backup and recovery (real PostgreSQL)
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-6.1 | State survives restart; grants execute once across processes; DB outage ⇒ R17 | `test_persistence.py` (15 tests) |
| SAT-6.2 | A DB row alone never authorises; mirror tampering degrades the Gate | `test_a_database_row_alone_never_authorises`, `test_truncated_chain_file_vs_mirror_degrades_gate` |
| SAT-6.3 | Backup restores into a fresh cluster with identity, RLS and replay protection intact | `test_backup.py::test_backup_restores_into_a_fresh_cluster` |
| SAT-6.4 | Wrong-order restore fails closed; older DB + newer chain stays replay-safe | `test_chain_older_than_database_fails_closed`, `test_older_database_newer_chain_stays_replay_safe` |
| SAT-6.5 | Tampered backups refused; backups never overwrite; restore never silently overwrites a live chain; DB password not in argv | remaining `test_backup.py` tests |
| SAT-6.6 | Compose backup → data loss → restore gives an identical chain head and row count | manual drill, `evidence/production-hardening-v1.3.txt` §4 (re-run per release) |

## SAT-7 Monitoring and operational security
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-7.1 | `/ready` is 503 whenever the Gate is degraded or persistence is down | `test_readiness_reflects_fail_closed_state` |
| SAT-7.2 | `/metrics` disabled without a token; tenant credentials refused; no secrets in output | `test_metrics_endpoint_requires_its_own_token` |
| SAT-7.3 | Security events emitted and contain no tokens, keys, sessions, secrets or destinations | `test_security_events_never_contain_secrets`; live log scan |
| SAT-7.4 | Per-credential rate limit | `test_per_credential_rate_limit` |
| SAT-7.5 | No secrets in the repository | secret scan (`evidence/secret-scan.txt`, re-run per release) |
| SAT-7.6 | Dependencies: `npm audit` 0 and `pip-audit` clean on `requirements-lock.txt` | manual, per release |

## SAT-8 v1.4 additions
| ID | Acceptance criterion | Test |
|---|---|---|
| SAT-8.1 | Runtime DB login is least-privilege; over-privileged account refused (also after auto-recovery) | `test_db_privileges.py` (14) |
| SAT-8.2 | Missing tenant context sees/writes nothing; forged cross-tenant writes rejected; no evidence rewriting; no OS/DDL escape; no pooled context leak | `test_db_privileges.py` |
| SAT-8.3 | Data loss / replacement / rollback => RECOVERY_REQUIRED; acceptance audited in the chain | `test_integrity.py` (15) |
| SAT-8.4 | Human accounts: invitations, scrypt, TOTP (RFC vectors, replay), recovery codes, resets, lock-out, enumeration resistance, session revocation, no secrets in logs | `test_accounts.py` (22) |
| SAT-8.5 | Shared rate limits: exact admission under concurrency, restart, multiple instances, outage behaviour | `test_ratelimit.py` (7) |
| SAT-8.6 | Signed client identity; forged/stale/unsigned headers not trusted | `test_identity.py` |
| SAT-8.7 | Encrypted backups; wrong key / corruption / forged manifest / missing / swapped refused; interrupted restores safe | `test_backup.py` (13) |
| SAT-8.8 | Alerts fire, de-duplicate, never block, carry no secrets | `test_alerts.py` (14) |
| SAT-8.9 | Every protected route refuses bad credentials; platform/tenant separation | `test_route_auth.py` (9) |

## Not covered (must not be claimed)
External penetration test · load / soak testing · multi-replica behaviour · public TSA anchoring · live Meta Llama ·
MFA / SSO · encrypted backups · disaster-recovery RTO/RPO measurement · browser E2E of every console screen per role.
