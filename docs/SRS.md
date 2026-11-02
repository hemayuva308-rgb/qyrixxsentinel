# QYRIX SENTINEL — Software Requirements Specification with traceability (v1.2)

Source of truth: `docs/QYRIX_SENTINEL_FINAL_MASTER_PLAN.md`. Status: **TESTED** (automated test executed and passing),
**IMPLEMENTED** (code, verified manually/in browser, no automated test), **PARTIAL**, **NOT IMPLEMENTED**.
Tests: `backend/tests/` (`test_sentinel.py`=S, `test_hardening.py`=H, `test_v12_controls.py`=V, `test_classifier.py`=C).

## Functional requirements

| ID | Requirement (plan §) | Code | Test / evidence | Status |
|---|---|---|---|---|
| FR-INS-1 | Extract domains, commands, secret refs from skill/README/config (9.1) | `gateway.inspect_text` | S `test_base64_destination_is_blocked`, C suite | TESTED |
| FR-INS-2 | Normalise obfuscation (base64, hxxp, [.], %-encoding) | `gateway.norm` | benchmark T1/T2 | TESTED |
| FR-INS-3 | Redact secrets before storage/logging/AI (9.1) | `_redact`, `step_ep`, `_prove`, `classify` | S `test_raw_secret_never_stored_in_proof`, H `test_only_redacted_text_is_sent_to_ai`, V `test_provenance_text_is_redacted_before_storage` | TESTED |
| FR-INS-4 | Size limits | pydantic `max_length` | — | IMPLEMENTED |
| FR-INS-5 | Reviewer-only inspection upload / Integrator 403 (11) | `identity.PERMISSIONS["inspect"]`, `api.inspect_ep` | `test_identity.py::test_integrator_inspection_upload_is_forbidden`, `test_rbac_matrix` | TESTED |
| FR-PRV-1 | TRUSTED/UNTRUSTED/UNVERIFIED, session starts UNVERIFIED (9.2) | `provenance.normalize_label` | V `test_step_ids_are_uuid4_and_labels_canonical`, S `test_unknown_label_never_becomes_trusted` | TESTED |
| FR-PRV-2 | UUID v4 lineage | `ProvenanceStore.add_step` | V same | TESTED |
| FR-PRV-3 | Child trust ≤ ancestor; never raised | `lowest()` | V `test_child_trust_never_exceeds_ancestor` | TESTED |
| FR-PRV-4 | 50-step window, delayed provenance retained | `_mem`, `_index` | S `test_memory_is_capped_at_50`, V `test_trust_survives_eviction_from_50_step_window`, benchmark L1 | TESTED |
| FR-PRV-5 | Cycle detection `LINEAGE_CYCLE_DETECTED` | `lineage()` | V `test_lineage_cycle_detected_and_blocked` | TESTED |
| FR-GATE-1 | Validate destination+action+data+auth before execution, default deny (9.3) | `evaluate` | H SSRF/default-deny suite | TESTED |
| FR-GATE-2 | AI never authorises | gate never calls `classify` | H `test_ai_can_never_allow_anything`, C `test_gate_decision_never_depends_on_classification` | TESTED |
| FR-GATE-3 | Fail closed on error / proof failure | `evaluate` | H `test_proof_write_failure_fails_closed` | TESTED |
| FR-GATE-4 | Block before adapter invocation / egress | grant-only execution | S `test_attack_blocked_with_zero_external_calls`, V `test_block_issues_no_grant`, benchmark `external_calls_delta=0` | TESTED |
| FR-EXE-1 | `/tools/execute` accepts only `gate_evaluation_id`+`grant_id`; 400 `CLIENT_PARAMS_NOT_ALLOWED` before lookup (11) | `execute_grant` | V `test_client_params_rejected_before_lookup` | TESTED |
| FR-EXE-2 | Server loads immutable params, recomputes digest | `execute_grant` | V `test_grant_expiry_and_tampered_params_refused` | TESTED |
| FR-EXE-3 | Grant single-use, bound to its evaluation, expiring | `_new_grant`, `execute_grant` | V `test_file_read_executes_through_grant_and_is_single_use`, `test_grant_bound_to_its_own_evaluation` | TESTED |
| FR-APR-1 | Approval exact scope, expiring, single-use | `_digest`, `evaluate` | S/H approval tests | TESTED |
| FR-APR-2 | Consumption atomic with grant creation; 20 parallel ⇒ one | `evaluate` critical section | V `test_20_parallel_resubmissions_yield_exactly_one_grant`, H `test_20_concurrent_uses…` | TESTED |
| FR-APR-3 | Grant insertion failure rolls back approval | `evaluate` | V `test_grant_creation_failure_rolls_back_approval`, `test_proof_failure_rolls_back_grant_and_approval` | TESTED |
| FR-APR-4 | No public consume endpoint; no public CONSUMED status | routes | V `test_no_public_approval_consume_endpoint` | TESTED |
| FR-APR-5 | Agents cannot approve | `require_admin` | H `test_agent_cannot_approve_reset_or_benchmark` | TESTED |
| FR-NET-1 | Validate all A/AAAA answers, reject mixed, pin IP, no second lookup, keep hostname for SNI (11) | `netguard`, `HttpAdapter` | H `test_execute_resolves_validates_pins…`, `test_dns_answer_in_private_range…` | TESTED (mocked DNS); live TLS NOT RUN |
| FR-NET-2 | Every redirect needs fresh Gate + grant; max 5 | `redirect_of`, R15/R16 | V `test_redirect_is_not_followed_and_needs_fresh_gate` | TESTED |
| FR-NET-3 | Strip credentials cross-host | adapter sends none | code review | IMPLEMENTED (vacuous: no credentials sent) |
| FR-FILE-1 | Descriptor-relative jail, no symlinks, no traversal/races, 1 MB streaming limit (11) | `adapter.read_jailed`, `confine_path` | V `test_read_jailed_rejects…`, `test_confine_path_rejects_symlink…`, H file tests | TESTED |
| FR-PRF-1 | Canonical JSON + SHA-256 chain, append-only (9.4) | `proof.py`, `_record` | V `test_new_records_are_canonical_v2…` | TESTED |
| FR-PRF-2 | Empty bundle fails; malformed hash FAIL; tampered FAIL; no anchor ⇒ PARTIAL_UNANCHORED | `verify_bundle` | V `test_bundle_verification_outcomes` | TESTED |
| FR-PRF-3 | No raw secrets in proof | `_prove` | S `test_raw_secret_never_stored_in_proof` | TESTED |
| FR-PRF-4 | Trusted external anchoring of the chain head | `app/anchor.py`, `proof.evaluate_anchors` | `tests/test_anchor.py` (local TSA) | IMPLEMENTED_NOT_VERIFIED (public TSA) |
| FR-PRF-5 | Signing key isolation/revocation; clock anomaly handling | — | — | NOT IMPLEMENTED |
| FR-PER-1 | Durable provenance, approvals, evaluations, grants, proof metadata in PostgreSQL with migrations | `app/persistence.py`, `migrations/` | `tests/test_persistence.py`, `evidence/persistence-docker-restart.txt` | TESTED |
| FR-PER-2 | Expired/revoked grants never execute; replay rejected across restarts and processes | `execute_grant`, `consume_grant`, `revoke_grant` | `tests/test_persistence.py` | TESTED |
| FR-PER-3 | DB outage never creates an authorisation bypass | R17, fail-closed writes | `test_database_outage_fails_closed_and_recovers`, Docker outage evidence | TESTED |
| FR-LLM-1 | Meta Llama advisory classification, strict schema, timeouts, fallback (10) | `classify` | C suite incl. real-socket `test_real_provider_timeout_falls_back_within_budget`, `test_real_provider_failures_never_produce_an_allow` | TESTED (failure paths on real sockets); live **NOT LIVE VERIFIED** (`evidence/llama-verification.txt`) |
| FR-DEMO-3 | Judging workflow ATTACK→INSPECT→PROVENANCE→BLOCK→PROOF→SAFE against a running deployment, every claim asserted | `scripts/demo_judging.py` | `evidence/demo-judging-console.txt` | TESTED |
| FR-DEMO-1 | Public demo: fixed scenarios, isolated state, separate chain, no egress, rate limited (5 §6) | `demo.py`, `/api/demo` | V demo tests | TESTED |
| FR-DEMO-2 | UI shows ALLOW/BLOCK only after backend response; labelled SIMULATED DEMO | `LiveDemo.tsx` | Playwright run (validation report) | IMPLEMENTED |
| FR-BEN-1 | Exact 10-case benchmark 3/3/2/2 with prevention, FP, completion, latency (13) | `benchmark_cases`, `run_benchmark` | V `test_benchmark_exact_composition_and_results`, `evidence/benchmark-results.json` | TESTED |
| FR-WEB-1 | Public light website routes `/`, features, how-it-works, pricing, security, forensic-lab, contact | `src/app/(site)` | route sweep (validation report) | IMPLEMENTED |
| FR-WEB-2 | Dashboard at `/dashboard`, forensic at `/forensic`, login preserved, dark theme preserved | `src/app/(app)` | Playwright authenticated run | IMPLEMENTED |
| FR-WEB-3 | Original logo SVG + favicon | `public/brand`, `app/icon.svg` | — | IMPLEMENTED |
| FR-WEB-4 | Reduced motion, responsive, keyboard focus | `globals.css`, components | sweep at 390/820/1440 px, no overflow | IMPLEMENTED (no automated a11y suite) |
| FR-SAAS-1 | Organisations, users, invitations, RBAC roles, tenant isolation (8) | `identity.py`, `tenancy.py`, `api.py`, `002_tenancy_identity.sql` | `test_identity.py`, `test_tenancy.py` (real PostgreSQL) | PARTIAL — tenants, 7 roles, API keys, sessions, isolation + RLS TESTED; human users, invitations, SSO/MFA NOT IMPLEMENTED |
| FR-SAAS-2 | Usage metering, quotas, plans enforced server-side | — | — | NOT IMPLEMENTED |
| FR-SAAS-3 | Payment integration | — | — | NOT IMPLEMENTED (pricing labelled proposed) |
| FR-PDF-1 | Forensic report export (PDF) | JSON bundle export only | — | PARTIAL |
| FR-POL-1 | Immutable policy versions; draft vs publish | — | — | NOT IMPLEMENTED (policy is code) |

## Non-functional
| ID | Requirement | Status |
|---|---|---|
| NFR-1 | Gate latency measured | benchmark avg/max recorded in evidence |
| NFR-2 | No secrets in source, bundle, logs | bundle grep + secret scan in validation report |
| NFR-3 | Linear-time parsing (no ReDoS) on 100 KB input | existing regressions in C/H suites |
| NFR-4 | Container hardening | read-only, cap_drop ALL, no-new-privileges, non-root, internal-only backend network — verified with `docker inspect` (`evidence/docker-compose-validation.txt`) |
| NFR-5 | Content-Security-Policy | enforced, inline scripts allowed (`evidence/csp-check.txt`) |
