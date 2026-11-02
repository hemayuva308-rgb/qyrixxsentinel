# QYRIX SENTINEL — Production-Readiness Assessment (v1.4)

Date 2026-11-02 · branch `claude/hopeful-franklin-5ggx72` (local commits after `bfbea14`) · backend 1.4.0.
Supersedes the v1.3 assessment (history in git).

## Verdict: **CONTROLLED BETA READY**

Fit for a small number of design-partner tenants on a single-replica deployment, operated with the runbooks,
monitoring and backups described in `docs/OPERATIONS.md` and `docs/DISASTER_RECOVERY.md`. **Not** a production
candidate: no independent penetration test has been performed, the CI pipeline has not yet run on GitHub,
multi-replica operation and load are untested, and the items under "Not implemented" remain. Passing tests (302) and a
passing 10-case benchmark are author-written evidence, not proof of security.

Categories: **IV** implemented and verified (automated tests and/or a recorded live drill in this repository — by the
authors) · **IN** implemented but not independently/fully verified · **P** partially implemented · **NI** not
implemented · **BX** blocked by an external dependency. Nothing has been independently verified by a third party yet.

## 1. Security foundation

| Requirement | Class | Evidence / gap |
|---|---|---|
| Deterministic default-deny Gate is the sole execution authority; grant-only execution | IV | core suites; benchmark 7/7 blocked, 3/3 allowed, 0 FP, 0 external calls |
| Meta Llama advisory only (never authorises); timeout / malformed / failure / hostile-output paths | IV | `test_classifier.py` |
| Meta Llama live provider verification | BX | no credentials; provider hosts unreachable |
| Least-privilege runtime DB account; admin-only migrations; startup self-check | IV | `test_db_privileges.py`, live DB roles |
| RLS on all tenant data incl. credentials; missing context fails closed; no pooled context leak | IV | adversarial SQL + concurrency tests, live RLS |
| Tenant isolation at API level (IDOR, client hints ignored, unknown fields refused) | IV | `test_tenancy.py`, `test_route_auth.py` |
| Isolation against code execution inside the backend | NI | one runtime role serves all tenants; needs per-tenant roles/processes |
| Silent data-loss detection + audited recovery | IV | `test_integrity.py`, live total-loss drill |
| Human accounts, invitations, RBAC, TOTP MFA, recovery codes, resets, lock-out, audit | IV | `test_accounts.py`, live E2E |
| SSO (OIDC/SAML), WebAuthn, breached-password screening | NI | — |
| E-mail delivery | P | signed webhook boundary; no relay shipped or configured |
| Sessions: server-side, expiry, revocation on every privilege change | IV | identity + accounts tests |
| Distributed rate limiting (atomic, restart-proof, multi-instance) | IV | `test_ratelimit.py` incl. two real processes |
| Spoof-resistant client identity | IV | signed-header tests, live X-Forwarded-For test |
| Multi-replica operation under load | IN | design supports it; not load-tested |
| Encrypted, signed backups; verified staged restore | IV | `test_backup.py`, live drill |
| PITR / WAL archiving; RTO measured at production scale | NI | RTO measured only on small synthetic data |
| Secret-safe structured security events; alert rules; runbooks | IV | `test_alerts.py`, promtool, `docs/OPERATIONS.md` |
| Alert delivery to an on-call system | P | signed webhook + Prometheus rules; no receiver configured |
| CI: tests, typecheck, build, audits, hash + lockfile checks, gitleaks, bandit, CodeQL, compose validation, SBOM, Grype | IN | workflow written, actionlint-clean, every step run locally except CodeQL/Grype; **not yet run on GitHub** |
| Digest-pinned base images; clean no-cache build | IV | clean build recorded (registry mirror; CA injection the only difference) |
| Signed images / SBOMs, provenance attestations | NI | — |
| Proof anchoring with a public TSA | BX | public TSAs unreachable here; local TSA verified |
| Independent penetration test | NI | plan ready: `docs/SECURITY_TEST_PLAN.md` |
| LlamaFirewall comparison | P | offline scanners only (0/7 attacks flagged); model/LLM scanners not run |
| Pipelock comparison | BX | release located; execution refused by this environment's permission policy |

## 2. Product requirements (separate phase; not security-blocking)

| Requirement | Class |
|---|---|
| Organisation onboarding | P — platform API creates tenant + invites owner; no self-service UI |
| Human accounts and invitations | IV — API + login / invite / reset UI; no member-management page |
| Workspace management | P — per-tenant workspaces created automatically; no management UI |
| API-key lifecycle | IV (API) / P (no UI) |
| Usage metering, quotas | NI |
| Billing integration | NI |
| Customer documentation | P — operator documentation only |
| Support workflow | NI |
| Customer data retention and deletion | NI — evidence is append-only by design; policy undefined |
| Tenant-level audit export | P — per-tenant proof bundle; no export of security events / membership history |
| Service-level monitoring (SLOs) | P — metrics + readiness; no SLO definitions |

## 3. Remaining risks

**Critical:** none known and unmitigated in the reviewed code — a statement limited by the absence of an independent test.

**High:**
1. No independent penetration test.
2. Code execution inside the backend process can select any tenant's RLS context (shared runtime role).
3. CI pipeline not yet executed on GitHub; OS-package vulnerability scanning of images runs only there.
4. Multi-replica behaviour and load / DoS resilience untested (scrypt cost, DB connection exhaustion).
5. No SSO / WebAuthn; MFA is TOTP only.

**Medium:** no PITR; the witness is defeated by an attacker holding DB + chain + witness + witness key when
`QYRIX_EXPECTED_INSTALL_ID` is not set; CSP allows inline scripts; public TSA anchoring unverified; artifacts unsigned;
e-mail and alert receivers are operator-provided; DNS has no explicit timeout.

## 4. Security issues found and fixed in this round
1. **The runtime DB account was a superuser with BYPASSRLS** (Docker `POSTGRES_USER`); RLS relied on `SET LOCAL ROLE`.
2. **Fail-open recovery:** auto-recovery flipped a never-attached context to `postgres` without privilege/schema checks.
3. Silent total data loss was undetectable.
4. **Per-IP limits bypassable** through a client-supplied `X-Forwarded-For`; the demo trusted an unsigned header.
5. The Gate silently ignored unknown request fields (now 422).
6. The old RLS test passed on a column error rather than on RLS (rewritten; adversarial suite added).
7. The alert metric call crashed (label collision) and a defensive wrapper hid it (fixed; engine errors now alert).
8. Events logged the internal context name instead of the tenant id; secrets were filtered only by field name.
9. The SBOM omitted every Python package (lock-file name).

## 5. Next priorities
1. Independent penetration test (scenarios A and B in the test plan); fix and re-test findings.
2. Run the CI workflow on GitHub; resolve any Grype / CodeQL findings; sign images and SBOMs.
3. Per-tenant database roles (or processes) to contain code execution in the backend.
4. Load and multi-replica testing; pool and scrypt cost tuning; edge DoS controls.
5. PITR (WAL archiving) and a timed production-scale restore from off-site storage.
6. SSO (OIDC) + WebAuthn; breached-password check; a real mail relay.
7. Scheduled public-TSA anchoring with an anchor-age alert.
8. Product phase: member / key management UI, retention and deletion policy, tenant audit export, metering, billing.
