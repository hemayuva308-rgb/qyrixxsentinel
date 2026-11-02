# QYRIX SENTINEL — Production-Readiness Assessment (Assessment B, v1.3)

Date: 2026-11-02 · Branch `claude/hopeful-franklin-5ggx72` · Backend 1.3.0

**Verdict: NOT production-ready for paying, multi-tenant customers.** This build is a hardened **controlled beta**: a
single-replica deployment for design partners, under an operator who reads the "Blocked" and "Not implemented" rows below.
A successful hackathon demo is *not* evidence of production readiness, and this assessment does not treat it as such.
No external security audit or penetration test has been performed.

Classification legend
* **IT** Implemented and tested: automated tests or a recorded drill in this repository exercise it; evidence named.
* **IU** Implemented but not sufficiently tested: code exists; the test depth is not enough to rely on it in production.
* **NI** Not implemented.
* **BX** Blocked by external dependency: needs an account, credential, network access or third party that was not available.

## 1. Requirements and classification

### 1.1 Core security function (must never regress)
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| C1 | Deterministic default-deny Execution Gate (R0–R17), fail closed | IT | `test_sentinel.py`, `test_v12_controls.py`, `test_hardening.py` |
| C2 | Grant-only execution bound to stored parameters; single use; replay refused | IT | same + `test_persistence.py` (cross-process) |
| C3 | Monotone trust provenance (UUID v4, cycle detection, trust index) | IT | `test_sentinel.py`, `test_persistence.py` |
| C4 | SSRF / DNS rebinding / redirect / path-traversal defences | IT | `test_hardening.py`; live TLS-SNI pinning not verified (IU part) |
| C5 | Tamper-evident proof chain; PASS only with a verified anchor | IT | `test_anchor.py`, `test_sentinel.py` |
| C6 | Meta Llama advisory only (never authorises) | IT | `test_classifier.py` (mocked providers) |
| C7 | Live Meta Llama classification | BX | no `META_API_KEY`; provider hosts blocked from this environment |
| C8 | Day-1 LlamaFirewall / Pipelock baseline comparison | BX | LlamaFirewall install/run needs the owner's permission (refused by the environment's permission policy); Pipelock unreachable |

### 1.2 Tenant isolation
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| T1 | Tenant derived only from the credential | IT | `test_identity.py`, `test_tenancy.py` |
| T2 | Per-tenant provenance, approvals, evaluations, grants, chain, anchors, workspace, allowlist | IT | `test_tenancy.py` (real PostgreSQL), live E2E |
| T3 | Tenant filter in every SQL statement + PostgreSQL RLS (`FORCE`) under least-privilege role | IT | `test_row_level_security_…`, live DB check |
| T4 | Cross-tenant IDOR refused (grants, approvals, revocation, provenance, keys, proofs) | IT | `test_tenancy.py` |
| T5 | Multi-tenancy off by default; refused without PostgreSQL | IT | `test_tenancy.py` part 1 |
| T6 | Tenant disable cuts keys and sessions immediately | IT | `test_disabling_a_tenant_cuts_keys_and_sessions` |
| T7 | OS-level isolation between tenants (separate processes / containers / encryption keys) | NI | one process and one DB cluster for all tenants |
| T8 | Isolation verified by an external penetration test | NI | — |

### 1.3 Authentication, authorization, sessions
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| A1 | Strong operator tokens (≥ 24 chars, placeholders refused, constant-time) | IT | `test_hardening.py`, `test_placeholder_token.py` |
| A2 | Tenant API keys: random 256-bit, hashed, shown once, expiring, revocable | IT | `test_identity.py` |
| A3 | 7-role permission matrix enforced server-side on every route | IT | `test_rbac_matrix` |
| A4 | No privilege escalation through key minting | IT | `test_privilege_escalation_…` |
| A5 | Platform operator without tenant data access | IT | unit + live E2E |
| A6 | Server-side sessions: hashed, absolute + idle expiry, server-side logout | IT | `test_identity.py`, live E2E |
| A7 | Sessions die on key revocation, token rotation, tenant disable | IT | `test_identity.py`, `test_tenancy.py` |
| A8 | Browser never holds the credential (httpOnly SameSite=Strict session cookie) | IT | live E2E |
| A9 | CSRF protection on state-changing console calls | IT | proxy CSRF guard (live E2E), earlier `evidence/authenticated-flow.txt` |
| A10 | Human user accounts, invitations, SSO (OIDC/SAML), MFA | NI | credentials are role API keys |
| A11 | Per-object ownership inside a tenant | NI | — |
| A12 | Browser E2E of every console screen for every role | IU | API-level matrix is tested; UI per role is not |

### 1.4 API security and abuse controls
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| P1 | Strict request schemas (extra fields refused), size limits | IT | `test_v12_controls.py`, `test_identity.py` (422 cases) |
| P2 | Per-credential rate limit | IT | `test_per_credential_rate_limit` |
| P3 | Per-client + global auth-failure throttling; spoof-resistant client id | IT | `test_identity.py` (3 tests) |
| P4 | Rate limiting shared across replicas / restarts | NI | in-process limiter (risk T28) |
| P5 | Security headers / CSP | IT | `evidence/csp-check.txt`, route sweep; CSP still allows inline scripts (IU part) |
| P6 | TLS termination / HSTS | NI | deployment responsibility; Compose publishes HTTP on 127.0.0.1 only |
| P7 | Load and soak testing | NI | — |

### 1.5 Persistent data, proof anchoring, backup / recovery
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| D1 | Durable state in PostgreSQL; restart-safe; outage fails closed | IT | `test_persistence.py` (15, real clusters), Docker restart evidence |
| D2 | Append-only proof mirror and anchors (DB triggers) | IT | `test_proof_mirror_and_anchors_are_append_only` |
| D3 | DB password only via Docker secret / password file | IT | `test_persistence.py`, `evidence/docker-secret-validation.txt` |
| D4 | RFC 3161 anchoring with independent verification (`openssl ts -verify`) | IT | `test_anchor.py` against a local TSA |
| D5 | Anchoring against a public / commercial TSA | BX | outbound access to a public TSA not available here |
| D6 | Scheduled (automatic) anchoring | NI | anchoring is on demand |
| D7 | Consistent online backup (DB first, chain second, hash manifest) | IT | `test_backup.py`, Compose drill |
| D8 | Restore into a fresh cluster; wrong-order restore fails closed; replay-safe | IT | `test_backup.py` |
| D9 | Backup encryption, off-site custody, retention | NI | operator responsibility; not in tooling |
| D10 | Point-in-time recovery, HA / replication, measured RTO/RPO | NI | — |
| D11 | Alarm on silent total data loss (empty DB + chain) | NI | risk T29, reproduced in the drill |
| D12 | Encryption at rest | NI | depends on host / managed DB |
| D13 | Data retention / deletion policy per tenant | NI | evidence is append-only by design; policy undefined |

### 1.6 Monitoring and operational security
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| O1 | Readiness endpoint reflecting fail-closed state; container health checks | IT | `test_readiness_…`, Compose (backend/db/frontend healthy) |
| O2 | Token-protected Prometheus metrics, per-tenant gauges | IT | `test_metrics_…`, live E2E |
| O3 | Structured security events without secrets | IT | `test_security_events_never_contain_secrets`, live log scan |
| O4 | Alerting rules, dashboards, on-call runbooks | NI | metrics exist; nothing consumes them yet |
| O5 | Central log shipping / retention / tamper protection of logs | NI | stdout only |
| O6 | Least-privilege containers (read-only FS, no caps, no-new-privileges, non-root) | IT | `docker-compose.yml`; validated running |
| O7 | Network egress isolation of the backend (internal network) | IT | `evidence/docker-compose-validation.txt`; opt-in egress mode only application-level (IU) |
| O8 | Secrets out of code, history, logs, bundles | IT | secret scans; GitGuardian incidents 39389421/39389422 (false positives, removed) still need manual resolution in the GitGuardian dashboard |
| O9 | Separate DB login roles for migration vs runtime | NI | runtime connects as owner and drops to `qyrix_app` per transaction |
| O10 | Secrets manager integration / automated rotation | NI | env + Docker secret files |

### 1.7 Supply chain and dependencies
| # | Requirement | Class | Evidence / note |
|---|---|---|---|
| S1 | Python dependencies pinned with hashes, installed with `--require-hashes` | IT | `requirements-lock.txt`; suite green on the locked set (Python 3.12) |
| S2 | Known-vulnerability scan clean | IT | `npm audit` 0; `pip-audit` (PyPI service) clean — at commit time only |
| S3 | Continuous dependency scanning in CI | NI | no CI pipeline in this repository |
| S4 | Base images pinned by digest; SBOM; signed images | NI | tags only |
| S5 | Clean-base reproducible image build | IU | blocked during this run by Docker Hub 429; validated on the cached base layers (see evidence) |
| S6 | Failure modes of every external dependency documented | IT (docs) | `docs/DEPENDENCY_AND_FAILURE_MODES.md` |

### 1.8 Commercial SaaS features (separate phase, by decision)
| # | Requirement | Class | Note |
|---|---|---|---|
| B1 | Usage metering, quotas in the Gate path | NI | not required for security; deferred |
| B2 | Subscriptions, billing, invoices, payment provider | NI | deferred; pricing pages say "proposed" |
| B3 | Self-service signup / organisation management UI | NI | platform API only |

## 2. Security risks (open or partial)
| Risk | Severity | Why | Mitigation path |
|---|---|---|---|
| No external pen test of the tenancy boundary (T18 residual) | High | isolation is tested by its authors only | independent test before onboarding a second customer |
| No MFA / SSO; role API keys are bearer secrets | High | a leaked owner key = full tenant control until revoked | OIDC + MFA for humans; keep keys for machines with short TTLs |
| Silent total data loss (T29) | High | empty state boots as a fresh install | persist a deployment fingerprint / expected chain head outside the data volume; `/ready` fails if it regresses |
| Rate limits per process (T28) | Medium | restarts or replicas reset counters | shared limiter (PostgreSQL or Redis) before scaling out |
| Backups unencrypted by tooling (T26) | Medium | contain audit data and key hashes | age/GPG encryption + off-site custody in the backup script |
| Public TSA anchoring not verified (T11) | Medium | external non-repudiation unproven in the field | run against a commercial TSA with egress; schedule anchoring |
| Base images not digest-pinned, no SBOM (T27) | Medium | supply-chain drift | digest pins, SBOM, image signing in CI |
| CSP allows inline scripts (T12) | Medium | XSS impact larger if an injection exists | nonce-based CSP |
| Runtime connects as DB owner | Medium | an RCE in the app could bypass RLS by not dropping role | separate `qyrix_runtime` LOGIN role that is a member of `qyrix_app` only |
| Live Meta Llama unverified | Low (advisory) | cannot affect Gate decisions | run `llama_live_check.py` with real credentials |

## 3. Test evidence summary
* Backend: **210 passed, 1 skipped** (`evidence/pytest-junit.xml`, sha256 `cd749baf…fcfa5`); the skip is the opt-in live Llama test.
* Same suite on Python 3.12 with the hash-locked dependencies (before the final two regression tests): 208 passed, 1 skipped.
* Live Docker Compose: 3 services healthy; **22/22** live E2E checks; judging workflow ALL CHECKS PASSED; backup → loss → restore identical.
* Four defects were found **only** by the live stack and fixed with regression tests (read-only tenant workspace ⇒ 500,
  duplicate tenant ⇒ 500, wrong tenant name, frontend healthcheck binding) — evidence that unit tests alone are insufficient.
* Frontend: `tsc --noEmit` clean; production build succeeded inside the image; `npm audit` 0.
* Detailed record: `evidence/production-hardening-v1.3.txt`. Acceptance catalogue: `docs/SECURITY_ACCEPTANCE_TESTS.md`.

## 4. Architecture changes in this phase
1. **Identity layer** (`app/identity.py`): principals (tenant, role, credential), env tokens, hashed API keys, server-side sessions,
   permission matrix, platform principal, limiter, Memory/PostgreSQL stores.
2. **API layer** (`app/api.py`): all routes moved out of `gateway.py`, which is now domain logic only; every handler resolves
   its `GateContext` from the authenticated principal.
3. **Tenancy** (`app/tenancy.py`): lazily built per-tenant contexts; fail-closed construction.
4. **Database** (`migrations/002_tenancy_identity.sql`): tenants, api_keys, sessions; `tenant_id` on every data table;
   `qyrix_app` role; RLS `FORCE`; tenant-scoped primary keys for proofs.
5. **Persistence** (`app/persistence.py`): shared connection per DSN, per-transaction `SET LOCAL ROLE` + tenant setting.
6. **Observability** (`app/observability.py`): metrics, readiness, JSON security events.
7. **Frontend**: credential → session exchange; the cookie holds only `qss_`; logout revokes server-side; client id forwarded.
8. **Operations**: Compose health checks, workspace volume, identity/monitoring settings, `backup.sh` / `restore.sh` /
   `backup.py`, hash-locked Python dependencies, npm override.

Behaviour changes to note: `inspect` now requires owner/admin/security_reviewer (agent tokens get 403, per the plan's
"integrator inspection upload disabled"); `requested_by` in approval requests is set from the credential.

## 5. Next implementation priorities (in order)
1. **Data-loss alarm (T29)** — expected-state fingerprint outside the data volume; `/ready` fails on regression.
2. **Separate runtime DB login role** that cannot bypass RLS; migrations under a different role.
3. **Human identity**: OIDC SSO + MFA for console users; keep API keys for agents with short TTLs and rotation.
4. **Shared rate limiter + multi-replica readiness** (state in PostgreSQL, sticky-free), then load/soak tests.
5. **CI pipeline**: tests with PostgreSQL, `npm audit`/`pip-audit`, secret scan, SBOM, digest-pinned images, signed builds.
6. **Encrypted, scheduled, off-site backups** with a timed restore drill (measure RTO/RPO).
7. **Scheduled RFC 3161 anchoring** against a commercial TSA; anchor-age metric + alert.
8. **Alerting and runbooks** on the existing metrics (degraded Gate, persistence down, auth-failure spikes).
9. **External penetration test** focused on the tenant boundary and the execution adapters.
10. Then the separate commercial phase: metering, quotas, billing.
