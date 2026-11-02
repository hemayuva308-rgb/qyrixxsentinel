# QYRIX SENTINEL — Security Test Plan (v1.4, prepared for an independent penetration test)

**Status: NO independent penetration test has been performed.** This plan prepares one. Section 3 lists, per threat,
what is already covered by automated tests in this repository (author-written — they prove the cases the authors
thought of, not the absence of others) and what an **external tester must do**. Section 4 lists the logistics.

## 1. Scope

| In scope | Out of scope (unless agreed) |
|---|---|
| Backend API `/api/v1/*` (FastAPI), frontend (Next.js) incl. `/api/session`, `/api/account/*`, `/api/proxy/*`, `/api/demo` | Third-party providers (Meta Llama / Baseten, TSA, mail relay) |
| PostgreSQL schema, roles, RLS as deployed by `app.migrate` | Host OS / hypervisor / cloud account |
| Docker Compose deployment (`docker-compose.yml`), images, secrets handling | Denial of service against shared infrastructure |
| Execution Gate, adapters (`http`, `file.read`), proof chain, anchoring, backup/restore tooling | Social engineering |

Architecture and trust boundaries: `docs/ARCHITECTURE.md`, `security/threat-model.md`. Roles and permissions:
`docs/API_SPECIFICATION.md`. Expected fail-closed behaviour: `docs/DEPENDENCY_AUDIT.md`.

## 2. Test environment to provide the tester
1. A fresh Compose deployment from a tagged commit (`docker compose up` with generated secrets), `QYRIX_MULTI_TENANT=1`,
   `QYRIX_PLATFORM_TOKEN` set, TLS proxy in front, `QYRIX_TRUSTED_PROXY_HOPS=1`.
2. Two tenants (`acme`, `globex`) with: one owner account each (password + TOTP), API keys of every role, an approver
   human account, sample provenance / evaluations / grants / approvals, an RFC 3161 anchor if a TSA is reachable.
3. Grey-box material: this repository, `docs/*`, the runtime DB password **only if** RLS testing from a compromised-backend
   position is in scope (scenario B below).
4. Two scenarios: **A** external attacker / malicious tenant user (black/grey box); **B** assumed breach — code execution
   inside the backend container (to verify blast radius claims: RLS limits, no superuser, no evidence rewriting).

## 3. Threat-driven test cases

Legend — *Auto*: automated test(s) in this repo (file::name or file); *External*: must be performed by the tester.

| # | Area | Objective | Auto (already passing) | External tester |
|---|---|---|---|---|
| T-01 | Authentication bypass | No protected route without valid credentials | `test_route_auth.py` (all 38 protected routes × 6 bad credentials); `test_identity.py` malformed credentials | Header smuggling, HTTP desync between proxy/Next/uvicorn, path normalisation (`/api/v1/../`, encoded slashes, case), method override headers |
| T-02 | Authorization bypass / RBAC | Role matrix server-side; no escalation | `test_identity.py::test_rbac_matrix`, privilege-escalation tests; `test_accounts.py::test_membership_management_rules` | Mass assignment on every body; race conditions on role changes; parameter pollution; JSON type confusion |
| T-03 | Cross-tenant access (IDOR) | No read/write of another tenant via any id | `test_tenancy.py` (grants, approvals, revocation, provenance, keys, proofs, client hints); live Compose E2E | Enumerate every id-taking route with ids from the other tenant; timing / error-message oracles; export endpoints |
| T-04 | PostgreSQL RLS bypass | Runtime account cannot cross tenants by SQL | `test_db_privileges.py` (14 adversarial tests as the real runtime login: no-context, forged inserts, column privileges, `row_security=off`, SET ROLE, COPY PROGRAM, DDL) | Scenario B: attempt every escape with the runtime credential; confirm the documented residual (runtime can choose tenant context) and nothing beyond it; SECURITY DEFINER functions for search_path / injection issues |
| T-05 | API-key theft & replay | Stolen key usable only until revoked; hashes only at rest | `test_identity.py` (hashed, revocation kills sessions, expiry) | Key leakage in logs/errors/referrers; replay after revocation across replicas |
| T-06 | Session hijacking | Sessions server-side, httpOnly, revocable, expiring | `test_identity.py` session tests; `test_accounts.py` (password change / reset / role change revoke) ; E2E cookie flags | Cookie attributes behind TLS, fixation, logout CSRF, concurrent session abuse, session in URL anywhere |
| T-07 | MFA / account recovery | No session without MFA; TOTP replay; recovery codes single-use; uniform errors | `test_accounts.py` (22 tests incl. RFC 6238 vectors, replay, challenge burn, throttling, enumeration) | Brute force across replicas/IPs, reset-token leakage, invitation hijack, timing-based user enumeration, MFA fatigue |
| T-08 | CSRF | State changes need same-origin + CSRF header | E2E proxy CSRF check (v1.3 evidence) | Full CSRF review of `/api/session`, `/api/account/*`, `/api/proxy/*` incl. content-type tricks, `null` origin |
| T-09 | XSS | No script injection; CSP | CSP evidence (`evidence/csp-check.txt`); React escaping | Stored/reflected/DOM XSS in console (provenance text, approval scopes, names, invitation fields); CSP bypass (note: inline scripts allowed) |
| T-10 | SSRF | Gate + adapter refuse internal/metadata targets, rebinding, redirects | `test_hardening.py`, `test_v12_controls.py` (IP classes, DNS answers, pinning, redirects) | DNS rebinding with real resolvers, IPv6 forms, alternative encodings, TLS SNI vs pinned IP, egress-override mode |
| T-11 | Path traversal & symlinks | `file.read` jailed per tenant | `test_hardening.py` (O_NOFOLLOW walk, symlink races), `test_tenancy.py::test_workspaces_are_isolated` | Race conditions on real filesystems, unicode normalisation, hard links, bind mounts |
| T-12 | Command injection | `shell` never executes; injection patterns blocked | `test_sentinel.py`, benchmark D2 | Any path from input to `subprocess` (anchor.py, backup.py use fixed argv) |
| T-13 | Prompt injection | Untrusted instructions cannot authorise actions | Benchmark (direct/transformed/delayed), provenance tests, `test_classifier.py` (LLM advisory only, hostile outputs) | Novel obfuscations, multi-step laundering through TRUSTED summaries, unicode homoglyphs, delayed instructions beyond the 50-step window |
| T-14 | Malicious skill execution | Skill content cannot reach tools without passing the Gate | Benchmark D1/D3/T1/T2; Inspector tests | Realistic malicious skills / MCP tool descriptions against an agent integration |
| T-15 | Tool-execution bypass | Execution only with a single-use grant bound to stored params | `test_v12_controls.py`, `test_persistence.py` (replay across processes, DB row alone never authorises) | Grant id guessing, race on consume, param tampering, redirect hop abuse |
| T-16 | Proof-chain tampering | Edits/reorder/truncation detected; anchors | `test_anchor.py`, `test_persistence.py`, `test_integrity.py`, `test_alerts.py` | Offline forging with storage access; anchor substitution; verifier robustness |
| T-17 | Backup tampering | Encrypted, signed, verified before restore | `test_backup.py` (wrong key, corrupt, forged manifest, swapped/missing, interrupted) | Attack the restore scripts (paths, tar members), key handling, off-site storage ACLs |
| T-18 | Rate-limit bypass | Limits shared, spoof-resistant | `test_ratelimit.py` (concurrency, multi-instance, restart, 2 real processes), signed client-id tests | Header spoofing through the real proxy chain, distributed sources, limiter exhaustion (DB load) |
| T-19 | Denial of service | Bounded inputs, fail-closed but available | size limits in schemas; pool / limiter tests | Load/soak (not done), slow-loris via proxy, expensive regex (ReDoS) inputs, scrypt cost amplification, DB connection exhaustion |
| T-20 | Secret leakage | No secrets in logs, responses, bundles, images, history | `test_identity.py`, `test_accounts.py`, `test_alerts.py` log scans; gitleaks over history; E2E log scan | Error pages, stack traces, browser bundle, image layers, `/proc` in containers, backups |
| T-21 | Dependency & container vulns | No known vulnerable deps; pinned images | `npm audit` 0, `pip-audit` clean, digest-pinned bases, SBOM; CI Grype gate | Image scan with current DBs (not possible offline here), container breakout config review |
| T-22 | Data-loss / integrity | Loss or replacement never silent | `test_integrity.py` (15 scenarios) | Attempt undetected rollback with partial access (DB-only, chain-only, witness-only) |

## 4. Rules of engagement & reporting
* Test window, source IPs and contacts agreed in writing; production data never used.
* Findings rated with CVSS v3.1 + business impact; every finding re-tested after the fix and the regression test added
  to this repository (the automated column grows).
* Deliverables: report, raw evidence, list of untested areas. The product's readiness verdict
  (`docs/PRODUCTION_READINESS.md`) may only move past "controlled beta" after critical/high findings are fixed and
  re-tested by the external party.

## 5. Safe automated checks run for this release (2026-11-02)
Backend suite (incl. all Auto entries above), route authorization sweep, gitleaks (history + tracked tree), bandit
(0 medium/high), npm audit (0), pip-audit (0), actionlint, promtool, Compose config validation, live Compose E2E
(`evidence/production-hardening-v1.4.txt`). Not run locally: CodeQL and Grype (no database download possible in this
environment) — they run in CI (`.github/workflows/security.yml`).
