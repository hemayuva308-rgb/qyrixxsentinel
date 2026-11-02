# QYRIX SENTINEL — Threat Model (v1.4)

Method: STRIDE over the trust boundaries in `docs/ARCHITECTURE.md`. Status: **M** mitigated and tested · **P** partial · **O** open.

## Assets
Agent tool capabilities (HTTP egress, workspace files) · secrets reachable by agents · proof chain (evidence) ·
operator tokens · tenant API keys and console sessions · human accounts (passwords, TOTP, recovery codes) · state witness · backups and backup keys · approval decisions · tenant isolation · backups · public demo availability.

## Trust boundaries
B1 browser ↔ frontend · B2 frontend ↔ backend (internal network) · B3 instruction content ↔ agent · B4 agent ↔ Gate ·
B5 adapter ↔ external network · B6 backend ↔ LLM provider · B7 backend ↔ proof storage · B8 tenant ↔ tenant (shared process and database) ·
B9 platform operator ↔ tenant data · B10 operator ↔ backups / dependency supply chain.

## Threats

| # | Threat (STRIDE) | Boundary | Mitigation | Status |
|---|---|---|---|---|
| T1 | Prompt-injected instruction makes agent exfiltrate a credential to an attacker host (I) | B3/B4 | allowlist (R1), secret rules (R2/R12), provenance taint (R3) | M |
| T2 | Obfuscated destination (base64, hxxp, `[.]`, `%2D`) evades matching (T/I) | B3/B4 | `norm()` decoding before inspection; host parsing via `urlsplit` | M |
| T3 | Delayed instruction executed many steps later after a trusted-looking summary (S) | B3/B4 | monotone trust through parents; trust index survives the 50-step window | M |
| T4 | Approved action swapped for a different one before execution (T) | B4 | grant bound to stored params digest; `/tools/execute` rejects client params | M |
| T5 | Approval replay / race to obtain multiple executions (E) | B4 | single-use approval consumed with grant creation under lock; single-use grants | M |
| T6 | SSRF to metadata/internal services, DNS rebinding, mixed answers (I/E) | B5 | IP classification, all-answer validation, IP pinning, no second lookup | M (live TLS P) |
| T7 | Open redirect bounces to an internal or unapproved host (E) | B5 | redirects never followed; each hop re-gated; max 5 | M |
| T8 | Path traversal / symlink race to read secrets from disk (I) | B4 | descriptor-relative `O_NOFOLLOW` walk, protected names, symlinks rejected at gate | M |
| T9 | LLM output used to authorise or the LLM receives secrets (E/I) | B6 | gate never reads classification; redacted bounded input; strict schema | M |
| T10 | Evidence tampering / deletion / reordering (R/T) | B7 | canonical hash chain, verify on load ⇒ degraded block-all, offline verifier | M (unanchored: P) |
| T11 | Attacker with storage access rewrites the whole chain consistently (R/T) | B7 | RFC 3161 anchors of the head (rewrite ⇒ ANCHOR_MISMATCH/FAIL); DB mirror cross-check at startup | P (needs a configured, independent TSA and regular anchoring) |
| T21 | Database outage or tampering used to bypass single-use grants (E/T) | B2 | fail-closed R17; atomic DB consume; grants only loaded with ALLOW evidence; append-only triggers | M |
| T12 | Token theft via XSS or leakage to client JS (S/I) | B1 | httpOnly SameSite=Strict cookie; no token in bundle; CSP (self-only, no eval, frame-ancestors none) | P (CSP allows inline scripts) |
| T13 | CSRF against operator session (T) | B1 | `x-qs-csrf` header + origin check on non-GET proxy and session routes | M |
| T14 | Agent token approves its own requests (E) | B4 | `approval.decide` permission only for owner/admin/approver; `requested_by`/`decided_by` taken from the authenticated principal, never the body | M |
| T22 | Credential brute force / stuffing (S) | B1/B2 | 256-bit API keys; scrypt passwords; per-account lock-out (known and unknown accounts alike), per-IP and global limits in a SHARED PostgreSQL limiter (multi-instance, survives restarts); visitor IP only from signed, trusted-proxy-derived identity; auth scopes fail closed if the limiter store is down | M (residual: targeted account lock-out DoS by design) |
| T23 | Session theft or replay (S) | B1 | server-side `qss_` sessions (hash stored), httpOnly SameSite=Strict, absolute + idle expiry; revoked on logout, key revocation, token rotation, tenant disable, password change/reset, MFA reset, role change, membership removal | M |
| T24 | Privilege escalation by minting a stronger key (E) | B2 | role grant ceiling (admin cannot mint owner), no tenant field accepted, unknown roles 422 | M |
| T25 | Platform operator reads or changes tenant data (I/E) | B9 | platform principal has no tenant permissions (403 on every tenant endpoint) and cannot open console sessions | M (residual: DB superuser and host root can read everything) |
| T26 | Backup theft / tampering (I/T) | B10 | age encryption to offline-held keys (backup host cannot decrypt), HMAC-signed manifest, verified + trial-decrypted before any restore, staged restore, no HTTP route serves backups, witness never backed up | M (residual: off-site storage controls are the operator's) |
| T27 | Malicious or vulnerable dependency (E) | B10 | hash-locked Python deps, npm lockfile + `npm ci`, digest-pinned base images, SHA-pinned CI actions, checksum-verified CI tools, pip-audit / npm audit / gitleaks / bandit / CodeQL / Grype in CI, SBOMs | P (no signed SBOM/images; OS-package scan only in CI) |
| T28 | Rate-limit bypass via replicas, restarts or spoofed IP headers (D/S) | B2 | shared limiter in PostgreSQL (atomic per bucket); signed client identity; untrusted IP => per-IP skipped, per-account + global remain | M (multi-replica load not tested) |
| T29 | Silent total data loss / rollback (A/R) | B7 | installation identity + HMAC state witness on separate storage + optional `QYRIX_EXPECTED_INSTALL_ID`; any disagreement => RECOVERY_REQUIRED, Gate blocks, critical alert; audited operator acceptance written into the proof chain | M (residual: attacker with DB + chain + witness + witness key and no expected id configured) |
| T15 | Public demo used as an SSRF/exfil proxy (E/I) | B1/B2 | scenario enum only, sandbox adapter, demo allowlist, no workspace, tested no DNS | M |
| T16 | Public demo abused for DoS (D) | B1/B2 | per-client and global rate limits, kill switch; fresh small context | P (client key comes from forwarded header) |
| T17 | Demo evidence pollutes production audit chain (T) | B2/B7 | separate in-memory context per request; tested production chain unchanged | M |
| T18 | Cross-tenant data access (I) | B8 | per-tenant `GateContext`; tenant filter in every statement; RLS on every tenant table incl. api_keys/sessions/memberships/invitations; backend logs in as `qyrix_runtime` (no superuser/BYPASSRLS/ownership, verified at startup); missing context matches nothing; credential lookups only via hash-only SECURITY DEFINER functions. Tested: IDOR suite, 14 adversarial SQL tests as the real runtime login, pool leak test, live DB | **M** (residual: code execution INSIDE the backend can choose any tenant context; no per-tenant DB roles/processes; no external pen test) |
| T19 | ReDoS via crafted inspection input (D) | B4 | linear-time parsers; size limits | M |
| T20 | Backend process bypasses adapter for egress (E) | B5 | default deployment: backend on an internal-only network (no route out, tested); opt-in egress mode: code structure only | M default / P opt-in |

| T30 | Database privilege escalation from the application (E) | B2 | runtime login least-privilege (verified at startup, fail closed); column-scoped grants; no DDL/TEMP/COPY PROGRAM; migrations only by the one-shot admin job; recovery path re-verifies (fixed v1.3 fail-open) | M |
| T31 | Human account takeover (S/E) | B1 | scrypt, password policy, mandatory TOTP (replay-protected, secret AES-GCM encrypted), one-time 80-bit recovery codes, single-use invitations/resets/challenges, uniform errors + dummy hashing, audit events | M (no WebAuthn; no breached-password check; e-mail delivery is an external boundary) |
| T32 | Spoofed visitor identity to dodge per-IP limits (S) | B1/B2 | FOUND + FIXED v1.4: client X-Forwarded-For was trusted; now trusted-hop derivation + HMAC-signed hand-off | M |
| T33 | Silent failure of security monitoring (R) | B7 | alert engine errors counted and alerted; webhook queue bounded; Prometheus rules validated | P (alert delivery depends on operator infrastructure) |

## Residual risk summary
High: no independent penetration test; code execution inside the backend can select any tenant context (T18).
Partial: supply-chain signing and offline OS-package scanning (T27), monitoring delivery (T33), anchoring needs a reachable independent TSA (T11), CSP inline scripts (T12), egress-override mode (T20), live TLS pinning (T6), multi-replica load (T28).
