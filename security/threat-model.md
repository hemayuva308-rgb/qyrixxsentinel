# QYRIX SENTINEL — Threat Model (v1.3)

Method: STRIDE over the trust boundaries in `docs/ARCHITECTURE.md`. Status: **M** mitigated and tested · **P** partial · **O** open.

## Assets
Agent tool capabilities (HTTP egress, workspace files) · secrets reachable by agents · proof chain (evidence) ·
operator tokens · tenant API keys and console sessions · approval decisions · tenant isolation · backups · public demo availability.

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
| T22 | Credential brute force / stuffing (S) | B1/B2 | 24+ char tokens, 256-bit API keys, per-client and global auth-failure throttling (429), keys stored as SHA-256 only | M (residual: limits are per process) |
| T23 | Session theft or replay after logout (S) | B1 | server-side `qss_` sessions (hash only stored), httpOnly SameSite=Strict cookie, absolute + idle expiry, logout revokes server-side, key revocation and operator-token rotation kill sessions | M |
| T24 | Privilege escalation by minting a stronger key (E) | B2 | role grant ceiling (admin cannot mint owner), no tenant field accepted, unknown roles 422 | M |
| T25 | Platform operator reads or changes tenant data (I/E) | B9 | platform principal has no tenant permissions (403 on every tenant endpoint) and cannot open console sessions | M (residual: DB superuser and host root can read everything) |
| T26 | Backup theft exposes audit data and key hashes (I) | B10 | backups mode 700, git-ignored, hash manifest; no plaintext keys/sessions in backups | P (encryption at rest / off-site custody is the operator's job) |
| T27 | Malicious or vulnerable dependency (E) | B10 | Python runtime deps fully pinned with hashes (`--require-hashes`); npm lockfile; `pip-audit` + `npm audit` clean at commit time | P (no SBOM signing, no continuous scanning, base images not digest-pinned) |
| T28 | Rate limits bypassed by spreading load over replicas (D) | B2 | single-replica deployment documented; global auth-failure ceiling | P (in-process limiter) |
| T29 | Silent total data loss treated as a fresh install (A/R) | B7 | backup/restore drill tested; wrong-order restores fail closed | **O** (an empty DB + empty chain starts as a new deployment without alarm) |
| T15 | Public demo used as an SSRF/exfil proxy (E/I) | B1/B2 | scenario enum only, sandbox adapter, demo allowlist, no workspace, tested no DNS | M |
| T16 | Public demo abused for DoS (D) | B1/B2 | per-client and global rate limits, kill switch; fresh small context | P (client key comes from forwarded header) |
| T17 | Demo evidence pollutes production audit chain (T) | B2/B7 | separate in-memory context per request; tested production chain unchanged | M |
| T18 | Cross-tenant data access (I) | B8 | per-tenant `GateContext` (own provenance, approvals, evaluations, grants, chain file, anchors, workspace, allowlist); every SQL statement filtered by tenant; PostgreSQL RLS (`FORCE`) under the least-privilege `qyrix_app` role; multi-tenancy off by default and refused without PostgreSQL. Tested: IDOR on grants/approvals/provenance/proofs/keys, raw-SQL RLS, live Compose stack | **M** (residual: one OS process and one DB cluster for all tenants; no per-tenant encryption keys; no external pen test) |
| T19 | ReDoS via crafted inspection input (D) | B4 | linear-time parsers; size limits | M |
| T20 | Backend process bypasses adapter for egress (E) | B5 | default deployment: backend on an internal-only network (no route out, tested); opt-in egress mode: code structure only | M default / P opt-in |

## Residual risk summary
Open: silent total data loss detection (T29). Partial: per-process rate limits (T28), backup encryption custody (T26), supply-chain signing (T27). Partial: anchoring depends on a configured independent TSA (T11). Partial: CSP inline scripts (T12), egress when the opt-in override is used (T20),
demo client identification behind proxies (T16), live TLS pinning verification (T6).
