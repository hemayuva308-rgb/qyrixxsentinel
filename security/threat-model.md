# QYRIX SENTINEL — Threat Model (v1.2)

Method: STRIDE over the trust boundaries in `docs/ARCHITECTURE.md`. Status: **M** mitigated and tested · **P** partial · **O** open.

## Assets
Agent tool capabilities (HTTP egress, workspace files) · secrets reachable by agents · proof chain (evidence) ·
operator tokens · approval decisions · public demo availability.

## Trust boundaries
B1 browser ↔ frontend · B2 frontend ↔ backend (internal network) · B3 instruction content ↔ agent · B4 agent ↔ Gate ·
B5 adapter ↔ external network · B6 backend ↔ LLM provider · B7 backend ↔ proof storage.

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
| T11 | Attacker with storage access rewrites the whole chain consistently (R/T) | B7 | requires external anchoring | **O** |
| T12 | Token theft via XSS or leakage to client JS (S/I) | B1 | httpOnly SameSite=Strict cookie; no token in bundle | P (no CSP) |
| T13 | CSRF against operator session (T) | B1 | `x-qs-csrf` header + origin check on non-GET proxy and session routes | M |
| T14 | Agent token approves its own requests (E) | B4 | admin-only decision endpoint | M |
| T15 | Public demo used as an SSRF/exfil proxy (E/I) | B1/B2 | scenario enum only, sandbox adapter, demo allowlist, no workspace, tested no DNS | M |
| T16 | Public demo abused for DoS (D) | B1/B2 | per-client and global rate limits, kill switch; fresh small context | P (client key comes from forwarded header) |
| T17 | Demo evidence pollutes production audit chain (T) | B2/B7 | separate in-memory context per request; tested production chain unchanged | M |
| T18 | Cross-tenant data access (I) | B2 | single-tenant build | **O** (multi-tenancy not implemented) |
| T19 | ReDoS via crafted inspection input (D) | B4 | linear-time parsers; size limits | M |
| T20 | Backend process bypasses adapter for egress (E) | B5 | code structure only | P (no network egress firewall) |

## Residual risk summary
Open: external anchoring (T11), tenant isolation (T18). Partial: CSP (T12), network-level egress control (T20),
demo client identification behind proxies (T16), live TLS pinning verification (T6).
