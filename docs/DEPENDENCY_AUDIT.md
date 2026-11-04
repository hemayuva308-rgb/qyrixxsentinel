# QYRIX SENTINEL — Dependency Audit and Failure Modes (v1.4)

Audit date 2026-11-02. Rule applied throughout: **when trust, authorization, persistence or verification cannot be
established, the Gate blocks or the API refuses (fail closed).** "Tested" = an automated test or a recorded drill in
this repository exercises it; "Analysed" = reasoning only.

## 1. Software supply chain

| Component | Pinning / integrity | Audit result (this commit) | Residual |
|---|---|---|---|
| Python runtime deps (`backend/requirements.txt` → `requirements-lock.txt`) | 28 packages, exact versions + SHA-256 hashes, image installs with `--require-hashes` | `pip-audit --vulnerability-service pypi`: no known vulnerabilities | OSV service unreachable here (CI uses OSV) |
| New in v1.4: `cryptography 50.0.2` (+ `cffi`, `pycparser`) | hash-locked | clean | PyCA, actively maintained; used only for AES-GCM of TOTP secrets |
| npm (`frontend/package-lock.json`) | lockfile, `npm ci` (consistency verified) ; `overrides` pins Next's nested PostCSS to 8.5.32 | `npm audit`: 0 vulnerabilities | transitive updates need re-audit |
| Base images | **digest-pinned**: `python:3.12-slim@sha256:aa943ce4…`, `node:22-slim@sha256:4b150b48…`, `postgres:16-alpine@sha256:0cefaabd…` | OS-package scan **not run here** (Grype DB not downloadable) — CI gate | digests must be bumped deliberately for OS patches |
| CI actions | pinned to commit SHAs resolved with `git ls-remote` (peeled for annotated tags); `aquasecurity/trivy-action` deliberately avoided (2026 tag-hijack incident) | actionlint clean | SHA review on every bump |
| CI tool binaries (gitleaks 8.30.0, syft 1.33.0, grype 0.100.0) | version + release checksum verified before use | — | trust root = the projects' GitHub releases |
| SBOM | Syft SPDX JSON: source (`evidence/sbom/source.spdx.json`, 90 packages) + both images in CI | — | SBOMs not signed |

### Accepted scanner exceptions (reviewed by hand — nothing suppressed silently)
* **gitleaks** (`.gitleaksignore`, 14 exact fingerprints): the synthetic credential `sk-synth-9f3a21c` (also in `evidence/benchmark-case-texts.json`) required by the
  unchanged benchmark case D1 and by tests, `RAWSECRET123` and a fake `sk-live-…` value asserted to be redacted in tests, and the weak-password **denylist** in
  `app/accounts.py`. No real secret. Any new finding fails CI.
* **gitleaks — C5 evidence digests** (2 of the 14 fingerprints, commit `c6ea13f`, `evidence/c5/validation.json` lines 573 and 755, rule `generic-api-key`):
  the matches are `token_sha256` fields — **SHA-256 digests of one-use, 128-bit CSPRNG canary tokens** recorded in the observer's signed ledger rows. The observer
  stores only the digest, never the token, and the digest cannot be reversed to a usable token. They are not raw credentials. The file is signed (`evidence_sig`
  verified by `ops/observer/verify_evidence.py`), so redacting it would invalidate the evidence; the exact `commit:file:rule:line` fingerprints are therefore
  accepted instead of any path or rule allowlist. A regenerated evidence file will produce new findings that must be reviewed again. Separately, GitGuardian flags two
  synthetic payloads in `evidence/redteam/template-v1.cases.jsonl` (not a gitleaks finding; the corpus is covered by a SHA-256 digest and is unchanged).
* **bandit** (31 LOW, 0 MEDIUM/HIGH after the PR #1 remediation; `evidence/sbom/bandit-report.json`, summary only — no code snippets): B110 try/except/pass — all are best-effort
  side effects after a fail-closed decision (compensations, last-used timestamps, cleanup, base64 probe); B603/B607/B404
  — fixed-argv `openssl` / `pg_dump` calls; B105 — false positives (secret file paths). PR #1 CodeQL / GitGuardian review: `evidence/pr1-security-remediation.md`.
* **Grype policy in CI**: fail on *critical with an available fix*; unfixed findings are reported in the artifact,
  not ignored — review them on each release.

## 2. Runtime dependencies and failure modes

| Dependency | Failure | Behaviour | Evidence |
|---|---|---|---|
| PostgreSQL | down at start | persistence `down` ⇒ every evaluation BLOCK (R17); `/ready` 503 | Tested |
| | down mid-request | authenticated requests 503 (auth-failure limiter fails closed first); evaluations that reach the Gate BLOCK; never a partial grant; automatic recovery re-verifies account + mirror | Tested + live drill |
| | over-privileged runtime account | persistence refused (critical alert); the 2 s auto-recovery re-runs the FULL verified attach (v1.3 fail-open fixed) | Tested |
| | killed connections (restart) | one safe retry only if the failure hit the first statement | Tested |
| | wiped / replaced / older copy | RECOVERY_REQUIRED (witness), Gate blocks, critical alert | Tested + live drill |
| Chain volume | corrupted / truncated / deleted | degraded or RECOVERY_REQUIRED; block all | Tested |
| Witness volume / key | missing / forged / wrong key | RECOVERY_REQUIRED | Tested |
| Shared rate-limit store (PostgreSQL) | unavailable | auth scopes (authfail, login, mfa, reset, invite) 503; general request limits degrade to per-instance counters | Tested |
| `data_key` (TOTP secrets) | missing / wrong | MFA verification 503 — no login without MFA, no fallback | Tested |
| Mail relay (`QYRIX_MAIL_WEBHOOK_URL`) | not configured | nothing sent; tokens shown once to authorised admins | Tested |
| Alert webhook | slow / failing | bounded background queue, never blocks requests; delivery metric | Tested |
| RFC 3161 TSA | not configured / unreachable / bad token | PARTIAL_UNANCHORED, anchor refused | Tested (local TSA); public TSAs unreachable here |
| Meta Llama / Baseten | absent / down / hostile output | heuristic fallback; advisory only, never authorises | Tested (mocked + real sockets); live NOT verified |
| DNS | failure / mixed answers | BLOCK | Tested; no explicit DNS timeout (open) |
| Frontend → backend | backend unreachable | 502; no credential cached | Analysed |

## 3. Configuration failure modes

| Misconfiguration | Behaviour |
|---|---|
| Operator tokens unset / < 24 chars / `CHANGE_ME…` | credential refused |
| DB password file missing / empty / placeholder | R17 fail closed |
| `QYRIX_DB_USER` = admin / superuser | refused at startup (`db_privilege_violation`) |
| Schema not migrated | refused at startup (run `python -m app.migrate`) |
| `QYRIX_STATE_WITNESS_DIR` / key unset in durable mode | RECOVERY_REQUIRED (`WITNESS_NOT_CONFIGURED`) |
| `QYRIX_STATE_WITNESS=disabled` | explicit UNSAFE opt-out (tests/dev): the Gate is not blocked, but `/ready` stays 503 (DISABLED is not a ready state), `qyrix_integrity_ok=-1`, alert `state_witness_disabled` |
| `QYRIX_CLIENT_SIG_KEY_FILE` missing | client headers ignored; TCP peer used (all browser traffic = one per-IP bucket) |
| `QYRIX_TRUSTED_PROXY_HOPS=0` behind a proxy | per-IP limits skipped (per-account + global remain) |
| `QYRIX_REQUIRE_MFA=0` | password-only human sessions (warning event on every such login) |
| `QYRIX_ENABLE_DEMO_RESET=1` | the runtime may call the evidence-reset function (granted at migration time) — demo only |
| `QYRIX_COOKIE_SECURE=0` behind HTTPS | cookies without `Secure` — set 1 |
| egress override enabled | backend can reach the internet; only application-level adapter controls |

## 4. External verification status
| Item | Status |
|---|---|
| Meta Llama live call | **Blocked**: no credentials, provider hosts unreachable |
| Public RFC 3161 TSA | **Blocked**: freetsa / digicert / sectigo / ssl.com unreachable from this environment |
| LlamaFirewall comparison | **Partial**: offline scanners only (regex + hidden-ASCII) on the 10 benchmark texts: 0/7 attacks, 0/3 safe flagged (`evidence/llamafirewall-offline-comparison.json`); PromptGuard / AlignmentCheck / CodeShield not run (model download / LLM / extra deps) |
| Pipelock comparison | **Not run**: v3.7.1 release with checksums located; executing the third-party binary (even in a network-less container) was refused by this environment's permission policy — needs the owner's explicit approval |
| CodeQL / Grype | run only in CI (not possible offline) |
| Independent penetration test | **Not performed** (`docs/SECURITY_TEST_PLAN.md`) |
