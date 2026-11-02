# PR #1 security remediation (CodeQL + GitGuardian) — 2026-11-02

Values of secrets/fixtures are deliberately not reproduced here.

## CodeQL (7 new alerts on PR #1; 5 visible as PR review threads)

| Alert | Rule | Location (PR head cccbfd0) | Verdict after data-flow trace | Change |
|---|---|---|---|---|
| #6 (high) | py/weak-sensitive-data-hashing | `backend/app/identity.py:83` `_sha()` | **Partly real.** 6 of 7 callers hash server-minted 256-bit tokens (API keys `qsk_`, sessions `qss_`) for lookup — SHA-256 is correct there (no brute force possible; a slow KDF would add per-request CPU/DoS cost). 1 caller (`_env_fingerprint`) stored a truncated fast SHA-256 of the OPERATOR-CHOSEN env token in `sessions.cred_fp` → offline guessing for anyone with DB read. | `_sha` removed. `token_digest()` accepts only the exact minted format (`^q(sk\|ss)_[A-Za-z0-9_-]{43}$`), returns None otherwise, output byte-identical (no migration). Env fingerprint now scrypt (N=2^15, r=8, p=1), cached per process. Same split in `accounts.py` (`_token_digest` for qsi_/qpr_/qch_, `_rc_digest` for 80-bit recovery codes, `_bucket` for limiter keys). |
| #3 (high) | py/clear-text-logging-sensitive-data | `backend/scripts/demo_judging.py:76` | **False positive in effect** (printed text had the synthetic key masked) but the display string was derived from the secret-bearing string. | Display text now built from a template that never contains the key. |
| #7 (high) | py/incomplete-url-substring-sanitization | `backend/scripts/demo_judging.py:79` | **False positive**: `in` on a LIST of host names (exact membership), in a demo assertion, not a security decision. | Rewritten as explicit exact host equality. |
| #4 (medium) | py/stack-trace-exposure | `backend/app/api.py:101` (`/tools/execute`) | **Real (low impact)**: adapter/netguard `str(e)` and exception class names reached the response. | Fixed vocabulary `_public_exec_error`; unknown errors → "execution failed"; class name only in the internal security log. |
| #5 (medium) | py/stack-trace-exposure | `backend/app/api.py:228-229` (`/status`) | **Real (low impact)**: integrity reasons included `CHECK_FAILED:<ExceptionClass>` — also on the UNAUTHENTICATED `/api/v1/ready`. | Reasons restricted to the fixed `integrity.REASONS` set via `reason_of()`. |
| #1, #2 | not visible | no review thread; the code-scanning alert list is not reachable from this environment, and running CodeQL locally was refused by the environment's permission policy | **Unverified** | The whole classes were remediated: also `str(e)` of LLM-provider errors in `/inspect` (`_public_llm_error`), openssl stderr (server paths) in anchor verification detail, exception class names in anchor errors. Confirm with the next CodeQL run. |

Tests: `backend/tests/test_remediation.py` (16): byte-compatibility of stored digests, refusal of non-token inputs, existing keys/sessions still authenticate, scrypt fingerprint + rotation detection, fixed vocabularies, `/ready` and `/status` carry no exception text/class.
Compatibility: API-key / session / invitation / reset / challenge / recovery-code digests unchanged. Only operator-env-token console sessions created before this change stop matching (their fingerprint format changed) — those users sign in again (sessions last ≤ 8 h).

## GitGuardian (7 occurrences, 6 incidents) — none is a real credential; no rotation required

| GG id | Commit | File:line | Type | Classification |
|---|---|---|---|---|
| 39422167 | 2c0e0cb | evidence/sbom/bandit-report.json:750 | Generic Password | bandit's report quoting the demo's synthetic `sk-synth-…` value |
| 39389421 | 3f6c6dd | docker-compose.yml:11 | Generic Password | `${POSTGRES_PASSWORD:?…}` — a variable reference, no value (removed in 637169d) |
| 39389422 | 3f6c6dd | backend/tests/test_classifier.py:359 | Generic High Entropy Secret | synthetic test fixture (replaced in 637169d) |
| 39422168 | 882f40a | backend/tests/test_alerts.py:104 | Bearer Token | fake value used to prove log redaction |
| 39422166 | 0bdb8d0 | backend/tests/test_accounts.py:40 | Generic Password | weak-password DENYLIST examples |
| 39422165 | 477da07 | backend/tests/test_route_auth.py:54 | Base64 Basic Auth | the default pair `admin:admin`, a deliberately invalid credential in the auth-bypass sweep |
| 39422165 | cccbfd0 | evidence/pytest-junit.xml:1 | Base64 Basic Auth | the same test value echoed into test ids |

Current tree: all of these literals are now built at runtime or removed (bandit report regenerated as a summary without code/quotes; parametrized tests use ids so values never enter the test report). Git history was NOT rewritten (no force push), so GitGuardian will keep showing the historical occurrences until they are marked as false positive / test credential in the GitGuardian dashboard by the owner.
