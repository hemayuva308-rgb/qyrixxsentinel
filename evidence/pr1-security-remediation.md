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

---

# Follow-up investigation after 98e5694 (CodeQL: 4 HIGH; GitGuardian: same 7)

## SARIF availability (requirement 1) — NOT obtained
The latest run (41434513485) has one artifact (`sbom-and-scans`); the CodeQL action uploads SARIF directly to code
scanning and keeps no artifact. The GitHub tools available to this agent have no code-scanning endpoint, the `gh` CLI
is restricted to search in this session, and running CodeQL locally was refused by the environment's permission
policy. **The full SARIF (rule ids, locations, data-flow paths) for all 4 alerts was therefore not retrieved.**
Ways to obtain it (owner's choice): (a) Security → Code scanning → filter `pr:1` → each alert's "Show paths", or
download via `GET /repos/{owner}/{repo}/code-scanning/analyses/{id}` with `Accept: application/sarif+json`;
(b) approve a CI change that keeps the SARIF as a workflow artifact; (c) allow the CodeQL bundle locally.

Visible from PR threads: **#8** `py/weak-sensitive-data-hashing` at `backend/app/identity.py:95`
(`return hashlib.sha256(token.encode()).hexdigest()` in `token_digest`) with **4 "password" sources = 4 paths into ONE
sink, i.e. one alert**; **#3** `py/clear-text-logging-sensitive-data` at `backend/scripts/demo_judging.py:79`.
The other 2 HIGH alerts have no thread and are **unidentified**.

## Call-site and data-source trace (requirements 3-4)
`identity.token_digest(token)` — hashes only if `token` matches `^q(sk|ss)_[A-Za-z0-9_-]{43}$`, else returns None:
| Caller | Input origin | Kind |
|---|---|---|
| `authenticate()` (key branch, session branch) | `Authorization` header (via `auth.principal`) or `create_session(credential)` | presented value; hashed only if it has the minted format; env/operator tokens are matched earlier by constant-time compare and never reach it |
| `create_session()`, `create_user_session()` | `"qss_" + secrets.token_urlsafe(32)` | minted, 256-bit |
| `end_session()` | `Authorization` header | presented value, format-gated |
| `create_key()` | `"qsk_" + secrets.token_urlsafe(32)` | minted, 256-bit |

`accounts._token_digest` (qsi_/qpr_/qch_, minted by `_tok` = `token_urlsafe(32)`), `accounts._rc_digest`
(16 base32 chars = 80 random bits minted by `_new_recovery_codes`), `accounts._bucket` (tenant/e-mail limiter keys —
not secrets). Every password-named value in `app/` (AST scan) flows only into `verify_password`, `hash_password`,
`_dummy_verify` (scrypt) or `password_problem`. Operator env token fingerprint: scrypt. `migrate.scram_verifier`:
PBKDF2-HMAC-SHA256 + SHA-256 per RFC 5802/7677 (the format PostgreSQL requires) over a 256-bit random secret.

Runtime confirmation (full suite, temporary probe plugin, values never recorded): 672 digest calls —
`identity.token_digest` 328 hashed / 22 refused, `accounts._token_digest` 150 / 8, `accounts._rc_digest` 164 / 0;
**hashed inputs without the minted format: 0; test passwords ever hashed: 0.**

**Conclusion:** SHA-256 receives only server-minted high-entropy tokens (or attacker-presented strings of that exact
format, which are not anyone's secret). No password or operator-chosen value can reach it. **#8 is a false positive.**
Most plausible cause (unconfirmed without SARIF): CodeQL over-approximates flow through the generic dispatcher
`api._call(fn, *a)`, merging password arguments of different call sites.
**#3**: the printed `ins["secrets"]` are the Inspector's redacted references (`["api_key", "sk-***"]`, verified at
runtime); no secret is logged — false positive (the source is the key name `secrets`).

## SHA-256 → HMAC / scrypt assessment (requirement 5) — NOT changed; decision for the owner
| Aspect | Impact of switching |
|---|---|
| Stored digests | `api_keys.key_hash`, `sessions.id_hash`, `invitations/password_resets/login_challenges.token_hash`, `recovery_codes.code_hash` are SHA-256 hex. Plaintexts are never stored, so existing rows cannot be re-hashed. |
| Lookup | Done by digest equality in SECURITY DEFINER functions (`qyrix_lookup_key/_session/_invitation`). A new scheme needs dual lookup (new + legacy) until every legacy row is gone. |
| Lifetimes of legacy rows | sessions ≤ 8 h, challenges 5 min, resets 30 min, invitations 72 h — expire naturally; **API keys and recovery codes do not expire by default** → need rotation / regeneration campaign or permanent dual lookup. |
| Revocation | `qyrix_end_session`, key revocation and session revocation match by hash — every path must revoke both forms during migration. |
| HMAC | Needs a new server-side pepper (secret management, rotation, backup); protects nothing extra for 256-bit tokens (a leaked SHA-256 of a 256-bit token is already infeasible to invert). |
| scrypt | Adds ~50-100 ms CPU per authenticated request → DoS amplification; same migration problems. |
**Recommendation:** keep SHA-256 for minted tokens; record #8 as a false positive with this evidence. Dismissing it in
GitHub is the owner's decision (not done by the agent).

## GitGuardian classification guide (requirement 7) — no history rewrite, nothing dismissed
| Incident | Occurrence (commit · file:line) | Detector | Evidence-based classification | Suggested dashboard status |
|---|---|---|---|---|
| 39422167 | 2c0e0cb · evidence/sbom/bandit-report.json:750 | Generic Password | bandit's text quoting the synthetic demo key `sk-synth-…` (also in the repo's benchmark/demo fixtures) | False positive (test data) |
| 39389421 | 3f6c6dd · docker-compose.yml:11 | Generic Password | `${POSTGRES_PASSWORD:?…}` variable reference — contains no value | False positive |
| 39389422 | 3f6c6dd · backend/tests/test_classifier.py:359 | Generic High Entropy | synthetic `api_key=…` test fixture | Test credential |
| 39422168 | 882f40a · backend/tests/test_alerts.py:104 | Bearer Token | fake bearer used to prove log redaction | Test credential |
| 39422166 | 0bdb8d0 · backend/tests/test_accounts.py:40 | Generic Password | weak-password denylist examples | Test credential |
| 39422165 | 477da07 · backend/tests/test_route_auth.py:54 and cccbfd0 · evidence/pytest-junit.xml:1 | Base64 Basic Auth | `admin:admin` default pair, deliberately invalid in the auth-bypass sweep, echoed into test ids | Test credential |
How to verify any of them yourself without exposing values: open the commit in GitHub, confirm the value is a
fixture/reference used only by tests or docs, and that no deployment config, CI secret or `.env` uses it. If a finding
ever matches a value used by a real system, treat it as real: rotate it in that system first, then resolve.
None of the 7 needs rotation. The check stays red until the owner resolves them in the dashboard (98e5694 added none).

---

# Round 3 (uncommitted, awaiting owner approval)

| Alert | Rule | Location | Status |
|---|---|---|---|
| #3 | py/clear-text-logging-sensitive-data | backend/scripts/demo_judging.py:79 | **Defensive fix applied**: the line now prints only `len(ins.get("secrets") or [])`. The list was already redacted by the Inspector (no secret was ever printed). Test: `backend/tests/test_demo_logging.py` (3 tests; verified to FAIL against the old line and pass with the fix). |
| #8 | py/weak-sensitive-data-hashing | backend/app/identity.py:95 (`token_digest`) | **Retained SHA-256 — false positive.** No new evidence of a vulnerability: caller trace, AST scan and runtime probe (672 digest calls, 0 hashed without the minted-token format, 0 passwords hashed) unchanged. Replacing it would invalidate every stored API-key/session digest (see the migration table above). Copilot's suggested SHA-256 replacement NOT applied. 4 "password" sources = 4 paths to this one sink; the source locations themselves are **not verified** (SARIF unavailable). |
| 2 × HIGH | py/polynomial-redos | backend/app/gateway.py:101 (repeated `-`) and :104 (repeated ` `) | Identified by the owner from the Security tab. **Fixed in round 4** below. |

Nothing dismissed in CodeQL or GitGuardian. Suite at the time of round 3: 321 passed, 1 skipped (see round 4 for the current count). Benchmark unchanged (7/7, 3/3, 0 FP).

Note on #3: the Inspector's `secrets` list holds matched keyword names (`api_key`, `token`, …), `sk-***` masks and any
`aws_…` identifier, which is printed in full. It never held a `sk-` value. The script now prints only the count.

---

# Round 4 (uncommitted, awaiting owner approval): py/polynomial-redos in `_redact`

**Sinks.** `gateway.py:101` `_KV_NAME.finditer(s)` with `(?<![\w.-])[\w.-]+(?=\s*[=:])` (hyphens), and `:104`
`_KV_VAL.match(s, pos)` with `(\s*[=:]\s*)[^\s&"',;]+` (spaces). **Sources** (uncontrolled text reaching `_redact`): provenance
step text (`api.py`, ≤5 000), gate `dest`/`cmd` in BLOCK proof records (≤2 048/4 096), `file.read` content (≤1 MiB),
LLM reply `explanation`, `/inspect` text before the LLM call (≤100 000), demo scenario text.

**Backtracking.** Without its lookbehind, `[\w.-]+(?=…)` restarts at every position of a hyphen run and rescans to its
end: O(n²). Measured locally: 40 000 hyphens took 20.5 s. `\s*[=:]\s*` under unanchored search does the same on space runs:
40 000 spaces took 7.3 s. As deployed, both were linear (the lookbehind admits only run starts and `match` is anchored;
`_redact` took 3 ms on 40 000 chars). Safety therefore rested on two subtle properties that CodeQL does not model and a
later edit could silently remove.

**Fix.** The two regexes are replaced by a deterministic single-pass scanner. Name runs are disjoint, the whitespace and
value after a name are scanned at most once more, and an overlapping name is skipped before its value is scanned, so
each character is visited a constant number of times: O(n) by construction. `_KV_WORD` (a literal alternation on a name slice)
is kept. An explicit limit `REDACT_MAX_CHARS` = 1 MiB + 4 KiB, above every legitimate caller (file.read is 1 MiB),
returns `[REDACTED: input too large]` instead of the text (fail closed). `token_digest()` is untouched.

**Tests (`backend/tests/test_redact_redos.py`, 53).**
- Output is byte-identical to the old implementation (used as an oracle) on 31 normal and edge inputs (Unicode
  spaces/letters, Kelvin sign, long s, superscripts) and on 4 000 seeded random strings.
- Linearity is measured by counting executed lines (deterministic, no wall-clock thresholds) on 8 adversarial shapes
  (long hyphens, long spaces, mixed): 4× input ⇒ ≤ 4× steps + 50. Two quadratic mutations each FAIL this test: retrying from
  the next character (as the regex does without its lookbehind) fails the hyphen cases, and rescanning whitespace from
  every position fails the three space cases.
- 200 000-char adversarial inputs complete with output identical to the oracle.
- Exhaustive check over all 1 114 112 code points: `str.isalnum()`/`"_.-"` equals `[\w.-]` and `str.isspace()` equals `\s`
  (0 mismatches on Python 3.13 and on 3.12, the CI version). A 50 000-case differential run on 3.12 had 0 mismatches.
- The rest of `_redact` stays linear: `SECRET.sub` measured on adversarial inputs (`sk-` repeats, `aws_` repeats,
  `key=` + hyphens, `=: ` repeats) is roughly 4× the time for 4× the input.
- Oversized input fails closed.
- A full 1 MiB file and the file adapter still redact normally.

**Results.**
- Full suite: 374 passed, 1 skipped (live Meta API).
- Benchmark unchanged: 7/7 blocked, 3/3 allowed, 0 FP. Its regenerated evidence files were restored, so there is no
  churn.
- bandit (`backend/app`, `backend/scripts`): 31 LOW, 0 Medium/High (unchanged; none in the changed lines).
- `gitleaks git` (the CI mode): no leaks, including on a simulated commit of these changes in a scratch clone. A `gitleaks dir` scan of the working tree hits only untracked `.next` build output, the
  ignored benchmark fixture, and `gateway.py:958`, the existing synthetic D1 benchmark case. That last entry's
  working-tree fingerprint in `.gitleaksignore` (`:886`) was already stale at HEAD (line 931); it is not changed here.
- CodeQL could not be run locally. Confirmation needs the next CI run.
