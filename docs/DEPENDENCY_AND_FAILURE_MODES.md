# QYRIX SENTINEL — External Dependencies and Failure Modes (v1.3)

Rule applied throughout: **when trust, authorization, persistence or verification cannot be established, the Gate
blocks or the API refuses (fail closed).** Availability is sacrificed before integrity. "Tested" means an automated
test or a recorded drill in this repository exercises the failure; "Analysed" means reasoning only.

## 1. Runtime dependencies

| Dependency | Used for | Failure | Behaviour | Evidence |
|---|---|---|---|---|
| PostgreSQL 16 | durable provenance, approvals, evaluations, grants, proof mirror, anchors, tenants, API keys, sessions | down at start | default tenant: persistence `down` ⇒ every evaluation BLOCK `R17_PERSISTENCE_UNAVAILABLE`; `/ready` 503 | Tested (`test_persistence.py` outage) |
| | | down mid-request | transaction fails ⇒ `PersistenceError` ⇒ R17 BLOCK / execute 503; never a partial grant | Tested |
| | | identity tables unreachable | authentication ⇒ 503 `authentication unavailable` (no fallback to "allow") | Analysed (code path in `auth.principal`) |
| | | data tampered (proof mirror ≠ chain prefix) | Gate degraded, persistence down, block all | Tested |
| | | restored in wrong order (chain older than DB) | degraded + down (fail closed) | Tested (`test_backup.py`) |
| | | **emptied completely** (DB + chain) | starts as a fresh install, **no alarm** | Tested drill — **open risk T29** |
| Chain files (`/data` volume) | primary tamper-evident proof chain | corrupted / reordered / truncated | verify on load fails ⇒ degraded ⇒ block all | Tested |
| | | volume read-only / full | `_record` fails ⇒ request errors; the DB-first write order means no ALLOW is executable without its proof record | Analysed |
| Tenant workspace root (`/workspaces`) | per-tenant `file.read` jail | not writable / missing | 503 `TENANT_CONTEXT_UNAVAILABLE`; context not cached; retried next request | Tested (regression) |
| RFC 3161 TSA (`QYRIX_TSA_URL`) | external anchoring of the chain head | not configured | `anchor_status` NOT_CONFIGURED; verification stays `PARTIAL_UNANCHORED` (never PASS) | Tested |
| | | unreachable / timeout / bad token / wrong CA | anchor refused, nothing stored; status unchanged | Tested (local TSA, `test_anchor.py`) |
| | | public TSA | **not verified from this environment** (egress blocked) | Blocked by external dependency |
| `openssl` CLI | `ts -query/-verify` | missing | anchoring unavailable; tests skip | Tested (skip guard) |
| Meta Llama / Baseten | **advisory** classification only | not configured / down / malformed output / timeout | labelled heuristic fallback; the Gate never reads the classification | Tested (mocked); live **not verified** |
| DNS resolver | destination validation before HTTP execution | failure / mixed public+private answers | BLOCK (all answers must be public and pinned) | Tested |
| | | slow resolver | no explicit DNS timeout (OS default) | **Open** (known gap) |
| Target HTTP APIs | executing ALLOWed http actions | redirect / error / TLS failure | redirects never followed (re-gated); errors returned, recorded | Tested (local servers) |
| Next.js frontend | console, proxy, session exchange | backend unreachable | 502 to the browser; no credential cached | Tested (route code) |
| In-process rate limiter | auth throttling, per-credential limits | process restart | counters reset (attacker gets a fresh window) | Analysed — **partial (T28)** |
| | | multiple replicas | each replica counts separately | Analysed — single replica documented |

## 2. Build / supply-chain dependencies

| Dependency | Control | Status at this commit | Residual |
|---|---|---|---|
| Python packages (PyPI) | `requirements-lock.txt`: 25 packages pinned with SHA-256 hashes, installed with `--require-hashes` | `pip-audit` (PyPI advisories): no known vulnerabilities | no SBOM; no continuous scan; osv.dev unreachable here |
| npm packages | `package-lock.json`, `npm ci`; `overrides` pins Next's nested PostCSS to 8.5.32 | `npm audit`: 0 vulnerabilities | transitive updates need re-audit; no SBOM |
| Base images `python:3.12-slim`, `node:22-slim`, `postgres:16-alpine` | tags | not digest-pinned | **pin by digest** before production; Docker Hub rate limits observed during this run |
| Docker Hub availability | image pulls | 429 rate limiting reproduced | use a registry mirror / pre-pulled images for production builds |

## 3. Configuration failure modes

| Misconfiguration | Behaviour |
|---|---|
| `QYRIX_ADMIN_TOKEN` / `AGENT` / `PLATFORM` / `METRICS` unset, < 24 chars or `CHANGE_ME…` | that credential is refused (nobody can use it); `/metrics` returns 404 |
| DB password file missing / empty / `CHANGE_ME` | `PersistenceError` ⇒ R17 fail closed |
| `QYRIX_MULTI_TENANT=1` without PostgreSQL | tenant creation 409 `PERSISTENCE_REQUIRED`; tenant requests 503 |
| `QYRIX_MULTI_TENANT` unset | non-default tenant credentials ⇒ 403 `MULTI_TENANCY_DISABLED` |
| `QYRIX_TRUST_CLIENT_HEADER=1` with the API exposed directly | clients can spoof `X-Qyrix-Client` to dodge the *per-client* auth throttle (the global ceiling still applies) — only enable when the API is reachable solely from the frontend (Compose default) |
| `QYRIX_ENABLE_DEMO_RESET=1` in production | `/reset` and `/benchmark` can wipe evidence (admin/owner only) — keep 0 |
| `QYRIX_COOKIE_SECURE=0` behind HTTPS | session cookie sent without `Secure` — set 1 for any HTTPS deployment |
| egress override (`docker-compose.egress.yml`) enabled | backend can reach the internet; only the application-level adapter controls egress (no network allowlist) |

## 4. Recovery procedures
* **Backup:** `scripts/backup.sh` (Compose) or `python backend/scripts/backup.py backup` — database FIRST, chain files SECOND, SHA-256
  manifest. Store encrypted and off-host (the tooling does not encrypt).
* **Restore:** `scripts/restore.sh backups/<ts> --yes` — verifies the manifest, stops the app, restores DB then chain, restarts; the
  backend re-verifies the chain and the DB mirror and fails closed on any inconsistency.
* **Key compromise:** revoke the key (`POST /sentinel/keys/{id}/revoke`) — its sessions die immediately. Operator env token
  compromise: rotate the env value and restart — all sessions opened with the old value die.
* **Tenant compromise:** `POST /platform/tenants/{id}/disable` — all its keys and sessions stop working immediately.
* **Evidence tampering detected (degraded):** the Gate blocks everything; investigate with `backend/scripts/verify_proof.py`,
  restore from a known-good backup. There is intentionally no "clear degraded" API.
