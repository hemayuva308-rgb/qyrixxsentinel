# QYRIX SENTINEL — Trust-to-Execution Guard (v1.4, controlled beta — see docs/PRODUCTION_READINESS.md)

**Secure every AI action. Before execution.**
A deterministic, default-deny checkpoint between AI agents and their tools. It inspects what the agent read, tracks the
trust provenance of every instruction, decides ALLOW/BLOCK before any tool runs, and records verifiable evidence.
Meta Llama classifies and explains untrusted instructions; **it can never allow an action**: enforcement is deterministic policy.

> Detection is not prevention. We enforce from trust to execution.

```
Inspect → Establish Trust → Evaluate → Authorize or Block → Execute Safely (grant) → Verify Proof
```

## What is in this repository
| Part | Path |
|---|---|
| Backend (FastAPI): Inspector, Provenance, Gate, controlled adapter, Proof, RFC 3161 anchoring, PostgreSQL persistence, identity (roles, API keys, sessions), tenant isolation (RLS), metrics, public demo | `backend/app/`, `backend/migrations/` |
| Tests (302 passing, 1 opt-in live test skipped; incl. adversarial PostgreSQL privilege tests, data-loss detection, MFA, shared rate limits, encrypted backups, route sweep) | `backend/tests/` |
| Benchmark · offline proof verifier · judging workflow · Llama live check · local test TSA | `backend/scripts/run_benchmark.py`, `verify_proof.py`, `demo_judging.py`, `llama_live_check.py`, `local_tsa.py` |
| Public light-theme website (`/`, features, how-it-works, pricing, security, forensic-lab, contact, docs) | `frontend/src/app/(site)/` |
| Authenticated dark product (`/login`, `/dashboard`, `/forensic`) | `frontend/src/app/(app)/` |
| Brand assets (SVG mark, lockups, favicon) | `frontend/public/brand/`, `frontend/src/app/icon.svg` |
| Documentation · security gates · threat model · evidence | `docs/`, `security/`, `evidence/` |

Start with `docs/PRODUCTION_READINESS.md` (production-readiness classification), `docs/OPERATIONS.md`, `docs/DISASTER_RECOVERY.md`, `docs/SECURITY_TEST_PLAN.md`, `docs/ORIGINAL_PLAN_ASSESSMENT.md` (hackathon plan completion), `docs/SECURITY_ACCEPTANCE_TESTS.md`, `docs/DEPENDENCY_AUDIT.md`, `docs/FINAL_SUBMISSION_READINESS_REPORT.md` (v1.2 submission status), `docs/QYRIX_SENTINEL_FINAL_MASTER_PLAN.md`
(authoritative spec), `docs/DEMO_SCRIPT.md` + `DEMO_NARRATION.md` + `DEMO_RECORDING_CHECKLIST.md` (3-minute demo) and `docs/SUBMISSION_CHECKLIST.md`.

## Results (from `evidence/`)
| | |
|---|---|
| 10-case benchmark (3 safe / 3 direct / 2 transformed / 2 delayed) | 7/7 attacks blocked · 0/3 false positives · 3/3 safe tasks completed · 0 external calls · sub-ms average |
| Proof chain | intact; `PARTIAL_UNANCHORED` in the default deployment (no TSA configured) — `PASS` only with a verified RFC 3161 anchor on the head |
| Persistence | PostgreSQL: records survive a backend restart; grants single-use, revocable, expiring; DB outage fails closed (Docker-verified) |
| Tests | 302 passed, 1 skipped · typecheck + clean no-cache production builds · Docker Compose validated (30/30 live E2E, total-loss + encrypted restore drill) |
| Meta Llama | integrated, advisory only, failure paths tested on real sockets — **NOT LIVE VERIFIED** (no credentials / provider blocked here) |

## Run with Docker Compose
```bash
cp .env.example .env      # replace both CHANGE_ME tokens:  openssl rand -hex 32
mkdir -p secrets && for f in db_admin_password db_runtime_password state_witness_key data_key client_sig_key; do openssl rand -hex 32 > secrets/$f; done && chmod 644 secrets/*   # see secrets/README.md
docker compose up --build # db + backend + frontend · http://127.0.0.1:3000 (sign in at /login with the admin token or an API key)
```
Only the web container is published (on 127.0.0.1). The API sits on an **internal-only network with no internet egress**; the Gate
can still ALLOW, but nothing can leave. For real outbound tools or Meta Llama calls, opt in:
```bash
docker compose -f docker-compose.yml -f docker-compose.egress.yml up -d --build
```
Set `QYRIX_ENABLE_DEMO_RESET=1` only for demo/evaluation environments (it enables reset and the benchmark, which wipe evidence).

## Operations (v1.3)
* **Sign-in** — `/login` exchanges an operator token or a tenant API key for a server-side session (`qss_…`, 8 h absolute /
  30 min idle). The browser holds only that session in an httpOnly cookie; logout revokes it on the server.
* **API keys and roles** — `POST /api/v1/sentinel/keys {"role": "approver", "name": "alice"}` (owner/admin). Roles: owner, admin,
  security_reviewer, approver, auditor, integrator, agent (matrix in `docs/API_SPECIFICATION.md`). Keys are shown once and stored hashed.
* **Multi-tenancy (off by default)** — set `QYRIX_MULTI_TENANT=1` and `QYRIX_PLATFORM_TOKEN`; the platform operator creates tenants
  (`POST /api/v1/platform/tenants`) and bootstrap keys but cannot read tenant data. Each tenant gets its own chain, workspace,
  deny-all destination allowlist and PostgreSQL row-level-security view. Refused without PostgreSQL.
* **Monitoring** — `GET /api/v1/ready` (used by the Compose health check), `GET /api/v1/metrics` with `QYRIX_METRICS_TOKEN`
  (Prometheus text), JSON security events on the backend's stdout.
* **Backup / restore** — `scripts/backup.sh` (database first, then the proof chain volume, hash manifest; store it encrypted and
  off-host), `scripts/restore.sh backups/<timestamp> --yes`. The backend re-verifies the restored chain and fails closed on mismatch.
* **Dependencies** — Python installs from the hash-pinned `backend/requirements-lock.txt`; tests need `requirements-dev.txt`.

## Run without Docker
```bash
cp .env.example .env && ./scripts/dev.sh
```

## External proof anchoring (RFC 3161, optional)
Set `QYRIX_TSA_URL` (an RFC 3161 Time-Stamp Authority) and `QYRIX_TSA_CA_FILE` (its CA certificate, mounted read-only in the backend),
start with the egress override, then use **ANCHOR HEAD (RFC 3161)** in `/forensic` (admin) or `POST /api/v1/sentinel/proofs/anchor`.
Verify independently: `python backend/scripts/verify_proof.py bundle.json --tsa-ca tsa-ca.pem` or `openssl ts -verify`.
For rehearsal only, `python backend/scripts/local_tsa.py` runs a LOCAL TEST TSA (not external — never present its PASS as external anchoring).

## Judging demo (3 minutes)
```bash
QYRIX_TOKEN=<admin token> python backend/scripts/demo_judging.py      # ATTACK → INSPECT → PROVENANCE → BLOCK → PROOF → SAFE, every claim asserted
```
Then follow `docs/DEMO_SCRIPT.md` in the browser (homepage demo, `/forensic-lab`, `/forensic`).

## Test, benchmark, verify
```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest -q
cd backend && python scripts/run_benchmark.py --out ../evidence      # exact 10 cases, writes evidence + hashes
cd backend && python scripts/verify_proof.py ../evidence/benchmark-proof-bundle.json
cd frontend && npm ci && npx tsc --noEmit && npm run build
```

## Controlled execution (API)
```
POST /api/v1/sentinel/gate/evaluate   {tool, method, dest, data, lineage:[uuid], approval_id?}
  → {verdict, rules, gate_evaluation_id, grant_id | null, proof}
POST /api/v1/tools/execute            {gate_evaluation_id, grant_id}    # anything else → 400 CLIENT_PARAMS_NOT_ALLOWED
```
Full reference: `docs/API_SPECIFICATION.md`.

## Public demo
The homepage and `/forensic-lab` call `POST /api/v1/demo/run` with one of four fixed scenarios (safe, direct, transformed,
delayed). Each request runs the **real Gate** in a fresh isolated context with an in-memory proof chain and a sandbox
adapter: no network, no files, no commands, nothing written to the production audit chain. It is labelled **SIMULATED DEMO**.

## Known limits (do not claim beyond this)
- **Not production-ready for paying multi-tenant customers** — see `docs/PRODUCTION_READINESS.md`. Tenant isolation, roles, API keys and
  sessions are implemented and tested, but there is no SSO/MFA, no external penetration test, rate limits are per process, backups are not
  encrypted by the tooling, and total data loss is not alarmed. No usage metering, quotas or billing. Pricing on the website is *proposed*.
- One backend process per database. Without database settings (`QYRIX_DB_HOST` + password file, or `QYRIX_DATABASE_URL`; non-Docker default)
  state is in memory and lost on restart. The database password is only ever read from a file (Docker secret), never from configuration.
- Anchoring is implemented and tested against a local TSA, but **not verified with a public TSA**; without a configured TSA the chain
  reports `PARTIAL_UNANCHORED`, never `PASS`.
- Default Docker deployment: backend has no network egress. With `docker-compose.egress.yml`, egress is limited by application controls only
  (no per-destination network allowlist). TLS SNI/cert behaviour of the pinned request is not verified live.
- Tools: `http` and `file.read` execute through the adapter; `shell` never executes.
- Meta Llama live provider calls are **NOT LIVE VERIFIED** (no credentials; provider hosts blocked in the build environment). Failure handling
  (timeout, 5xx, garbage, hostile output) is tested on real sockets. To verify on your machine:
  `cd backend && META_API_KEY=... META_MODEL=<your model id> python scripts/llama_live_check.py --out ../evidence/llama-live-check.json`.
- The 10-case benchmark measures those synthetic cases only.
- Content-Security-Policy is enforced but allows inline scripts (Next.js bootstrap). No automated accessibility suite, no third-party audit.

## Meta AI classifier (advisory only)
`classify()` in `backend/app/gateway.py`: Meta Model API → Baseten → labelled heuristic. Only redacted, bounded (4,000 chars)
text is sent as JSON data under a fixed system prompt, no tools, temperature 0; the reply must be exactly `{label, explanation}`.
The Gate never calls or reads the classifier (`test_gate_decision_never_depends_on_classification`).
Evaluation of the classifiers: `cd backend && python -m eval.run_eval`.
