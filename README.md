# QYRIX SENTINEL — Trust-to-Execution Guard (v1.2, controlled beta)

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
| Backend (FastAPI): Inspector, Provenance, Gate, controlled adapter, Proof, public demo | `backend/app/` |
| Tests (122 passing, 1 opt-in live test skipped) | `backend/tests/` |
| Benchmark CLI with retained evidence · offline proof verifier | `backend/scripts/run_benchmark.py`, `backend/scripts/verify_proof.py` |
| Public light-theme website (`/`, features, how-it-works, pricing, security, forensic-lab, contact, docs) | `frontend/src/app/(site)/` |
| Authenticated dark product (`/login`, `/dashboard`, `/forensic`) | `frontend/src/app/(app)/` |
| Brand assets (SVG mark, lockups, favicon) | `frontend/public/brand/`, `frontend/src/app/icon.svg` |
| Documentation · security gates · threat model · evidence | `docs/`, `security/`, `evidence/` |

Start with `docs/QYRIX_SENTINEL_FINAL_MASTER_PLAN.md` (authoritative spec) and `docs/IMPLEMENTATION_REPORT.md` (what is done, tested and open).

## Run with Docker Compose
```bash
cp .env.example .env      # replace every CHANGE_ME value:  openssl rand -hex 32
docker compose up --build # http://127.0.0.1:3000   (sign in at /login with the admin or agent token)
```
Only the web container is published (on 127.0.0.1); the API stays on the internal network. Set `QYRIX_ENABLE_DEMO_RESET=1`
only for demo/evaluation environments (it enables reset and the benchmark, which wipe evidence).

## Run without Docker
```bash
cp .env.example .env && ./scripts/dev.sh
```

## Test, benchmark, verify
```bash
cd backend && pip install -r requirements.txt && python -m pytest -q
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
- **Single tenant.** No organisations, tenant isolation, usage metering, quotas or billing. Pricing on the website is *proposed*.
- Provenance, approvals, evaluations and grants are in memory (lost on restart). The proof chain persists to a file.
- Proof chain is tamper-evident and **unanchored**: verification reports `PARTIAL_UNANCHORED`, never `PASS`.
- Egress is accounted in-process; no network-level egress firewall. TLS SNI/cert behaviour of the pinned request is not verified live.
- Tools: `http` and `file.read` execute through the adapter; `shell` never executes.
- Meta Llama live provider calls are **not verified** here (tests use mocks and recorded fixtures):
  `cd backend && META_API_KEY=... META_MODEL=... python scripts/verify_meta.py --record`.
- The 10-case benchmark measures those synthetic cases only.
- No CSP header, no automated accessibility suite, no third-party audit.

## Meta AI classifier (advisory only)
`classify()` in `backend/app/gateway.py`: Meta Model API → Baseten → labelled heuristic. Only redacted, bounded (4,000 chars)
text is sent as JSON data under a fixed system prompt, no tools, temperature 0; the reply must be exactly `{label, explanation}`.
The Gate never calls or reads the classifier (`test_gate_decision_never_depends_on_classification`).
Evaluation of the classifiers: `cd backend && python -m eval.run_eval`.
