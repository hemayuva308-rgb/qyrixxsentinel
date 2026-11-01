# Qyrix Sentinel - Trust-to-Execution Guard (MVP v1.1)

Deterministic, default-deny gate between an AI agent and its tools. Llama (Meta AI / Baseten) classifies and explains
untrusted instructions; **it can never allow an action** - enforcement is deterministic policy.

Pipeline: **Inspector -> Trust Provenance (50-step memory, taint) -> Execution Gate -> Verifiable Proof (hash chain)**.

## Run
    cp .env.example .env        # fill tokens (openssl rand -hex 32), set QYRIX_ENABLE_DEMO_RESET=1 only for demo/eval
    docker compose up --build   # UI: http://127.0.0.1:3000   (sign in with the admin token)
    # or without Docker:  ./scripts/dev.sh

## Test
    cd backend && pip install -r requirements.txt && python -m pytest -q      # 45 tests
    cd frontend && npm install && npx tsc --noEmit && npm run build

## What is enforced (all covered by tests)
Auth on every endpoint (admin vs agent); agent cannot approve/reset/benchmark; unknown tool/destination = BLOCK;
SSRF (loopback, private, link-local, userinfo, non-canonical IPs, DNS answers incl. mixed) = BLOCK; DNS-validated + IP-pinned
execution, redirects never followed; approvals server-side only, bound to the payload hash, expiring, single-use, race-safe;
decision written to the proof chain **before** any request; broken chain => gate blocks everything; secrets redacted in proofs
and before any AI call; `file.read` confined to the workspace (symlinks resolved, protected names denied).

## Known limits (do not claim beyond this)
- Single-tenant, single-process; provenance/approvals are in memory (lost on restart). Proof chain persists to a file.
- Chain is tamper-EVIDENT and UNANCHORED (no external checkpoint). "Zero external calls" is an in-process counter,
  not network-level proof. DNS resolution has no timeout. TLS SNI/cert verification of the pinned request is untested.
- `shell` never executes (always BLOCK). `file.read` is gated but the gate does not return file contents.
- Meta AI endpoint/model are configuration; the live provider call has not been verified (tests use mocks).
- Benchmark = 10 synthetic cases; it measures these cases only.
- Secret regex is broad (can false-positive on words like "token").

## Meta AI classifier (advisory only)
`classify()` in `backend/app/gateway.py`: Meta Model API (`https://api.meta.ai/v1`, `/chat/completions`) -> Baseten -> labelled heuristic.
- The gate never calls or reads the classifier (test: `test_gate_decision_never_depends_on_classification`).
- Only redacted, bounded (4000 chars) text is sent, as JSON data under a fixed system prompt; no tools, temperature 0.
- The reply must be exactly `{"label","explanation"}`; anything else (extra keys, prose, bad label) is discarded and the next provider is tried.
- `-contributor` models and non-https base URLs are refused. The Inspector UI shows provider, model, latency and failed attempts.
- **Live status: NOT verified in CI.** Run `cd backend && META_API_KEY=... META_MODEL=muse-spark-1.3 python scripts/verify_meta.py [--record]` on your machine.
- Opt-in live test: `QYRIX_LIVE_TESTS=1 META_API_KEY=... META_MODEL=... python -m pytest tests/test_classifier.py -k live`.
- Evaluation: `cd backend && python -m eval.run_eval` (18 labelled synthetic items; LLM is measured only when a provider really answers).
