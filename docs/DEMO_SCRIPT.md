# QYRIX SENTINEL — 3-minute judging demo

**Flow:** ATTACK → INSPECT → PROVENANCE → BLOCK → PROOF → SAFE TASK COMPLETION.
Everything shown comes from real backend responses. Data is synthetic (`sk-synth-*` keys, RFC 2606 `example.net` hosts).
No metric on screen is estimated or illustrative except the clearly labelled concept animation and proof preview.

## Before the demo (T–10 min)
```bash
cp .env.example .env                       # set both tokens: openssl rand -hex 32 ; QYRIX_ENABLE_DEMO_RESET=1 for the benchmark
docker compose up -d --build               # http://127.0.0.1:3000  (backend has NO network egress by default)
```
Rehearse once with the CLI (asserts every claim, exits non-zero if anything is off):
```bash
QYRIX_TOKEN=<admin token> python backend/scripts/demo_judging.py
```
Open three tabs: `/` (scrolled to **Interactive demo**), `/forensic-lab`, `/login` → sign in → `/dashboard`.
Optional reset for a clean chain: Forensic Lab → **RUN 10 CASES** (this resets the demo-mode chain and runs the benchmark).

## Script (≈ 3:00)

| Time | Show | Say |
|---|---|---|
| 0:00–0:20 | Homepage hero | "Agents read instructions and call tools. Detection after the fact is not prevention. QYRIX SENTINEL sits between the agent and every tool and decides **before** execution." |
| 0:20–0:50 | Homepage **Run Direct Attack** | "A third-party skill README tells the agent to upload a key. The Inspector finds the unapproved host and the secret reference. The README is UNVERIFIED. The Gate blocks with R1, R2, R3; no grant, the adapter is never called, **external calls: 0**. The decision is the real backend one, from an isolated sandbox." |
| 0:50–1:15 | **Run Delayed Attack** | "Harder case: an untrusted email is summarised 20 steps later by a step the agent labels TRUSTED. Trust can only go down, so the summary is still UNTRUSTED and the secret can't leave. Note the advisory classifier calls this text **benign**; it doesn't matter, AI never authorises." |
| 1:15–1:35 | Decision card → "Independent safe task … ALLOW → completed" | "Blocking an attack doesn't break the agent: an independent trusted task still completes." |
| 1:35–2:05 | `/forensic-lab` → **Verify in your browser**, **Tamper a copy** | "Every decision is a canonical-JSON record hash-chained to the last. This page re-computes the chain in your browser with WebCrypto. Flip one verdict in a copy and it fails at that record. We report PARTIAL_UNANCHORED, not PASS, because external anchoring isn't built yet." |
| 2:05–2:40 | Terminal: `demo_judging.py` (pre-run output or live) | "Same flow on the production API, through the real login and proxy: attack blocked, forged grant refused, client parameters rejected with CLIENT_PARAMS_NOT_ALLOWED, 0 external calls, tamper detected, then the safe file read executes through a single-use grant and a replay is refused." |
| 2:40–3:00 | `/forensic` benchmark table | "On the exact 10-case plan benchmark, 3 safe, 3 direct, 2 transformed, 2 delayed: 7 of 7 attacks blocked, 3 of 3 safe tasks allowed, sub-millisecond average. These are 10 synthetic cases, not a coverage claim. Detection is not prevention. We enforce from trust to execution." |

## Facts to have ready (from evidence/)
- Benchmark: 7/7 blocked, 0/3 false positives, 3/3 safe completed, 0 external calls (`evidence/benchmark-results.json`).
- Tests: see `evidence/pytest-junit.xml`.
- Llama: integrated as advisory classifier with strict schema; **not live-verified** in this environment (no key, provider hosts blocked) — `evidence/llama-verification.txt`. With a key: `META_API_KEY=… META_MODEL=… python backend/scripts/verify_meta.py` (needs the egress override).
- Backend container has no network egress by default (`docker-compose.yml`, `internal: true`); real outbound tools need `-f docker-compose.egress.yml`.

## If something goes wrong
| Symptom | Cause | Fix |
|---|---|---|
| Demo shows "No result … rate limit" | > 20 runs/min from one client | wait a minute or raise `QYRIX_DEMO_RATE_PER_MIN` |
| Demo shows "backend unreachable" | backend container down | `docker compose ps`, `docker compose up -d backend` |
| Gate blocks everything with R11 | stored proof chain fails verification | expected fail-closed behaviour; in demo mode use RUN 10 CASES (resets) |
| Benchmark button disabled | `QYRIX_ENABLE_DEMO_RESET` not 1 | set it in `.env`, `docker compose up -d` |
