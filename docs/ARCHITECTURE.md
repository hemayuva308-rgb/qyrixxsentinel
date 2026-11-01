# QYRIX SENTINEL — Architecture (as implemented, v1.2)

Status legend: **IMPLEMENTED** (code exists) · **TESTED** (automated test executed in this repo) · **PARTIAL** · **NOT IMPLEMENTED** · **PLANNED**.

## 1. System context

```
            ┌──────────────────────────── Docker network "internal" ───────────────────────────┐
 Browser ──▶│ frontend (Next.js 15, :3000, published on 127.0.0.1 only)                         │
            │   (site)  public light website  /, /features, /how-it-works, /pricing, /security, │
            │           /forensic-lab, /contact, /docs, /privacy, /terms                         │
            │   (app)   dark product          /login, /dashboard, /forensic  (middleware-gated)  │
            │   /api/session   login: verifies token, stores it in httpOnly cookie              │
            │   /api/proxy/*   authenticated same-origin proxy (CSRF header + origin check)     │
            │   /api/demo      public relay: forwards ONLY a fixed scenario id                  │
            │                         │                                                        │
            │                         ▼                                                        │
            │ backend (FastAPI, :8000, NOT published)                                          │
            │   QyrixGateMiddleware   sole-path: only /api/v1/* and /                          │
            │   /api/v1/sentinel/*    Inspector · Provenance · Gate · Approvals · Proof        │
            │   /api/v1/tools/execute grant-only controlled execution                          │
            │   /api/v1/demo/*        isolated public sandbox                                   │
            │   volume chain:/data    proof_chain.jsonl (append-only, fsync)                   │
            └──────────────────────────────────────────────────────────────────────────────────┘
                                      │ (only after ALLOW + grant, via HttpAdapter)
                                      ▼
                            approved external destinations
```

Style: **modular monolith**. One FastAPI process, modules separated by file and by an explicit `GateContext`.
PostgreSQL persistence is **IMPLEMENTED** (optional; enabled by `QYRIX_DATABASE_URL`, on by default in Docker Compose).
Multi-tenancy is **NOT_IMPLEMENTED** (see SAAS_PRODUCTION_REQUIREMENTS.md). Supported deployment: **one backend process per database**.

## 2. Backend modules

| Module | File | Responsibility | Status |
|---|---|---|---|
| Auth | `app/auth.py` | Bearer tokens, roles `admin` / `agent`, fail-closed when unset/short/placeholder | TESTED |
| Sole-path middleware | `app/core/gate.py` | Rejects any path outside `/api/v1` | TESTED |
| Skill Inspector | `app/gateway.py` (`norm`, `extract_domains`, `inspect_text`, `_redact`) | Normalise obfuscation, extract domains/commands/secrets, redact | TESTED |
| Advisory classifier | `app/gateway.py` (`classify`) | Meta Llama → Baseten → heuristic; strict schema; advisory only | TESTED (mocked); live NOT VERIFIED |
| Trust Provenance | `app/provenance.py` | `ProvenanceStore`: UUID v4 ids, TRUSTED/UNTRUSTED/UNVERIFIED, monotone trust, 50-step window, bounded trust index, cycle detection | TESTED |
| Execution Gate | `app/gateway.py` (`evaluate`) | Deterministic default-deny policy, approval consumption + grant creation + proof append in one critical section | TESTED |
| Controlled execution | `app/gateway.py` (`execute_grant`) + `app/adapter.py` | Grant-only execution; Http/File/Sandbox adapters | TESTED |
| Network guard | `app/netguard.py` | Destination parsing, SSRF classification, all-answer DNS validation, IP pinning, path confinement | TESTED |
| Verifiable Proof | `app/proof.py` | Canonical JSON v2 records, SHA-256 chain, PASS/FAIL/PARTIAL_UNANCHORED, bundle verification | TESTED |
| Public demo | `app/demo.py` | Fixed scenarios in a fresh isolated `GateContext` per request; sandbox adapter; rate limit | TESTED |
| Persistence | `app/persistence.py`, `migrations/001_core_persistence.sql` | PostgreSQL: provenance, approvals, evaluations, grants (atomic consume/revoke), append-only proof mirror and anchors | TESTED (real PostgreSQL, restart + outage) |
| External anchoring | `app/anchor.py` | RFC 3161 TSA client; tokens verified with `openssl ts -verify`; PASS only when a verified token covers the head | TESTED against a local TSA; public TSA NOT VERIFIED |

### GateContext

All mutable security state lives in a `GateContext`: provenance store, proof chain (+ optional file), approvals,
evaluations, grants, adapters, egress counter, latency samples, degraded flag, lock.

* `PROD` — the production context (chain file `QYRIX_CHAIN_FILE`, real adapters, env allowlist). The v1.1 module
  names (`_chain`, `_appr`, `_state`, …) are aliases of `PROD`'s objects.
* Demo — `demo.new_context()` per request: new `ProvenanceStore`, in-memory chain (no file), demo allowlist
  (`api.example.com`, `docs.example.com`), `SandboxAdapter` for every tool, no workspace.
* Benchmark CLI — `scripts/run_benchmark.py`: isolated context, its own chain file, **no adapters**.

## 3. Enforcement flow

```
inspect ─▶ provenance.add_step (UUID, effective trust = min(declared, ancestors))
          │
agent ─▶ POST /sentinel/gate/evaluate {tool, method, dest, cmd, data, lineage[], approval_id?, redirect_of?}
          │  (lock) rules → verdict
          │  ALLOW: store {params, digest} as gate evaluation; create grant; consume approval   ┐ atomic,
          │  append proof record (fsync)                                                       ┘ rolled back on failure
          ◀─ {verdict, rules, gate_evaluation_id, grant_id|null, proof}
agent ─▶ POST /tools/execute {gate_evaluation_id, grant_id}   (anything else → 400 CLIENT_PARAMS_NOT_ALLOWED)
          │  (lock) validate grant ↔ evaluation, unused, unexpired, digest recomputed, not degraded
          │  consume grant; append EXECUTION_STARTED (fsync)
          │  adapter(params)   ← stored params only
          │  append EXECUTED | EXECUTION_FAILED
          ◀─ {executed, result, proof_start, proof_result}
```

Evaluation performs no DNS lookup and no network I/O. DNS resolution and the request happen only inside
`HttpAdapter`, after the grant has been consumed and the start event recorded.

## 4. Frontend structure

| Area | Path | Notes |
|---|---|---|
| Root layout | `src/app/layout.tsx` | metadata only; themes are scoped below |
| Dark product | `src/app/(app)/…` | `.theme-app` wrapper; dashboard, forensic, login; panels in `src/components/*.tsx` |
| Light website | `src/app/(site)/…` | `.theme-site` wrapper; header/footer in `src/components/site/` |
| Brand | `src/components/brand/BrandMark.tsx`, `public/brand/*`, `src/app/icon.svg`, `apple-icon.png` | one geometry for all variants |
| Motion | `src/components/site/motion.tsx`, `globals.css` | IntersectionObserver reveals, SMIL pause when off-screen, `prefers-reduced-motion` |
| Demo client | `src/lib/demo.ts`, `LiveDemo.tsx`, `ForensicExplorer.tsx` | render only after a backend response |
| Browser verifier | `src/lib/verify.ts` | WebCrypto re-computation of the canonical chain |

No animation library was added (CSS + SVG/SMIL + IntersectionObserver only). Runtime dependencies are unchanged:
`next`, `react`, `react-dom`, `lucide-react`.

## 5. Persistence

| Data | Where | Durability |
|---|---|---|
| Proof chain | `QYRIX_CHAIN_FILE` JSONL, fsync per record (source of truth) + append-only `proof_records` mirror in PostgreSQL | survives restart; file verified on load; DB mirror must be a prefix of the file (else gate degraded) |
| Provenance, approvals, evaluations, grants | PostgreSQL when `QYRIX_DATABASE_URL` is set (memory otherwise) | survive restart; grants loaded only if their evaluation has an ALLOW record in the verified chain |
| Anchors | `<chain>.anchors.jsonl` + `proof_anchors` table | survive restart; re-checked against the chain on load |
| Demo state | per-request memory | discarded after the response |

Write order (fail closed): ALLOW → DB transaction {evaluation, grant, approval consumption} → proof record (file fsync → memory → DB mirror).
Execution: memory checks → Gate revalidation of stored params → atomic DB `UPDATE grants … RETURNING` → EXECUTION_STARTED → adapter.
DB unavailable ⇒ `persistence: down` ⇒ evaluations BLOCK with `R17_PERSISTENCE_UNAVAILABLE`, writes 503, execution refused; recovers automatically.

## 6. Deployment

`docker-compose.yml`: backend not published and attached only to `internal` (`internal: true`: **no egress**), read-only
root FS, tmpfs `/tmp`, `cap_drop: ALL`, `no-new-privileges`, non-root uid 10001, named volume for the chain. Frontend on `internal`
+ `edge` (for the published port `127.0.0.1:3000`), read-only, `cap_drop: ALL`, `no-new-privileges`. Outbound tool execution and
Meta Llama calls require `-f docker-compose.egress.yml`. Security headers incl. CSP come from `frontend/next.config.ts`. TLS termination is expected in front of the frontend (set `QYRIX_COOKIE_SECURE=1`).
