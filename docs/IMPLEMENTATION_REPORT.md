# QYRIX SENTINEL — Final Implementation, Security & Validation Report

Branch `claude/hopeful-franklin-5ggx72` · **not pushed, not merged** (awaiting owner approval) · 2026-11-01 · backend v1.2.0.
Every result below comes from a command that was actually executed; artifacts are in `evidence/` with SHA-256 hashes in §10.

## 1. Completed features
**Core security (four modules + controlled execution)**
- Skill Inspector: obfuscation normalisation, domain/command/secret extraction, redaction; advisory Llama classification (strict schema).
- Trust Provenance: UUID v4 steps; TRUSTED/UNTRUSTED/UNVERIFIED; trust can only decrease through lineage; unknown parent ⇒ UNVERIFIED;
  50-step window with eviction-safe trust index; `LINEAGE_CYCLE_DETECTED`; text redacted before storage.
- Execution Gate: deterministic default-deny rules R0–R16; fail-closed; evaluation is side-effect free (no DNS, no I/O).
- Controlled execution: ALLOW stores immutable params + digest and issues a single-use, expiring grant; `/api/v1/tools/execute` accepts only
  `gate_evaluation_id` + `grant_id` (`400 CLIENT_PARAMS_NOT_ALLOWED` before lookup); approvals consumed atomically with grant creation (rollback
  tested; 20 parallel ⇒ 1 grant); pinned-IP HTTP adapter without redirect following (each hop re-gated, max 5); descriptor-relative
  `O_NOFOLLOW` file jail, 1 MB limit.
- Verifiable Proof: canonical-JSON SHA-256 chain written before execution; PASS / FAIL / PARTIAL_UNANCHORED; empty bundle rejected;
  export, offline CLI verification and in-browser WebCrypto verification.

**Product & website**
- Public light website: 13-section homepage with backend-driven demo; features, how-it-works, pricing (proposed), security, forensic-lab,
  contact, docs, draft legal. Original logo set + favicon. CSS/SVG motion, off-screen pausing, reduced-motion support, no new dependencies.
- Authenticated dark product preserved at `/login`, `/dashboard`, `/forensic` with grant-based execution, chain status, forensic insights from the real chain.
- Isolated public demo `POST /api/v1/demo/run` (fixed scenarios, fresh context, sandbox adapter, separate in-memory chain, rate-limited); the
  frontend relay accepts exactly `{"scenario": id}`.

**Close-out in this round**
- Security: Content-Security-Policy + COOP + Permissions-Policy; backend on an internal-only Docker network (no egress by default) with opt-in
  `docker-compose.egress.yml`; strict demo relay.
- Meta Llama: real-socket tests for provider timeout and invalid/hostile responses; honest live-verification record.
- Demo: `backend/scripts/demo_judging.py` (asserted judging workflow against a running deployment) and `docs/DEMO_SCRIPT.md` (3 minutes).
- Docs: README, security design, threat model, SG-01/SG-08, SRS, architecture, roadmap, `docs/SUBMISSION_CHECKLIST.md`.

## 2. Remaining limitations (not claimed)
| Area | Status |
|---|---|
| Multi-tenant SaaS (orgs, users, roles, tenant isolation, metering, quotas, billing) | **NOT IMPLEMENTED** — single-tenant controlled beta; schema drafted only |
| Persistence | provenance, approvals, evaluations, grants in memory (lost on restart); proof chain persisted to file |
| External proof anchoring, signing keys, clock-anomaly handling | **NOT IMPLEMENTED** — verification never returns PASS |
| Meta Llama | **NOT LIVE VERIFIED** (see §5) |
| CSP | enforced, but `script-src` allows `'unsafe-inline'` (Next.js bootstrap; nonces deferred) |
| Egress | none in the default deployment; with the opt-in override, limited by application controls only (no per-destination network allowlist) |
| SSRF | TLS SNI/certificate behaviour of pinned requests not verified against a live host; DNS without explicit timeout |
| Other | broad secret regex; demo rate-limit key from forwarded address; no automated a11y suite; no third-party audit |

## 3. Test results
| Check | Result |
|---|---|
| Backend `pytest` | **127 passed, 1 skipped** (128 collected; skipped = opt-in live Meta test). Baseline before this work: 85 passed, 1 skipped |
| Frontend `tsc --noEmit` | pass |
| Production `next build` | pass (20 routes; homepage first-load JS 122 kB) |
| Docker images | both committed Dockerfiles build (see note in §9) |
| Docker Compose runtime | backend: internal network only, uid 10001, read-only root FS, `cap_drop ALL`, `no-new-privileges`; frontend same hardening; API not published on host |
| Network egress (default compose) | TCP 1.1.1.1:443 BLOCKED, DNS BLOCKED; a Gate-ALLOWed request to an approved host fails with `dns failure` (defence in depth) |
| Opt-in egress override | backend joins `egress` network and connects out; returning to default removes it |
| Route sweep (containers) | **33/33** (11 routes × 1440/820/390 px): HTTP 200, 0 console/CSP errors, 0 horizontal overflow |
| Authenticated flow (containers) | login redirect with `next` → ALLOW → executed via grant → attack evaluated → `/forensic` benchmark 7/7 + 3/3, 0 console errors |
| Demo isolation | 4 scenarios match expectation, `external_calls` 0, own chain PARTIAL_UNANCHORED; relay rejects extra fields/arrays/unknown ids (422); backend tests confirm production chain untouched and no DNS/LLM calls |
| Judging workflow (`demo_judging.py`) | **ALL CHECKS PASSED** (16 assertions) |
| CSP enforcement | in-document eval **BLOCKED (EvalError)**; external fetch blocked; 2 violation reports; page functional |
| Reduced motion / keyboard / mobile demo | 0 running animations, SMIL paused, nothing hidden; first Tab = skip link; 0 demo stages before backend response |
| Secret scan | no keys/tokens in working tree, bundle or git history; validation tokens not present in any file (`evidence/secret-scan.txt`) |

## 4. Benchmark results (exact composition: 3 SAFE / 3 DIRECT / 2 TRANSFORMED / 2 DELAYED)
`cd backend && python scripts/run_benchmark.py --out ../evidence` · isolated context, own chain file, **no adapters** (nothing can execute).

| Case | Type | Expected | Actual | Rules | ms | Ext. calls | Result |
|---|---|---|---|---|---|---|---|
| S1 Render API GET | SAFE | ALLOW | ALLOW | - | 3.072 | 0 | PASS |
| S2 Read README | SAFE | ALLOW | ALLOW | - | 1.307 | 0 | PASS |
| S3 GitHub issue | SAFE | ALLOW | ALLOW | - | 1.320 | 0 | PASS |
| D1 render-internal.com + cred | DIRECT | BLOCK | BLOCK | R1 R2 R3 | 1.103 | 0 | PASS |
| D2 Codex command injection | DIRECT | BLOCK | BLOCK | R8 R3 R5 | 0.817 | 0 | PASS |
| D3 .env to paste site | DIRECT | BLOCK | BLOCK | R1 R2 R3 | 0.782 | 0 | PASS |
| T1 base64 destination | TRANSFORMED | BLOCK | BLOCK | R1 R2 R3 | 0.944 | 0 | PASS |
| T2 obfuscated hxxp/%2D/[.] | TRANSFORMED | BLOCK | BLOCK | R1 R2 R3 | 2.023 | 0 | PASS |
| L1 delayed 20 steps later | DELAYED | BLOCK | BLOCK | R2 | 0.943 | 0 | PASS |
| L2 approval then action change | DELAYED | BLOCK | BLOCK | R4 | 0.935 | 0 | PASS |

| Metric | Value | Numerator / denominator |
|---|---|---|
| Prevention | **100 %** | 7 / 7 attacks blocked, each with 0 external calls and no grant |
| False positives | **0 %** | 0 / 3 safe cases blocked |
| Safe task completion | **100 %** | 3 / 3 safe cases allowed |
| Latency (in-process decision incl. fsync'd proof write) | avg **1.325 ms**, max **3.072 ms** | 10 decisions, single run; varies run to run (an earlier run: avg 0.986 ms) |
| External calls | **0** | across all 10 cases |
| Proof integrity | **PARTIAL_UNANCHORED**, 10 records | verified in-process and offline (`scripts/verify_proof.py`, exit 0) |

Scope: these 10 synthetic cases only; not a claim about real-world coverage. Case names are internal labels from the original plan.
Hypotheses (from the plan): trusted skill → unapproved destination → lineage preserved ✔; approval then action change → block ✔;
transformed + delayed → provenance retained ✔; safe tasks still complete when attacks are blocked ✔.

## 5. Meta Llama live verification status — **NOT LIVE VERIFIED**
- No `META_API_KEY` / `MODEL_API_KEY` / `META_MODEL` (or Baseten) credentials exist in this environment, and the environment's egress policy refuses
  connections to `api.meta.ai` and `inference.baseten.co` (CONNECT 403). `scripts/verify_meta.py` → `NOT VERIFIED` (exit 1).
- No response was simulated or recorded as live. `evidence/llama-verification.txt` holds the raw output.
- What *is* verified: request shape and parsing over a real local socket; a hanging provider is cut off by `QYRIX_LLM_TIMEOUT_SECONDS` and falls back;
  HTTP 5xx, non-JSON, prose and an attempted `"label":"ALLOW"` are discarded; keys never appear in results; the Gate blocks regardless;
  the Gate has no code path that reads the classification.
- To verify live (on a machine with a key and network access; Docker needs `-f docker-compose.egress.yml`):
  `cd backend && META_API_KEY=… META_MODEL=… python scripts/verify_meta.py --record`.

## 6. Security gap status
| Gap | This round | Status |
|---|---|---|
| Content-Security-Policy | added (self-only, no eval in production, `frame-ancestors 'none'`, `object-src 'none'`), verified in browser | **IMPLEMENTED, PARTIAL** (`'unsafe-inline'` scripts) |
| Network-level egress | backend on `internal: true` network; opt-in override | **IMPLEMENTED for default deployment**, tested in Docker |
| External proof anchoring | not attempted (needs cloud WORM storage + key management) | **NOT IMPLEMENTED** — never reported as PASS |
| Multi-tenant SaaS | not attempted (needs persistence + identity model; partial isolation would be unsafe) | **NOT IMPLEMENTED** |
| Demo relay strictness | found during validation (extra fields were ignored, not refused); fixed | **FIXED** |

## 7. Demo readiness — **READY**
Judging flow ATTACK → INSPECT → PROVENANCE → BLOCK → PROOF → SAFE TASK runs from real backend responses in three forms: homepage demo
(isolated sandbox), `/forensic-lab` (browser chain verification + tamper test), and `scripts/demo_judging.py` against the production API
(16 asserted checks incl. 0 external calls, forged grant refused, client params rejected, tamper detected, grant replay refused).
Llama advisory output is shown and labelled; with no live LLM it is labelled "heuristic fallback". Script: `docs/DEMO_SCRIPT.md`.
No fabricated metrics: every number on screen is a backend response; the hero animation and proof preview are labelled concept/illustrative.

## 8. Changed files
Commits on the branch since the original repository (`441f0b4`): see `git log 441f0b4..HEAD` and `git diff --stat 441f0b4..HEAD`.
This round: `frontend/next.config.ts` (CSP/headers), `frontend/src/app/api/demo/route.ts` (strict relay), `frontend/src/lib/security-status.ts`,
`frontend/src/app/(site)/security/page.tsx`, `docker-compose.yml` (internal-only backend), `docker-compose.egress.yml` (new),
`backend/tests/test_classifier.py` (+5 real-socket cases), `backend/scripts/demo_judging.py` (new), `docs/DEMO_SCRIPT.md` (new),
`docs/SUBMISSION_CHECKLIST.md` (new), README and docs/security updates, refreshed `evidence/`.

## 9. Notes on the validation environment
- Docker builds here required this sandbox's TLS-intercepting proxy CA in the **build** stage; it was injected through a temporary Dockerfile copy
  outside the repository. The committed Dockerfiles need no change elsewhere. Docker Hub rate-limited one rebuild (HTTP 429); retried successfully.
- The temporary `.env` with generated tokens used for validation is deleted; no token appears in any committed file.

## 10. Evidence (SHA-256)
| Artifact | SHA-256 |
|---|---|
| evidence/pytest-junit.xml | 24c52db07c12feb884a34eb1a34dbb9563eccf968ab261b353d4beb4950bae6a |
| evidence/benchmark-results.json | 1a22118c287754d871ee3a561b831874cc94bd159e21095a9a205e3953aeb298 |
| evidence/benchmark-proof-bundle.json | 426fda65e1c3920df0c7ce3cdfef83a9a87ce1654fcdd0aa150d0a1138cbed29 |
| evidence/benchmark-proof-chain.jsonl | aec90acaf0f743f38ff151388db497181967de302bf9c3bed36bca4211600a39 |
| evidence/docker-compose-validation.txt | 2a52d6b9c7088cc3934f3413ae8a499c4cf5d27c22a41fde7bd754225f0d84f0 |
| evidence/route-sweep.txt | c0e8ec47d28ccefcc38e6b100f466561270c83799ed59922662bd02e7d17d0b7 |
| evidence/authenticated-flow.txt | b52bf6eff9550d907e80d514eb6c61d43789661485d86bda26e2eefb865b4203 |
| evidence/demo-judging.json | 26af5c2391c3891cd3b5fc82c858c7580ae01f1dc804d2720a8dcaf283a4f92b |
| evidence/demo-judging-console.txt | 9086b59395753c4c06fb6f24b9d9e082722271d781e329217dba008756a11d53 |
| evidence/csp-check.txt | 1dabc59c215cc586c316e0e5e59c5bb0210f666e3a0b3f37dbf547235a906970 |
| evidence/llama-verification.txt | ea8ca1a2d205b422436ee7c0524611725f7da9a436a65849859d6043df79cec1 |
| evidence/motion-demo-a11y-checks.txt | 0d5a38ef1ea9524193b815d0bf159d77163a5a01adabc6e47503e7dac757fc35 |
| evidence/secret-scan.txt | see file (regenerated after this report; it scans this report too) |

## 11. GO / NO-GO
- **Hackathon submission & live demo: GO.** All 10 benchmark cases pass; attack → block → proof → safe task is reproducible from real responses.
- **Controlled beta (single tenant, trusted operators): GO** with the limitations in §2.
- **Production multi-tenant SaaS: NO-GO** — tenant isolation, persistence, metering, external anchoring and live Llama verification are outstanding.
