# QYRIX SENTINEL — Final Submission Readiness Report

Branch `claude/hopeful-franklin-5ggx72` · **not pushed, not merged, `main` untouched** · 2026-11-01 · backend v1.2.0 (+ persistence & anchoring).
Status vocabulary: **VERIFIED** (executed test/evidence in this repo) · **IMPLEMENTED_NOT_VERIFIED** · **NOT_CONFIGURED** · **NOT_IMPLEMENTED** · **BLOCKED**.
Every VERIFIED item names its evidence in `evidence/` (SHA-256 in §13).

## 1. Completed features
| Feature | Status | Evidence |
|---|---|---|
| Skill Inspector (obfuscation-aware extraction, redaction) | VERIFIED | `pytest-junit.xml` (test_sentinel, test_classifier) |
| Trust Provenance (UUID v4, monotone trust, 50-step window, cycle detection) | VERIFIED | `pytest-junit.xml` (test_v12_controls) |
| Execution Gate (deterministic default-deny, fail-closed, R0–R17) | VERIFIED | `pytest-junit.xml`, `benchmark-results.json` |
| Grant-only controlled execution (`/tools/execute` = ids only) | VERIFIED | `pytest-junit.xml`, `demo-judging-console.txt` |
| Verifiable Proof (canonical JSON SHA-256 chain, bundle + offline + browser verification) | VERIFIED | `benchmark-proof-bundle.json`, `pytest-junit.xml` |
| **PostgreSQL persistence** (provenance, approvals, evaluations, grants, proof mirror, anchors) | VERIFIED | `persistence-anchor-tests.txt`, `persistence-docker-restart.txt` |
| **RFC 3161 external anchoring** — mechanism | VERIFIED against a real local TSA | `persistence-anchor-tests.txt` (test_anchor) |
| **RFC 3161 external anchoring** — with a public/independent TSA | BLOCKED (network) / NOT_CONFIGURED | `docker-compose-validation.txt` (409 ANCHOR_NOT_CONFIGURED) |
| Meta Llama advisory classifier — failure handling | VERIFIED (real sockets) | `llama-failure-path-tests.txt` |
| Meta Llama — live API | NOT_CONFIGURED + BLOCKED | `llama-live-check.json`, `llama-verification.txt` |
| Public website, isolated demo, Forensic Lab, dark product | VERIFIED | `route-sweep.txt`, `authenticated-flow.txt`, `motion-demo-a11y-checks.txt` |
| CSP, internal-only backend network, container hardening | VERIFIED | `csp-check.txt`, `docker-compose-validation.txt` |
| Multi-tenancy, metering, billing | NOT_IMPLEMENTED (by decision) | `docs/SAAS_PRODUCTION_REQUIREMENTS.md` |
| 3-minute demo materials | VERIFIED (docs) · narrated video NOT recorded | `DEMO_SCRIPT.md`, `DEMO_NARRATION.md`, `DEMO_RECORDING_CHECKLIST.md`; silent walkthrough MP4 |

## 2. Newly implemented in this round
1. **PostgreSQL persistence** — `backend/app/persistence.py`, `backend/migrations/001_core_persistence.sql`, wiring in `gateway.py`/`provenance.py`:
   ALLOW writes {evaluation, grant, approval consumption} in one DB transaction **before** the decision is recorded; grants consumed with
   an atomic conditional `UPDATE … RETURNING`; admin grant revocation (`POST /sentinel/grants/{id}/revoke`, recorded in the chain);
   Gate **revalidates** stored parameters against current policy before execution; startup loads only grants whose evaluation has an ALLOW
   record in the verified chain; DB proof mirror must be a prefix of the chain file; append-only triggers; DB outage ⇒ `R17_PERSISTENCE_UNAVAILABLE`
   (fail closed) with automatic recovery; Docker Compose `db` service (internal network, health-checked, capabilities dropped).
2. **RFC 3161 anchoring** — `backend/app/anchor.py`, `proof.evaluate_anchors`, `POST /sentinel/proofs/anchor`, `GET /sentinel/proofs/anchors`,
   anchors in export bundles, `verify_proof.py --tsa-ca`, ANCHOR HEAD button + anchor status in `/forensic`, `tests/tsa_local.py`, `scripts/local_tsa.py`.
3. **Llama** — `scripts/llama_live_check.py` (5 synthetic inputs incl. tool description + untrusted skill, real-endpoint failure probes, Gate-independence check);
   new real-socket tests: auth failure (401), provider outage, schema-valid *benign* answer for an exfiltration request (still BLOCKED).
4. **Demo** — `DEMO_SCRIPT.md` (7-segment timeline), `DEMO_NARRATION.md`, `DEMO_RECORDING_CHECKLIST.md`; `demo_judging.py` shows storage + anchoring status;
   automated silent walkthrough `qyrix-demo-walkthrough-silent.mp4` (3:01, not committed).
5. **Docs** — `SAAS_PRODUCTION_REQUIREMENTS.md` (new) and updates to README, architecture, API, database, security design, threat model, SG-05, SG-06, SRS, roadmap, checklist.

## 3. Test results
| Suite | Result |
|---|---|
| Backend `pytest` (all) | **155 passed, 1 skipped, 0 failed** (156 collected; skipped = opt-in live Meta test) — `pytest-junit.xml` |
| of which PostgreSQL persistence (real clusters incl. SIGKILL restart of a real uvicorn) | 13 passed |
| of which RFC 3161 anchoring (real local TSA) | 13 passed |
| of which Llama failure paths on real sockets | timeout, 5xx, garbage, prose, `"ALLOW"` label, 401, outage, benign-for-malicious — all passed |
| Frontend `tsc --noEmit` | pass |
| Production `next build` | pass (20 routes) |
| Docker Compose (db + backend + frontend) | up; hardening verified with `docker inspect`; API and PostgreSQL not published |
| Docker persistence: create → `docker compose restart backend` → verify | records present; grant executed once; replay 409; revoked 409 |
| Docker DB outage: `docker compose stop db` | evaluate BLOCK `R17_PERSISTENCE_UNAVAILABLE`, writes 503; after `start db` ALLOW + execution recover |
| Network egress (default) | TCP + DNS blocked from the backend; Gate-ALLOWed request fails at network layer |
| Route sweep (containers) | 33/33: HTTP 200, 0 console/CSP errors, 0 horizontal overflow |
| Authenticated flow + UI benchmark (containers, PostgreSQL) | pass, 0 console errors |
| Judging workflow (`demo_judging.py`, containers, PostgreSQL) | ALL CHECKS PASSED (16) |
| CSP | in-document eval blocked; external fetch blocked |
| Reduced motion / keyboard / mobile demo gating | pass |
| Secret scan (tree, bundle, history, run secrets) | clean — `secret-scan.txt` |

## 4. Benchmark results (original 10 cases, unchanged composition and expectations)
| Case | Type | Expected | Actual | Rules | ms | Ext. calls | Result |
|---|---|---|---|---|---|---|---|
| S1 Render API GET | SAFE | ALLOW | ALLOW | - | 2.996 | 0 | PASS |
| S2 Read README | SAFE | ALLOW | ALLOW | - | 0.798 | 0 | PASS |
| S3 GitHub issue | SAFE | ALLOW | ALLOW | - | 0.537 | 0 | PASS |
| D1 render-internal.com + cred | DIRECT | BLOCK | BLOCK | R1 R2 R3 | 0.655 | 0 | PASS |
| D2 Codex command injection | DIRECT | BLOCK | BLOCK | R8 R3 R5 | 0.527 | 0 | PASS |
| D3 .env to paste site | DIRECT | BLOCK | BLOCK | R1 R2 R3 | 0.503 | 0 | PASS |
| T1 base64 destination | TRANSFORMED | BLOCK | BLOCK | R1 R2 R3 | 0.584 | 0 | PASS |
| T2 obfuscated hxxp/%2D/[.] | TRANSFORMED | BLOCK | BLOCK | R1 R2 R3 | 0.626 | 0 | PASS |
| L1 delayed 20 steps later | DELAYED | BLOCK | BLOCK | R2 | 0.422 | 0 | PASS |
| L2 approval then action change | DELAYED | BLOCK | BLOCK | R4 | 0.376 | 0 | PASS |

**Attack prevention 7/7 = 100 %** · **False positives 0/3 = 0 %** · **Safe task completion 3/3 = 100 %** · **Average latency 0.802 ms** (max 2.996 ms; varies per run) ·
**External calls 0** · **Proof verification PARTIAL_UNANCHORED** (10 records, verified in-process and offline; no anchor in the benchmark context).
The same 10 cases also passed through the UI against PostgreSQL in Docker (7/7 + 3/3). Scope: these synthetic cases only.

## 5. Live Llama API status — **NOT_CONFIGURED** and **BLOCKED** (NOT LIVE VERIFIED)
- Configuration as implemented: `META_API_KEY` (or `MODEL_API_KEY`), `META_MODEL` (model id from your Meta account — none is assumed),
  optional `META_BASE_URL` (default `https://api.meta.ai/v1`, OpenAI-compatible `POST /chat/completions`, Bearer auth), `QYRIX_LLM_TIMEOUT_SECONDS`;
  Baseten fallback `BASETEN_API_KEY`/`BASETEN_MODEL`. Request: temperature 0, fixed system prompt, redacted text as JSON data; reply must be exactly `{label, explanation}`.
- This environment: no credentials, and its egress policy denies `api.meta.ai` and `inference.baseten.co` (CONNECT 403).
  `llama_live_check.py` → `NOT LIVE VERIFIED - not configured`. No response was simulated.
- Verified regardless of the provider: advisory only; the Gate blocked every malicious case (`llama-live-check.json` gate section); a schema-valid
  "benign" model answer, an attempted "ALLOW" label, timeout, 401, 5xx, garbage and outage never unblock and never fail open.

## 6. External proof anchoring status — **IMPLEMENTED; mechanism VERIFIED; public TSA BLOCKED; default deployment NOT_CONFIGURED**
- Workflow: admin `POST /sentinel/proofs/anchor` → TimeStampReq (SHA-256 head imprint, nonce, certReq) → TSA → token verified with
  `openssl ts -verify -queryfile` (imprint, nonce, signature, chain to `QYRIX_TSA_CA_FILE`) → stored (file + PostgreSQL, append-only) →
  `verify` reports **PASS** only if the latest verified anchor covers the current head; prefix ⇒ PARTIAL_UNANCHORED; contradiction or bad token ⇒ FAIL (+ gate degraded on contradiction).
- Evidence: 13 tests against a real local TSA (PASS, prefix, tamper, mismatch, rogue TSA, forged token, 500, garbage, unreachable, offline verify with/without trust anchor, restart).
- Not claimed: anchoring with an independent public TSA (every public TSA tested was blocked by the network policy). The deployed stack reports
  `ANCHOR_NOT_CONFIGURED` and `PARTIAL_UNANCHORED`. The local TSA is a test tool, not external anchoring.

## 7. PostgreSQL persistence status — **VERIFIED**
Restart (pytest with real PostgreSQL incl. SIGKILL of a real backend process; and `docker compose restart backend`), replay after restart and across
processes, expiry, revocation, forged DB rows never authorise, mirror truncation detected, DB outage fails closed and recovers, append-only enforced.
Limitation: one backend process per database (a second stale process cannot double-consume and fails closed).

## 8. Remaining limitations
Single tenant; no metering/billing; public-TSA anchoring not verified, no WORM/S3 copy, no scheduled anchoring; Llama not live-verified;
CSP allows inline scripts; opt-in egress mode has no per-destination network allowlist; TLS SNI with pinned IP not tested live; DNS without explicit timeout;
broad secret regex; no automated accessibility suite; no third-party audit; narrated demo video not recorded.

## 9. Known security risks
| Risk | Severity | Mitigation / status |
|---|---|---|
| Chain + anchor store rewritten by someone with server storage access, no independent TSA configured | High (for evidence) | configure a public TSA and anchor regularly (implemented, not configured) |
| Cross-tenant access if offered as multi-tenant SaaS | Critical | NOT_IMPLEMENTED — must not be offered as multi-tenant |
| XSS impact limited by CSP but inline scripts allowed | Medium | token in httpOnly cookie; nonce-based CSP planned |
| Egress-override deployments rely on application controls | Medium | default deployment has no egress |
| `gate_evaluations.params` stored in clear in PostgreSQL | Low–Medium | only Gate-ALLOWed (non-secret-pattern) data; internal network; encrypt at rest in production |
| Demo rate-limit identity from forwarded header | Low | global limit also enforced |

## 10. Hackathon readiness — **GO**
All 10 benchmark cases pass; ATTACK → INSPECT → PROVENANCE → BLOCK → PROOF → SAFE runs on the real stack; demo docs ready; statuses honest.

## 11. Production readiness — **NO-GO for real SaaS**
Missing: multi-tenancy + isolation tests, identity (SSO, per-tenant keys), metering/quotas, billing, verified independent anchoring, HA database,
multi-replica chain append, monitoring/incident response, third-party security audit. See `docs/SAAS_PRODUCTION_REQUIREMENTS.md`.
A single-tenant controlled beta with trusted operators is acceptable with the limitations in §8.

## 12. Exact steps required before submission
1. Review this report and the diff; approve.
2. Llama (optional but scores 25 %): add `META_API_KEY` + `META_MODEL` as environment secrets (never in chat or files) and allow `api.meta.ai`
   (environment settings → Network access), start a new session or run locally, then
   `cd backend && python scripts/llama_live_check.py --out ../evidence/llama-live-check.json`. Update reports **only** with the real result.
3. Anchoring (optional): set `QYRIX_TSA_URL` + `QYRIX_TSA_CA_FILE` for a public RFC 3161 TSA, run with `-f docker-compose.egress.yml`, click ANCHOR HEAD, confirm PASS.
4. Record the narrated video with `docs/DEMO_RECORDING_CHECKLIST.md` (the silent MP4 is timing reference only).
5. Push the branch (Claude GitHub App access or your own push from the bundle), open a PR to `main`, merge after review, submit.

## 13. Evidence (SHA-256)
| Artifact | SHA-256 |
|---|---|
| evidence/pytest-junit.xml | 9b699ec51a119d4cdf8573da73eebfa1d538ca399a6b9cefe71bf6214e2bc1e7 |
| evidence/persistence-anchor-tests.txt | 31d1346ad6436f974e43883f9f9bf5938afda2d84f1413e7af3493e49461076c |
| evidence/persistence-docker-restart.txt | 2b6d8f7f91219a3bdfdc29311683f440b60c3fc18a9f7e455df348e6f3db86dd |
| evidence/llama-failure-path-tests.txt | 8d0d1547a291633c2657ea3666e2556a96de624744af98b3355e403e48e02b74 |
| evidence/llama-live-check.json | 1120b867cf7d83ced065aa2419a69aface05789475eb00cdafc0d04301fa0084 |
| evidence/llama-verification.txt | ea8ca1a2d205b422436ee7c0524611725f7da9a436a65849859d6043df79cec1 |
| evidence/benchmark-results.json | 98a6ec6ed0a6bc9f5900570a38eb9b4514cb2bf0123209766b2dc169af9ae50e |
| evidence/benchmark-proof-bundle.json | 9de09e9b0c0b1ce5d63e6888764cffc977f2b0888446e939cd3d8ba0e7b202b2 |
| evidence/benchmark-proof-chain.jsonl | 7fa79e89227f63de0f86b6b1282f9991ed83e1d25964331d2b3fede32cde0e9d |
| evidence/docker-compose-validation.txt | b58a245d22581dfa597bfb5e9eaf47125bbcf4975b32bab8eb4bd8e8521bdeaa |
| evidence/demo-judging-console.txt | 0247a79d8a25e6707840cb01d08c64d1ecdece9df07b902b1b8815897b0e3bc4 |
| evidence/demo-judging.json | 2b6c8be6be09b5a6376a0fefbfc05da61e9c2bf3bf364bfd13b22a31c6117181 |
| evidence/route-sweep.txt | c0e8ec47d28ccefcc38e6b100f466561270c83799ed59922662bd02e7d17d0b7 |
| evidence/authenticated-flow.txt | b52bf6eff9550d907e80d514eb6c61d43789661485d86bda26e2eefb865b4203 |
| evidence/motion-demo-a11y-checks.txt | 0d5a38ef1ea9524193b815d0bf159d77163a5a01adabc6e47503e7dac757fc35 |
| evidence/csp-check.txt | 4c3f69dc491b27b4b073c2845f8b20f079e34d792acea7f953c1990e838d4798 |
| evidence/secret-scan.txt | 1736437bf3ae2d7c3f43340842f0ee42d597bef77e12f439f51637a6818dc5c0 |
| qyrix-demo-walkthrough-silent.mp4 (not committed) | fad3018962582896e58769a40f951fe34c6c66d97f1cf0ebd6388432c73ba518 |

Docker note: images were built from the committed Dockerfiles with this sandbox's TLS-proxy CA injected into the build stage only (outside the repo);
no change is needed elsewhere. Docker Hub rate-limited some pulls; retries succeeded.
