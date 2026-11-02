# QYRIX SENTINEL — Meta Hackathon submission checklist

Legend: ✅ done and evidenced · ⚠️ done with a stated limitation · ❌ not done (reason stated) · ⏳ waiting on the owner.

## Locked 6-day plan
| Day | Deliverable | Status | Evidence |
|---|---|---|---|
| 1 | Baseline + select skill with unverified domain + synthetic credential | ⚠️ | skill + synthetic `sk-synth-*` fixtures done; **external baseline (LlamaFirewall / Pipelock) NOT RUN**: LlamaFirewall needs the owner's permission to install/run here, Pipelock unreachable. (Previously marked ✅ in error; the "baseline" in IMPLEMENTATION_REPORT is the repository test baseline, not the tool comparison.) |
| 2 | `provenance.py` + `gateway.py` | ✅ | `backend/app/provenance.py`, `gateway.py` (+ `proof.py`, `adapter.py`, `demo.py`) |
| 3 | Attack reproduce: synthetic cred + untrusted skill → assert external calls 0 + BLOCKED log | ✅ | `demo_judging.py` step 4; benchmark `external_calls_delta=0` |
| 4 | Benchmark 10 cases (3/3/2/2): prevention %, FP %, completion %, latency | ✅ | `evidence/benchmark-results.json` — 100 % / 0 % / 100 % / avg 0.802 ms (latest run; varies per run) |
| 5 | Meta AI integration + dashboard (attack → block → proof → SAFE ok) | ⚠️ | integrated + tested; **NOT LIVE VERIFIED** (no key, hosts blocked) — `evidence/llama-verification.txt`; dashboard done |
| 6 | GitHub clean + README + results + limitations + 3-min demo video + submit | ⏳ | repo clean, README, results, limitations, demo script/narration/recording checklist done; silent automated walkthrough (`qyrix-demo-walkthrough-silent.mp4`) exists as reference; **narrated video, push and submission await owner** |

## Judging criteria
| Criterion | What to show | Status |
|---|---|---|
| Impact 30 % — real incident pattern reproduced + prevented | skill README exfil, command injection, obfuscated & delayed variants all blocked before execution | ✅ |
| Meta AI 25 % — real classification | advisory Llama classifier with strict schema, evidence explanation, failure handling | ⚠️ live call not verified here — say so on stage |
| Tech 20 % — binding + provenance + tests | grant bound to params digest, monotone provenance, PostgreSQL persistence, RFC 3161 anchoring, tenant isolation + RBAC (v1.3), 210 passing tests | ✅ |
| Demo 25 % — attack → block → proof → SAFE | `docs/DEMO_SCRIPT.md`, `DEMO_NARRATION.md`, `DEMO_RECORDING_CHECKLIST.md`, homepage demo, `demo_judging.py` | ✅ (video ⏳) |

## Repository hygiene
| Item | Status |
|---|---|
| No `.env`, keys, tokens, passwords committed (working tree, bundle, history scanned) | ✅ `evidence/secret-scan.txt` |
| `.env.example` placeholders only (`CHANGE_ME…`, refused by auth) | ✅ |
| No `node_modules`, `.next`, venvs, caches in repo or ZIP | ✅ |
| Docs match code (README, architecture, API, security, SRS traceability, threat model, SG-01…08) | ✅ (updated for v1.3; see also `ORIGINAL_PLAN_ASSESSMENT.md`, `PRODUCTION_READINESS.md`) |
| Limitations stated (README, `/security`, IMPLEMENTATION_REPORT §2) | ✅ |
| Pricing labelled proposed; no fake checkout | ✅ |
| No fabricated metrics; illustrative visuals labelled | ✅ |

## Before submitting (owner actions)
1. ⏳ Approve the final report; then push the branch (`git push -u origin claude/hopeful-franklin-5ggx72`) — needs the Claude GitHub App or your own push.
2. ⏳ Llama: add `META_API_KEY`/`META_MODEL` as environment secrets and allow `api.meta.ai` (or run locally), then
   `python backend/scripts/llama_live_check.py --out evidence/llama-live-check.json`; update reports only with the real result.
3. ⏳ Optional: configure a public RFC 3161 TSA (`QYRIX_TSA_URL`, `QYRIX_TSA_CA_FILE`, egress override), anchor, and confirm `PASS`.
4. ⏳ Record the narrated 3-minute video with `docs/DEMO_RECORDING_CHECKLIST.md`.
5. ⏳ Open a PR to `main` and merge after review.
