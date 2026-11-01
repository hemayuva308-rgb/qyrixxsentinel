# QYRIX SENTINEL — demo recording checklist

Status of the video in this repository: **NOT RECORDED** (a narrated video must be recorded by the team locally).
An automated, silent walkthrough capture may exist as `qyrix-demo-walkthrough-silent.mp4` (3:01, 1440×900, H.264) next to the delivered ZIP; it is
a timing/reference aid only — not the submission video (no narration, scripted input).

## 1. Environment (once, ~10 min)
- [ ] Docker Desktop running; ports 3000 free.
- [ ] `cp .env.example .env`; set `QYRIX_ADMIN_TOKEN`, `QYRIX_AGENT_TOKEN`, `POSTGRES_PASSWORD` to `openssl rand -hex 32` values;
      `QYRIX_ENABLE_DEMO_RESET=1`. Never show `.env` on screen.
- [ ] Optional, only if real: Meta key (`META_API_KEY`, `META_MODEL`) and/or an RFC 3161 TSA (`QYRIX_TSA_URL`, `QYRIX_TSA_CA_FILE`)
      plus `-f docker-compose.egress.yml`. Verify first: `python backend/scripts/llama_live_check.py` → must print `LIVE_VERIFIED`
      before you say "live" on camera. Otherwise use the default narration.

## 2. Backend and frontend startup
```bash
docker compose up -d --build
```
- [ ] `docker compose ps` → db healthy, backend Up, frontend Up.
- [ ] http://127.0.0.1:3000 loads; `/login` accepts the admin token.
- [ ] Dashboard badges: API/GATE/PROVENANCE/PROOF available, STORAGE PostgreSQL.

## 3. Demo scenario reset (right before recording)
- [ ] `/forensic` → **RUN 10 CASES** (resets the demo-mode chain and runs the benchmark: expect 7/7 blocked, 3/3 safe), then reload `/dashboard`.
      Alternatively `docker compose down -v && docker compose up -d` for a completely empty state.
- [ ] Rehearse once: `QYRIX_TOKEN=<admin token> python backend/scripts/demo_judging.py` → "ALL CHECKS PASSED". Reset again.
- [ ] Have the six inputs from `docs/DEMO_SCRIPT.md` in a text file **off-screen** to paste.

## 4. Browser preparation
- [ ] Chrome/Edge, new profile, no extensions, bookmarks bar hidden, zoom 100 %, window 1440×900 (or 1920×1080 at 125 %).
- [ ] Tabs in order: `/` · `/dashboard` · `/forensic`. Signed in. Close dev tools.
- [ ] Notifications off (OS do-not-disturb). No password manager pop-ups (new profile).
- [ ] Do not open `/api/...` URLs or `.env` on screen.

## 5. Screen recording settings
- [ ] OBS / QuickTime / Loom: 1080p, 30 fps, display capture of the browser window only.
- [ ] Microphone: external or headset, noise suppression on, levels peaking ~-12 dB; record a 5-second test.
- [ ] Cursor highlight on (optional). Keyboard shortcuts overlay off.

## 6. Narration
- [ ] Read `docs/DEMO_NARRATION.md`; keep to 2:50–3:00. Say only numbers visible on screen.
- [ ] Use the honest-status lines (Llama not live-verified unless proven; PARTIAL_UNANCHORED unless a real anchor shows PASS).

## 7. Final playback review
- [ ] Length ≤ 3:00. Audio clear the whole way.
- [ ] Every segment visible: Problem, Skill Inspection, Attack, Gate BLOCK (rules + no grant + external calls), Proof (verify + tamper), Safe execution, Impact line.
- [ ] No token, password, `.env`, personal email or real key visible in any frame (scrub with pause).
- [ ] No claim of live Llama or external anchoring unless the screen shows it.
- [ ] Export MP4 (H.264), name `qyrix-sentinel-demo.mp4`; update `docs/SUBMISSION_CHECKLIST.md` → Day 6 video ✅ only once the file exists.
