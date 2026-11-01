# Phase 1 security cleanup (2026-11-01)

Findings (values intentionally not reproduced):
- `.env.example` held two real-looking 64-hex tokens (admin, agent): replaced with `CHANGE_ME_*` placeholders.
- `backend/.env` shipped inside the ZIP with the same two tokens: removed.
- `.venv/` (~150 MB), `.pytest_cache`, `__pycache__`, `tsconfig.tsbuildinfo`, runtime `proof_chain.jsonl` removed from the distributable.
- Code hits for "key/password/token" are synthetic test/benchmark fixtures (fake keys, `render-internal.com`), not credentials.

Must be rotated by the owner: `QYRIX_ADMIN_TOKEN`, `QYRIX_AGENT_TOKEN` (treat the old values as exposed anywhere the ZIP or
`.env.example` was shared). If a real `META_API_KEY` or `BASETEN_API_KEY` was ever pasted into any copy of `.env`, rotate it too;
the `.env` seen had no Meta key set.

Hardening added: `app/auth.py` refuses any token starting with `CHANGE_ME`, so copying the example file cannot create a working login.
