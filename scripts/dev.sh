#!/usr/bin/env bash
# Local run without Docker. Usage: cp .env.example .env && edit && ./scripts/dev.sh
set -euo pipefail
cd "$(dirname "$0")/.."
set -a; . ./.env; set +a
(cd backend && pip install -q -r requirements.txt && python -m uvicorn app.main:app --port 8000) &
(cd frontend && npm install --no-audit --no-fund && npm run build && BACKEND_URL=http://127.0.0.1:8000 node .next/standalone/server.js) &
wait
