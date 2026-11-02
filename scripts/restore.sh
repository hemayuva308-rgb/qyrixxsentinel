#!/usr/bin/env bash
# Restore a backup made by scripts/backup.sh into a Docker Compose deployment. DESTRUCTIVE: replaces the database and
# the proof chain volume. The backend is stopped during restore; on start it re-verifies the chain and the DB proof
# mirror and fails closed (Gate degraded, R17) if they are inconsistent.
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:?usage: scripts/restore.sh backups/<timestamp> --yes}"
[ "${2:-}" = "--yes" ] || { echo "refusing without --yes (this replaces all durable state)"; exit 2; }
python3 - "$src" <<'PY'
import hashlib, json, os, sys
d = sys.argv[1]; m = json.load(open(os.path.join(d, "manifest.json")))
assert m.get("format") == "qyrix-backup/1", "unknown backup format"
for f, h in m["files"].items():
    if hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() != h:
        sys.exit("backup file %s does not match its manifest hash" % f)
print("manifest verified")
PY
docker compose stop frontend backend
docker compose exec -T db psql -U qyrix -d qyrix -v ON_ERROR_STOP=1 -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qyrix_app') THEN CREATE ROLE qyrix_app NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END \$\$;"
docker compose exec -T db pg_restore -U qyrix -d qyrix --clean --if-exists --no-owner --single-transaction --exit-on-error < "$src/db.dump"
bid=$(docker compose ps -aq backend)
docker run --rm --volumes-from "$bid" -v "$(cd "$src" && pwd):/restore:ro" --user 0 --network none --entrypoint sh postgres:16-alpine \
  -c 'find /data -name "*.jsonl" -delete && tar -xf /restore/chain.tar -C /data --no-same-owner && chown -R 10001 /data'
docker compose start backend frontend
echo "restored from $src; check: docker compose ps (backend health = /api/v1/ready)"
