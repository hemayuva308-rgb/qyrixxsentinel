#!/usr/bin/env bash
# Online backup of a Docker Compose deployment. Order matters (see backend/scripts/backup.py): DATABASE FIRST, CHAIN SECOND.
# Output: ./backups/<UTC timestamp>/{db.dump,chain.tar,manifest.json}, mode 700. Store it encrypted, off-host.
set -euo pipefail
cd "$(dirname "$0")/.."
out="backups/$(date -u +%Y%m%dT%H%M%SZ)"
umask 077
mkdir -p "$out"
docker compose exec -T db pg_dump -U qyrix -d qyrix --format=custom --no-owner > "$out/db.dump"
bid=$(docker compose ps -q backend)
docker cp "$bid:/data/." - > "$out/chain.tar"          # tar stream of the chain volume (chains, tenant chains, anchors)
python3 - "$out" <<'PY'
import hashlib, json, sys, os, time
d = sys.argv[1]
sha = lambda p: hashlib.sha256(open(os.path.join(d, p), "rb").read()).hexdigest()
json.dump({"format": "qyrix-backup/1", "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "order": ["db.dump", "chain.tar"],
           "files": {f: sha(f) for f in ("db.dump", "chain.tar")}}, open(os.path.join(d, "manifest.json"), "w"), indent=2)
PY
echo "backup written to $out"
