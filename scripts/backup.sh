#!/usr/bin/env bash
# Encrypted online backup of a Docker Compose deployment (see backend/scripts/backup.py for the design).
# Requires on the host: docker, age, python3 (stdlib only). Keys (NOT in this repository, NOT in ./secrets):
#   QYRIX_BACKUP_RECIPIENTS_FILE  age PUBLIC recipient(s) - the backup host cannot decrypt
#   QYRIX_BACKUP_SIGNING_KEY_FILE manifest HMAC key (>= 32 chars)
# Optional: QYRIX_BACKUP_UPLOAD_CMD='rclone copy {dir} offsite:qyrix-backups'  (encrypted files only)
# Output: ./backups/<UTC timestamp>/{db.dump.age, chain.tar.age, manifest.json}, dir 700 / files 600. No plaintext on disk.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${QYRIX_BACKUP_RECIPIENTS_FILE:?set QYRIX_BACKUP_RECIPIENTS_FILE (age public recipients file)}"
: "${QYRIX_BACKUP_SIGNING_KEY_FILE:?set QYRIX_BACKUP_SIGNING_KEY_FILE}"
umask 077
started=$(date +%s)
out="backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$out"
trap 'rc=$?; if [ $rc -ne 0 ]; then rm -rf "$out"; echo "backup FAILED (partial output removed)" >&2; fi' EXIT
# 1) database FIRST (admin account inside the db container; ownership kept), streamed into age
docker compose exec -T db pg_dump -U qyrix -d qyrix --format=custom | age -e -R "$QYRIX_BACKUP_RECIPIENTS_FILE" > "$out/db.dump.age"
# 2) proof chain volume SECOND, streamed into age
bid=$(docker compose ps -q backend)
docker cp "$bid:/data/." - | age -e -R "$QYRIX_BACKUP_RECIPIENTS_FILE" > "$out/chain.tar.age"
iid=$(docker compose exec -T db psql -U qyrix -d qyrix -tAc "SELECT install_id FROM installation" 2>/dev/null || true)
python3 backend/scripts/backup.py seal --out "$out" --install-id "$iid" --started "$started" > /dev/null
if [ -n "${QYRIX_BACKUP_UPLOAD_CMD:-}" ]; then
  eval "${QYRIX_BACKUP_UPLOAD_CMD//\{dir\}/$out}"
fi
# monitored (ops/prometheus/qyrix-alerts.yml QyrixBackupTooOld) via node_exporter --collector.textfile.directory=backups
printf '# TYPE qyrix_backup_last_success_timestamp_seconds gauge\nqyrix_backup_last_success_timestamp_seconds %s\n' "$(date -u +%s)" > backups/qyrix_backup.prom.tmp
mv backups/qyrix_backup.prom.tmp backups/qyrix_backup.prom
echo "encrypted backup written to $out"
