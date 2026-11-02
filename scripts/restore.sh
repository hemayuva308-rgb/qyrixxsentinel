#!/usr/bin/env bash
# Restore an encrypted backup into a Docker Compose deployment. DESTRUCTIVE for the database and the proof chain volume.
# Needs QYRIX_BACKUP_IDENTITY_FILE (age PRIVATE identity - bring it from offline storage) + QYRIX_BACKUP_SIGNING_KEY_FILE.
# Stages: verify signature + hashes + full trial decryption (nothing touched) -> stop app -> roles -> pg_restore in ONE
# transaction -> migrate -> chain extracted to a staging dir in the volume, then swapped (previous chain kept in
# /data/.pre-restore-<ts>) -> backend left STOPPED: run `app.recovery status/accept` (restoring old data is never silent).
set -euo pipefail
cd "$(dirname "$0")/.."
src="${1:?usage: scripts/restore.sh backups/<timestamp> --yes}"
[ "${2:-}" = "--yes" ] || { echo "refusing without --yes (this replaces the database and the proof chain)"; exit 2; }
: "${QYRIX_BACKUP_IDENTITY_FILE:?set QYRIX_BACKUP_IDENTITY_FILE (age private identity)}"
: "${QYRIX_BACKUP_SIGNING_KEY_FILE:?set QYRIX_BACKUP_SIGNING_KEY_FILE}"
python3 backend/scripts/backup.py verify --from "$src" --decrypt > /dev/null && echo "manifest signature, hashes and decryption verified"
docker compose stop frontend backend
docker compose exec -T db psql -U qyrix -d qyrix -v ON_ERROR_STOP=1 -q -c "DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qyrix_app') THEN CREATE ROLE qyrix_app NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qyrix_runtime') THEN CREATE ROLE qyrix_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qyrix_auth') THEN CREATE ROLE qyrix_auth NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='qyrix_maint') THEN CREATE ROLE qyrix_maint NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
END \$\$;"
age -d -i "$QYRIX_BACKUP_IDENTITY_FILE" "$src/db.dump.age" | \
  docker compose exec -T db pg_restore -U qyrix -d qyrix --clean --if-exists --single-transaction --exit-on-error
echo "database restored (single transaction)"
docker compose run --rm migrate
bid=$(docker compose ps -aq backend)
img=$(docker compose config --images | grep '^postgres' | head -1)
ts=$(date -u +%Y%m%dT%H%M%SZ)
age -d -i "$QYRIX_BACKUP_IDENTITY_FILE" "$src/chain.tar.age" | \
  docker run --rm -i --volumes-from "$bid" --user 0 --network none --entrypoint sh "$img" -c "set -e
    rm -rf /data/.staging && mkdir /data/.staging && tar -xf - -C /data/.staging -o
    mkdir /data/.pre-restore-$ts
    for e in /data/* ; do [ -e \"\$e\" ] && mv \"\$e\" /data/.pre-restore-$ts/ ; done
    for e in /data/.staging/* ; do [ -e \"\$e\" ] && mv \"\$e\" /data/ ; done
    rmdir /data/.staging && chown -R 10001 /data"
echo "proof chain restored (previous chain kept in volume at /data/.pre-restore-$ts)"
cat <<MSG
NEXT (backend is intentionally still stopped):
  docker compose run --rm backend python -m app.recovery status
  docker compose run --rm backend python -m app.recovery accept --reason "restored $src after <incident id>"
  docker compose start backend frontend
MSG
