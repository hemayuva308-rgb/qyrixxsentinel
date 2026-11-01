# Local secrets (never committed)

Everything in this folder except this README is git-ignored.

Docker Compose reads the PostgreSQL password from `secrets/db_password` (a Docker secret mounted at
`/run/secrets/db_password` in the `db` and `backend` containers). Create it once before `docker compose up`:

```bash
openssl rand -hex 32 > secrets/db_password
chmod 644 secrets/db_password   # file-based Compose secrets keep host permissions; the non-root containers must read it
```

Keep the folder itself private on shared machines. A missing, empty or `CHANGE_ME` password makes the backend fail closed
(every Gate decision BLOCKs with `R17_PERSISTENCE_UNAVAILABLE`).
