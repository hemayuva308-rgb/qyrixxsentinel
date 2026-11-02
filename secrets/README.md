# Local secrets (never committed)

Everything in this folder except this README is git-ignored. Create the files once before `docker compose up`:

```bash
openssl rand -hex 32 > secrets/db_admin_password      # PostgreSQL superuser: mounted ONLY into `db` and the one-shot `migrate`
openssl rand -hex 32 > secrets/db_runtime_password    # least-privilege `qyrix_runtime` login: mounted into `backend` (+ `migrate`)
openssl rand -hex 32 > secrets/state_witness_key      # HMAC key sealing the data-loss witness (see docs/DISASTER_RECOVERY.md)
chmod 644 secrets/db_admin_password secrets/db_runtime_password secrets/state_witness_key
# file-based Compose secrets keep host permissions; the non-root containers must be able to read them
```

Keep this folder private on shared machines (`chmod 700 secrets`). The backend never receives the admin password: if it
is configured with an over-privileged database account it refuses to start persistence (every Gate decision BLOCKs with
`R17_PERSISTENCE_UNAVAILABLE`). A missing, empty or `CHANGE_ME` secret fails closed the same way.

Backup encryption keys are deliberately **not** kept here: the backup host holds only the age *public* recipient; the
private identity lives offline (see `docs/DISASTER_RECOVERY.md`).

Upgrading from v1.3 (`secrets/db_password`): `mv secrets/db_password secrets/db_admin_password`, create
`db_runtime_password`, then `docker compose up` - the `migrate` service provisions the runtime role.
