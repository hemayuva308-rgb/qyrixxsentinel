"""Database migrations and runtime-role provisioning. Runs ONLY with the administrative account, as a one-shot job
(Docker Compose service `migrate`), never inside the long-running backend.

    python -m app.migrate [--runtime-password-file /run/secrets/db_runtime_password] [--allow-demo-reset]

Admin connection: QYRIX_ADMIN_DATABASE_URL, or QYRIX_DB_HOST/PORT/NAME + QYRIX_DB_ADMIN_USER + QYRIX_DB_ADMIN_PASSWORD_FILE.
The runtime password is read from a file and sent to PostgreSQL as a SCRAM-SHA-256 verifier computed locally, so the
plaintext never appears in SQL text, server logs or this process's output.
"""
import argparse
import base64
import glob
import hashlib
import hmac
import os
import secrets
import sys
from typing import List, Optional

from app import persistence

ROLES_SQL = """
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_app') THEN
    CREATE ROLE qyrix_app NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_runtime') THEN
    CREATE ROLE qyrix_runtime LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION INHERIT; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_auth') THEN
    CREATE ROLE qyrix_auth NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB; END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_maint') THEN
    CREATE ROLE qyrix_maint NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB; END IF;
END $$;
"""


def scram_verifier(password: str, iterations: int = 4096) -> str:
    """RFC 5802/7677 SCRAM-SHA-256 verifier in PostgreSQL's stored format (same as libpq's PQencryptPasswordConn)."""
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return "SCRAM-SHA-256$%d:%s$%s:%s" % (iterations, b(salt), b(stored_key), b(server_key))


def ensure_roles(admin_dsn: str) -> None:
    """Roles are cluster-global and not part of pg_dump; restores need them to exist before pg_restore."""
    import psycopg
    with psycopg.connect(admin_dsn, autocommit=True) as c:
        c.execute(ROLES_SQL)


def migrate(admin_dsn: str, runtime_password: Optional[str] = None, allow_demo_reset: bool = False) -> List[str]:
    import psycopg
    from psycopg import sql
    applied: List[str] = []
    with psycopg.connect(admin_dsn, autocommit=False, connect_timeout=10) as conn:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(424242)")          # one migrator at a time
            cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            cur.execute("SELECT name FROM schema_migrations")
            done = {r[0] for r in cur.fetchall()}
            for path in sorted(glob.glob(os.path.join(persistence.MIGRATIONS, "*.sql"))):
                name = os.path.basename(path)
                if name in done:
                    continue
                cur.execute(open(path).read())
                cur.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
                applied.append(name)
            if runtime_password is not None:
                if len(runtime_password) < 24 or "CHANGE_ME" in runtime_password:
                    raise SystemExit("runtime password must be >= 24 characters and not a placeholder")
                cur.execute(sql.SQL("ALTER ROLE qyrix_runtime PASSWORD {}").format(sql.Literal(scram_verifier(runtime_password))))
            fn = sql.SQL("FUNCTION qyrix_reset_tenant_evidence(text)")
            if allow_demo_reset:
                cur.execute(sql.SQL("GRANT EXECUTE ON {} TO qyrix_app").format(fn))
            else:
                cur.execute(sql.SQL("REVOKE EXECUTE ON {} FROM qyrix_app").format(fn))
    return applied


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Apply migrations and provision the least-privilege runtime role.")
    ap.add_argument("--runtime-password-file", default=os.getenv("QYRIX_DB_RUNTIME_PASSWORD_FILE", ""))
    ap.add_argument("--allow-demo-reset", action="store_true", default=os.getenv("QYRIX_ENABLE_DEMO_RESET") == "1",
                    help="grant the runtime the evidence-reset function (demo/evaluation deployments ONLY)")
    a = ap.parse_args(argv)
    dsn = persistence.admin_dsn_from_env()
    if not dsn:
        print("no administrative database connection configured", file=sys.stderr)
        return 2
    pw = None
    if a.runtime_password_file:
        pw = persistence._read_secret(a.runtime_password_file)
    applied = migrate(dsn, pw, a.allow_demo_reset)
    print("migrations applied: %s; runtime password %s; demo reset %s" % (
        ", ".join(applied) or "none (up to date)", "set" if pw else "unchanged", "ALLOWED" if a.allow_demo_reset else "denied"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
