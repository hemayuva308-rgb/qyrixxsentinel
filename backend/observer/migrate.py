"""Observer database migrations (one-shot, ADMIN account of observer-db; never the backend DB, never the runtime).

    OBSERVER_ADMIN_DATABASE_URL=... python -m observer.migrate [--runtime-password-file FILE]

The runtime password is sent as a locally computed SCRAM-SHA-256 verifier (plaintext never in SQL or logs)."""
import argparse
import base64
import glob
import hashlib
import hmac
import os
import secrets
import sys
from typing import List, Optional

MIGRATIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")


def scram_verifier(password: str, iterations: int = 4096) -> str:
    salt = secrets.token_bytes(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    sk = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b = lambda x: base64.b64encode(x).decode()
    return "SCRAM-SHA-256$%d:%s$%s:%s" % (iterations, b(salt), b(hashlib.sha256(ck).digest()), b(sk))


def expected() -> List[str]:
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(MIGRATIONS, "O*.sql")))


def migrate(admin_dsn: str, runtime_password: Optional[str] = None) -> List[str]:
    import psycopg
    from psycopg import sql
    applied = []
    with psycopg.connect(admin_dsn, autocommit=False, connect_timeout=10) as conn:
        with conn.transaction(), conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(515151)")
            cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            cur.execute("SELECT name FROM schema_migrations")
            done = {r[0] for r in cur.fetchall()}
            for name in expected():
                if name not in done:
                    cur.execute(open(os.path.join(MIGRATIONS, name)).read())
                    cur.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
                    applied.append(name)
            cur.execute("GRANT SELECT ON schema_migrations TO observer_runtime")
            if runtime_password is not None:
                if len(runtime_password) < 24 or "CHANGE_ME" in runtime_password:
                    raise SystemExit("runtime password must be >= 24 characters and not a placeholder")
                cur.execute(sql.SQL("ALTER ROLE observer_runtime PASSWORD {}").format(sql.Literal(scram_verifier(runtime_password))))
    return applied


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runtime-password-file")
    a = ap.parse_args(argv)
    dsn = os.getenv("OBSERVER_ADMIN_DATABASE_URL", "").strip()
    if not dsn:
        print("OBSERVER_ADMIN_DATABASE_URL is required", file=sys.stderr)
        return 2
    pw = open(a.runtime_password_file).read().strip() if a.runtime_password_file else None
    print("applied: " + (", ".join(migrate(dsn, pw)) or "nothing (up to date)"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
