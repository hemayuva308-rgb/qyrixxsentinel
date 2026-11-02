"""Consistent backup / restore of Qyrix Sentinel durable state.

Durable state = PostgreSQL (provenance, approvals, evaluations, grants, proof mirror, anchors, tenants, API keys,
sessions) + the proof chain files (default tenant chain, per-tenant chains, anchor files) in the chain directory.

ORDERING INVARIANT (why this is consistent without stopping the service):
  the backend writes the DB transaction BEFORE appending the proof record, and on startup requires the DB proof mirror
  to be a PREFIX of the chain file. So we dump the DB FIRST and copy the chain files SECOND: the chain copy can only be
  longer than the DB mirror (back-filled on start), never shorter. Restoring a chain older than the DB is detected on
  startup and fails closed (Gate degraded + persistence down), never silently accepted.

Usage (ADMIN connection: QYRIX_ADMIN_DATABASE_URL or QYRIX_DB_HOST + QYRIX_DB_ADMIN_* + password file; never on the command line;
the least-privilege runtime account cannot read every tenant and is deliberately not usable for backups):
  python scripts/backup.py backup  --chain-dir /data --out /backups/2026-11-02
  python scripts/backup.py restore --chain-dir /data --from /backups/2026-11-02 [--force]
  python scripts/backup.py verify  --from /backups/2026-11-02
"""
import argparse, hashlib, json, os, shutil, subprocess, sys, tarfile, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import persistence  # noqa: E402

FORMAT = "qyrix-backup/1"


def _pg_env(dsn: str):
    """Split the password out of the DSN so it is passed through the environment, never argv (visible in `ps`)."""
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    d = conninfo_to_dict(dsn)
    pw = d.pop("password", None)
    env = dict(os.environ)
    if pw:
        env["PGPASSWORD"] = pw
    return make_conninfo(**d), env


def _tool(name: str) -> str:
    for d in [os.getenv("QYRIX_PG_BIN", "")] + sorted(__import__("glob").glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if d and os.path.exists(os.path.join(d, name)):
            return os.path.join(d, name)
    p = shutil.which(name)
    if not p:
        raise SystemExit("%s not found (install the PostgreSQL client tools or set QYRIX_PG_BIN)" % name)
    return p


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def backup(dsn: str, chain_dir: str, out: str) -> dict:
    os.makedirs(out, exist_ok=False)                              # never overwrite an existing backup
    conn, env = _pg_env(dsn)
    t0 = time.time()
    # 1) database first (one consistent snapshot: pg_dump runs in a single repeatable-read transaction)
    # ownership is kept: SECURITY DEFINER lookup functions must stay owned by the unprivileged qyrix_auth role
    subprocess.run([_tool("pg_dump"), "--format=custom", "--file", os.path.join(out, "db.dump"), "--dbname", conn],
                   env=env, check=True, capture_output=True)
    # 2) chain files second (may be longer than the DB mirror; that is the safe direction)
    with tarfile.open(os.path.join(out, "chain.tar"), "w") as tar:
        if os.path.isdir(chain_dir):
            for root, _, files in os.walk(chain_dir):
                for f in sorted(files):
                    if f.endswith(".jsonl"):
                        p = os.path.join(root, f)
                        tar.add(p, arcname=os.path.relpath(p, chain_dir))
    m = {"format": FORMAT, "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)), "order": ["db.dump", "chain.tar"],
         "files": {f: _sha(os.path.join(out, f)) for f in ("db.dump", "chain.tar")}}
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(m, f, indent=2)
    os.chmod(out, 0o700)
    return m


def verify(src: str) -> dict:
    with open(os.path.join(src, "manifest.json")) as f:
        m = json.load(f)
    if m.get("format") != FORMAT:
        raise SystemExit("unknown backup format")
    for name, digest in m["files"].items():
        if _sha(os.path.join(src, name)) != digest:
            raise SystemExit("backup file %s does not match its manifest hash (corrupted or tampered)" % name)
    return m


def restore(dsn: str, chain_dir: str, src: str, force: bool = False) -> dict:
    m = verify(src)
    existing = [f for _, _, fs in os.walk(chain_dir) for f in fs if f.endswith(".jsonl")] if os.path.isdir(chain_dir) else []
    if existing and not force:
        raise SystemExit("chain directory is not empty; stop the backend and pass --force to replace it")
    conn, env = _pg_env(dsn)
    from app import migrate as _migrate
    _migrate.ensure_roles(dsn)                    # roles are cluster-global and not part of pg_dump
    # replace the schema wholesale (ownership + grants + RLS policies restored as dumped)
    subprocess.run([_tool("pg_restore"), "--clean", "--if-exists", "--single-transaction", "--exit-on-error",
                    "--dbname", conn, os.path.join(src, "db.dump")], env=env, check=True, capture_output=True)
    _migrate.migrate(dsn)                         # bring an older backup up to the current schema / privileges
    if existing:
        for root, _, fs in os.walk(chain_dir):
            for f in fs:
                if f.endswith(".jsonl"):
                    os.remove(os.path.join(root, f))
    os.makedirs(chain_dir, exist_ok=True)
    with tarfile.open(os.path.join(src, "chain.tar")) as tar:
        tar.extractall(chain_dir, filter="data")                  # no absolute paths / traversal / devices
    return m


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["backup", "restore", "verify"])
    ap.add_argument("--chain-dir")
    ap.add_argument("--out")
    ap.add_argument("--from", dest="src")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "verify":
        print(json.dumps(verify(a.src), indent=2)); return 0
    dsn = persistence.admin_dsn_from_env()
    if not dsn:
        raise SystemExit("no administrative database connection configured (QYRIX_ADMIN_DATABASE_URL or QYRIX_DB_HOST + admin password file)")
    if a.cmd == "backup":
        print(json.dumps(backup(dsn, a.chain_dir, a.out), indent=2))
    else:
        print(json.dumps(restore(dsn, a.chain_dir, a.src, a.force), indent=2))
        print("restored. Start the backend: it re-verifies the chain and the DB proof mirror and fails closed on mismatch.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
