"""PostgreSQL persistence for provenance, approvals, gate evaluations, grants, proof index and anchors.

Enabled when QYRIX_DATABASE_URL or QYRIX_DB_HOST (+ password file) is set - see dsn_from_env(); otherwise the
v1.2 in-memory behaviour is unchanged.

Security properties:
- Fail closed: every method raises on any database error; callers turn that into BLOCK / refusal. Nothing is ever
  authorised because a row exists - execution still requires the in-memory evaluation, a matching ALLOW record in the
  verified proof chain, digest re-computation, Gate revalidation and an atomic DB grant consumption.
- Atomicity in the database, not only in the process: approval consumption + evaluation + grant insert are one
  transaction; grant consumption is a single conditional UPDATE ... RETURNING (unused, not revoked, not expired).
- Append-only proof mirror and anchors (trigger-enforced). Placeholder credentials in the URL are refused.
"""
import glob
import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional

MIGRATIONS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "migrations")


class PersistenceError(Exception):
    pass


class PersistenceConflict(PersistenceError):
    """A state conflict (e.g. approval already consumed by another process) - not an outage."""


DEFAULT_PASSWORD_FILE = "/run/secrets/db_password"


def dsn_from_env() -> Optional[str]:
    """Database connection settings, without ever putting a password in configuration files.
    1. QYRIX_DATABASE_URL (non-Docker convenience; prefer a ~/.pgpass file over embedding a password), or
    2. QYRIX_DB_HOST [+ QYRIX_DB_PORT, QYRIX_DB_NAME, QYRIX_DB_USER] with the password read from a file:
       QYRIX_DB_PASSWORD_FILE (default /run/secrets/db_password = the Docker Compose secret).
    Returns None for in-memory mode. Raises PersistenceError (=> Gate fails closed) on a missing/empty/placeholder secret."""
    url = os.getenv("QYRIX_DATABASE_URL", "").strip()
    if url:
        return url
    host = os.getenv("QYRIX_DB_HOST", "").strip()
    if not host:
        return None
    path = os.getenv("QYRIX_DB_PASSWORD_FILE", "").strip() or DEFAULT_PASSWORD_FILE
    try:
        with open(path) as f:
            secret = f.read().strip()
    except OSError:
        raise PersistenceError("database password file not readable") from None
    if not secret or "CHANGE_ME" in secret:
        raise PersistenceError("database password missing or still a placeholder")
    from psycopg.conninfo import make_conninfo   # escapes every value correctly
    return make_conninfo(host=host, port=os.getenv("QYRIX_DB_PORT", "5432"), dbname=os.getenv("QYRIX_DB_NAME", "qyrix"),
                         user=os.getenv("QYRIX_DB_USER", "qyrix"), password=secret, connect_timeout="5")


def _ts(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, timezone.utc)


def _iso(v) -> str:
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")


class _Connection:
    """One connection per database shared by every tenant view; transactions are serialised (single process).
    Tenant-scoped transactions run as the least-privilege role `qyrix_app` with `qyrix.tenant_id` set, so PostgreSQL
    row-level security enforces isolation in addition to the explicit tenant filters in every query."""

    def __init__(self, dsn: str, timeout: int):
        import psycopg                      # imported lazily: memory mode needs no driver
        self._psycopg, self.dsn, self.timeout = psycopg, dsn, timeout
        self._conn = None
        self.lock = threading.RLock()
        self.app_role = False               # becomes True once migration 002 created qyrix_app

    def _c(self):
        try:
            if self._conn is None or self._conn.closed or self._conn.broken:
                self._conn = self._psycopg.connect(self.dsn, connect_timeout=self.timeout, autocommit=False)
            return self._conn
        except Exception as e:
            self._conn = None
            raise PersistenceError("database unavailable: " + type(e).__name__) from None

    def run(self, fn, tenant: Optional[str] = None, as_app: bool = True):
        """fn(cursor) in one transaction. Any error => rollback + PersistenceError (fail closed)."""
        with self.lock:
            conn = self._c()
            try:
                with conn.transaction():
                    with conn.cursor() as cur:
                        if tenant is not None:
                            if as_app and self.app_role:
                                cur.execute("SET LOCAL ROLE qyrix_app")
                            cur.execute("SELECT set_config('qyrix.tenant_id', %s, true)", (tenant,))
                        return fn(cur)
            except PersistenceError:
                raise
            except Exception as e:
                try:
                    if conn.broken:
                        self._conn = None
                except Exception:
                    self._conn = None
                raise PersistenceError("database error: " + type(e).__name__) from None


_POOL: Dict[str, _Connection] = {}
_POOL_LOCK = threading.Lock()


def shared_connection(dsn: str, timeout: int = 5) -> _Connection:
    with _POOL_LOCK:
        if dsn not in _POOL:
            _POOL[dsn] = _Connection(dsn, timeout)
        return _POOL[dsn]


class PgPersistence:
    """Tenant-bound view of the database. Every statement is scoped to `self.t` (filters + RLS)."""
    name = "postgres"

    def __init__(self, dsn: str, tenant_id: str = "default", connect_timeout: int = 5):
        if not dsn or "CHANGE_ME" in dsn:
            raise PersistenceError("database settings missing or still a placeholder")
        if not TENANT_RE.match(tenant_id or ""):
            raise PersistenceError("invalid tenant id")
        self.dsn, self.t = dsn, tenant_id
        self.db = shared_connection(dsn, connect_timeout)

    def _run(self, fn):
        return self.db.run(fn, tenant=self.t, as_app=True)

    def _run_owner(self, fn):
        return self.db.run(fn, tenant=self.t, as_app=False)

    def ping(self) -> bool:
        self.db.run(lambda cur: cur.execute("SELECT 1"))
        return True

    def migrate(self) -> List[str]:
        def go(cur):
            cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
            cur.execute("SELECT pg_advisory_xact_lock(424242)")          # one migrator at a time
            cur.execute("SELECT name FROM schema_migrations")
            done = {r[0] for r in cur.fetchall()}
            applied = []
            for path in sorted(glob.glob(os.path.join(MIGRATIONS, "*.sql"))):
                name = os.path.basename(path)
                if name in done:
                    continue
                cur.execute(open(path).read())
                cur.execute("INSERT INTO schema_migrations (name) VALUES (%s)", (name,))
                applied.append(name)
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'qyrix_app'")
            return applied, cur.fetchone() is not None
        applied, role = self.db.run(go)
        self.db.app_role = role
        return applied

    def tenant_exists(self) -> bool:
        def go(cur):
            cur.execute("SELECT 1 FROM tenants WHERE id=%s AND disabled_at IS NULL", (self.t,))
            return cur.fetchone() is not None
        return self.db.run(go)

    # ---- provenance
    def save_step(self, s: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO provenance_steps (tenant_id, id, source, declared_label, effective_label, text_redacted, parents, unknown_parents, created_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (self.t, s["id"], s["source"], s["declared_label"], s["label"], s["text"], s["parents"], s["unknown_parents"], s["ts"])))

    def load_steps(self, window: int, index_limit: int):
        def go(cur):
            cur.execute("SELECT id, source, declared_label, effective_label, text_redacted, parents, unknown_parents, created_at"
                        " FROM provenance_steps WHERE tenant_id=%s ORDER BY seq DESC LIMIT %s", (self.t, window))
            recent = [{"id": str(r[0]), "source": r[1], "declared_label": r[2], "label": r[3], "text": r[4], "parents": list(r[5]),
                       "unknown_parents": list(r[6]), "tainted": r[3] != "TRUSTED", "ts": _iso(r[7])} for r in cur.fetchall()][::-1]
            cur.execute("SELECT id, effective_label FROM provenance_steps WHERE tenant_id=%s ORDER BY seq DESC LIMIT %s", (self.t, index_limit))
            index = [(str(r[0]), r[1]) for r in cur.fetchall()][::-1]
            return recent, index
        return self._run(go)

    # ---- approvals
    def save_approval(self, a: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO approvals (tenant_id, id, status, used, digest, scope, requested_by, decided_by, created_at, expires_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, used=EXCLUDED.used, decided_by=EXCLUDED.decided_by, updated_at=now()"
            " WHERE approvals.tenant_id = EXCLUDED.tenant_id",
            (self.t, a["id"], a["status"], a["used"], a["digest"], json.dumps(a["scope"]), a["requested_by"], a["decided_by"], a["ts"], _ts(a["exp"]))))

    def decide_approval(self, aid: str, status: str, who: str) -> None:
        """Only a pending, unused approval of THIS tenant can be decided (DB-level guard against double decisions)."""
        def go(cur):
            cur.execute("UPDATE approvals SET status=%s, decided_by=%s, updated_at=now() WHERE tenant_id=%s AND id=%s"
                        " AND status='pending' AND used=false RETURNING id", (status, who, self.t, aid))
            if cur.fetchone() is None:
                raise PersistenceConflict("approval not pending")
        self._run(go)

    def load_approvals(self) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT id, status, used, digest, scope, requested_by, decided_by, created_at, expires_at FROM approvals"
                        " WHERE tenant_id=%s ORDER BY created_at", (self.t,))
            return [{"id": r[0], "status": r[1], "used": r[2], "digest": r[3].strip(), "scope": r[4], "requested_by": r[5], "decided_by": r[6],
                     "ts": _iso(r[7]), "exp": r[8].timestamp(), "expires_at": _iso(r[8])} for r in cur.fetchall()]
        return self._run(go)

    # ---- evaluations & grants
    def save_evaluation(self, ev: Dict, grant: Optional[Dict] = None, approval_id: Optional[str] = None) -> None:
        """One transaction: evaluation (+ grant + approval consumption). Approval must be approved, unused, this tenant's."""
        def go(cur):
            cur.execute("INSERT INTO gate_evaluations (tenant_id, id, verdict, rule_ids, params, params_digest, hop, host, created_at)"
                        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (self.t, ev["id"], ev["verdict"], ev["rules"], json.dumps(ev["params"]), ev["digest"], ev["hop"], ev["host"], _ts(ev["ts"])))
            if grant:
                if approval_id:
                    cur.execute("UPDATE approvals SET used=true, updated_at=now() WHERE tenant_id=%s AND id=%s AND status='approved'"
                                " AND used=false AND expires_at > now() RETURNING id", (self.t, approval_id))
                    if cur.fetchone() is None:
                        raise PersistenceConflict("approval already consumed or not valid")
                cur.execute("INSERT INTO grants (tenant_id, id, gate_evaluation_id, params_digest, approval_id, created_at, expires_at)"
                            " VALUES (%s,%s,%s,%s,%s,now(),%s)", (self.t, grant["id"], ev["id"], grant["digest"], approval_id, _ts(grant["exp"])))
        self._run(go)

    def consume_grant(self, gid: str, eid: str, digest: str) -> bool:
        """Atomic single use. False => already used, revoked, expired, unknown, other tenant or mismatched."""
        def go(cur):
            cur.execute("UPDATE grants SET used_at=now() WHERE tenant_id=%s AND id=%s AND gate_evaluation_id=%s AND params_digest=%s"
                        " AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING id", (self.t, gid, eid, digest))
            return cur.fetchone() is not None
        return self._run(go)

    def revoke_grant(self, gid: str, who: str) -> bool:
        def go(cur):
            cur.execute("UPDATE grants SET revoked_at=now(), revoked_by=%s WHERE tenant_id=%s AND id=%s AND used_at IS NULL"
                        " AND revoked_at IS NULL RETURNING id", (who, self.t, gid))
            return cur.fetchone() is not None
        return self._run(go)

    def set_redirect(self, eid: str, location: str) -> None:
        self._run(lambda cur: cur.execute("UPDATE gate_evaluations SET redirect_location=%s WHERE tenant_id=%s AND id=%s", (location, self.t, eid)))

    def load_evaluations(self, limit: int):
        def go(cur):
            cur.execute("SELECT id, verdict, rule_ids, params, params_digest, hop, host, redirect_location, created_at"
                        " FROM gate_evaluations WHERE tenant_id=%s ORDER BY created_at DESC LIMIT %s", (self.t, limit))
            evs = [{"id": str(r[0]), "verdict": r[1], "rules": list(r[2]), "params": r[3], "digest": r[4].strip(), "hop": r[5],
                    "host": r[6], "redirect_location": r[7], "ts": r[8].timestamp()} for r in cur.fetchall()][::-1]
            cur.execute("SELECT id, gate_evaluation_id, params_digest, expires_at, used_at, revoked_at FROM grants WHERE tenant_id=%s", (self.t,))
            grants = [{"id": r[0], "gate_evaluation_id": str(r[1]), "digest": r[2].strip(), "exp": r[3].timestamp(), "expires_at": _iso(r[3]),
                       "used": r[4] is not None, "revoked": r[5] is not None} for r in cur.fetchall()]
            return evs, grants
        return self._run(go)

    # ---- proof mirror & anchors
    def save_proof(self, r: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO proof_records (tenant_id, n, hash, prev, kind, verdict, gate_evaluation_id, recorded_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (self.t, r["n"], r["hash"], r["prev"], r.get("kind", "gate_decision"), r["verdict"], r.get("gate_evaluation_id"), r["ts"])))

    def load_proof_index(self) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT n, hash, prev FROM proof_records WHERE tenant_id=%s ORDER BY n", (self.t,))
            return [{"n": r[0], "hash": r[1].strip(), "prev": r[2].strip()} for r in cur.fetchall()]
        return self._run(go)

    def save_anchor(self, a: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO proof_anchors (tenant_id, id, n, head_hash, method, tsa_url, token_b64, gen_time, serial, created_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (self.t, a["id"], a["n"], a["head_hash"], a["method"], a["tsa_url"], a["token_b64"], a.get("gen_time"), a.get("serial"), a["created_at"])))

    def load_anchors(self) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT id, n, head_hash, method, tsa_url, token_b64, gen_time, serial, created_at FROM proof_anchors"
                        " WHERE tenant_id=%s ORDER BY created_at", (self.t,))
            return [{"id": str(r[0]), "n": r[1], "head_hash": r[2].strip(), "method": r[3], "tsa_url": r[4], "token_b64": r[5],
                     "gen_time": r[6], "serial": r[7], "created_at": _iso(r[8])} for r in cur.fetchall()]
        return self._run(go)

    def reset(self) -> None:
        """Demo/eval reset of THIS tenant only (guarded by QYRIX_ENABLE_DEMO_RESET at the API). Runs as the table owner,
        because the application role can never delete evidence."""
        def go(cur):
            cur.execute("SELECT set_config('qyrix.allow_reset', 'on', true)")
            for t in ("grants", "gate_evaluations", "approvals", "provenance_steps", "proof_records", "proof_anchors"):
                cur.execute("DELETE FROM %s WHERE tenant_id = %%s" % t, (self.t,))
        self._run_owner(go)
