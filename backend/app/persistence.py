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


DEFAULT_PASSWORD_FILE = "/run/secrets/db_runtime_password"
DEFAULT_ADMIN_PASSWORD_FILE = "/run/secrets/db_admin_password"
DEFAULT_RUNTIME_USER = "qyrix_runtime"


def _read_secret(path: str) -> str:
    try:
        with open(path) as f:
            secret = f.read().strip()
    except OSError:
        raise PersistenceError("database password file not readable") from None
    if not secret or "CHANGE_ME" in secret:
        raise PersistenceError("database password missing or still a placeholder")
    return secret


def admin_dsn_from_env() -> Optional[str]:
    """Administrative (migration / backup / restore) connection. NEVER used by the long-running backend.
    QYRIX_ADMIN_DATABASE_URL, or QYRIX_DB_HOST [+PORT, NAME] + QYRIX_DB_ADMIN_USER (default qyrix) +
    QYRIX_DB_ADMIN_PASSWORD_FILE (default /run/secrets/db_admin_password)."""
    url = os.getenv("QYRIX_ADMIN_DATABASE_URL", "").strip()
    if url:
        return url
    host = os.getenv("QYRIX_DB_HOST", "").strip()
    if not host:
        return None
    secret = _read_secret(os.getenv("QYRIX_DB_ADMIN_PASSWORD_FILE", "").strip() or DEFAULT_ADMIN_PASSWORD_FILE)
    from psycopg.conninfo import make_conninfo
    return make_conninfo(host=host, port=os.getenv("QYRIX_DB_PORT", "5432"), dbname=os.getenv("QYRIX_DB_NAME", "qyrix"),
                         user=os.getenv("QYRIX_DB_ADMIN_USER", "qyrix"), password=secret, connect_timeout="5")


def dsn_from_env() -> Optional[str]:
    """Database connection settings, without ever putting a password in configuration files.
    1. QYRIX_DATABASE_URL (non-Docker convenience; prefer a ~/.pgpass file over embedding a password), or
    2. QYRIX_DB_HOST [+ QYRIX_DB_PORT, QYRIX_DB_NAME, QYRIX_DB_USER] with the password read from a file:
       QYRIX_DB_PASSWORD_FILE (default /run/secrets/db_runtime_password = the Docker Compose secret) and
       QYRIX_DB_USER (default qyrix_runtime - the least-privilege login; the backend refuses over-privileged accounts).
    Returns None for in-memory mode. Raises PersistenceError (=> Gate fails closed) on a missing/empty/placeholder secret."""
    url = os.getenv("QYRIX_DATABASE_URL", "").strip()
    if url:
        return url
    host = os.getenv("QYRIX_DB_HOST", "").strip()
    if not host:
        return None
    secret = _read_secret(os.getenv("QYRIX_DB_PASSWORD_FILE", "").strip() or DEFAULT_PASSWORD_FILE)
    from psycopg.conninfo import make_conninfo   # escapes every value correctly
    return make_conninfo(host=host, port=os.getenv("QYRIX_DB_PORT", "5432"), dbname=os.getenv("QYRIX_DB_NAME", "qyrix"),
                         user=os.getenv("QYRIX_DB_USER", DEFAULT_RUNTIME_USER), password=secret, connect_timeout="5")


def _ts(epoch: float) -> datetime:
    return datetime.fromtimestamp(epoch, timezone.utc)


def _iso(v) -> str:
    return v.isoformat() if hasattr(v, "isoformat") else str(v)


TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")


class _Pool:
    """A small pool of connections for ONE database (the least-privilege runtime account).

    Tenant context safety: every transaction begins with set_config('qyrix.tenant_id', <tenant or ''>, is_local=true),
    so the setting is (a) always explicitly (re)written at the start of each transaction and (b) discarded by PostgreSQL
    at COMMIT/ROLLBACK. A connection is returned to the pool only if it is idle (no open transaction); anything else is
    closed. Tenant context therefore cannot leak between requests or tenants sharing a pooled connection."""

    def __init__(self, dsn: str, timeout: int, size: int):
        import psycopg                      # imported lazily: memory mode needs no driver
        import queue
        self._psycopg, self.dsn, self.timeout, self.size = psycopg, dsn, timeout, max(1, size)
        self._idle = queue.LifoQueue()
        self._slots = threading.BoundedSemaphore(self.size)
        self.lock = threading.RLock()       # kept for callers that serialise multi-call sequences

    def _connect(self):
        try:
            return self._psycopg.connect(self.dsn, connect_timeout=self.timeout, autocommit=False)
        except Exception as e:
            raise PersistenceError("database unavailable: " + type(e).__name__) from None

    def _checkout(self):
        if not self._slots.acquire(timeout=self.timeout):
            raise PersistenceError("database pool exhausted")
        while True:
            try:
                conn = self._idle.get_nowait()
            except Exception:
                break
            if not conn.closed and not conn.broken:
                return conn
        try:
            return self._connect()
        except Exception:
            self._slots.release()
            raise

    def _checkin(self, conn):
        try:
            idle = (not conn.closed and not conn.broken
                    and conn.info.transaction_status == self._psycopg.pq.TransactionStatus.IDLE)
            if idle:
                self._idle.put(conn)
            else:
                conn.close()
        finally:
            self._slots.release()

    def run(self, fn, tenant: Optional[str] = None, _retry: bool = True):
        """fn(cursor) in one transaction, tenant context set first. Any error => rollback + PersistenceError.
        A pooled connection killed by a server restart fails on the FIRST statement (the tenant set_config), before any
        of fn's work: that case alone is retried once on a fresh connection."""
        conn = self._checkout()
        started = False
        try:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute("SELECT set_config('qyrix.tenant_id', %s, true)", (tenant or "",))
                    started = True
                    return fn(cur)
        except PersistenceError:
            raise
        except Exception as e:
            if getattr(e, "qyrix_passthrough", False):
                raise                                  # a policy refusal (e.g. AuthError), not an outage; already rolled back
            if not isinstance(e, self._psycopg.OperationalError):
                return self._fail(e, tenant)
            if not started and _retry:
                try:
                    conn.close()
                except Exception:
                    pass
                self._checkin(conn)
                conn = None
                return self.run(fn, tenant, _retry=False)
            raise PersistenceError("database unavailable") from None
        finally:
            if conn is not None:
                self._checkin(conn)

    def _fail(self, e, tenant):
        msg = str(getattr(e, "diag", None) and e.diag.message_primary or "")
        if "row-level security" in msg:
            from app import observability as obs       # an RLS violation is never expected from correct code
            obs.inc("qyrix_tenant_isolation_violations_total")
            obs.event("tenant_isolation_violation", severity="critical", tenant=tenant or "", error=type(e).__name__)
        raise PersistenceError("database error: " + type(e).__name__) from None

    def close_all(self):
        while True:
            try:
                self._idle.get_nowait().close()
            except Exception:
                return


_POOL: Dict[str, _Pool] = {}
_POOL_LOCK = threading.Lock()


def shared_connection(dsn: str, timeout: int = 5) -> _Pool:
    with _POOL_LOCK:
        if dsn not in _POOL:
            _POOL[dsn] = _Pool(dsn, timeout, int(os.getenv("QYRIX_DB_POOL_SIZE", "5")))
        return _POOL[dsn]


def expected_migrations() -> List[str]:
    return sorted(os.path.basename(p) for p in glob.glob(os.path.join(MIGRATIONS, "*.sql")))


RUNTIME_CHECK_SQL = """
SELECT r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
       (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relowner = r.oid) AS owned,
       (SELECT d.datdba = r.oid FROM pg_database d WHERE d.datname = current_database()) AS db_owner,
       (SELECT count(*) FROM pg_roles x WHERE x.oid <> r.oid AND (x.rolsuper OR x.rolbypassrls OR x.rolcreaterole
                                   OR x.rolname IN ('qyrix_auth', 'qyrix_maint', 'qyrix_feed'))
                                   AND pg_has_role(r.oid, x.oid, 'MEMBER')) AS powerful_memberships,
       pg_has_role(r.oid, 'qyrix_app', 'MEMBER') AS app_member
  FROM pg_roles r WHERE r.rolname = current_user
"""


def runtime_privilege_problems(cur) -> List[str]:
    """Empty list = the connected account is a proper least-privilege runtime account."""
    cur.execute(RUNTIME_CHECK_SQL)
    r = cur.fetchone()
    names = ["superuser", "bypassrls", "createrole", "createdb", "replication"]
    problems = [n for n, v in zip(names, r[:5]) if v]
    if r[5]:
        problems.append("owns %d table(s)/object(s)" % r[5])
    if r[6]:
        problems.append("owns the database")
    if r[7]:
        problems.append("member of a privileged role")
    if not r[8]:
        problems.append("not a member of qyrix_app")
    return problems


class PgPersistence:
    """Tenant-bound view of the database. Every statement is scoped to `self.t` (explicit filters + RLS), runs as the
    least-privilege runtime account and never changes role."""
    name = "postgres"

    def __init__(self, dsn: str, tenant_id: str = "default", connect_timeout: int = 5):
        if not dsn or "CHANGE_ME" in dsn:
            raise PersistenceError("database settings missing or still a placeholder")
        if not TENANT_RE.match(tenant_id or ""):
            raise PersistenceError("invalid tenant id")
        self.dsn, self.t = dsn, tenant_id
        self.db = shared_connection(dsn, connect_timeout)

    def _run(self, fn):
        return self.db.run(fn, tenant=self.t)

    def ping(self) -> bool:
        self.db.run(lambda cur: cur.execute("SELECT 1"))
        return True

    def verify_runtime(self) -> None:
        """Startup gate: refuse (fail closed) unless connected as a least-privilege account to a fully migrated schema.
        The backend never migrates; `python -m app.migrate` does, with the separate administrative account."""
        def go(cur):
            problems = runtime_privilege_problems(cur)
            cur.execute("SELECT name FROM schema_migrations")
            done = {x[0] for x in cur.fetchall()}
            return problems, [m for m in expected_migrations() if m not in done]
        try:
            problems, missing = self.db.run(go)
        except PersistenceError:
            raise
        if problems:
            from app import observability as obs
            obs.inc("qyrix_db_privilege_violations_total")
            obs.event("db_privilege_violation", severity="critical", problems=",".join(problems))
            raise PersistenceError("runtime database account is over-privileged: " + ", ".join(problems))
        if missing:
            raise PersistenceError("database schema not migrated (run `python -m app.migrate`): missing " + ", ".join(missing))

    # ---- installation identity (silent data-loss detection, app/integrity.py)
    def install_id(self) -> Optional[str]:
        def go(cur):
            cur.execute("SELECT install_id FROM installation WHERE id = 1")
            r = cur.fetchone()
            return str(r[0]) if r else None
        return self.db.run(go)

    def init_install(self, install_id: str) -> str:
        """Insert-once; returns the id actually stored (an existing one wins)."""
        def go(cur):
            cur.execute("INSERT INTO installation (id, install_id) VALUES (1, %s) ON CONFLICT (id) DO NOTHING", (install_id,))
            cur.execute("SELECT install_id FROM installation WHERE id = 1")
            return str(cur.fetchone()[0])
        return self.db.run(go)

    def proof_census(self) -> Dict[str, int]:
        def go(cur):
            cur.execute("SELECT tenants, records FROM qyrix_proof_census()")
            r = cur.fetchone()
            return {"tenants": int(r[0]), "records": int(r[1])}
        return self.db.run(go)

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

    # ---- observer outbox (Phase C2, migration 008; only used when QYRIX_OBSERVER_URL is set)
    @staticmethod
    def _emit(cur, ev: Dict) -> None:
        """Allocate the next gap-free seq and write the outbox row IN THE CALLER'S TRANSACTION (qyrix_observer_emit,
        SECURITY DEFINER). If the surrounding transaction rolls back, the number and the row disappear with it."""
        cur.execute("SELECT out_epoch, out_seq FROM qyrix_observer_emit(%s, %s, %s, %s)",
                    (ev["producer_id"], ev["type"], ev["event_id"], json.dumps(ev["body"])))

    def emit_event(self, ev: Dict) -> None:
        """A standalone event in its own transaction (grant refusals - nothing else is written)."""
        self._run(lambda cur: self._emit(cur, ev))

    def observer_feed(self, producer_id: str) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT out_tenant, out_epoch, out_allocated, out_unsent, out_stale_unsent FROM qyrix_observer_feed(%s)",
                        (producer_id,))
            return [{"tenant": r[0], "epoch": r[1], "allocated": r[2], "unsent": r[3], "stale_unsent": r[4]} for r in cur.fetchall()]
        return self.db.run(go)

    def observer_next_hb(self, producer_id: str):
        def go(cur):
            cur.execute("SELECT out_epoch, out_hb_seq FROM qyrix_observer_next_hb(%s)", (producer_id,))
            return tuple(cur.fetchone())
        return self.db.run(go)

    def outbox_unsent(self, epoch: int, limit: int = 200) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT seq, event_id, producer_id, type, body, created_at FROM observer_outbox WHERE tenant_id=%s"
                        " AND epoch=%s AND sent_at IS NULL ORDER BY seq LIMIT %s", (self.t, epoch, limit))
            return [{"seq": r[0], "event_id": str(r[1]), "producer_id": r[2], "type": r[3], "body": r[4], "created_at": r[5]}
                    for r in cur.fetchall()]
        return self._run(go)

    def outbox_mark(self, epoch: int, seq: int, sent: bool) -> None:
        sql = ("UPDATE observer_outbox SET sent_at=now(), attempts=attempts+1" if sent
               else "UPDATE observer_outbox SET attempts=attempts+1")
        self._run(lambda cur: cur.execute(sql + " WHERE tenant_id=%s AND epoch=%s AND seq=%s", (self.t, epoch, seq)))

    def proof_head(self):
        def go(cur):
            cur.execute("SELECT n, hash FROM proof_records WHERE tenant_id=%s ORDER BY n DESC LIMIT 1", (self.t,))
            r = cur.fetchone()
            return (r[0], r[1].strip()) if r else (None, None)
        return self._run(go)

    # ---- evaluations & grants
    def save_evaluation(self, ev: Dict, grant: Optional[Dict] = None, approval_id: Optional[str] = None,
                        events: Optional[List[Dict]] = None) -> None:
        """One transaction: evaluation (+ grant + approval consumption) (+ observer outbox events, Phase C2).
        Approval must be approved, unused, this tenant's."""
        def go(cur):
            cur.execute("INSERT INTO gate_evaluations (tenant_id, id, verdict, rule_ids, params, params_digest, hop, host, created_at,"
                        " agent_id, task_id, policy_version, correlation_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (self.t, ev["id"], ev["verdict"], ev["rules"], json.dumps(ev["params"]), ev["digest"], ev["hop"], ev["host"], _ts(ev["ts"]),
                         ev.get("agent_id"), ev.get("task_id"), ev.get("policy_version"), ev.get("correlation_id")))
            if grant:
                if approval_id:
                    cur.execute("UPDATE approvals SET used=true, updated_at=now() WHERE tenant_id=%s AND id=%s AND status='approved'"
                                " AND used=false AND expires_at > now() RETURNING id", (self.t, approval_id))
                    if cur.fetchone() is None:
                        raise PersistenceConflict("approval already consumed or not valid")
                cur.execute("INSERT INTO grants (tenant_id, id, gate_evaluation_id, params_digest, approval_id, created_at, expires_at,"
                            " agent_id, task_id, policy_version, execution_id) VALUES (%s,%s,%s,%s,%s,now(),%s,%s,%s,%s,%s)",
                            (self.t, grant["id"], ev["id"], grant["digest"], approval_id, _ts(grant["exp"]),
                             grant.get("agent_id"), grant.get("task_id"), grant.get("policy_version"), grant.get("execution_id")))
            for e in events or ():
                self._emit(cur, e)
        self._run(go)

    def consume_grant(self, gid: str, eid: str, digest: str, agent_id: Optional[str] = None, task_id: Optional[str] = None,
                      policy_version: Optional[str] = None, event: Optional[Dict] = None) -> bool:
        """Atomic single use. False => already used, revoked, expired, unknown, other tenant, mismatched digest, or a
        binding (agent, task, policy version) that differs from the one recorded at issue time. NULL never equals a
        value, so legacy unbound rows cannot be consumed by an authenticated caller (fail closed)."""
        def go(cur):
            cur.execute("UPDATE grants SET used_at=now() WHERE tenant_id=%s AND id=%s AND gate_evaluation_id=%s AND params_digest=%s"
                        " AND agent_id IS NOT DISTINCT FROM %s AND task_id IS NOT DISTINCT FROM %s"
                        " AND policy_version IS NOT DISTINCT FROM %s"
                        " AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING id, execution_id",
                        (self.t, gid, eid, digest, agent_id, task_id, policy_version))
            r = cur.fetchone()
            if r is not None and event is not None:   # the consumption and its grant event commit (or fail) together
                body = dict(event["body"], execution_id=str(r[1]) if r[1] else None)
                self._emit(cur, dict(event, body=body))
            return r is not None
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
            cur.execute("SELECT id, gate_evaluation_id, params_digest, expires_at, used_at, revoked_at, agent_id, task_id, policy_version,"
                        " execution_id FROM grants WHERE tenant_id=%s", (self.t,))
            grants = [{"id": r[0], "gate_evaluation_id": str(r[1]), "digest": r[2].strip(), "exp": r[3].timestamp(), "expires_at": _iso(r[3]),
                       "used": r[4] is not None, "revoked": r[5] is not None, "agent_id": r[6], "task_id": r[7],
                       "policy_version": r[8].strip() if r[8] else None, "execution_id": str(r[9]) if r[9] else None}
                      for r in cur.fetchall()]
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
        """Demo/eval reset of THIS tenant only. The runtime cannot DELETE evidence; it may only call the SECURITY DEFINER
        function qyrix_reset_tenant_evidence, and only if the operator granted it at migration time
        (`python -m app.migrate --allow-demo-reset`). Otherwise this raises (=> refused, nothing deleted)."""
        self._run(lambda cur: cur.execute("SELECT qyrix_reset_tenant_evidence(%s)", (self.t,)))
