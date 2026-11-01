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


class PgPersistence:
    name = "postgres"

    def __init__(self, dsn: str, connect_timeout: int = 5):
        if not dsn or "CHANGE_ME" in dsn:
            raise PersistenceError("database URL missing or still a placeholder")
        import psycopg                      # imported lazily: memory mode needs no driver
        self._psycopg = psycopg
        self.dsn, self.timeout = dsn, connect_timeout
        self._conn = None

    # ---- connection
    def _c(self):
        try:
            if self._conn is None or self._conn.closed or self._conn.broken:
                self._conn = self._psycopg.connect(self.dsn, connect_timeout=self.timeout, autocommit=False)
            return self._conn
        except Exception as e:
            self._conn = None
            raise PersistenceError("database unavailable: " + type(e).__name__) from None

    def _run(self, fn):
        """Run fn(cursor) in one transaction. Any error => rollback + PersistenceError (fail closed)."""
        conn = self._c()
        try:
            with conn.transaction():
                with conn.cursor() as cur:
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

    def ping(self) -> bool:
        self._run(lambda cur: cur.execute("SELECT 1"))
        return True

    def migrate(self) -> List[str]:
        def go(cur):
            cur.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())")
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
            return applied
        return self._run(go)

    # ---- provenance
    def save_step(self, s: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO provenance_steps (id, source, declared_label, effective_label, text_redacted, parents, unknown_parents, created_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
            (s["id"], s["source"], s["declared_label"], s["label"], s["text"], s["parents"], s["unknown_parents"], s["ts"])))

    def load_steps(self, window: int, index_limit: int):
        def go(cur):
            cur.execute("SELECT id, source, declared_label, effective_label, text_redacted, parents, unknown_parents, created_at"
                        " FROM provenance_steps ORDER BY seq DESC LIMIT %s", (window,))
            recent = [{"id": str(r[0]), "source": r[1], "declared_label": r[2], "label": r[3], "text": r[4], "parents": list(r[5]),
                       "unknown_parents": list(r[6]), "tainted": r[3] != "TRUSTED", "ts": _iso(r[7])} for r in cur.fetchall()][::-1]
            cur.execute("SELECT id, effective_label FROM provenance_steps ORDER BY seq DESC LIMIT %s", (index_limit,))
            index = [(str(r[0]), r[1]) for r in cur.fetchall()][::-1]
            return recent, index
        return self._run(go)

    # ---- approvals
    def save_approval(self, a: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO approvals (id, status, used, digest, scope, requested_by, decided_by, created_at, expires_at)"
            " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
            " ON CONFLICT (id) DO UPDATE SET status=EXCLUDED.status, used=EXCLUDED.used, decided_by=EXCLUDED.decided_by, updated_at=now()",
            (a["id"], a["status"], a["used"], a["digest"], json.dumps(a["scope"]), a["requested_by"], a["decided_by"], a["ts"], _ts(a["exp"]))))

    def decide_approval(self, aid: str, status: str, who: str) -> None:
        """Only a pending, unused approval can be decided (DB-level guard against double decisions)."""
        def go(cur):
            cur.execute("UPDATE approvals SET status=%s, decided_by=%s, updated_at=now() WHERE id=%s AND status='pending' AND used=false RETURNING id",
                        (status, who, aid))
            if cur.fetchone() is None:
                raise PersistenceConflict("approval not pending")
        self._run(go)

    def load_approvals(self) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT id, status, used, digest, scope, requested_by, decided_by, created_at, expires_at FROM approvals ORDER BY created_at")
            return [{"id": r[0], "status": r[1], "used": r[2], "digest": r[3].strip(), "scope": r[4], "requested_by": r[5], "decided_by": r[6],
                     "ts": _iso(r[7]), "exp": r[8].timestamp(), "expires_at": _iso(r[8])} for r in cur.fetchall()]
        return self._run(go)

    # ---- evaluations & grants
    def save_evaluation(self, ev: Dict, grant: Optional[Dict] = None, approval_id: Optional[str] = None) -> None:
        """One transaction: evaluation (+ grant + approval consumption). Approval must be approved and unused."""
        def go(cur):
            cur.execute("INSERT INTO gate_evaluations (id, verdict, rule_ids, params, params_digest, hop, host, created_at)"
                        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (ev["id"], ev["verdict"], ev["rules"], json.dumps(ev["params"]), ev["digest"], ev["hop"], ev["host"], _ts(ev["ts"])))
            if grant:
                if approval_id:
                    cur.execute("UPDATE approvals SET used=true, updated_at=now() WHERE id=%s AND status='approved' AND used=false"
                                " AND expires_at > now() RETURNING id", (approval_id,))
                    if cur.fetchone() is None:
                        raise PersistenceConflict("approval already consumed or not valid")
                cur.execute("INSERT INTO grants (id, gate_evaluation_id, params_digest, approval_id, created_at, expires_at)"
                            " VALUES (%s,%s,%s,%s,now(),%s)", (grant["id"], ev["id"], grant["digest"], approval_id, _ts(grant["exp"])))
        self._run(go)

    def consume_grant(self, gid: str, eid: str, digest: str) -> bool:
        """Atomic single use. False => already used, revoked, expired, unknown or mismatched (never executes)."""
        def go(cur):
            cur.execute("UPDATE grants SET used_at=now() WHERE id=%s AND gate_evaluation_id=%s AND params_digest=%s"
                        " AND used_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING id", (gid, eid, digest))
            return cur.fetchone() is not None
        return self._run(go)

    def revoke_grant(self, gid: str, who: str) -> bool:
        def go(cur):
            cur.execute("UPDATE grants SET revoked_at=now(), revoked_by=%s WHERE id=%s AND used_at IS NULL AND revoked_at IS NULL RETURNING id",
                        (who, gid))
            return cur.fetchone() is not None
        return self._run(go)

    def set_redirect(self, eid: str, location: str) -> None:
        self._run(lambda cur: cur.execute("UPDATE gate_evaluations SET redirect_location=%s WHERE id=%s", (location, eid)))

    def load_evaluations(self, limit: int):
        def go(cur):
            cur.execute("SELECT id, verdict, rule_ids, params, params_digest, hop, host, redirect_location, created_at"
                        " FROM gate_evaluations ORDER BY created_at DESC LIMIT %s", (limit,))
            evs = [{"id": str(r[0]), "verdict": r[1], "rules": list(r[2]), "params": r[3], "digest": r[4].strip(), "hop": r[5],
                    "host": r[6], "redirect_location": r[7], "ts": r[8].timestamp()} for r in cur.fetchall()][::-1]
            cur.execute("SELECT id, gate_evaluation_id, params_digest, expires_at, used_at, revoked_at FROM grants")
            grants = [{"id": r[0], "gate_evaluation_id": str(r[1]), "digest": r[2].strip(), "exp": r[3].timestamp(), "expires_at": _iso(r[3]),
                       "used": r[4] is not None, "revoked": r[5] is not None} for r in cur.fetchall()]
            return evs, grants
        return self._run(go)

    # ---- proof mirror & anchors
    def save_proof(self, r: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO proof_records (n, hash, prev, kind, verdict, gate_evaluation_id, recorded_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (r["n"], r["hash"], r["prev"], r.get("kind", "gate_decision"), r["verdict"], r.get("gate_evaluation_id"), r["ts"])))

    def load_proof_index(self) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT n, hash, prev FROM proof_records ORDER BY n")
            return [{"n": r[0], "hash": r[1].strip(), "prev": r[2].strip()} for r in cur.fetchall()]
        return self._run(go)

    def save_anchor(self, a: Dict) -> None:
        self._run(lambda cur: cur.execute(
            "INSERT INTO proof_anchors (id, n, head_hash, method, tsa_url, token_b64, gen_time, serial, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (a["id"], a["n"], a["head_hash"], a["method"], a["tsa_url"], a["token_b64"], a.get("gen_time"), a.get("serial"), a["created_at"])))

    def load_anchors(self) -> List[Dict]:
        def go(cur):
            cur.execute("SELECT id, n, head_hash, method, tsa_url, token_b64, gen_time, serial, created_at FROM proof_anchors ORDER BY created_at")
            return [{"id": str(r[0]), "n": r[1], "head_hash": r[2].strip(), "method": r[3], "tsa_url": r[4], "token_b64": r[5],
                     "gen_time": r[6], "serial": r[7], "created_at": _iso(r[8])} for r in cur.fetchall()]
        return self._run(go)

    def reset(self) -> None:
        """Demo/eval reset only (guarded by QYRIX_ENABLE_DEMO_RESET at the API)."""
        self._run(lambda cur: cur.execute("TRUNCATE grants, gate_evaluations, approvals, provenance_steps, proof_records, proof_anchors"))
