"""Observer database access (observer-db only; never the backend database).

Every unit of work is ONE transaction that first sets the transaction-local tenant setting (observer.tenant, '' when
none) and takes the global ingest lock, so ledger appends, watermark updates and the event rows they describe commit
or roll back together and the hash chain is strictly linear."""
import os
import queue
import threading
from typing import Callable, Optional

INGEST_LOCK = 0x51C0B5E7         # pg_advisory_xact_lock key: one ingest / monitor transaction at a time


class DbError(Exception):
    pass


def dsn_from_env() -> Optional[str]:
    """OBSERVER_DATABASE_URL, or OBSERVER_DB_HOST [+PORT, NAME, USER] + OBSERVER_DB_PASSWORD_FILE."""
    url = os.getenv("OBSERVER_DATABASE_URL", "").strip()
    if url:
        return url
    host = os.getenv("OBSERVER_DB_HOST", "").strip()
    if not host:
        return None
    path = os.getenv("OBSERVER_DB_PASSWORD_FILE", "/run/secrets/observer_db_runtime_password")
    try:
        secret = open(path).read().strip()
    except OSError:
        raise DbError("observer database password file not readable") from None
    if not secret or "CHANGE_ME" in secret:
        raise DbError("observer database password missing or a placeholder")
    from psycopg.conninfo import make_conninfo
    return make_conninfo(host=host, port=os.getenv("OBSERVER_DB_PORT", "5432"), dbname=os.getenv("OBSERVER_DB_NAME", "observer"),
                         user=os.getenv("OBSERVER_DB_USER", "observer_runtime"), password=secret, connect_timeout="5")


class Database:
    def __init__(self, dsn: str, size: int = 4, timeout: int = 5):
        import psycopg
        self._pg, self.dsn, self.timeout = psycopg, dsn, timeout
        self._idle: "queue.LifoQueue" = queue.LifoQueue()
        self._slots = threading.BoundedSemaphore(max(1, size))

    def _get(self):
        if not self._slots.acquire(timeout=self.timeout):
            raise DbError("observer database pool exhausted")
        while True:
            try:
                c = self._idle.get_nowait()
            except queue.Empty:
                break
            if not c.closed and not c.broken:
                return c
        try:
            return self._pg.connect(self.dsn, connect_timeout=self.timeout, autocommit=False)
        except Exception as e:
            self._slots.release()
            raise DbError("observer database unavailable: " + type(e).__name__) from None

    def _put(self, c):
        try:
            if not c.closed and not c.broken and c.info.transaction_status == self._pg.pq.TransactionStatus.IDLE:
                self._idle.put(c)
            else:
                c.close()
        finally:
            self._slots.release()

    def run(self, fn: Callable, lock: bool = True):
        c = self._get()
        try:
            with c.transaction():
                with c.cursor() as cur:
                    cur.execute("SELECT set_config('observer.tenant', '', true)")
                    if lock:
                        cur.execute("SELECT pg_advisory_xact_lock(%s)", (INGEST_LOCK,))
                    return fn(cur)
        except DbError:
            raise
        except Exception as e:
            if getattr(e, "observer_passthrough", False):
                raise
            raise DbError("observer database error: " + type(e).__name__) from e
        finally:
            self._put(c)

    def close(self):
        while True:
            try:
                self._idle.get_nowait().close()
            except queue.Empty:
                return


def set_tenant(cur, tenant: Optional[str]) -> None:
    cur.execute("SELECT set_config('observer.tenant', %s, true)", (tenant or "",))


RUNTIME_CHECK = """
SELECT r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication,
       (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relowner = r.oid),
       (SELECT d.datdba = r.oid FROM pg_database d WHERE d.datname = current_database()),
       (SELECT count(*) FROM pg_roles x WHERE x.oid <> r.oid AND x.rolname = 'observer_lookup'
                                   AND pg_has_role(r.oid, x.oid, 'MEMBER'))
  FROM pg_roles r WHERE r.rolname = current_user
"""


def runtime_problems(cur):
    cur.execute(RUNTIME_CHECK)
    r = cur.fetchone()
    out = [n for n, v in zip(["superuser", "bypassrls", "createrole", "createdb", "replication"], r[:5]) if v]
    if r[5]:
        out.append("owns objects")
    if r[6]:
        out.append("owns the database")
    if r[7]:
        out.append("member of observer_lookup")
    return out
