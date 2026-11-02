"""Adversarial PostgreSQL tests for privilege separation and tenant isolation (Phase B, v1.4).

Every attack below is run as the REAL runtime login (qyrix_runtime) the backend uses - no SET ROLE, no helper code -
i.e. it models an attacker who has achieved SQL injection or code execution inside the backend process.
The privileged admin account is used only to set up data and to check ground truth."""
import threading, uuid
import pytest

import app.gateway as g
from app import identity, migrate, persistence, provenance as prov
from app.identity import Principal
from tests.test_persistence import Cluster, HAVE_PG, A
from app import adapter

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def db():
    c = Cluster()
    import psycopg
    a, b = persistence.PgPersistence(c.url, "acme"), persistence.PgPersistence(c.url, "globex")
    with psycopg.connect(c.admin_url, autocommit=True) as conn:
        conn.execute("INSERT INTO tenants (id, name) VALUES ('acme','Acme'), ('globex','Globex')")
    store = identity.PgStore(persistence.shared_connection(c.url))
    identity.use_store(store)
    ka = identity.create_key(Principal(None, "platform", "env:platform"), "acme", "owner", "k", None)
    identity.use_store(identity.MemoryStore())
    ev = {"id": str(uuid.uuid4()), "verdict": "ALLOW", "rules": [], "params": {"tool": "file.read"}, "digest": "a" * 64,
          "hop": 0, "host": None, "ts": 1.7e9}
    a.save_evaluation(ev, {"id": "grt_acme", "digest": "a" * 64, "exp": 4e9})
    a.save_step({"id": str(uuid.uuid4()), "source": "t", "declared_label": "TRUSTED", "label": "TRUSTED", "text": "acme secret plan",
                 "parents": [], "unknown_parents": [], "ts": "2026-11-02T00:00:00Z"})
    a.save_proof({"n": 1, "hash": "b" * 64, "prev": "0" * 64, "verdict": "ALLOW", "ts": "2026-11-02T00:00:00Z"})
    yield {"c": c, "a": a, "b": b, "key": ka, "ev": ev}
    persistence._POOL.clear()
    c.destroy()


def rt(db):
    import psycopg
    return psycopg.connect(db["c"].url, autocommit=False)


def denied(conn, sql, params=None, tenant="acme"):
    """True if the statement fails for the runtime account (each attempt in its own transaction)."""
    import psycopg
    try:
        with conn.transaction():
            conn.execute("SELECT set_config('qyrix.tenant_id', %s, true)", (tenant,))
            conn.execute(sql, params)
        return False
    except psycopg.Error:
        return True


TENANT_TABLES = ("provenance_steps", "approvals", "gate_evaluations", "grants", "proof_records", "proof_anchors", "api_keys", "sessions")


def test_runtime_account_is_least_privilege(db):
    with rt(db) as c, c.cursor() as cur:
        assert persistence.runtime_privilege_problems(cur) == []
        cur.execute("SELECT rolsuper, rolbypassrls, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolname = current_user")
        assert cur.fetchone() == (False, False, False, False)


def test_backend_refuses_an_over_privileged_account(db, tmp_path):
    with pytest.raises(persistence.PersistenceError, match="over-privileged.*superuser"):
        persistence.PgPersistence(db["c"].admin_url).verify_runtime()
    ctx = g.GateContext("t", prov.ProvenanceStore(), str(tmp_path / "c.jsonl"), lambda: (), {"file.read": adapter.FileAdapter(str(tmp_path), g._redact)}, str(tmp_path))
    try:
        g.attach_persistence(ctx, persistence.PgPersistence(db["c"].admin_url))
    except Exception:
        ctx.state["persistence"] = "down"
    assert ctx.state["persistence"] == "down"
    for _ in range(2):                    # also after the 2 s auto-recovery window (regression: v1.3 recovered fail-open)
        r = g.evaluate(A(tool="file.read", dest="README.md"), ctx)
        assert r["verdict"] == "BLOCK" and "R17_PERSISTENCE_UNAVAILABLE" in r["rules"]
        ctx.state["db_retry"] = 0
    assert ctx.state["persistence"] == "down"


def test_runtime_cannot_escalate_to_privileged_roles(db):
    with rt(db) as c:
        for role in ("qyrix", "qyrix_auth", "qyrix_maint", "postgres", "pg_read_server_files", "pg_execute_server_program"):
            assert denied(c, "SET ROLE %s" % role), role


def test_missing_tenant_context_sees_and_writes_nothing(db):
    with rt(db) as c:
        for tenant in ("", None):
            with c.transaction():
                if tenant is not None:
                    c.execute("SELECT set_config('qyrix.tenant_id', %s, true)", (tenant,))
                for t in TENANT_TABLES:
                    col = "1"
                    n = c.execute("SELECT count(%s) FROM %s" % (col, t)).fetchone()[0] if t not in ("api_keys", "sessions") else \
                        c.execute("SELECT count(tenant_id) FROM %s" % t).fetchone()[0]
                    assert n == 0, (t, tenant)
        assert denied(c, "INSERT INTO proof_records (tenant_id, n, hash, prev, kind, verdict, recorded_at) "
                         "VALUES ('acme', 99, %s, %s, 'x', 'ALLOW', now())", ("c" * 64, "0" * 64), tenant="")


def test_other_tenants_rows_are_invisible_even_with_explicit_filters(db):
    with rt(db) as c, c.transaction():
        c.execute("SELECT set_config('qyrix.tenant_id', 'globex', true)")
        for t in TENANT_TABLES:
            assert c.execute("SELECT count(tenant_id) FROM %s WHERE tenant_id = 'acme'" % t).fetchone()[0] == 0, t
    import psycopg                                               # ground truth: the rows exist
    with psycopg.connect(db["c"].admin_url) as a:
        assert a.execute("SELECT count(*) FROM grants WHERE tenant_id='acme'").fetchone()[0] == 1


def test_forged_cross_tenant_writes_are_rejected_by_rls(db):
    with rt(db) as c:
        assert denied(c, "INSERT INTO provenance_steps (tenant_id, id, source, declared_label, effective_label, created_at) "
                         "VALUES ('acme', %s, 'x', 'TRUSTED', 'TRUSTED', now())", (str(uuid.uuid4()),), tenant="globex")
        assert denied(c, "INSERT INTO grants (tenant_id, id, gate_evaluation_id, params_digest, created_at, expires_at) "
                         "VALUES ('acme', 'grt_forged', %s, %s, now(), now() + interval '1 hour')", (db["ev"]["id"], "a" * 64), tenant="globex")
        assert denied(c, "INSERT INTO api_keys (id, tenant_id, role, name, key_hash, created_by) VALUES "
                         "('key_forged', 'acme', 'owner', 'x', %s, 'attacker')", ("d" * 64,), tenant="globex")
        with c.transaction():                                    # cross-tenant UPDATE silently matches nothing
            c.execute("SELECT set_config('qyrix.tenant_id', 'globex', true)")
            assert c.execute("UPDATE grants SET revoked_at = now() WHERE tenant_id = 'acme'").rowcount == 0
            assert c.execute("UPDATE api_keys SET revoked_at = now() WHERE tenant_id = 'acme'").rowcount == 0
    assert db["a"].load_evaluations(10)[1][0]["revoked"] is False


def test_column_privileges_prevent_rewriting_evidence(db):
    with rt(db) as c:
        # positive controls: the legitimate operations still work, so "denied" below is not an artefact of bad SQL
        for ok in ("SELECT count(*) FROM grants", "UPDATE grants SET revoked_by = revoked_by WHERE false",
                   "UPDATE approvals SET status = status WHERE false", "UPDATE api_keys SET revoked_at = revoked_at WHERE false",
                   "SELECT id, role FROM api_keys"):
            assert not denied(c, ok), ok
        for sql in ("UPDATE gate_evaluations SET verdict = 'ALLOW'", "UPDATE gate_evaluations SET params_digest = 'x'",
                    "UPDATE grants SET params_digest = 'x'", "UPDATE grants SET expires_at = now() + interval '9 years'",
                    "UPDATE proof_records SET verdict = 'ALLOW'", "UPDATE approvals SET digest = 'x'", "UPDATE api_keys SET role = 'owner'",
                    "UPDATE tenants SET approved_domains = '{evil.example}'", "DELETE FROM grants", "DELETE FROM proof_records",
                    "TRUNCATE proof_records", "DELETE FROM tenants", "SELECT key_hash FROM api_keys", "SELECT id_hash FROM sessions"):
            assert denied(c, sql), sql


def test_runtime_cannot_escape_to_the_os_or_change_schema(db):
    with rt(db) as c:
        for sql in ("COPY (SELECT 1) TO PROGRAM 'id'", "SELECT pg_read_file('/etc/passwd')", "SELECT * FROM pg_authid",
                    "CREATE TABLE x (a int)", "CREATE TEMP TABLE x (a int)", "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'SELECT 1'",
                    "ALTER TABLE grants DISABLE ROW LEVEL SECURITY", "DROP POLICY tenant_isolation ON grants", "ALTER ROLE qyrix_runtime BYPASSRLS",
                    "CREATE ROLE evil SUPERUSER", "ALTER TABLE proof_records DISABLE TRIGGER USER"):
            assert denied(c, sql), sql


def test_row_security_cannot_be_switched_off(db):
    import psycopg
    with rt(db) as c:
        with pytest.raises(psycopg.Error, match="row-level security"):
            with c.transaction():
                c.execute("SET LOCAL row_security = off")
                c.execute("SELECT count(*) FROM grants").fetchone()


def test_credential_lookup_functions_cannot_enumerate(db):
    with rt(db) as c, c.transaction():
        for probe in ("", "%", "' OR '1'='1", "a" * 63, "0" * 64):
            assert c.execute("SELECT count(*) FROM qyrix_lookup_key(%s)", (probe,)).fetchone()[0] == 0, probe
            assert c.execute("SELECT count(*) FROM qyrix_lookup_session(%s)", (probe,)).fetchone()[0] == 0, probe
        h = identity._sha(db["key"]["api_key"])
        rows = c.execute("SELECT tenant_id, role FROM qyrix_lookup_key(%s)", (h,)).fetchall()
        assert rows == [("acme", "owner")]


def test_evidence_reset_needs_an_explicit_grant_and_stays_in_tenant(db):
    with rt(db) as c:
        assert denied(c, "SELECT qyrix_reset_tenant_evidence('acme')")                       # not granted by default
    migrate.migrate(db["c"].admin_url, allow_demo_reset=True)
    try:
        with rt(db) as c:
            assert denied(c, "SELECT qyrix_reset_tenant_evidence('acme')", tenant="globex")  # other tenant's evidence
            assert denied(c, "SELECT qyrix_reset_tenant_evidence(NULL)", tenant="")
    finally:
        migrate.migrate(db["c"].admin_url, allow_demo_reset=False)
    assert len(db["a"].load_proof_index()) == 1


def test_tenant_context_comes_only_from_the_server(db):
    """The tenant setting is written with a bind parameter from the authenticated principal; a hostile value is just a
    string that matches no tenant (no SQL injection into set_config, no wildcard)."""
    for hostile in ("acme' OR '1'='1", "%", "acme;RESET ALL", "*"):
        with pytest.raises(persistence.PersistenceError):
            persistence.PgPersistence(db["c"].url, hostile)                  # rejected before any query
        assert db["c"] and persistence.shared_connection(db["c"].url).run(
            lambda cur: cur.execute("SELECT count(tenant_id) FROM grants").fetchone()[0], tenant=hostile) == 0


def test_known_limitation_runtime_can_choose_any_tenant_context(db):
    """DOCUMENTED RESIDUAL RISK (not a pass condition for isolation): one runtime account serves all tenants, so code
    running inside the backend can set qyrix.tenant_id to any tenant. RLS + privilege separation stop application bugs,
    evidence rewriting, schema changes and OS escape - they do not contain a full backend compromise. Per-tenant runtime
    roles / processes are the documented next step (docs/PRODUCTION_READINESS.md)."""
    with rt(db) as c, c.transaction():
        c.execute("SELECT set_config('qyrix.tenant_id', 'acme', true)")
        assert c.execute("SELECT count(*) FROM grants").fetchone()[0] == 1


def test_pool_never_leaks_tenant_context_under_concurrency(db):
    """20 threads, alternating tenants, pool of 3 connections, injected failures and a hostile session-level set_config:
    every transaction must see exactly its own tenant setting and only its own rows."""
    pool = persistence._Pool(db["c"].url, 5, 3)
    errors, seen = [], []

    def work(i):
        tenant = ("acme", "globex", None)[i % 3]
        try:
            def go(cur):
                cur.execute("SELECT current_setting('qyrix.tenant_id', true)")
                setting = cur.fetchone()[0]
                cur.execute("SELECT count(*) FROM grants")
                n = cur.fetchone()[0]
                if i % 4 == 0:
                    cur.execute("SELECT set_config('qyrix.tenant_id', 'acme', false)")   # hostile SESSION-level leak attempt
                if i % 5 == 0:
                    raise RuntimeError("injected failure => rollback")
                return setting, n
            for _ in range(10):
                try:
                    seen.append((tenant, pool.run(go, tenant=tenant)))
                except persistence.PersistenceError:
                    pass
        except Exception as e:
            errors.append(repr(e))

    ts = [threading.Thread(target=work, args=(i,)) for i in range(20)]
    [t.start() for t in ts]; [t.join() for t in ts]
    pool.close_all()
    assert not errors
    assert len(seen) >= 100
    for tenant, (setting, n) in seen:
        assert setting == (tenant or ""), (tenant, setting)
        assert n == (1 if tenant == "acme" else 0), (tenant, n)
