"""v1.5 P1 on REAL PostgreSQL: migration 007 over existing (pre-007) data, binding enforced by the atomic SQL itself,
runtime-role privileges on the new columns, tenant isolation, and binding durability across a restart."""
import os
import shutil
import tempfile
import time
import uuid

import pytest

import app.gateway as g
from app import migrate, persistence
from tests.test_persistence import HAVE_PG, Cluster, boot

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")
NEW_GRANT_COLS = {"agent_id", "task_id", "policy_version"}
NEW_EVAL_COLS = NEW_GRANT_COLS | {"correlation_id"}


def _cols(conn, table):
    return {r[0] for r in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_name=%s", (table,))}


@pytest.fixture
def pre007(monkeypatch):
    """A cluster migrated only up to 006, holding legacy rows - then upgraded by the real migrator."""
    only = tempfile.mkdtemp(prefix="qyrix-mig-")
    for f in sorted(os.listdir(persistence.MIGRATIONS)):
        if f.endswith(".sql") and f < "007":
            shutil.copy(os.path.join(persistence.MIGRATIONS, f), only)
    real = persistence.MIGRATIONS
    monkeypatch.setattr(persistence, "MIGRATIONS", only)
    c = Cluster()                                                     # Cluster() runs migrate() => 001-006 only
    monkeypatch.setattr(persistence, "MIGRATIONS", real)
    yield c
    persistence._POOL.clear()
    c.destroy()
    shutil.rmtree(only, ignore_errors=True)


def test_migration_007_is_additive_and_preserves_existing_rows(pre007):
    import psycopg
    eid, gid = str(uuid.uuid4()), "grt_" + uuid.uuid4().hex
    with psycopg.connect(pre007.admin_url, autocommit=True) as a:
        assert not (NEW_GRANT_COLS & _cols(a, "grants"))              # really a pre-007 schema
        a.execute("INSERT INTO gate_evaluations (tenant_id, id, verdict, rule_ids, params, params_digest, hop, host, created_at)"
                  " VALUES ('default', %s, 'ALLOW', '{}', '{}'::jsonb, %s, 0, NULL, now())", (eid, "d" * 64))
        a.execute("INSERT INTO grants (tenant_id, id, gate_evaluation_id, params_digest, created_at, expires_at)"
                  " VALUES ('default', %s, %s, %s, now(), now() + interval '1 hour')", (gid, eid, "d" * 64))
        before = a.execute("SELECT count(*) FROM grants").fetchone()[0], a.execute("SELECT count(*) FROM gate_evaluations").fetchone()[0]
    applied = migrate.migrate(pre007.admin_url)
    assert applied == ["007_task_bound_grants.sql"]
    assert migrate.migrate(pre007.admin_url) == []                    # idempotent: nothing re-applied
    with psycopg.connect(pre007.admin_url, autocommit=True) as a:
        assert NEW_GRANT_COLS <= _cols(a, "grants") and NEW_EVAL_COLS <= _cols(a, "gate_evaluations")
        after = a.execute("SELECT count(*) FROM grants").fetchone()[0], a.execute("SELECT count(*) FROM gate_evaluations").fetchone()[0]
        assert after == before                                        # no row lost or added
        row = a.execute("SELECT params_digest, agent_id, task_id, policy_version, used_at FROM grants WHERE id=%s", (gid,)).fetchone()
        assert row[0] == "d" * 64 and row[1:] == (None, None, None, None)   # existing data untouched, binding NULL
    # the runtime account still passes the startup least-privilege + fully-migrated check
    db = persistence.PgPersistence(pre007.url, "default")
    db.verify_runtime()
    # a legacy (unbound) grant cannot be consumed by an authenticated caller: NULL never matches a binding
    assert db.consume_grant(gid, eid, "d" * 64, "env:agent", None, "p" * 64) is False


@pytest.fixture(scope="module")
def cl():
    c = Cluster()
    yield c
    persistence._POOL.clear()
    c.destroy()


def _row(db, agent="key:a1", task="t-1", pv="v" * 64):
    eid, gid = str(uuid.uuid4()), "grt_" + uuid.uuid4().hex
    db.save_evaluation({"id": eid, "verdict": "ALLOW", "rules": [], "params": {"tool": "http"}, "digest": "e" * 64, "hop": 0,
                        "host": None, "ts": time.time(), "agent_id": agent, "task_id": task, "policy_version": pv,
                        "correlation_id": "c-1"},
                       {"id": gid, "digest": "e" * 64, "exp": time.time() + 600, "agent_id": agent, "task_id": task,
                        "policy_version": pv})
    return eid, gid


def test_atomic_sql_enforces_every_binding_field(cl):
    db = persistence.PgPersistence(cl.url, "default")
    eid, gid = _row(db)
    assert db.consume_grant(gid, eid, "e" * 64, "key:OTHER", "t-1", "v" * 64) is False      # cross-agent
    assert db.consume_grant(gid, eid, "e" * 64, "key:a1", "t-2", "v" * 64) is False         # cross-task
    assert db.consume_grant(gid, eid, "e" * 64, "key:a1", None, "v" * 64) is False          # task omitted
    assert db.consume_grant(gid, eid, "e" * 64, "key:a1", "t-1", "w" * 64) is False         # policy changed
    assert db.consume_grant(gid, eid, "f" * 64, "key:a1", "t-1", "v" * 64) is False         # argument digest
    assert db.consume_grant(gid, eid, "e" * 64, "key:a1", "t-1", "v" * 64) is True          # exact binding: once
    assert db.consume_grant(gid, eid, "e" * 64, "key:a1", "t-1", "v" * 64) is False         # replay


def test_binding_is_tenant_isolated(cl):
    import psycopg
    with psycopg.connect(cl.admin_url, autocommit=True) as a:
        a.execute("INSERT INTO tenants (id, name) VALUES ('acme7','Acme7') ON CONFLICT DO NOTHING")
    db, other = persistence.PgPersistence(cl.url, "default"), persistence.PgPersistence(cl.url, "acme7")
    eid, gid = _row(db)
    assert other.consume_grant(gid, eid, "e" * 64, "key:a1", "t-1", "v" * 64) is False      # RLS: invisible to acme7
    assert db.consume_grant(gid, eid, "e" * 64, "key:a1", "t-1", "v" * 64) is True


def test_runtime_role_can_write_but_never_rewrite_a_binding(cl):
    import psycopg
    db = persistence.PgPersistence(cl.url, "default")
    eid, gid = _row(db)                                               # INSERT with the new columns works (runtime role)
    with psycopg.connect(cl.url, autocommit=False) as conn:
        for col in ("agent_id", "task_id", "policy_version"):
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute("SELECT set_config('qyrix.tenant_id', 'default', true)")
                    conn.execute("UPDATE grants SET %s = 'x' WHERE id = %%s" % col, (gid,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("SELECT set_config('qyrix.tenant_id', 'default', true)")
                conn.execute("UPDATE gate_evaluations SET agent_id = 'x' WHERE id = %s", (eid,))
        with conn.transaction():                                      # the one allowed write path is unchanged
            conn.execute("SELECT set_config('qyrix.tenant_id', 'default', true)")
            assert conn.execute("UPDATE grants SET used_at = now() WHERE id = %s RETURNING id", (gid,)).fetchone()


def test_binding_survives_restart_and_is_enforced_after_reload(tmp_path):
    c = Cluster()
    try:
        ws = tmp_path / "ws"; ws.mkdir(); (ws / "README.md").write_text("hello workspace")
        env = {"url": c.url, "chain": str(tmp_path / "chain.jsonl"), "ws": str(ws), "cluster": c}
        c1 = boot(env)
        t = c1.prov.add_step("ticket", "TRUSTED", "read")
        r = g.evaluate(g.Action(tool="file.read", dest="README.md", lineage=[t["id"]], task_id="job-9"), c1, agent_id="key:a1")
        assert r["verdict"] == "ALLOW"
        c2 = boot(env)                                                # a new process loads grants from PostgreSQL
        gr = c2.grants[r["grant_id"]]
        assert (gr["agent_id"], gr["task_id"], gr["policy_version"]) == ("key:a1", "job-9", r["policy_version"])
        body = {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"], "task_id": "job-9"}
        with pytest.raises(g.ExecRefused) as e:
            g.execute_grant(body, c2, agent_id="key:intruder")
        assert e.value.code == "GRANT_AGENT_MISMATCH"
        with pytest.raises(g.ExecRefused) as e:
            g.execute_grant({**body, "task_id": "job-10"}, c2, agent_id="key:a1")
        assert e.value.code == "GRANT_TASK_MISMATCH"
        x = g.execute_grant(body, c2, agent_id="key:a1")
        assert x["executed"] and x["result"]["content"] == "hello workspace"
        c3 = boot(env)
        with pytest.raises(g.ExecRefused) as e:
            g.execute_grant(body, c3, agent_id="key:a1")
        assert e.value.code == "GRANT_REPLAY"
    finally:
        persistence._POOL.clear()
        c.destroy()


def test_policy_change_across_restart_invalidates_persisted_grant(tmp_path):
    c = Cluster()
    try:
        ws = tmp_path / "ws"; ws.mkdir(); (ws / "README.md").write_text("x")
        env = {"url": c.url, "chain": str(tmp_path / "chain.jsonl"), "ws": str(ws), "cluster": c}
        c1 = boot(env)
        t = c1.prov.add_step("ticket", "TRUSTED", "read")
        r = g.evaluate(g.Action(tool="file.read", dest="README.md", lineage=[t["id"]]), c1, agent_id="key:a1")
        c2 = boot(env)
        c2.approved = lambda: ("api.example.com", "added-after-restart.example")   # operator changed the allowlist
        with pytest.raises(g.ExecRefused) as e:
            g.execute_grant({"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}, c2, agent_id="key:a1")
        assert e.value.code == "GRANT_POLICY_CHANGED"
    finally:
        persistence._POOL.clear()
        c.destroy()
