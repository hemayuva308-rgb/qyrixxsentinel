"""Backup / restore acceptance tests against real PostgreSQL clusters (scripts/backup.py).

Proves: a backup restores into a FRESH cluster with identity, provenance, approvals, grants and proofs intact; restored
state cannot be used to replay executions; restoring in the wrong order (chain older than DB) fails closed; an older DB
with a newer chain stays replay-safe; tampered backups are refused; the DB password never appears in argv."""
import json, os, shutil, sys
import pytest

import app.gateway as g
from app import adapter, identity, persistence, provenance as prov
from app.identity import Principal
from tests.test_persistence import Cluster, HAVE_PG, A

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import backup as bk  # noqa: E402

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture
def two(tmp_path):
    src, dst = Cluster(), Cluster()
    ws = tmp_path / "ws"; ws.mkdir(); (ws / "README.md").write_text("hello workspace")
    chain_dir = tmp_path / "chain"; chain_dir.mkdir()
    yield {"src": src, "dst": dst, "ws": str(ws), "chain_dir": str(chain_dir), "tmp": tmp_path}
    src.destroy(); dst.destroy()
    persistence._POOL.clear()


def boot(url, chain_dir, ws):
    ctx = g.GateContext("t", prov.ProvenanceStore(), os.path.join(chain_dir, "chain.jsonl"), lambda: ("api.example.com",),
                        {"file.read": adapter.FileAdapter(ws, g._redact)}, ws)
    g._load_chain(ctx)
    g._load_anchors(ctx)
    try:
        g.attach_persistence(ctx, persistence.PgPersistence(url))
    except Exception:
        ctx.state["persistence"] = "down"
    return ctx


def run(ctx, r):
    return g.execute_grant({"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}, ctx)


def refused(ctx, r):
    with pytest.raises(g.ExecRefused) as e:
        run(ctx, r)
    return e.value.code


def populate(env):
    c = boot(env["src"].url, env["chain_dir"], env["ws"])
    assert c.state["persistence"] == "postgres"
    t = c.prov.add_step("ticket", "TRUSTED", "read readme")
    u = c.prov.add_step("skill", "UNTRUSTED", "x")
    used = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c)
    assert run(c, used)["executed"]
    unused = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c)
    apr = g.create_approval(g.ApprovalReq(tool="http", method="DELETE", dest="https://api.example.com/v1/x"), c)
    g.decide_approval(apr["id"], "approve", "admin", c)
    identity.use_store(identity.PgStore(persistence.shared_connection(env["src"].url)))
    key = identity.create_key(Principal("default", "owner", "test"), "default", "auditor", "backup-test", None)
    identity.use_store(identity.MemoryStore())
    return c, {"t": t, "u": u, "used": used, "unused": unused, "apr": apr, "key": key}


def test_backup_restores_into_a_fresh_cluster(two):
    c, s = populate(two)
    out = str(two["tmp"] / "bk")
    m = bk.backup(two["src"].url, two["chain_dir"], out)
    assert m["order"] == ["db.dump", "chain.tar"] and oct(os.stat(out).st_mode & 0o777) == "0o700"

    shutil.rmtree(two["chain_dir"]); os.makedirs(two["chain_dir"])
    two["src"].destroy()                                            # the original database is gone
    bk.restore(two["dst"].url, two["chain_dir"], out)

    r = boot(two["dst"].url, two["chain_dir"], two["ws"])
    assert r.state["persistence"] == "postgres" and not r.state["degraded"]
    assert g.verify_chain(r)["valid"] and len(r.chain) == len(c.chain)
    assert r.prov.trust_of(s["u"]["id"]) == "UNTRUSTED" and r.appr[s["apr"]["id"]]["status"] == "approved"
    assert refused(r, s["used"]) == "GRANT_REPLAY"                  # restored state cannot replay an execution
    assert run(r, s["unused"])["executed"]
    assert refused(r, s["unused"]) == "GRANT_REPLAY"
    identity.use_store(identity.PgStore(persistence.shared_connection(two["dst"].url)))
    try:
        assert identity.authenticate(s["key"]["api_key"]).role == "auditor"   # API keys (hashes) survive restore
    finally:
        identity.use_store(identity.MemoryStore())
    import psycopg                                                  # RLS + least-privilege role survive restore
    with psycopg.connect(two["dst"].url) as conn, conn.transaction():
        conn.execute("SET LOCAL ROLE qyrix_app")
        assert conn.execute("SELECT count(*) FROM proof_records").fetchone()[0] == 0     # no tenant set => nothing
        with pytest.raises(psycopg.Error):
            conn.execute("SELECT count(*) FROM api_keys")


def test_chain_older_than_database_fails_closed(two):
    c, _ = populate(two)
    early = str(two["tmp"] / "early-chain")
    shutil.copytree(two["chain_dir"], early)                        # WRONG ORDER: chain captured first...
    g.evaluate(A(tool="file.read", dest="README.md"), c)            # ...more decisions happen...
    out = str(two["tmp"] / "bk")
    bk.backup(two["src"].url, two["chain_dir"], out)                # ...then the DB is captured
    shutil.rmtree(two["chain_dir"]); shutil.copytree(early, two["chain_dir"])
    bk.restore(two["dst"].url, str(two["tmp"] / "unused-dir"), out)
    r = boot(two["dst"].url, two["chain_dir"], two["ws"])
    assert r.state["degraded"] is True and r.state["persistence"] == "down"
    assert g.evaluate(A(tool="file.read", dest="README.md"), r)["verdict"] == "BLOCK"


def test_older_database_newer_chain_stays_replay_safe(two):
    """The safe direction of the ordering invariant: DB snapshot taken, THEN a grant executes, THEN the chain is copied.
    After restore the grant row says 'unused' but the chain holds EXECUTION_STARTED => it is loaded as used."""
    c, s = populate(two)
    old = str(two["tmp"] / "old"); new = str(two["tmp"] / "new"); mixed = str(two["tmp"] / "mixed")
    bk.backup(two["src"].url, two["chain_dir"], old)                 # DB while 'unused' is unused
    assert run(c, s["unused"])["executed"]                            # executes after the DB snapshot
    bk.backup(two["src"].url, two["chain_dir"], new)                 # chain containing EXECUTION_STARTED
    os.makedirs(mixed)
    shutil.copy(os.path.join(old, "db.dump"), mixed); shutil.copy(os.path.join(new, "chain.tar"), mixed)
    with open(os.path.join(mixed, "manifest.json"), "w") as f:
        json.dump({"format": bk.FORMAT, "order": ["db.dump", "chain.tar"],
                   "files": {n: bk._sha(os.path.join(mixed, n)) for n in ("db.dump", "chain.tar")}}, f)
    restored_chain = str(two["tmp"] / "restored")
    bk.restore(two["dst"].url, restored_chain, mixed)
    r = boot(two["dst"].url, restored_chain, two["ws"])
    assert r.state["persistence"] == "postgres" and not r.state["degraded"]   # DB mirror is a prefix: back-filled
    assert r.grants[s["unused"]["grant_id"]]["used"] is True
    assert refused(r, s["unused"]) == "GRANT_REPLAY"


def test_tampered_backup_is_refused(two):
    populate(two)
    out = str(two["tmp"] / "bk")
    bk.backup(two["src"].url, two["chain_dir"], out)
    with open(os.path.join(out, "chain.tar"), "r+b") as f:
        f.seek(600); f.write(b"X")
    with pytest.raises(SystemExit, match="does not match its manifest"):
        bk.restore(two["dst"].url, str(two["tmp"] / "new"), out)


def test_restore_refuses_to_overwrite_live_chain_and_backup_never_overwrites(two):
    populate(two)
    out = str(two["tmp"] / "bk")
    bk.backup(two["src"].url, two["chain_dir"], out)
    with pytest.raises(FileExistsError):
        bk.backup(two["src"].url, two["chain_dir"], out)
    with pytest.raises(SystemExit, match="not empty"):
        bk.restore(two["dst"].url, two["chain_dir"], out)


def test_password_is_passed_by_environment_not_argv():
    marker = "synthetic-" + "not-a-password"                     # built at runtime: no credential-shaped literal in source
    conn, env = bk._pg_env("host=db port=5432 dbname=qyrix user=qyrix password=" + marker)
    assert marker not in conn and env["PGPASSWORD"] == marker
