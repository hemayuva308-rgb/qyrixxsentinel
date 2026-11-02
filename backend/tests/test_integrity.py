"""Silent data-loss detection (Phase C) against real PostgreSQL: database deletion, proof-chain deletion, total loss,
partial loss, witness forgery/loss, foreign database, backup restore + operator acceptance, first install, upgrade."""
import io, json, logging, os, shutil, subprocess, sys
import pytest

import app.gateway as g
from app import adapter, integrity, migrate, persistence, provenance as prov, recovery
from tests.test_persistence import Cluster, HAVE_PG, A

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import backup as bk  # noqa: E402
from tests.test_backup import keys  # noqa: E402,F401  (autouse: age identity + signing key for backups)

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = Cluster()
    yield c
    c.destroy()


def _new_db(cluster, name):
    import psycopg
    with psycopg.connect(cluster.admin_url, autocommit=True) as c:
        c.execute("DROP DATABASE IF EXISTS %s WITH (FORCE)" % name)
        c.execute("CREATE DATABASE %s" % name)
    admin = cluster.admin_url.rsplit("/", 1)[0] + "/" + name
    migrate.migrate(admin)
    return admin, cluster.runtime_url(name)


@pytest.fixture
def env(cluster, tmp_path, monkeypatch):
    name = "i" + os.urandom(4).hex()
    admin, url = _new_db(cluster, name)
    d = {"cluster": cluster, "name": name, "admin": admin, "url": url,
         "chain": str(tmp_path / "chain" / "proof_chain.jsonl"), "ws": str(tmp_path / "ws"), "wdir": str(tmp_path / "witness"),
         "key": str(tmp_path / "witness.key"), "tmp": tmp_path}
    for p in (os.path.dirname(d["chain"]), d["ws"], d["wdir"]):
        os.makedirs(p)
    open(os.path.join(d["ws"], "README.md"), "w").write("hello workspace")
    open(d["key"], "w").write(os.urandom(32).hex())
    monkeypatch.delenv("QYRIX_STATE_WITNESS", raising=False)
    monkeypatch.delenv("QYRIX_EXPECTED_INSTALL_ID", raising=False)
    monkeypatch.setenv("QYRIX_STATE_WITNESS_DIR", d["wdir"])
    monkeypatch.setenv("QYRIX_STATE_WITNESS_KEY_FILE", d["key"])
    monkeypatch.setenv("QYRIX_CHAIN_FILE", d["chain"])
    monkeypatch.setenv("QYRIX_DATABASE_URL", url)
    yield d
    integrity.reset_for_tests()
    persistence._POOL.clear()


def boot(env):
    """A fresh backend PROCESS: integrity state reset, chain from file, durable state from PostgreSQL."""
    integrity.reset_for_tests()
    persistence._POOL.clear()
    ctx = g.GateContext("t", prov.ProvenanceStore(), env["chain"], lambda: ("api.example.com",),
                        {"file.read": adapter.FileAdapter(env["ws"], g._redact)}, env["ws"])
    g._load_chain(ctx)
    try:
        g.attach_persistence(ctx, persistence.PgPersistence(env["url"]))
    except Exception:
        ctx.state["persistence"] = "down"
    return ctx


def status(ctx):
    return ctx.state.get("integrity", {}).get("status"), ctx.state.get("integrity", {}).get("reason")


def blocked(ctx):
    r = g.evaluate(A(tool="file.read", dest="README.md"), ctx)
    return r["verdict"] == "BLOCK" and r["grant_id"] is None


def use(ctx, n=3):
    t = ctx.prov.add_step("ticket", "TRUSTED", "read readme")
    for _ in range(n):
        assert g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), ctx)["verdict"] == "ALLOW"


def wipe_db(env):
    _new_db(env["cluster"], env["name"])                         # DROP + CREATE + migrate: an empty, valid schema


def test_fresh_install_then_normal_restart(env):
    c = boot(env)
    assert integrity.snapshot()["status"] == integrity.FRESH and status(c)[0] == integrity.OK
    use(c)
    w = integrity.read_witness()
    assert w["tenants"]["default"]["n"] == len(c.chain) and w["tenants"]["default"]["head"] == c.chain[-1]["hash"]
    c2 = boot(env)
    assert integrity.snapshot()["status"] == integrity.OK and status(c2) == (integrity.OK, None)
    assert not blocked(c2)


def test_database_deletion_is_detected(env):
    use(boot(env))
    wipe_db(env)
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "DATABASE_LOST_OR_REPLACED") and blocked(c)


def test_proof_chain_deletion_is_detected(env):
    use(boot(env))
    os.remove(env["chain"])
    c = boot(env)
    assert status(c)[0] == integrity.RECOVERY and blocked(c)
    assert status(c)[1] in ("PROOF_CHAIN_REGRESSED",)


def test_total_loss_of_database_and_chain_is_detected(env):
    use(boot(env))
    wipe_db(env); os.remove(env["chain"])
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "DATABASE_LOST_OR_REPLACED") and blocked(c)


def test_total_loss_including_witness_caught_by_expected_install_id(env, monkeypatch):
    use(boot(env))
    monkeypatch.setenv("QYRIX_EXPECTED_INSTALL_ID", integrity.read_witness()["install_id"])
    wipe_db(env); os.remove(env["chain"]); shutil.rmtree(env["wdir"]); os.makedirs(env["wdir"])
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "EXPECTED_INSTALLATION_MISSING") and blocked(c)


def test_known_limitation_total_loss_without_expected_id_looks_fresh(env):
    """DOCUMENTED LIMITATION: if DB, chain AND witness are all gone and no QYRIX_EXPECTED_INSTALL_ID is configured, nothing
    is left to compare against. The start is then reported as FRESH_INSTALL with a warning event (alert on it)."""
    use(boot(env))
    wipe_db(env); os.remove(env["chain"]); shutil.rmtree(env["wdir"]); os.makedirs(env["wdir"])
    buf = io.StringIO(); h = logging.StreamHandler(buf); logging.getLogger("qyrix.security").addHandler(h)
    try:
        boot(env)
    finally:
        logging.getLogger("qyrix.security").removeHandler(h)
    assert integrity.snapshot()["status"] == integrity.FRESH and '"event":"installation_initialized"' in buf.getvalue()


def test_partial_loss_truncated_chain_and_deleted_db_rows(env):
    use(boot(env), 4)
    lines = open(env["chain"]).read().splitlines()
    open(env["chain"], "w").write("\n".join(lines[:-2]) + "\n")
    c = boot(env)
    assert status(c)[0] == integrity.RECOVERY and blocked(c)
    open(env["chain"], "w").write("\n".join(lines) + "\n")       # chain repaired, now lose DB evidence rows instead
    import psycopg
    with psycopg.connect(env["admin"], autocommit=True) as a:
        a.execute("ALTER TABLE proof_records DISABLE TRIGGER USER")
        a.execute("DELETE FROM proof_records WHERE n > 1")
        a.execute("ALTER TABLE proof_records ENABLE TRIGGER USER")
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "DATABASE_EVIDENCE_REGRESSED") and blocked(c)


def test_forged_or_missing_witness_is_detected(env):
    use(boot(env))
    p = os.path.join(env["wdir"], "witness.json")
    doc = json.load(open(p)); doc["body"]["tenants"]["default"]["n"] = 1      # attacker lowers the mark without the key
    json.dump(doc, open(p, "w"))
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "WITNESS_FORGED_OR_WRONG_KEY") and blocked(c)
    os.remove(p)
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "WITNESS_MISSING") and blocked(c)


def test_wrong_witness_key_is_detected(env):
    use(boot(env))
    open(env["key"], "w").write(os.urandom(32).hex())
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "WITNESS_FORGED_OR_WRONG_KEY") and blocked(c)


def test_database_from_another_installation_is_detected(env, cluster):
    use(boot(env))
    other_admin, other_url = _new_db(cluster, env["name"] + "x")
    persistence.PgPersistence(other_url).init_install("00000000-0000-4000-8000-000000000001")
    env["url"] = other_url
    c = boot(env)
    assert status(c)[0] == integrity.RECOVERY and status(c)[1] == "INSTALLATION_MISMATCH" and blocked(c)


def test_legacy_upgrade_with_existing_data_is_adopted(env):
    use(boot(env))
    import psycopg
    with psycopg.connect(env["admin"], autocommit=True) as a:      # simulate a v1.3 database: data, but no identity yet
        a.execute("ALTER TABLE installation DISABLE TRIGGER USER"); a.execute("DELETE FROM installation")
        a.execute("ALTER TABLE installation ENABLE TRIGGER USER")
    os.remove(os.path.join(env["wdir"], "witness.json"))
    c = boot(env)
    assert integrity.snapshot()["status"] == integrity.ADOPTED and status(c)[0] == integrity.OK and not blocked(c)


def test_backup_restore_requires_operator_acceptance_and_is_recorded(env):
    c = boot(env); use(c, 2)
    bdir = str(env["tmp"] / "bk")
    bk.backup(env["admin"], os.path.dirname(env["chain"]), bdir)
    use(c, 3)                                                       # work done AFTER the backup
    bk.restore(env["admin"], os.path.dirname(env["chain"]), bdir, force=True)
    r = boot(env)
    assert status(r) == (integrity.RECOVERY, "PROOF_CHAIN_REGRESSED") and blocked(r)   # restoring old data is never silent
    with pytest.raises(SystemExit):
        recovery.accept("short")                                    # a real incident reason is mandatory
    out = recovery.accept("restored backup bk after simulated disk failure (test)")
    assert out["accepted"] and out["pending_proof_records"] >= 1
    r2 = boot(env)
    assert status(r2)[0] == integrity.OK and not blocked(r2), status(r2)
    assert any(x.get("verdict") == "RECOVERY_ACCEPTED" for x in r2.chain) and g.verify_chain(r2)["valid"]
    w = integrity.read_witness()
    assert w["recoveries"][-1]["reason"].startswith("restored backup") and not w.get("pending_records")
    r3 = boot(env)                                                  # acknowledgement is written exactly once
    assert sum(1 for x in r3.chain if x.get("verdict") == "RECOVERY_ACCEPTED") == 1


def test_accept_refuses_tampered_chain_and_missing_identity(env):
    use(boot(env))
    lines = open(env["chain"]).read().splitlines()
    rec = json.loads(lines[0]); rec["verdict"] = "BLOCK"; lines[0] = json.dumps(rec)
    open(env["chain"], "w").write("\n".join(lines) + "\n")
    with pytest.raises(SystemExit, match="tampering"):
        recovery.accept("investigating incident INC-1 (test)")
    os.remove(env["chain"]); wipe_db(env)
    with pytest.raises(SystemExit, match="no installation identity"):
        recovery.accept("database rebuilt after incident INC-2 (test)")
    assert recovery.accept("database rebuilt after incident INC-2 (test)", new_installation=True)["accepted"]
    assert status(boot(env))[0] == integrity.OK


def test_unconfigured_or_disabled_witness(env, monkeypatch):
    monkeypatch.delenv("QYRIX_STATE_WITNESS_DIR")
    c = boot(env)
    assert status(c) == (integrity.RECOVERY, "WITNESS_NOT_CONFIGURED")
    assert blocked(c)
    monkeypatch.setenv("QYRIX_STATE_WITNESS", "disabled")             # explicit, documented UNSAFE opt-out
    c = boot(env)
    assert status(c)[0] == integrity.DISABLED and not blocked(c)


def test_recovery_cli_status_reports_without_secrets(env):
    use(boot(env))
    out = subprocess.run([sys.executable, "-m", "app.recovery", "status"], capture_output=True, text=True,
                         cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))), env=os.environ.copy())
    assert out.returncode == 0, out.stderr
    s = json.loads(out.stdout)
    assert s["witness"]["install_id"] == s["database_install_id"] and s["chains"]["default"]["valid"]
    assert open(env["key"]).read().strip() not in out.stdout
