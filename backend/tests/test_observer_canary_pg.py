"""Phase C3 on REAL PostgreSQL (observer-db): observer canaries under the owner's amended decisions D1-D5.
Tokens, hashing, run-before-submission, P2 client (evaluate only, disabled by default), HTTP/file sensors (loopback /
observer-owned), positive controls, DECISION_MISSING, discrepancies, repeated / forged / late observations, expiry and
cleanup, restart, DB and backend failures, tenant isolation, O002 migration + privileges, and NO verdict anywhere."""
import json
import os
import shutil
import tempfile
import urllib.request
import uuid

import psycopg
import pytest

from observer import canary as oc, migrate as omigrate
from observer.canary import CanaryError, CanaryService, FileCanarySensor, HttpCanarySensor, P2Client
from observer.db import Database, DbError, runtime_problems
from tests.observer_support import HAVE_PG, T0, Clock, Keys, ObserverCluster, envelope, make_observer, raw

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")
RESULTS = ("ENFORCEMENT_VERIFIED", "BYPASS_DETECTED", "UNAUTHORIZED_EXECUTION")
NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@pytest.fixture(scope="module")
def cluster():
    c = ObserverCluster()
    yield c
    c.destroy()


@pytest.fixture
def env(cluster, tmp_path):
    url, admin = cluster.new_db()
    keys, clock = Keys(), Clock()
    obs = make_observer(url, keys, clock)
    svc = CanaryService(obs)
    svc.http = HttpCanarySensor(svc.record)
    d = tmp_path / "canary"
    svc.file = FileCanarySensor(svc.record, str(d), interval=0.05)
    yield {"url": url, "admin": admin, "keys": keys, "clock": clock, "obs": obs, "svc": svc, "dir": str(d)}
    svc.http.close(); svc.file.close()


def q(admin, sql, params=()):
    with psycopg.connect(admin, autocommit=True) as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else None


def kinds(e, run_id):
    return [r[0] for r in q(e["admin"], "SELECT kind FROM canary_run_events WHERE run_id=%s ORDER BY id", (run_id,))]


def finish(e):
    e["clock"].t += e["obs"].cfg.T_decision + 1
    return e["svc"].tick()


class FakeBackend:
    """Fixture transport for the P2 client. mode: block | allow | broken (performs the canary side effect itself) |
    down (connection refused before sending) | timeout (request sent, no response)."""

    def __init__(self, mode="block", on_call=None):
        self.mode, self.calls, self.on_call = mode, [], on_call

    def post(self, path, json=None, headers=None):
        self.calls.append((path, json, headers))
        if self.on_call:
            self.on_call(json)
        import httpx
        if self.mode == "down":
            raise httpx.ConnectError("refused")
        if self.mode == "timeout":
            raise httpx.ReadTimeout("no response")
        if self.mode == "broken":
            if json["tool"] == "http":
                NO_PROXY.open(json["dest"], timeout=2).close()
            else:
                open(json["dest"], "w").write("written by a non-enforcing integration")
        v = "ALLOW" if self.mode == "allow" else "BLOCK"
        return type("R", (), {"status_code": 200, "json": lambda s: {"verdict": v, "rules": [] if v == "ALLOW" else ["R1_DEST_NOT_APPROVED"]}})()


def live(e, mode="block", tenant="default", on_call=None, tmp=None):
    tf = os.path.join(tmp or e["dir"] + "-cred", "tok")
    os.makedirs(os.path.dirname(tf), exist_ok=True)
    open(tf, "w").write("qx_canary_agent_token_for_tests_only")
    fb = FakeBackend(mode, on_call)
    e["svc"].p2 = P2Client({tenant: {"key_id": "key_canary_01", "token_file": tf}}, fb, live=True)
    return fb


def claim(e, corr, verdict="BLOCK", tenant="default", seq=1):
    k = e["keys"]
    body = {"gate_evaluation_id": str(uuid.uuid4()), "correlation_id": corr, "verdict": verdict, "rule_ids": []}
    return e["obs"].ingest(raw(envelope(k.gate, k.gate_pid, "decision", body, tenant=tenant, seq=seq, issued=e["clock"].t)))


def no_verdicts(e):
    blob = json.dumps(q(e["admin"], "SELECT kind, detail FROM canary_run_events"), default=str) + json.dumps(
        q(e["admin"], "SELECT code, detail FROM ledger"), default=str)
    for r in RESULTS:
        assert r not in blob


# ---------------- tokens ----------------
def test_tokens_are_csprng_and_unique(monkeypatch):
    toks = {oc.mint() for _ in range(20000)}
    assert len(toks) == 20000 and all(len(t) == 32 and int(t, 16) >= 0 for t in toks)
    used = []
    real = oc.secrets.token_bytes
    monkeypatch.setattr(oc.secrets, "token_bytes", lambda n: used.append(n) or real(n))
    oc.mint()
    assert used == [16]                                                    # 128 bits from the CSPRNG


def test_run_is_recorded_before_submission_and_only_hashes_are_stored(env):
    seen = {}

    def at_submit(action):                                                 # what exists when the backend first sees it
        seen["token"] = action["dest"].rsplit("/", 1)[1]
        seen["rows"] = q(env["admin"], "SELECT count(*) FROM canary_runs")[0][0]
        seen["ledger"] = q(env["admin"], "SELECT count(*) FROM ledger WHERE code='CANARY_RUN_CREATED'")[0][0]
    live(env, "block", on_call=at_submit)
    r = env["svc"].start("default")
    assert seen["rows"] == 1 and seen["ledger"] == 1
    dump = json.dumps([q(env["admin"], "SELECT * FROM %s" % t) for t in
                       ("canary_runs", "canary_run_events", "observations", "ledger")], default=str)
    assert seen["token"] not in dump and oc.h(seen["token"]) in dump        # never the token, only its SHA-256
    assert "qx_canary_agent_token_for_tests_only" not in dump               # never the credential
    assert q(env["admin"], "SELECT credential_key_id, expected_condition, expected_basis FROM canary_runs") == [
        ("key_canary_01", "BLOCK", "construction")]
    assert r["correlation_id"].startswith("obs_") and len(r["correlation_id"]) == 36


# ---------------- P2 (D4) ----------------
def test_live_p2_is_disabled_by_default(env):
    r = env["svc"].start("default")
    assert r["submission"] == {"submitted": False, "disabled": True}
    finish(env)
    k = kinds(env, r["run_id"])
    assert k == ["CREATED", "SUBMISSION_DISABLED", "POSITIVE_CONTROL_PASSED", "WINDOW_ENDED", "CLEANED_UP"]
    end = q(env["admin"], "SELECT detail FROM canary_run_events WHERE kind='WINDOW_ENDED'")[0][0]
    assert end["decision_claim"].startswith("not_applicable") and end["result"] is None
    no_verdicts(env)


def test_p2_client_only_ever_calls_evaluate(env):
    fb = live(env, "allow")
    env["svc"].start("default"); env["svc"].start("default", "file")
    assert {c[0] for c in fb.calls} == {P2Client.EVALUATE}
    src = open(oc.__file__).read()
    assert "tools/execute" not in src and "tools/redeem" not in src and "/execute" not in src


def test_signed_block_claim_matches_expectation_without_any_verdict(env):
    live(env, "block")
    r = env["svc"].start("default")
    assert claim(env, r["correlation_id"], "BLOCK")[0] == 200
    finish(env)
    assert "DECISION_CLAIM_SEEN" in kinds(env, r["run_id"]) and "DECISION_DISCREPANCY" not in kinds(env, r["run_id"])
    end = q(env["admin"], "SELECT detail FROM canary_run_events WHERE kind='WINDOW_ENDED'")[0][0]
    assert end["decision_claim"] == {"verdict": "BLOCK", "evidence_level": "E0"} and end["result"] is None
    no_verdicts(env)


def test_discrepancies_are_recorded_not_concluded(env):
    live(env, "block")                                                      # REST says BLOCK ...
    r = env["svc"].start("default")
    claim(env, r["correlation_id"], "ALLOW")                                # ... signed claim says ALLOW
    finish(env)
    d = [x[0] for x in q(env["admin"], "SELECT detail FROM canary_run_events WHERE kind='DECISION_DISCREPANCY'")]
    assert {x["kind"] for x in d} == {"EXPECTATION_VS_SIGNED_CLAIM", "REST_RESPONSE_VS_SIGNED_CLAIM"}
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='DECISION_DISCREPANCY'") == [(2,)]
    no_verdicts(env)


def test_decision_missing_and_late_claim(env):
    live(env, "block")
    a = env["svc"].start("default")
    b = env["svc"].start("default")
    env["clock"].t += env["obs"].cfg.T_decision + 1
    claim(env, b["correlation_id"], "BLOCK")                                # arrives after T_decision
    env["svc"].tick()
    da = q(env["admin"], "SELECT detail FROM canary_run_events WHERE run_id=%s AND kind='DECISION_MISSING'", (a["run_id"],))
    db_ = q(env["admin"], "SELECT detail FROM canary_run_events WHERE run_id=%s AND kind='DECISION_MISSING'", (b["run_id"],))
    assert da[0][0]["late_claim"] is False and db_[0][0]["late_claim"] is True
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='DECISION_MISSING'") == [(2,)]


def test_rest_response_is_never_treated_as_a_claim(env):
    live(env, "block")                                                      # the backend's HTTP answer says BLOCK
    r = env["svc"].start("default")
    finish(env)                                                             # but no SIGNED claim arrived
    k = kinds(env, r["run_id"])
    assert "DECISION_MISSING" in k and "DECISION_CLAIM_SEEN" not in k


# ---------------- backend / database unavailable ----------------
def test_backend_unavailable(env):
    live(env, "down")
    a = env["svc"].start("default")
    assert a["submission"]["submitted"] is False
    live(env, "timeout")                                                    # sent, unknown outcome
    b = env["svc"].start("default")
    finish(env)
    assert "SUBMISSION_FAILED" in kinds(env, a["run_id"]) and "DECISION_MISSING" not in kinds(env, a["run_id"])
    assert "SUBMITTED" in kinds(env, b["run_id"]) and "DECISION_MISSING" in kinds(env, b["run_id"])
    no_verdicts(env)


def test_database_unavailable_nothing_submitted_and_hits_not_silent(env, keys=None):
    from observer.ingest import Observer
    from observer.feed import Config
    k = env["keys"]
    dead = Observer(Database("postgresql://observer_runtime@127.0.0.1:1/none", timeout=1), k.manifest(), k.observer,
                    Config(), env["clock"])
    svc = CanaryService(dead)
    svc.http = env["svc"].http
    fb = FakeBackend("block")
    svc.p2 = P2Client({"default": {"key_id": "k", "token_file": "/nonexistent"}}, fb, live=True)
    with pytest.raises(DbError):
        svc.start("default")
    assert fb.calls == []                                                   # no run record => no submission
    assert svc.record("canary_http", oc.mint()) is False and svc.unrecorded == 1


# ---------------- sensors and observations ----------------
def test_token_observation_is_e3_and_produces_no_verdict(env):
    live(env, "broken")                                                     # integration performs the side effect
    r = env["svc"].start("default")
    finish(env)
    obs = q(env["admin"], "SELECT sensor, purpose, timing, evidence_level FROM observations WHERE run_id=%s ORDER BY purpose",
            (r["run_id"],))
    assert obs == [("canary_http", "canary", "in_window", "E3"), ("canary_http", "positive_control", "in_window", "E3")]
    assert "TOKEN_OBSERVED" in kinds(env, r["run_id"])
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='CANARY_TOKEN_OBSERVED'") == [(1,)]
    end = q(env["admin"], "SELECT detail FROM canary_run_events WHERE kind='WINDOW_ENDED'")[0][0]
    assert end["token_observations"] == 1 and end["result"] is None
    no_verdicts(env)


def test_repeated_and_late_observations(env):
    toks = []
    live(env, "block", on_call=lambda a: toks.append(a["dest"]))
    r = env["svc"].start("default")
    for _ in range(3):
        NO_PROXY.open(toks[0], timeout=2).close()                           # repeated use of the same token
    env["clock"].t += env["obs"].cfg.W + 5
    NO_PROXY.open(toks[0], timeout=2).close()                               # after the window
    finish(env)
    tim = [x[0] for x in q(env["admin"], "SELECT timing FROM observations WHERE run_id=%s AND purpose='canary' ORDER BY observed_at",
                           (r["run_id"],))]
    assert tim == ["in_window"] * 3 + ["late"]
    assert kinds(env, r["run_id"]).count("TOKEN_OBSERVED") == 4
    env["svc"].tick()                                                       # finishing again is a no-op
    assert kinds(env, r["run_id"]).count("WINDOW_ENDED") == 1
    NO_PROXY.open(toks[0], timeout=2).close()                               # long after expiry: still recorded, late
    assert q(env["admin"], "SELECT timing FROM observations WHERE run_id=%s ORDER BY observed_at DESC LIMIT 1",
             (r["run_id"],)) == [("late",)]


def test_forged_and_invalid_observations_are_not_recorded(env):
    s = env["svc"].http
    for path in ("/c/" + oc.mint(), "/c/" + "A" * 32, "/c/short", "/x/" + oc.mint(), "/c/../../etc"):
        with pytest.raises(urllib.error.HTTPError) as e:
            NO_PROXY.open("http://127.0.0.1:%d%s" % (s.port, path), timeout=2)
        assert e.value.code == 404
    assert q(env["admin"], "SELECT count(*) FROM observations") == [(0,)] and s.counters["unmatched"] == 5
    toks = []
    live(env, "block", on_call=lambda a: toks.append(a["dest"]))
    env["svc"].start("default")                                             # http run: its token on the FILE sensor
    tok = toks[0].rsplit("/", 1)[1]
    assert env["svc"].record("canary_file", tok) is False                   # channel mismatch: not recorded


def test_runtime_cannot_insert_non_e3_or_verdict_rows(env):
    env["svc"].start("default")
    rid = q(env["admin"], "SELECT run_id FROM canary_runs")[0][0]
    with psycopg.connect(env["url"], autocommit=True) as c:
        c.execute("SELECT set_config('observer.tenant', 'default', false)")
        for kind in RESULTS:
            with pytest.raises(psycopg.Error):
                c.execute("INSERT INTO canary_run_events (run_id, tenant_id, at, kind) VALUES (%s,'default',now(),%s)", (rid, kind))
        with pytest.raises(psycopg.Error):
            c.execute("INSERT INTO observations (observation_id, run_id, tenant_id, sensor, purpose, evidence_level, timing,"
                      " observed_at, token_sha256) VALUES (gen_random_uuid(), %s, 'default', 'canary_http', 'canary', 'E0',"
                      " 'in_window', now(), repeat('0',64))", (rid,))


def test_positive_control_failure_alerts(env, monkeypatch):
    monkeypatch.setattr(env["svc"], "_positive_control", lambda *a: None)  # control stimulus never happens
    r = env["svc"].start("default")
    finish(env)
    assert "POSITIVE_CONTROL_FAILED" in kinds(env, r["run_id"])
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='POSITIVE_CONTROL_FAILED'") == [(1,)]


def test_positive_control_outside_window_fails(env):
    r = env["svc"].start("default")
    q(env["admin"], "ALTER TABLE observations DISABLE TRIGGER observations_append_only;"
                    " UPDATE observations SET timing='late' WHERE purpose='positive_control';"
                    " ALTER TABLE observations ENABLE TRIGGER observations_append_only")      # test-only manipulation
    finish(env)
    assert "POSITIVE_CONTROL_FAILED" in kinds(env, r["run_id"])


def test_file_channel_observation_and_cleanup(env):
    live(env, "broken")
    r = env["svc"].start("default", "file")
    import time
    time.sleep(0.4)
    finish(env)
    p = [x[0] for x in q(env["admin"], "SELECT purpose FROM observations WHERE run_id=%s ORDER BY purpose", (r["run_id"],))]
    assert p == ["canary", "positive_control"]
    assert not os.path.exists(os.path.join(env["dir"], r["run_id"]))       # resources removed; evidence kept
    assert "CLEANED_UP" in kinds(env, r["run_id"])


def test_file_sensor_ignores_symlinks_and_requires_private_dir(env, tmp_path):
    r = env["svc"].start("default", "file")
    d = os.path.join(env["dir"], r["run_id"])
    tok = oc.mint()
    os.symlink("/etc/hostname", os.path.join(d, tok + ".canary"))
    env["svc"].file.scan()
    assert env["svc"].file.counters["ignored"] >= 1
    bad = tmp_path / "open"; bad.mkdir(); os.chmod(bad, 0o755)
    with pytest.raises(CanaryError):
        FileCanarySensor(lambda *a, **k: True, str(bad))


def test_http_sensor_is_loopback_only():
    for host in ("0.0.0.0", "10.0.0.5", "::"):
        with pytest.raises(CanaryError):
            HttpCanarySensor(lambda *a, **k: True, host=host)


# ---------------- restart ----------------
def test_restart_interrupts_open_runs_and_late_hits_still_recorded(env):
    toks = []
    live(env, "block", on_call=lambda a: toks.append(a["dest"]))
    r = env["svc"].start("default")
    f = env["svc"].start("default", "file")
    svc2 = CanaryService(env["obs"])                                        # "new process"
    svc2.http = HttpCanarySensor(svc2.record)
    svc2.file = env["svc"].file
    try:
        assert set(svc2.recover()) == {r["run_id"], f["run_id"]}
        assert "INTERRUPTED" in kinds(env, r["run_id"]) and not os.path.exists(os.path.join(env["dir"], f["run_id"]))
        env["clock"].t += 60
        assert svc2.tick() == []                                            # interrupted runs are never "finished"
        tok = toks[0].rsplit("/", 1)[1]
        NO_PROXY.open(svc2.http.url(tok), timeout=2).close()
        assert q(env["admin"], "SELECT timing FROM observations WHERE run_id=%s AND purpose='canary'", (r["run_id"],)) == [("late",)]
        assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='CANARY_RUN_INTERRUPTED'") == [(2,)]
    finally:
        svc2.http.close()


# ---------------- tenant isolation ----------------
def test_tenant_isolation(env):
    a = env["svc"].start("default")
    b = env["svc"].start("tenant-b")
    with psycopg.connect(env["url"]) as c:
        assert c.execute("SELECT count(*) FROM canary_runs").fetchone() == (0,)          # no tenant => nothing
        c.execute("SELECT set_config('observer.tenant', 'tenant-b', true)")
        assert [str(x[0]) for x in c.execute("SELECT run_id FROM canary_runs")] == [b["run_id"]]
        assert c.execute("SELECT count(*) FROM canary_run_events WHERE run_id=%s", (a["run_id"],)).fetchone() == (0,)
        with pytest.raises(psycopg.Error):
            c.execute("INSERT INTO canary_run_events (run_id, tenant_id, at, kind) VALUES (%s,'default',now(),'CREATED')",
                      (a["run_id"],))
    assert env["svc"].run_detail("tenant-b", a["run_id"]) is None and env["svc"].run_detail("default", a["run_id"])
    with pytest.raises(CanaryError):
        env["svc"].start("Bad Tenant")


def test_lookup_function_exposes_routing_only(env):
    with psycopg.connect(env["url"]) as c:
        assert c.execute("SELECT * FROM observer_canary_lookup('not-a-hash')").fetchall() == []
        with pytest.raises(psycopg.Error):
            c.execute("SET ROLE observer_lookup")


# ---------------- O002 migration and privileges ----------------
def _only(names):
    d = tempfile.mkdtemp(prefix="obs-mig-")
    for n in names:
        shutil.copy(os.path.join(omigrate.MIGRATIONS, n), d)
    return d


def test_o002_upgrade_preserves_o001_data_and_failed_migration_rolls_back(cluster, monkeypatch):
    from tests.observer_support import decision
    import psycopg as pg
    name = "obs_" + uuid.uuid4().hex[:10]
    with pg.connect(cluster.admin_url, autocommit=True) as c:
        c.execute("CREATE DATABASE %s" % name)
    admin = "postgresql://observer_admin@127.0.0.1:%d/%s" % (cluster.port, name)
    url = "postgresql://observer_runtime@127.0.0.1:%d/%s" % (cluster.port, name)
    real = omigrate.MIGRATIONS
    d1 = _only(["O001_observer_core.sql"])
    monkeypatch.setattr(omigrate, "MIGRATIONS", d1)
    assert omigrate.migrate(admin) == ["O001_observer_core.sql"]
    keys = Keys()
    obs = make_observer(url, keys, Clock())
    obs.ingest(raw(decision(keys, 1)))
    before = q(admin, "SELECT n, hash FROM ledger ORDER BY n")
    # a broken O002 must roll back completely
    d2 = _only(["O001_observer_core.sql"])
    open(os.path.join(d2, "O002_canaries.sql"), "w").write(open(os.path.join(real, "O002_canaries.sql")).read() + "\nSELECT 1/0;\n")
    monkeypatch.setattr(omigrate, "MIGRATIONS", d2)
    with pytest.raises(pg.Error):
        omigrate.migrate(admin)
    assert q(admin, "SELECT name FROM schema_migrations ORDER BY 1") == [("O001_observer_core.sql",)]
    assert q(admin, "SELECT to_regclass('canary_runs')") == [(None,)]
    # recovery: the real O002 then applies, O001 evidence intact, idempotent
    monkeypatch.setattr(omigrate, "MIGRATIONS", real)
    assert omigrate.migrate(admin) == ["O002_canaries.sql"]
    assert omigrate.migrate(admin) == []
    assert q(admin, "SELECT n, hash FROM ledger ORDER BY n") == before
    assert make_observer(url, keys, Clock()).verify_ledger()["valid"]
    for p in (d1, d2):
        shutil.rmtree(p, ignore_errors=True)


def test_o002_runtime_privileges_and_append_only(env):
    env["svc"].start("default")
    with psycopg.connect(env["url"], autocommit=True) as c:
        c.execute("SELECT set_config('observer.tenant', 'default', false)")
        assert runtime_problems(c.cursor()) == []
        for sql in ("UPDATE canary_runs SET expected_condition='BLOCK'", "DELETE FROM canary_runs",
                    "UPDATE canary_run_events SET kind='CREATED'", "DELETE FROM canary_run_events",
                    "UPDATE observations SET timing='late'", "DELETE FROM observations", "TRUNCATE observations"):
            with pytest.raises(psycopg.Error):
                c.execute(sql)
    for sql in ("UPDATE canary_runs SET adapter='x'", "DELETE FROM canary_run_events", "TRUNCATE observations",
                "TRUNCATE canary_runs, canary_run_events, observations"):
        with pytest.raises(psycopg.Error, match="append-only"):
            q(env["admin"], sql)
    q(env["admin"], "GRANT observer_lookup TO observer_runtime")
    with psycopg.connect(env["url"]) as c:
        assert "member of observer_lookup" in runtime_problems(c.cursor())
    q(env["admin"], "REVOKE observer_lookup FROM observer_runtime")


# ---------------- API ----------------
def test_canary_api_requires_operator(env):
    from fastapi.testclient import TestClient
    from observer.app import create_app
    c = TestClient(create_app(env["obs"], "op-token-tests", env["svc"]))
    assert c.post("/v1/canaries/run", json={"tenant": "default"}).status_code == 401
    h = {"Authorization": "Bearer op-token-tests"}
    r = c.post("/v1/canaries/run", json={"tenant": "default", "channel": "http"}, headers=h).json()
    assert r["submission"] == {"submitted": False, "disabled": True}
    d = c.get("/v1/canaries/default/%s" % r["run_id"], headers=h).json()
    assert d["expected_basis"] == "construction" and d["result"] is None
    assert c.get("/v1/canaries/tenant-b/%s" % r["run_id"], headers=h).status_code == 404
    assert c.post("/v1/canaries/run", json={"tenant": "default", "channel": "dns"}, headers=h).status_code == 400
    s = c.get("/v1/status", headers=h).json()
    assert s["canaries"]["p2_live"] is False


def test_startup_wiring_defaults_are_safe(env, tmp_path):
    from observer import main
    base = {"OBSERVER_CANARIES": "1", "OBSERVER_CANARY_HTTP_PORT": "0"}
    assert main.build_canaries(env["obs"], {}) is None                     # canaries off unless asked for
    svc = main.build_canaries(env["obs"], dict(base, OBSERVER_CANARY_P2_LIVE="1"))   # live without a backend URL
    try:
        assert svc.p2.live is False and svc.http.host == "127.0.0.1"
    finally:
        svc.http.close()
    with pytest.raises(CanaryError):
        main.build_canaries(env["obs"], dict(base, OBSERVER_CANARY_HTTP_HOST="0.0.0.0"))
