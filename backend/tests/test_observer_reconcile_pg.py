"""C4 on REAL PostgreSQL: canary reconciliation end to end, versioned supersession, O003 constraints / RLS / append-only
/ upgrade, the tenant-scoped read API, and the C3-3 / C3-4 fixes."""
import hashlib
import json
import os
import shutil
import threading
import urllib.request
import uuid

import psycopg
import pytest

from observer import canary as oc, migrate as omigrate
from tests.observer_support import HAVE_PG, Clock, Keys, envelope, heartbeat, make_observer, raw
from tests.test_observer_canary_pg import (NO_PROXY, cluster, env, finish, kinds, live, q)  # noqa: F401

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


def claim(e, corr, verdict="BLOCK", tenant="default", seq=1, body_extra=None, geid=None):
    k = e["keys"]
    body = {"gate_evaluation_id": geid or str(uuid.uuid4()), "correlation_id": corr, "verdict": verdict, "rule_ids": [],
            **(body_extra or {})}
    return e["obs"].ingest(raw(envelope(k.gate, k.gate_pid, "decision", body, tenant=tenant, seq=seq, issued=e["clock"].t)))


def recon(e, run_id):
    return q(e["admin"], "SELECT version, result, reasons, evidence_level FROM reconciliations WHERE run_id=%s ORDER BY version",
             (run_id,))


def closing_heartbeat(e, hb_seq, alloc):
    k = e["keys"]
    return e["obs"].ingest(raw(heartbeat(k, hb_seq, {"default": {"allocated_through_seq": alloc}}, issued=e["clock"].t)))


# ---------------- end-to-end results ----------------
def test_bypass_detected_requires_e3_observation_and_signed_block(env):
    live(env, "broken")                                                     # non-enforcing integration (fixture)
    r = env["svc"].start("default")
    claim(env, r["correlation_id"], "BLOCK")
    finish(env)
    assert recon(env, r["run_id"]) == [(1, "BYPASS_DETECTED", [], "E3")]
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='BYPASS_DETECTED' AND kind='alert'") == [(1,)]


def test_honest_block_is_never_verified(env):
    live(env, "block")
    r = env["svc"].start("default")
    claim(env, r["correlation_id"], "BLOCK")
    finish(env)
    closing_heartbeat(env, 1, 1)
    env["clock"].t += 1
    env["svc"].tick()
    v, res, reasons, el = recon(env, r["run_id"])[-1]                       # latest version (feed completed later)
    assert res == "INCONCLUSIVE" and reasons == ["COVERAGE_UNATTESTED"] and el == "none"


def test_unauthorized_needs_closing_heartbeat_then_supersedes(env):
    live(env, "broken")
    r = env["svc"].start("default")
    finish(env)                                                             # no decision claim at all
    assert recon(env, r["run_id"]) == [(1, "INCONCLUSIVE", ["DECISION_FEED_INCOMPLETE"], "none")]
    closing_heartbeat(env, 1, 0)                                            # heartbeat after the due time
    env["clock"].t += 1
    env["svc"].tick()
    assert recon(env, r["run_id"])[-1] == (2, "UNAUTHORIZED_EXECUTION", [], "E3")
    sup = q(env["admin"], "SELECT supersedes IS NOT NULL FROM reconciliations WHERE run_id=%s AND version=2", (r["run_id"],))
    assert sup == [(True,)]
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='RESULT_ESCALATED'") == [(1,)]
    env["svc"].tick()
    assert len(recon(env, r["run_id"])) == 2                                # unchanged facts => no new version


def test_heartbeat_claiming_unseen_allocation_blocks_unauthorized(env):
    live(env, "broken")
    r = env["svc"].start("default")
    finish(env)
    closing_heartbeat(env, 1, 5)                                            # claims 5 allocated, none received
    env["clock"].t += 1
    env["svc"].tick()
    assert recon(env, r["run_id"])[-1][1:3] == ("INCONCLUSIVE", ["DECISION_FEED_INCOMPLETE"])


@pytest.mark.parametrize("case", ["disabled", "allow_claim", "reversed", "quarantined", "epoch", "interrupted", "no_pc"])
def test_every_missing_precondition_is_inconclusive(env, monkeypatch, case):
    if case != "disabled":
        live(env, "broken")
    if case == "no_pc":
        monkeypatch.setattr(env["svc"], "_positive_control", lambda *a: None)
    r = env["svc"].start("default")
    geid = str(uuid.uuid4())
    if case == "allow_claim":
        claim(env, r["correlation_id"], "ALLOW")
    elif case == "reversed":
        claim(env, r["correlation_id"], "ALLOW", geid=geid)
        claim(env, r["correlation_id"], "BLOCK", seq=2, geid=geid, body_extra={"reversed_from": "ALLOW"})
    else:
        claim(env, r["correlation_id"], "BLOCK")
    if case == "quarantined":
        claim(env, "other", "BLOCK", seq=1)                                 # seq reuse => stream quarantined
    if case == "epoch":
        k = env["keys"]
        ec = {"new_epoch": 2, "last_trusted_seq_per_tenant": {"default": 1}, "reason": "restored backup INC-12 audit"}
        env["obs"].ingest(raw(envelope(k.recovery, k.gate_pid, "epoch_change", ec, tenant=None, epoch=2, issued=env["clock"].t)))
    if case == "interrupted":
        env["svc"].recover()
        env["clock"].t += 20
        env["svc"].tick()
    else:
        finish(env)
    (v, res, reasons, el), = recon(env, r["run_id"])
    expected = {"disabled": "SUBMISSION_DISABLED", "allow_claim": "CLAIM_NOT_BLOCK", "reversed": "DECISION_REVERSED",
                "quarantined": "CLAIM_STREAM_QUARANTINED", "epoch": "EPOCH_BOUNDARY", "interrupted": "RUN_INTERRUPTED",
                "no_pc": "POSITIVE_CONTROL_NOT_PASSED"}[case]
    assert res == "INCONCLUSIVE" and expected in reasons, reasons


def test_backend_reported_heads_never_change_a_result(env):
    live(env, "block")
    r = env["svc"].start("default")
    claim(env, r["correlation_id"], "BLOCK")
    finish(env)
    before = recon(env, r["run_id"])
    q(env["admin"], "INSERT INTO producer_claims (tenant_id, producer_id, epoch, hb_seq, allocated_through_seq, proof_n,"
                    " proof_head, received_at) VALUES ('default', %s, 1, 99, 99, 99, repeat('f',64), now())", (env["keys"].gate_pid,))
    env["svc"].tick()
    assert recon(env, r["run_id"]) == before


# ---------------- O003 schema guarantees ----------------
def _row(e, run_id, **kw):
    v = dict(recon_id=str(uuid.uuid4()), version=9, supersedes=None, result="INCONCLUSIVE", reasons=["X"], el="none")
    v.update(kw)
    return ("INSERT INTO reconciliations (recon_id, run_id, tenant_id, version, supersedes, result, reasons, evidence_level,"
            " facts, decided_at, ledger_n, ledger_hash) VALUES (%s,%s,'default',%s,%s,%s,%s,%s,'{}',now(),1,repeat('0',64))",
            (v["recon_id"], run_id, v["version"], v["supersedes"], v["result"], v["reasons"], v["el"]))


def test_o003_constraints_rls_and_append_only(env):
    live(env, "broken")
    r = env["svc"].start("default")
    claim(env, r["correlation_id"], "BLOCK")
    finish(env)
    with psycopg.connect(env["url"], autocommit=True) as c:
        c.execute("SELECT set_config('observer.tenant', 'default', false)")
        for kw in ({"result": "ENFORCEMENT_VERIFIED", "reasons": [], "el": "E3", "version": 1},   # refused by schema
                   {"result": "BYPASS_DETECTED", "reasons": [], "el": "none", "version": 1},       # definite needs E3
                   {"result": "BYPASS_DETECTED", "reasons": ["X"], "el": "E3", "version": 1},      # definite has no reasons
                   {"result": "INCONCLUSIVE", "reasons": [], "version": 1},                        # inconclusive needs reasons
                   {"version": 2}):                                                                 # v2 must supersede
            sql, p = _row(env, r["run_id"], **kw)
            with pytest.raises(psycopg.Error):
                c.execute(sql, p)
        for sql in ("UPDATE reconciliations SET result='INCONCLUSIVE'", "DELETE FROM reconciliations", "TRUNCATE reconciliations"):
            with pytest.raises(psycopg.Error):
                c.execute(sql)
        c.execute("SELECT set_config('observer.tenant', 'tenant-b', false)")
        assert c.execute("SELECT count(*) FROM reconciliations").fetchone() == (0,)
    with pytest.raises(psycopg.Error, match="append-only"):
        q(env["admin"], "UPDATE reconciliations SET reasons='{}'")


def test_o003_upgrade_preserves_existing_data(cluster, monkeypatch):
    import tempfile
    name = "obs_" + uuid.uuid4().hex[:10]
    q(cluster.admin_url, "CREATE DATABASE %s" % name)
    admin = "postgresql://observer_admin@127.0.0.1:%d/%s" % (cluster.port, name)
    url = "postgresql://observer_runtime@127.0.0.1:%d/%s" % (cluster.port, name)
    real = omigrate.MIGRATIONS
    d = tempfile.mkdtemp()
    for n in ("O001_observer_core.sql", "O002_canaries.sql"):
        shutil.copy(os.path.join(real, n), d)
    monkeypatch.setattr(omigrate, "MIGRATIONS", d)
    omigrate.migrate(admin)
    keys = Keys()
    obs = make_observer(url, keys, Clock())
    svc = oc.CanaryService(obs)
    svc.http = oc.HttpCanarySensor(svc.record)
    try:
        run = svc.start("default")
        before = q(admin, "SELECT n, hash FROM ledger ORDER BY n")
        monkeypatch.setattr(omigrate, "MIGRATIONS", real)
        applied = omigrate.migrate(admin)
        assert applied[0] == "O003_reconciliations.sql" and all(m > "O003" for m in applied[1:])
        assert omigrate.migrate(admin) == []
        assert q(admin, "SELECT n, hash FROM ledger ORDER BY n") == before
        assert q(admin, "SELECT count(*) FROM canary_runs WHERE run_id=%s", (run["run_id"],)) == [(1,)]
        assert make_observer(url, keys, Clock()).verify_ledger()["valid"]
    finally:
        svc.http.close()
        shutil.rmtree(d, ignore_errors=True)


# ---------------- read API ----------------
def test_read_api_tenant_scoped_tokens(env):
    from fastapi.testclient import TestClient
    from observer.app import create_app
    live(env, "broken")
    a = env["svc"].start("default")
    claim(env, a["correlation_id"], "BLOCK")
    env["svc"].start("tenant-b")
    finish(env)
    rt = "read-token-tenant-b-for-tests"
    c = TestClient(create_app(env["obs"], "op-token", env["svc"],
                              [{"sha256": hashlib.sha256(rt.encode()).hexdigest(), "tenants": ["tenant-b"]}]))
    op = {"Authorization": "Bearer op-token"}
    j = c.get("/v1/reconciliations?tenant=default", headers=op).json()
    assert [x["result"] for x in j["reconciliations"]] == ["BYPASS_DETECTED"] and j["verified_possible"] is False
    rd = {"Authorization": "Bearer " + rt}
    assert c.get("/v1/reconciliations?tenant=default", headers=rd).status_code == 403
    jb = c.get("/v1/reconciliations?tenant=tenant-b", headers=rd).json()
    assert len(jb["reconciliations"]) == 1 and jb["reconciliations"][0]["result"] == "INCONCLUSIVE"
    assert c.get("/v1/reconciliations?tenant=default").status_code == 401
    assert c.get("/v1/reconciliations?tenant=default", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert c.get("/v1/reconciliations?tenant=BAD!", headers=op).status_code == 400
    assert c.post("/v1/canaries/run", json={"tenant": "tenant-b"}, headers=rd).status_code == 401   # read-only key
    assert c.get("/v1/status", headers=rd).status_code == 401
    assert c.get("/v1/reconciliations?tenant=default&since=2999-01-01T00:00:00%2B00:00", headers=op).json()["reconciliations"] == []


# ---------------- C3-3 / C3-4 ----------------
def test_c3_3_observation_cap_and_alert_throttle(env):
    toks = []
    live(env, "block", on_call=lambda a: toks.append(a["dest"]))
    r = env["svc"].start("default")
    for _ in range(oc.MAX_OBSERVATIONS_PER_RUN + 20):
        NO_PROXY.open(toks[0], timeout=2).close()
    stored = q(env["admin"], "SELECT count(*) FROM observations WHERE run_id=%s", (r["run_id"],))[0][0]
    assert stored == oc.MAX_OBSERVATIONS_PER_RUN and env["svc"].suppressed >= 20
    assert q(env["admin"], "SELECT count(*) FROM ledger WHERE code='CANARY_TOKEN_OBSERVED'") == [(1,)]
    env["clock"].t += oc.ALERT_EVERY_SECONDS + 1
    env["svc"].record("canary_http", toks[0].rsplit("/", 1)[1])            # capped: still counted, no new row


def test_c3_4_concurrent_scans_record_once_and_cleanup_prunes(env):
    svc = env["svc"]
    r = svc.start("default", "file")
    tok = oc.mint()
    q(env["admin"], "SELECT 1")
    path = svc.file.path(r["run_id"], tok)
    open(path, "w").write("x")                                              # unknown token: ignored, but tracked
    ts = [threading.Thread(target=svc.file.scan) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    pc = q(env["admin"], "SELECT count(*) FROM observations WHERE run_id=%s AND purpose='positive_control'", (r["run_id"],))
    assert pc == [(1,)]                                                     # never duplicated by concurrent scans
    svc.file.cleanup(r["run_id"])
    assert not [k for k in svc.file._seen if r["run_id"] in k]
