"""Phase C1 on REAL PostgreSQL (observer-db): signed ingest, idempotency, conflicts, gap-free watermarks, heartbeats,
epochs and quarantine, tenant isolation (RLS), append-only evidence, ledger chain + signatures, concurrency, API.
Design §5, §9, §12, §13, §14."""
import json
import threading
import uuid

import pytest

from observer import ledger as oledger
from observer.app import create_app
from observer.canonical import canonical
from observer.db import Database, runtime_problems
from observer.feed import Config
from observer.ingest import Observer
from tests.observer_support import (HAVE_PG, T0, Clock, Keys, ObserverCluster, decision, envelope, heartbeat, iso,
                                    make_observer, raw)

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = ObserverCluster()
    yield c
    c.destroy()


@pytest.fixture
def db(cluster):
    return cluster.new_db()


@pytest.fixture
def keys():
    return Keys()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def obs(db, keys, clock):
    return make_observer(db[0], keys, clock)


def q(admin, sql, params=()):
    import psycopg
    with psycopg.connect(admin, autocommit=True) as c:
        cur = c.execute(sql, params)
        return cur.fetchall() if cur.description else None


def wm(admin, keys, tenant="default", epoch=1):
    r = q(admin, "SELECT contiguous_seq, max_seq, attested_seq FROM watermarks WHERE producer_id=%s AND epoch=%s AND tenant_id=%s",
          (keys.gate_pid, epoch, tenant))
    return r[0] if r else None


def codes(admin):
    return [r[0] for r in q(admin, "SELECT code FROM ledger ORDER BY n")]


def hbt(alloc, tenant="default", **kw):
    return {tenant: {"allocated_through_seq": alloc, **kw}}


# ---------------- normal ingestion ----------------
def test_normal_event_ingestion_and_ledger(obs, db, keys):
    st, body = obs.ingest(raw(decision(keys, 1)))
    assert (st, body["status"], body["contiguous_seq"]) == (200, "accepted", 1)
    r = q(db[1], "SELECT type, seq, evidence_level, tenant_id FROM events")
    assert r == [("decision", 1, "E0", "default")]
    assert codes(db[1]) == ["MANIFEST_INSTALLED", "ACCEPTED"]
    assert obs.verify_ledger()["valid"]


def test_runtime_account_is_least_privilege(db):
    d = Database(db[0])
    assert d.run(runtime_problems, lock=False) == []
    import psycopg
    for sql in ("UPDATE ledger SET code='X'", "DELETE FROM events", "TRUNCATE ledger", "DELETE FROM watermarks",
                "UPDATE events SET seq=99", "CREATE TABLE x (a int)", "UPDATE producers SET producer_id='x'"):
        with psycopg.connect(db[0], autocommit=True) as c, pytest.raises(psycopg.Error):
            c.execute(sql)


def test_evidence_is_append_only_even_for_owner(obs, db, keys):
    obs.ingest(raw(decision(keys, 1)))
    import psycopg
    for sql in ("UPDATE ledger SET code='X'", "DELETE FROM ledger", "TRUNCATE events",
                "UPDATE events SET seq=7", "DELETE FROM key_manifests"):
        with psycopg.connect(db[1], autocommit=True) as c, pytest.raises(psycopg.Error, match="append-only"):
            c.execute(sql)


# ---------------- authentication / authorization ----------------
def test_invalid_signature_refused(obs, db, keys):
    env = decision(keys, 1)
    env["body"]["verdict"] = "ALLOW"                                  # changed after signing
    assert obs.ingest(raw(env)) == (401, {"error": "SIGNATURE_INVALID"})
    other = envelope(keys.other, keys.gate_pid, "decision", {"v": 1}, seq=1, key_id=keys.kid(keys.gate))
    assert obs.ingest(raw(other)) == (401, {"error": "SIGNATURE_INVALID"})
    assert q(db[1], "SELECT count(*) FROM events") == [(0,)]


def test_invalid_producer_identity_refused(obs, db, keys):
    env = envelope(keys.gate, "gate:" + str(uuid.uuid4()), "decision", {}, seq=1)     # unknown producer
    assert obs.ingest(raw(env)) == (403, {"error": "UNKNOWN_PRODUCER"})
    env = envelope(keys.gate, keys.adapter_pid, "decision", {}, seq=1)              # GATE key claims adapter identity
    assert obs.ingest(raw(env))[1]["error"] == "SIGNATURE_INVALID"
    env = envelope(keys.adapter, keys.gate_pid, "decision", {}, seq=1)              # adapter key claims gate identity
    assert obs.ingest(raw(env))[1]["error"] == "SIGNATURE_INVALID"


def test_scope_denied(obs, keys):
    assert obs.ingest(raw(envelope(keys.gate, keys.gate_pid, "adapter_report", {"integration": "x", "correlation_id": "c",
                                                                               "claims": {}})))[1]["error"] == "SCOPE_DENIED"
    assert obs.ingest(raw(envelope(keys.gate, keys.gate_pid, "observation", {"host": "x"})))[1]["error"] == "SCOPE_DENIED"
    assert obs.ingest(raw(envelope(keys.adapter, keys.adapter_pid, "decision", {}, seq=1)))[1]["error"] == "SCOPE_DENIED"


def test_revoked_or_expired_producer_key_refused(db, keys, clock):
    obs = make_observer(db[0], keys, clock, keys.manifest(gate_extra={"revoked_at": iso(T0 - 1)}))
    assert obs.ingest(raw(decision(keys, 1)))[1]["error"] == "SIGNATURE_INVALID"


def test_tenant_not_allowed_for_producer(db, keys, clock):
    obs = make_observer(db[0], keys, clock, keys.manifest(tenants=("default",)))
    assert obs.ingest(raw(decision(keys, 1, tenant="tenant-b")))[1]["error"] == "TENANT_MISMATCH"
    assert obs.ingest(raw(heartbeat(keys, 1, hbt(0, "tenant-b"))))[1]["error"] == "TENANT_MISMATCH"


def test_clock_skew(obs, keys):
    assert obs.ingest(raw(decision(keys, 1, issued=T0 + 500)))[1]["error"] == "CLOCK_SKEW"       # future-dated event
    assert obs.ingest(raw(decision(keys, 1, issued=T0 - 86400)))[0] == 200                       # outbox backlog: OK
    assert obs.ingest(raw(heartbeat(keys, 1, hbt(1), issued=T0 - 500)))[1]["error"] == "CLOCK_SKEW"
    assert obs.ingest(raw(heartbeat(keys, 1, hbt(1), issued=T0 + 500)))[1]["error"] == "CLOCK_SKEW"


def test_oversize_and_malformed_and_refusals_throttled(obs, db, keys):
    assert obs.ingest(b"x" * (70 * 1024))[0] == 413
    for _ in range(20):
        assert obs.ingest(b"{not json")[1]["error"] == "MALFORMED"
    assert codes(db[1]).count("MALFORMED") == 1                        # ledger is not a flood target
    assert obs.counters["MALFORMED"] == 20


# ---------------- duplicates and conflicts ----------------
def test_duplicate_delivery_is_idempotent(obs, db, keys):
    env = decision(keys, 1)
    assert obs.ingest(raw(env))[1]["status"] == "accepted"
    for _ in range(3):
        assert obs.ingest(raw(env)) == (200, {"status": "duplicate"})
    assert q(db[1], "SELECT count(*) FROM events") == [(1,)]
    assert codes(db[1]).count("ACCEPTED") == 1


def test_conflicting_duplicate_payload(obs, db, keys):
    env = decision(keys, 1)
    obs.ingest(raw(env))
    bad = decision(keys, 1, event_id=env["event_id"], body={"verdict": "ALLOW"})
    assert obs.ingest(raw(bad)) == (409, {"error": "EVENT_CONFLICT"})
    assert "EVENT_CONFLICT" in codes(db[1])
    assert q(db[1], "SELECT envelope->'body'->>'verdict' FROM events") == [("BLOCK",)]       # original kept


def test_event_id_reused_across_tenants_is_conflict(obs, db, keys):
    env = decision(keys, 1)
    obs.ingest(raw(env))
    other = decision(keys, 1, tenant="tenant-b", event_id=env["event_id"])
    assert obs.ingest(raw(other)) == (409, {"error": "EVENT_CONFLICT"})


# ---------------- sequence semantics ----------------
def test_missing_sequence_number_holds_watermark_and_alerts(db, keys, clock):
    obs = make_observer(db[0], keys, clock)
    for s in (1, 2, 4, 5):
        assert obs.ingest(raw(decision(keys, s)))[0] == 200
    assert wm(db[1], keys)[:2] == (2, 5)                              # events beyond the hole are held
    clock.t += obs.cfg.G + 1
    assert "DECISION_FEED_GAP:default" in obs.tick()
    assert "DECISION_FEED_GAP:default" not in obs.tick()                                   # alerted once
    assert obs.ingest(raw(decision(keys, 3)))[1]["contiguous_seq"] == 5                    # hole filled
    assert q(db[1], "SELECT gap_since, gap_alerted FROM watermarks") == [(None, False)]


def test_out_of_order_events(obs, db, keys):
    for s in (3, 1, 5, 2, 4):
        obs.ingest(raw(decision(keys, s)))
    assert wm(db[1], keys)[:2] == (5, 5)


def test_seq_reuse_with_different_content_quarantines(obs, db, keys):
    obs.ingest(raw(decision(keys, 1)))
    obs.ingest(raw(decision(keys, 2)))
    assert obs.ingest(raw(decision(keys, 2))) == (409, {"error": "PRODUCER_REGRESSION"})     # new event_id, same seq
    assert q(db[1], "SELECT status, reason FROM streams") == [("quarantined", "SEQ_REUSED_WITH_DIFFERENT_CONTENT")]
    assert obs.ingest(raw(decision(keys, 3))) == (409, {"error": "STREAM_QUARANTINED"})
    hb = heartbeat(keys, 1, hbt(3))
    assert obs.ingest(raw(hb)) == (409, {"error": "STREAM_QUARANTINED"})
    st = obs.status()["streams"][0]
    assert st["status"] == "quarantined" and "PRODUCER_REGRESSION" in st["conditions"]


def test_tenant_streams_are_independent(obs, db, keys):
    obs.ingest(raw(decision(keys, 2, tenant="default")))
    obs.ingest(raw(decision(keys, 1, tenant="tenant-b")))
    assert wm(db[1], keys, "default")[0] == 0 and wm(db[1], keys, "tenant-b")[0] == 1


# ---------------- heartbeats ----------------
def test_heartbeat_does_not_consume_seq_and_attests(obs, db, keys, clock):
    obs.ingest(raw(decision(keys, 1)))
    assert obs.ingest(raw(heartbeat(keys, 1, hbt(1, proof_n=5, proof_head="a" * 64)))) == (200, {"status": "accepted"})
    assert wm(db[1], keys) == (1, 1, 1)
    assert obs.ingest(raw(decision(keys, 2)))[1]["contiguous_seq"] == 2                       # next event is seq 2
    claim = q(db[1], "SELECT label, evidence_level, proof_n, proof_head FROM producer_claims")
    assert claim == [("backend_reported_head", "E0", 5, "a" * 64)]


def test_heartbeat_before_events_tail_detection(db, keys, clock):
    obs = make_observer(db[0], keys, clock)
    obs.ingest(raw(heartbeat(keys, 1, hbt(3))))                       # claims 3 allocated, none delivered yet
    assert wm(db[1], keys) == (0, 0, 3)
    clock.t += 5
    for s in (1, 2, 3):
        obs.ingest(raw(decision(keys, s, issued=clock.t)))
    assert q(db[1], "SELECT behind_since FROM watermarks") == [(None,)]                     # caught up within G
    obs.ingest(raw(heartbeat(keys, 2, hbt(6), issued=clock.t)))       # tail: events 4-6 withheld
    clock.t += obs.cfg.G + 1
    obs.ingest(raw(heartbeat(keys, 3, hbt(6), issued=clock.t)))       # heartbeats keep coming
    assert "DECISION_FEED_GAP_TAIL:default" in obs.tick()
    st = obs.status()["streams"][0]
    assert "DECISION_FEED_GAP_TAIL:default" in st["conditions"]


def test_old_heartbeat_never_lowers_watermark(obs, db, keys):
    obs.ingest(raw(heartbeat(keys, 5, hbt(10))))
    assert obs.ingest(raw(heartbeat(keys, 3, hbt(2)))) == (200, {"status": "out_of_order"})
    assert wm(db[1], keys)[2] == 10
    assert "HEARTBEAT_OUT_OF_ORDER" in codes(db[1])
    assert q(db[1], "SELECT hb_seq, status FROM heartbeats ORDER BY hb_seq") == [(3, "out_of_order"), (5, "accepted")]
    assert q(db[1], "SELECT last_hb_seq FROM streams") == [(5,)]


def test_heartbeat_replay_and_conflict(obs, keys):
    hb = heartbeat(keys, 1, hbt(0))
    obs.ingest(raw(hb))
    assert obs.ingest(raw(hb)) == (200, {"status": "duplicate"})
    assert obs.ingest(raw(heartbeat(keys, 1, hbt(7)))) == (409, {"error": "EVENT_CONFLICT"})


def test_heartbeat_counter_or_proof_regression_quarantines(obs, db, keys):
    obs.ingest(raw(heartbeat(keys, 1, hbt(5, proof_n=9, proof_head="b" * 64))))
    assert obs.ingest(raw(heartbeat(keys, 2, hbt(5, proof_n=9, proof_head="c" * 64)))) == (409, {"error": "PRODUCER_REGRESSION"})
    assert q(db[1], "SELECT status FROM streams") == [("quarantined",)]


def test_allocation_counter_regression_quarantines(obs, db, keys):
    obs.ingest(raw(heartbeat(keys, 1, hbt(8))))
    assert obs.ingest(raw(heartbeat(keys, 2, hbt(3)))) == (409, {"error": "PRODUCER_REGRESSION"})


def test_silent_producer(db, keys, clock):
    obs = make_observer(db[0], keys, clock)
    obs.ingest(raw(heartbeat(keys, 1, hbt(0))))
    assert obs.tick() == []
    clock.t += 3 * obs.cfg.H + 1
    assert any(x.startswith("PRODUCER_SILENT") for x in obs.tick())
    assert obs.tick() == []                                            # once per silence
    obs.ingest(raw(heartbeat(keys, 2, hbt(0), issued=clock.t)))        # resumes => re-armed
    clock.t += 3 * obs.cfg.H + 1
    assert any(x.startswith("PRODUCER_SILENT") for x in obs.tick())


# ---------------- epochs / restore (§5.4) ----------------
def epoch_change(keys, new_epoch, key=None, last=None, **kw):
    body = {"new_epoch": new_epoch, "last_trusted_seq_per_tenant": last or {"default": 1},
            "reason": "restored backup after disk failure (INC-1)"}
    k = key or keys.recovery
    return envelope(k, keys.gate_pid, "epoch_change", body, tenant=None, epoch=new_epoch, **kw)


def test_restore_quarantine_then_operator_epoch_change(obs, db, keys):
    obs.ingest(raw(decision(keys, 1)))
    obs.ingest(raw(decision(keys, 2)))
    assert obs.ingest(raw(decision(keys, 2)))[1]["error"] == "PRODUCER_REGRESSION"   # restored DB reuses seq 2
    assert obs.ingest(raw(decision(keys, 1, epoch=2)))[1]["error"] == "UNKNOWN_EPOCH"
    assert obs.ingest(raw(epoch_change(keys, 2))) == (200, {"status": "accepted", "epoch": 2})
    assert obs.ingest(raw(decision(keys, 1, epoch=2)))[1] == {"status": "accepted", "contiguous_seq": 1}
    assert obs.ingest(raw(decision(keys, 3, epoch=1)))[1]["error"] == "EPOCH_CLOSED"
    assert q(db[1], "SELECT epoch, status FROM streams ORDER BY epoch") == [(1, "quarantined"), (2, "active")]
    assert "EPOCH_CHANGED" in codes(db[1])


def test_gate_signed_epoch_change_refused(obs, db, keys):
    assert obs.ingest(raw(epoch_change(keys, 2, key=keys.gate)))[1]["error"] == "SCOPE_DENIED"
    assert obs.ingest(raw(epoch_change(keys, 2, key=keys.adapter)))[1]["error"] == "SIGNATURE_INVALID"
    assert q(db[1], "SELECT current_epoch FROM producers") in ([], [(1,)])


def test_epoch_change_must_be_next_and_is_idempotent(obs, keys):
    assert obs.ingest(raw(epoch_change(keys, 3)))[1]["error"] == "EPOCH_INVALID"
    ec = epoch_change(keys, 2)
    assert obs.ingest(raw(ec))[0] == 200
    assert obs.ingest(raw(ec)) == (200, {"status": "duplicate"})
    assert obs.ingest(raw(epoch_change(keys, 2)))[1]["error"] == "EPOCH_INVALID"     # replay with new event id
    bad = epoch_change(keys, 3)
    bad["body"]["reason"] = "short"
    from observer.canonical import canonical as c
    from observer import crypto
    bad["sig"] = crypto.sign(keys.recovery, c({k: v for k, v in bad.items() if k != "sig"}))
    assert obs.ingest(raw(bad))[1]["error"] == "MALFORMED"


def test_recovery_key_cannot_sign_decisions(obs, keys):
    env = envelope(keys.recovery, keys.gate_pid, "decision", {}, seq=1)
    assert obs.ingest(raw(env))[1]["error"] == "SIGNATURE_INVALID"      # recovery keys are only for epoch_change


# ---------------- adapter reports (E1) ----------------
def test_adapter_report_is_e1_and_has_no_stream(obs, db, keys):
    env = envelope(keys.adapter, keys.adapter_pid, "adapter_report",
                   {"integration": "mcp_proxy", "correlation_id": "c1", "execution_id": None, "claims": {"forwarded": True}})
    assert obs.ingest(raw(env)) == (200, {"status": "accepted", "evidence_level": "E1"})
    assert obs.ingest(raw(env)) == (200, {"status": "duplicate"})
    assert q(db[1], "SELECT type, evidence_level, seq FROM events") == [("adapter_report", "E1", None)]
    assert q(db[1], "SELECT count(*) FROM watermarks") == [(0,)]
    assert obs.ingest(raw(envelope(keys.adapter, keys.adapter_pid, "adapter_report", {"x": 1}, tenant="tenant-x")))[1][
        "error"] == "TENANT_MISMATCH"


# ---------------- tenant isolation (RLS) ----------------
def test_tenant_isolation_rls(obs, db, keys):
    obs.ingest(raw(decision(keys, 1, tenant="default")))
    obs.ingest(raw(decision(keys, 1, tenant="tenant-b")))
    obs.ingest(raw(heartbeat(keys, 1, {"default": {"allocated_through_seq": 1, "proof_n": 1, "proof_head": "d" * 64},
                                       "tenant-b": {"allocated_through_seq": 1, "proof_n": 1, "proof_head": "e" * 64}})))
    import psycopg
    with psycopg.connect(db[0]) as c:
        assert c.execute("SELECT count(*) FROM events").fetchone() == (0,)             # no tenant => no rows
        c.execute("SELECT set_config('observer.tenant', 'tenant-b', true)")
        assert c.execute("SELECT tenant_id FROM events").fetchall() == [("tenant-b",)]
        assert c.execute("SELECT proof_head FROM producer_claims").fetchall() == [("e" * 64,)]
        with pytest.raises(psycopg.Error):
            c.execute("INSERT INTO producer_claims (tenant_id, producer_id, epoch, hb_seq, allocated_through_seq, received_at)"
                      " VALUES ('default','x',1,1,1,now())")


def test_producer_claims_never_count_as_evidence(obs, db):
    """Backend-reported heads are labelled claims by constraint; nothing can store them as anything else."""
    import psycopg
    with psycopg.connect(db[1], autocommit=True) as c:
        for col, val in (("label", "observer_verified"), ("evidence_level", "E3")):
            with pytest.raises(psycopg.Error):
                c.execute("INSERT INTO producer_claims (tenant_id, producer_id, epoch, hb_seq, allocated_through_seq, received_at, %s)"
                          " VALUES ('default','x',1,1,1,now(),%%s)" % col, (val,))
        with pytest.raises(psycopg.Error):
            c.execute("INSERT INTO events (event_id, producer_id, epoch, tenant_id, seq, type, evidence_level, key_id, issued_at,"
                      " received_at, digest, envelope) VALUES (gen_random_uuid(),'x',1,'default',1,'decision','E3','k',now(),"
                      " now(), repeat('0',64), '{}')")


# ---------------- ledger integrity, keys, manifest ----------------
def test_ledger_tamper_detected_on_verify(obs, db, keys):
    for s in (1, 2, 3):
        obs.ingest(raw(decision(keys, s)))
    assert obs.verify_ledger()["valid"]
    q(db[1], "ALTER TABLE ledger DISABLE TRIGGER ledger_append_only; UPDATE ledger SET code='FORGED' WHERE n=2;"
             " ALTER TABLE ledger ENABLE TRIGGER ledger_append_only")
    v = obs.verify_ledger()
    assert not v["valid"] and v["n"] == 2 and v["reason"] == "HASH_MISMATCH"
    assert obs.ingest(raw(decision(keys, 4))) == (503, {"error": "LEDGER_INVALID"})        # degraded: refuse


def test_observer_refuses_to_sign_with_unlisted_or_revoked_key(db, keys, clock):
    m = keys.manifest(observer_extra={"revoked_at": iso(T0 + 10)})
    obs = make_observer(db[0], keys, clock, m)
    assert obs.ingest(raw(decision(keys, 1)))[0] == 200
    clock.t += 11
    assert obs.ingest(raw(decision(keys, 2, issued=clock.t))) == (503, {"error": "OBSERVER_KEY_INVALID"})
    assert q(db[1], "SELECT count(*) FROM events") == [(1,)]                                # nothing stored unsigned


def test_manifest_rollback_refused(db, keys, clock):
    make_observer(db[0], keys, clock, keys.manifest(version=2))
    from observer.envelope import Refused
    with pytest.raises(Refused, match="MANIFEST_ROLLBACK"):
        make_observer(db[0], keys, clock, keys.manifest(version=1))
    with pytest.raises(Refused, match="MANIFEST_VERSION_REUSED"):
        make_observer(db[0], keys, clock, keys.manifest(version=2, tenants=("default",)))


# ---------------- concurrency ----------------
def test_concurrent_ingest_keeps_ledger_linear_and_watermark_exact(db, keys, clock):
    obs = make_observer(db[0], keys, clock)
    obs.db = Database(db[0], size=8)
    envs = [decision(keys, s) for s in range(1, 61)]
    results = []

    def worker(chunk):
        for e in chunk:
            results.append(obs.ingest(raw(e))[0])
            results.append(obs.ingest(raw(e))[0])                     # concurrent duplicates too
    ts = [threading.Thread(target=worker, args=(envs[i::6],)) for i in range(6)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count(200) == 120
    assert wm(db[1], keys)[:2] == (60, 60)
    assert obs.verify_ledger() == {"valid": True, "records": 61, "head": obs.status()["ledger"]["head"]}


# ---------------- failure: observer DB unavailable ----------------
def test_observer_db_unavailable_refuses_with_503(keys, clock):
    obs = Observer(Database("postgresql://observer_runtime@127.0.0.1:1/none", timeout=1), keys.manifest(), keys.observer,
                   Config(), clock)
    assert obs.ingest(raw(decision(keys, 1))) == (503, {"error": "OBSERVER_DB_UNAVAILABLE"})


# ---------------- HTTP API ----------------
def test_http_api(obs, keys):
    from fastapi.testclient import TestClient
    c = TestClient(create_app(obs, "op-token-for-tests-only"))
    assert c.get("/v1/health").json() == {"health": "ok"}
    r = c.post("/v1/events", content=raw(decision(keys, 1)))
    assert r.status_code == 200 and r.json()["status"] == "accepted"
    assert c.post("/v1/events", content=b"x" * (65 * 1024)).status_code == 413
    assert c.get("/v1/status").status_code == 401
    assert c.get("/v1/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    s = c.get("/v1/status", headers={"Authorization": "Bearer op-token-for-tests-only"}).json()
    assert s["coverage"]["mediated"] is False and s["ledger"]["n"] == 2
    assert "ENFORCEMENT_VERIFIED" in s["evidence"] and "no result can be" in s["evidence"]
    for path in ("/v1/reconciliations", "/v1/evidence/export", "/v1/canaries/run"):
        assert c.get(path).status_code in (404, 405)                    # C3/C4/C7 endpoints do not exist
    assert TestClient(create_app(obs, None)).get("/v1/status").status_code == 503


def test_observer_main_build_refuses_overprivileged_or_unmigrated(cluster, keys, tmp_path, monkeypatch):
    from observer import crypto, main
    from observer.manifest import sign_manifest
    url, admin = cluster.new_db()
    mf = tmp_path / "m.json"; mf.write_text(json.dumps(sign_manifest(keys.manifest_doc(), keys.root)))
    kf = tmp_path / "o.pem"; crypto.write_private(str(kf), keys.observer)
    env = {"OBSERVER_MANIFEST_FILE": str(mf), "OBSERVER_ROOT_PUBLIC_KEY": keys.root_pub(), "OBSERVER_SIGNING_KEY_FILE": str(kf)}
    monkeypatch.setenv("OBSERVER_DATABASE_URL", admin)                  # the admin/owner account must be refused
    with pytest.raises(SystemExit, match="over-privileged"):
        main.build(env)
    monkeypatch.setenv("OBSERVER_DATABASE_URL", url)
    obs = main.build(env)
    assert obs.verify_ledger()["valid"] and obs.status()["manifest_version"] == 1
    env["OBSERVER_ROOT_PUBLIC_KEY"] = crypto.describe(keys.other)[1]
    from observer.manifest import ManifestError
    with pytest.raises(ManifestError):
        main.build(env)
