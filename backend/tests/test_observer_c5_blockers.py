"""C5 blocker fixes (audit F1, F3, F7) - regression tests on REAL PostgreSQL / a real uvicorn server."""
import json
import socket
import threading
import time
import urllib.request
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

from observer import crypto
from observer.app import create_app
from tests.observer_support import HAVE_PG, Clock, Keys, ObserverCluster, decision, envelope, make_observer, raw

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = ObserverCluster()
    yield c
    c.destroy()


@pytest.fixture
def ob(cluster):
    url, admin = cluster.new_db()
    keys = Keys()
    return {"obs": make_observer(url, keys, Clock()), "admin": admin, "keys": keys}


def q(admin, sql, p=()):
    with psycopg.connect(admin, autocommit=True) as c:
        cur = c.execute(sql, p)
        return cur.fetchall() if cur.description else None


# ---------------- F7: non-finite / malformed numbers ----------------
@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity", "1e400", "-1e999", "9" * 5000])
def test_f7_non_finite_and_absurd_numbers_are_malformed_not_500(ob, token):
    env = decision(ob["keys"], 1)
    body = json.dumps(env).replace('"verdict": "BLOCK"', '"verdict": %s' % token).encode()
    assert ob["obs"].ingest(body) == (400, {"error": "MALFORMED"})
    c = TestClient(create_app(ob["obs"], None), raise_server_exceptions=False)
    r = c.post("/v1/events", content=body)
    assert r.status_code == 400 and r.json() == {"error": "MALFORMED"}


def test_f7_deep_nesting_is_malformed(ob):
    deep = b'{"a":' * 100000 + b"1" + b"}" * 100000
    assert ob["obs"].ingest(deep[:60000])[0] in (400,)          # truncated JSON
    assert ob["obs"].ingest(b"[" * 30000 + b"]" * 30000) == (400, {"error": "MALFORMED"})    # < 64 KiB, > recursion limit


def test_f7_valid_events_still_accepted(ob):
    assert ob["obs"].ingest(raw(decision(ob["keys"], 1)))[1]["status"] == "accepted"


# ---------------- F1: unauthenticated ledger flooding ----------------
def test_f1_unauthenticated_refusals_do_not_multiply_ledger_rows(ob):
    k = crypto.generate()
    for i in range(300):
        env = envelope(k, "gate:%s" % uuid.uuid4(), "decision", {}, seq=1, tenant="default")
        assert ob["obs"].ingest(raw(env))[1]["error"] == "UNKNOWN_PRODUCER"
    for i in range(50):                                            # forged signature on a real producer id
        env = envelope(k, ob["keys"].gate_pid, "decision", {}, seq=i + 1, key_id=ob["keys"].kid(ob["keys"].gate))
        assert ob["obs"].ingest(raw(env))[1]["error"] == "SIGNATURE_INVALID"
    rows = q(ob["admin"], "SELECT code, producer_id, tenant_id, ref FROM ledger WHERE kind='refusal'")
    assert sorted(r[0] for r in rows) == ["SIGNATURE_INVALID", "UNKNOWN_PRODUCER"]        # one row per code
    assert all(r[1] is None and r[2] is None and r[3] is None for r in rows)              # nothing sender-chosen stored
    assert len(ob["obs"]._throttle) <= 2 and ob["obs"].counters["REFUSAL_THROTTLED"] >= 348


def test_f1_authenticated_security_alerts_still_recorded(ob):
    k = ob["keys"]
    for _ in range(3):
        assert ob["obs"].ingest(raw(envelope(k.gate, k.gate_pid, "observation", {})))[1]["error"] == "SCOPE_DENIED"
    rows = q(ob["admin"], "SELECT code, producer_id FROM ledger WHERE code='SCOPE_DENIED'")
    assert rows == [("SCOPE_DENIED", k.gate_pid)] * 3


def test_f1_throttle_map_is_bounded(ob, monkeypatch):
    from observer import ingest as ing
    monkeypatch.setattr(ing, "MAX_THROTTLE_KEYS", 4)
    obs = ob["obs"]
    for i in range(20):
        obs._throttle[("X%d" % i, "")] = obs.clock()                # fill beyond the bound
    obs.ingest(b"{bad")
    assert len(obs._throttle) <= 20 and obs.counters.get("REFUSAL_THROTTLED", 0) >= 1


def test_f1_per_source_rate_limit(ob, monkeypatch):
    from observer import app as oapp
    monkeypatch.setattr(oapp, "RATE_BURST", 5.0)
    monkeypatch.setattr(oapp, "RATE_PER_S", 0.001)
    c = TestClient(create_app(ob["obs"], "op"))
    codes = [c.post("/v1/events", content=b"{bad").status_code for _ in range(20)]
    assert codes.count(429) >= 14 and codes[:5] == [400] * 5
    s = c.get("/v1/status", headers={"Authorization": "Bearer op"}).json()
    assert s["ingest"]["rate_limited"] >= 14
    assert q(ob["admin"], "SELECT count(*) FROM ledger WHERE code='MALFORMED'") == [(1,)]


# ---------------- F3: no blocking work on the event loop ----------------
def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def test_f3_slow_ingest_does_not_block_health(ob, monkeypatch):
    import uvicorn
    obs = ob["obs"]
    monkeypatch.setattr(obs, "ingest", lambda raw_: (time.sleep(2.0), (200, {"status": "accepted"}))[1])
    port = _port()
    srv = uvicorn.Server(uvicorn.Config(create_app(obs, None), host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    try:
        def post():
            urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/v1/events" % port, data=b"{}", method="POST"),
                                   timeout=10).read()
        ps = [threading.Thread(target=post) for _ in range(4)]
        [p.start() for p in ps]
        time.sleep(0.3)
        t0 = time.time()
        assert json.load(urllib.request.urlopen("http://127.0.0.1:%d/v1/health" % port, timeout=5)) == {"health": "ok"}
        assert time.time() - t0 < 0.5                                       # loop stayed responsive
        [p.join() for p in ps]
    finally:
        srv.should_exit = True
        t.join(5)


def test_f3_inflight_bound_returns_busy(ob, monkeypatch):
    from observer import app as oapp
    monkeypatch.setattr(oapp, "MAX_INFLIGHT", 1)
    gate = threading.Event()
    monkeypatch.setattr(ob["obs"], "ingest", lambda raw_: (gate.wait(5), (200, {"status": "accepted"}))[1])
    c = TestClient(create_app(ob["obs"], None))
    out = []
    t = threading.Thread(target=lambda: out.append(c.post("/v1/events", content=b"{}").status_code)); t.start()
    time.sleep(0.3)
    assert c.post("/v1/events", content=b"{}").status_code == 503
    gate.set(); t.join(5)
    assert out == [200]
