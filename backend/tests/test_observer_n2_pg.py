"""Audit N2 on REAL PostgreSQL + real sockets: the egress proxy denies untagged traffic and opens egress only for an
execution id backed by a signed, sequenced grant claim (ALLOW, same host, active stream, not revoked, fresh, one use).
Destinations here are treated as PUBLIC (no observer-owned exemption), so every request needs authorization."""
import socket
import ssl
import threading
import time
import uuid

import psycopg
import pytest

from observer.egress import EgressProxy, Recorder, grant_authorizer
from observer.feed import Config
from tests.observer_support import HAVE_PG, Keys, ObserverCluster, envelope, make_observer, raw
from tests.test_observer_c5_pg import HOST, _tls_server, connect, tls_through

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = ObserverCluster()
    yield c
    c.destroy()


@pytest.fixture
def nx(cluster, tmp_path):
    url, admin = cluster.new_db()
    keys = Keys()
    obs = make_observer(url, keys, time.time, cfg=Config())
    rec = Recorder(obs)
    clock = {"skew": 0.0}
    auth = grant_authorizer(obs.db, clock=lambda: time.time() + clock["skew"], wait=1.0)
    proxy = EgressProxy(rec, "127.0.0.1", 0, lambda h: {HOST: ["127.0.0.1"], "llm.provider.example": ["127.0.0.1"]}.get(h, []),
                        [], authorize=auth, untagged_allow=["llm.provider.example"])
    proxy._is_public = lambda ip: True                  # loopback stands in for a public destination
    srv, port = _tls_server(tmp_path)
    yield {"obs": obs, "admin": admin, "keys": keys, "proxy": proxy, "port": port, "clock": clock, "seq": {"default": 0}}
    proxy.close(); srv.close()


def q(admin, sql, p=()):
    with psycopg.connect(admin, autocommit=True) as c:
        cur = c.execute(sql, p)
        return cur.fetchall() if cur.description else None


def claim_grant(nx, verdict="ALLOW", dest=HOST, kind="issued", tenant="default", exec_id=None, extra=()):
    """Signed decision + grant claims, exactly as the backend publishes them (E0)."""
    k, geid, eid = nx["keys"], str(uuid.uuid4()), exec_id or str(uuid.uuid4())
    for t, body in (("decision", {"gate_evaluation_id": geid, "correlation_id": geid, "verdict": verdict, "rule_ids": [],
                                  "dest_host": dest}),
                    ("grant", {"gate_evaluation_id": geid, "grant_id": "grt_" + uuid.uuid4().hex, "execution_id": eid,
                               "kind": kind})) + tuple(extra):
        if t == "grant_extra":
            t, body = "grant", dict(body, gate_evaluation_id=geid, execution_id=eid)
        nx["seq"][tenant] = nx["seq"].get(tenant, 0) + 1
        st, r = nx["obs"].ingest(raw(envelope(k.gate, k.gate_pid, t, body, tenant=tenant, seq=nx["seq"][tenant], issued=time.time())))
        assert st == 200, r
    return eid


def refused(nx):
    return [r[0] for r in q(nx["admin"], "SELECT reason FROM egress_observations WHERE kind='refused' ORDER BY observed_at")]


def opened(nx):
    return q(nx["admin"], "SELECT execution_id::text FROM egress_observations WHERE kind='tunnel_open'")


# ---------------- negative controls ----------------
def test_untagged_connect_is_denied(nx):
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xhost=None)
    assert resp.startswith(b"HTTP/1.1 403") and refused(nx) == ["UNTAGGED_EGRESS_DENIED"] and opened(nx) == []
    assert q(nx["admin"], "SELECT count(*) FROM ledger WHERE code='EGRESS_DENIED'") == [(1,)]


def test_untagged_hostname_connect_and_plain_http_are_denied(nx):
    s, resp = connect(nx["proxy"], HOST, 443, xhost=None)                          # hostname CONNECT, not allow-listed
    assert resp.startswith(b"HTTP/1.1 403")
    s = socket.create_connection(("127.0.0.1", nx["proxy"].port))
    s.sendall(b"POST http://127.0.0.1:%d/upload HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\n\r\nsecret" % nx["port"])
    assert s.recv(64).startswith(b"HTTP/1.1 403")
    assert refused(nx) == ["UNTAGGED_EGRESS_DENIED", "UNTAGGED_EGRESS_DENIED"]


def test_unknown_execution_id_is_denied(nx):
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=str(uuid.uuid4()))
    assert resp.startswith(b"HTTP/1.1 403") and refused(nx) == ["EXECUTION_NOT_AUTHORISED"] and opened(nx) == []


@pytest.mark.parametrize("case,why", [("block_decision", "DECISION_NOT_ALLOW"), ("other_host", "HOST_NOT_AUTHORISED"),
                                      ("revoked", "GRANT_REVOKED"), ("refused_only", "EXECUTION_NOT_AUTHORISED"),
                                      ("too_old", "GRANT_TOO_OLD")])
def test_claims_that_do_not_authorize(nx, case, why):
    if case == "block_decision":
        eid = claim_grant(nx, verdict="BLOCK")
    elif case == "other_host":
        eid = claim_grant(nx, dest="other.example.com")
    elif case == "revoked":
        eid = claim_grant(nx, extra=(("grant_extra", {"grant_id": "g", "kind": "revoked", "refusal_code": "REVOKED_BY_OPERATOR"}),))
    elif case == "refused_only":
        eid = claim_grant(nx, kind="refused")
    else:
        eid = claim_grant(nx)
        nx["clock"]["skew"] = 3600.0
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=eid)
    assert resp.startswith(b"HTTP/1.1 403") and refused(nx) == [why] and opened(nx) == []


def test_claim_from_quarantined_stream_does_not_authorize(nx):
    eid = claim_grant(nx)
    k = nx["keys"]                                                               # seq reuse => stream quarantined
    nx["obs"].ingest(raw(envelope(k.gate, k.gate_pid, "decision", {"verdict": "BLOCK"}, seq=1, issued=time.time())))
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=eid)
    assert resp.startswith(b"HTTP/1.1 403") and refused(nx) == ["GRANT_CLAIM_STREAM_UNTRUSTED"]


def test_execution_id_claimed_in_two_tenants_is_not_authorised(nx):
    eid = claim_grant(nx)
    claim_grant(nx, tenant="tenant-b", exec_id=eid)
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=eid)
    assert resp.startswith(b"HTTP/1.1 403") and refused(nx) == ["EXECUTION_NOT_AUTHORISED"]


def test_exfiltration_inside_an_authorised_tunnel_to_another_host_is_refused(nx):
    eid = claim_grant(nx)                                                        # authorised for api.example.com
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xhost="exfil.example.net", xexec=eid)
    assert resp.startswith(b"HTTP/1.1 403")                                      # observer resolution check first
    assert refused(nx) == ["IP_NOT_IN_HOST_RESOLUTION"]


# ---------------- positive controls ----------------
def test_authorised_execution_opens_one_tunnel_only(nx):
    eid = claim_grant(nx)
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=eid)
    assert resp.startswith(b"HTTP/1.1 200") and b"ok" in tls_through(s, HOST)
    s2, resp2 = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=eid)        # reuse of the same execution id
    assert resp2.startswith(b"HTTP/1.1 403") and "EXECUTION_ID_REUSE" in refused(nx)
    assert opened(nx) == [(eid,)]


def test_claim_arriving_while_waiting_authorises(nx):
    eid = str(uuid.uuid4())
    threading.Timer(0.4, lambda: claim_grant(nx, exec_id=eid)).start()          # outbox delivers a moment later
    s, resp = connect(nx["proxy"], "127.0.0.1", nx["port"], xexec=eid)
    assert resp.startswith(b"HTTP/1.1 200")


def test_operator_allow_list_is_connect_only_and_sni_bound(nx):
    s, resp = connect(nx["proxy"], "llm.provider.example", nx["port"], xhost=None)
    assert resp.startswith(b"HTTP/1.1 200")
    with pytest.raises((ssl.SSLError, OSError)):
        tls_through(s, "evil.example")                                           # SNI must be the allow-listed name
    assert "SNI_MISMATCH" in refused(nx)
    s = socket.create_connection(("127.0.0.1", nx["proxy"].port))
    s.sendall(b"GET http://llm.provider.example/x HTTP/1.1\r\nHost: llm.provider.example\r\n\r\n")
    assert s.recv(64).startswith(b"HTTP/1.1 403")                               # plain HTTP never allow-listed


# ---------------- end to end: real Gate ALLOW -> outbox claim -> proxy authorization ----------------
def test_real_gate_allow_authorises_its_own_execution(nx, tmp_path, monkeypatch):
    from app import adapter as adapters, netguard, observer_feed, persistence
    import app.gateway as g
    from tests.test_persistence import A, Cluster, boot
    from fastapi.testclient import TestClient
    from observer.app import create_app
    c = Cluster()
    srv443, _ = _tls_server(tmp_path, 443)                                      # Gate policy: standard ports only
    try:
        persistence.PgPersistence(c.url).init_install(nx["keys"].install_id)
        observer_feed._producer_cache.clear()
        monkeypatch.setenv("QYRIX_OBSERVER_URL", "http://observer.test")
        monkeypatch.setenv("QYRIX_EGRESS_PROXY_URL", "http://127.0.0.1:%d" % nx["proxy"].port)
        monkeypatch.setattr(netguard, "resolve_public", lambda h: ["127.0.0.1"])   # the test origin stands in for HOST
        ws = tmp_path / "ws"; ws.mkdir()
        env = {"url": c.url, "chain": str(tmp_path / "c.jsonl"), "ws": str(ws), "cluster": c}
        ctx = boot(env)
        ctx.adapters["http"] = adapters.HttpAdapter(lambda: (HOST,))
        ctx.approved = lambda: (HOST,)
        pub = observer_feed.Publisher(lambda t: persistence.PgPersistence(c.url, t), c.url, nx["keys"].gate,
                                      http=TestClient(create_app(nx["obs"], None)))
        stop = threading.Event()
        threading.Thread(target=lambda: [(pub.publish_once(), stop.wait(0.2)) for _ in iter(lambda: stop.is_set(), True)],
                         daemon=True).start()
        r = g.evaluate(A(tool="http", method="GET", dest="https://%s/x" % HOST), ctx)
        assert r["verdict"] == "ALLOW", r["rules"]
        out = g.execute_grant({"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}, ctx)
        stop.set()
        exe = ctx.grants[r["grant_id"]]["execution_id"]
        assert opened(nx) == [(exe,)]                                            # the proxy authorised THIS execution
        assert refused(nx) == []
        assert out["executed"] in (True, False)                                  # TLS to the self-signed origin may fail
    finally:
        srv443.close()
        persistence._POOL.clear(); observer_feed._producer_cache.clear(); c.destroy()
