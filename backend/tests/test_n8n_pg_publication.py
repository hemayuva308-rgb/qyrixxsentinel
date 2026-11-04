"""Phase 1A remediation: the n8n node against the REAL production claim path, with no test relay:

    n8n node (harness, real node class)
      -> Gate API over verified HTTPS (uvicorn) on REAL PostgreSQL, multi-tenant (tenant `acme`, agent key)
           decision + `issued` claim written in the evaluation transaction, `redeemed` claim in the redemption
           transaction (observer_outbox, migration 008)
      -> app.observer_feed.Publisher (advisory lock, ordered, signed) -> Observer /v1/events -> events (observer PG)
      -> EgressProxy + N2 grant_authorizer (requires issued + redeemed, same host, TTL, no refusal) -> TLS origin :443

Covers: correct correlation of decision / grant claims / tunnel by gate_evaluation_id, execution_id and correlation_id;
tenant attribution; Observer downtime (fail closed, grant consumed, backlog replays in order, no late tunnel);
publisher lag inside the proxy wait (allowed) and beyond it (fail closed)."""
import json
import os
import socket
import subprocess
import pathlib
import tempfile
import threading
import time

import psycopg
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app import identity, migrate, observer_feed, persistence, tenancy
from app.main import app
from observer.app import create_app
from observer.egress import EgressProxy, Recorder, grant_authorizer
from observer.feed import Config
from tests.observer_support import Keys, ObserverCluster, make_observer
from tests.test_n8n_http_node import HARNESS, HOST, NODE, Origin, base_env, free_port, gate_tls, node_spec, run
from tests.test_persistence import HAVE_PG, Cluster

pytestmark = [pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available"),
              pytest.mark.skipif(not NODE, reason="node not installed")]
PLATFORM = "platform-token-for-n8n-pg-tests-0123456789"
PROXY_WAIT = 3.0


class Link:
    """The publisher's HTTP client: the real Observer app, with switchable downtime (connection error) and lag."""
    def __init__(self, observer_http):
        self.http, self.down, self.lag = observer_http, False, 0.0

    def post(self, *a, **k):
        if self.down:
            raise ConnectionError("observer down (test)")
        return self.http.post(*a, **k)


@pytest.fixture(scope="module")
def pg():
    mp = pytest.MonkeyPatch()
    tmp = pathlib.Path(tempfile.mkdtemp())
    gc = Cluster()
    db = "n8n" + os.urandom(4).hex()
    with psycopg.connect(gc.admin_url, autocommit=True) as c:
        c.execute("CREATE DATABASE %s" % db)
    admin = gc.admin_url.rsplit("/", 1)[0] + "/" + db
    migrate.migrate(admin)
    url = gc.runtime_url(db)
    keys = Keys()
    persistence.PgPersistence(admin).init_install(keys.install_id)      # installation identity => gate producer id
    observer_feed._producer_cache.clear()
    for k, v in {"QYRIX_DATABASE_URL": url, "QYRIX_MULTI_TENANT": "1", "QYRIX_PLATFORM_TOKEN": PLATFORM,
                 "QYRIX_OBSERVER_URL": "http://observer.test"}.items():
        mp.setenv(k, v)
    identity.use_store(identity.PgStore(persistence.shared_connection(url))); identity.limiter.clear()
    pl = TestClient(app, headers={"Authorization": "Bearer " + PLATFORM})
    assert pl.post("/api/v1/platform/tenants", json={"id": "acme", "name": "Acme", "approved_domains": [HOST]}).status_code == 200
    agent = pl.post("/api/v1/platform/tenants/acme/keys", json={"role": "agent"}).json()["api_key"]

    oc = ObserverCluster(); ourl, oadmin = oc.new_db()
    obs = make_observer(ourl, keys, time.time, cfg=Config())
    link = Link(TestClient(create_app(obs, None)))
    pub = observer_feed.Publisher(lambda t: persistence.PgPersistence(url, t), url, keys.gate, http=link)
    stop = threading.Event()

    def publish_loop():
        while not stop.is_set():
            if not link.down:
                if link.lag:
                    stop.wait(link.lag)
                try:
                    pub.publish_once()
                except Exception:
                    pass
            stop.wait(0.1)
    threading.Thread(target=publish_loop, daemon=True).start()

    origin = Origin(tmp)
    cert, key = gate_tls(origin, tmp)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", ssl_certfile=cert, ssl_keyfile=key))
    threading.Thread(target=server.run, daemon=True).start()
    end = time.time() + 15
    while not server.started and time.time() < end:
        time.sleep(0.05)
    proxy = EgressProxy(Recorder(obs), "127.0.0.1", 0, lambda h: {HOST: ["127.0.0.1"]}.get(h, []), [],
                        authorize=grant_authorizer(obs.db, wait=PROXY_WAIT))           # production default: tagged 443 only
    proxy._is_public = lambda ip: True
    secrets_dir = tmp / "secrets"; secrets_dir.mkdir(); files_dir = tmp / "n8n-files"; files_dir.mkdir()
    tok = secrets_dir / "token"; tok.write_text(agent); os.chmod(tok, 0o600)
    yield {"gate": "https://127.0.0.1:%d" % port, "proxy": proxy, "origin": origin, "token_file": str(tok), "files_dir": files_dir,
           "link": link, "oadmin": oadmin, "admin": admin, "obs": obs, "pub": pub}
    stop.set(); server.should_exit = True; proxy.close(); origin.close()
    with tenancy._lock:
        tenancy._contexts.clear()
    identity.use_store(identity.MemoryStore())
    persistence._POOL.clear(); observer_feed._producer_cache.clear(); mp.undo()
    oc.destroy(); gc.destroy()


def oq(pg, sql, p=()):
    with psycopg.connect(pg["oadmin"], autocommit=True) as c:
        return c.execute(sql, p).fetchall()


def claims_for(pg, geid):
    return oq(pg, "SELECT tenant_id, type, envelope->'body'->>'kind', envelope->'body'->>'execution_id',"
                  " envelope->'body'->>'correlation_id', seq FROM events WHERE envelope->'body'->>'gate_evaluation_id'=%s"
                  " ORDER BY seq", (geid,))


def unsent(pg):
    with psycopg.connect(pg["admin"], autocommit=True) as c:
        return c.execute("SELECT count(*) FROM observer_outbox WHERE sent_at IS NULL").fetchone()[0]


def wait_until(f, timeout=15.0):
    end = time.time() + timeout
    while time.time() < end:
        if f():
            return True
        time.sleep(0.1)
    return False


def go(pg, path, **kw):
    spec = node_spec(url="https://%s/%s" % (HOST, path)); spec.update(kw)
    return run(pg, spec)[0]


def test_published_claims_authorise_exactly_this_execution_and_stay_correlated(pg):
    n0 = pg["origin"].count()
    r = go(pg, "pg-allowed")
    assert r["ok"], r
    q = r["output"][0]["qyrix"]
    assert pg["origin"].count() == n0 + 1 and q["evidence"] == "E1_ADAPTER_SELF_REPORT"
    assert wait_until(lambda: unsent(pg) == 0)
    rows = claims_for(pg, q["gate_evaluation_id"])
    assert {x[0] for x in rows} == {"acme"}                                          # tenant attribution
    assert [(x[1], x[2]) for x in rows] == [("decision", None), ("grant", "issued"), ("grant", "redeemed")]   # in order
    assert rows[0][4] == q["correlation_id"] == "n8n:wfTest01:42:node-1:0"           # decision carries the correlation id
    assert {x[3] for x in rows if x[1] == "grant"} == {q["execution_id"]}            # every grant claim: same execution id
    tunnels = oq(pg, "SELECT kind, host FROM egress_observations WHERE execution_id::text=%s ORDER BY observed_at", (q["execution_id"],))
    assert ("tunnel_open", HOST) in tunnels and all(t[1] == HOST for t in tunnels)


def test_observer_down_fails_closed_then_backlog_replays_without_a_late_tunnel(pg):
    n0 = pg["origin"].count()
    pg["link"].down = True
    try:
        r = go(pg, "pg-observer-down")
        assert not r["ok"] and r["code"] == "EGRESS_REFUSED" and pg["origin"].count() == n0
        assert r["outcome"] == "NOT_SENT_GRANT_CONSUMED"
        exe, geid = r["ids"]["execution_id"], r["ids"]["gate_evaluation_id"]
        refused = oq(pg, "SELECT reason FROM egress_observations WHERE kind='refused' AND execution_id::text=%s", (exe,))
        assert refused == [("EXECUTION_NOT_AUTHORISED",)]                             # nothing reached the observer
        assert unsent(pg) >= 3 and claims_for(pg, geid) == []
    finally:
        pg["link"].down = False
    pg["pub"].backoff, pg["pub"].next_try = 0.0, 0.0
    assert wait_until(lambda: unsent(pg) == 0)                                        # backlog replays, in order
    assert [(x[1], x[2]) for x in claims_for(pg, geid)] == [("decision", None), ("grant", "issued"), ("grant", "redeemed")]
    assert oq(pg, "SELECT count(*) FROM egress_observations WHERE kind='tunnel_open' AND execution_id::text=%s", (exe,)) == [(0,)]
    r2 = go(pg, "pg-after-recovery")                                                  # service resumes for new requests
    assert r2["ok"], r2


def test_publisher_lag_inside_the_proxy_wait_is_tolerated(pg):
    pg["link"].lag = 0.8                                                              # claims arrive ~1-2 s late
    try:
        r = go(pg, "pg-lag-ok")
    finally:
        pg["link"].lag = 0.0
    assert r["ok"], r


def test_publisher_lag_beyond_the_proxy_wait_fails_closed(pg):
    n0 = pg["origin"].count()
    pg["link"].lag = PROXY_WAIT + 2.5                                                 # redemption claim arrives too late
    try:
        r = go(pg, "pg-lag-too-long")
    finally:
        pg["link"].lag = 0.0
    assert not r["ok"] and r["code"] == "EGRESS_REFUSED" and pg["origin"].count() == n0
    reason = oq(pg, "SELECT reason FROM egress_observations WHERE kind='refused' AND execution_id::text=%s", (r["ids"]["execution_id"],))
    assert reason in ([("EXECUTION_NOT_AUTHORISED",)], [("EXECUTION_NOT_REDEEMED",)])
    assert wait_until(lambda: unsent(pg) == 0)


def test_issued_claim_published_without_redemption_never_opens_egress(pg):
    """HIGH-1 on the production path: a real evaluation (decision + issued claim published by the real Publisher) whose
    grant is never redeemed. Even with the execution id in hand, CONNECT is refused."""
    env = base_env(pg)
    spec = {"mode": "raw-evaluate", "action": {"tool": "http", "method": "GET", "dest": "https://%s/pg-unredeemed" % HOST, "cmd": "",
                                                "data": "{}", "correlation_id": "n8n:pg:unredeemed", "task_id": "n8n-wf-pg"}}
    out = json.loads(subprocess.run([NODE, HARNESS], input=json.dumps(spec), capture_output=True, text=True, env=env, timeout=60).stdout.splitlines()[-1])
    assert out["ok"], out
    geid = out["output"]["gateEvaluationId"]
    assert wait_until(lambda: [(x[1], x[2]) for x in claims_for(pg, geid)] == [("decision", None), ("grant", "issued")])
    exe = claims_for(pg, geid)[1][3]                                                  # read with observer-admin access
    s = socket.create_connection(("127.0.0.1", pg["proxy"].port), timeout=10)
    s.sendall(("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nX-Qyrix-Host: %s\r\nX-Qyrix-Execution: %s\r\n\r\n" % (HOST, exe)).encode())
    resp = s.recv(256); s.close()
    assert resp.startswith(b"HTTP/1.1 403")
    assert oq(pg, "SELECT reason FROM egress_observations WHERE kind='refused' AND execution_id::text=%s", (exe,)) == [("EXECUTION_NOT_REDEEMED",)]
