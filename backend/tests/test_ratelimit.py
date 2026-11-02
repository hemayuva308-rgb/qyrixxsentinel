"""Distributed rate limiting (Phase E) on real PostgreSQL: atomic counters under concurrency, several application
instances (separate pools = separate processes' view), restarts, backend outage behaviour per scope, privacy of keys,
and an end-to-end check with two real uvicorn processes sharing one database."""
import os, socket, subprocess, sys, threading, time, urllib.request
import pytest

from app import identity, migrate, persistence
from app.identity import AuthError, SharedLimiter
from tests.test_persistence import Cluster, HAVE_PG, _free_port

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = Cluster()
    yield c
    c.destroy()


@pytest.fixture
def url(cluster):
    import psycopg
    db = "r" + os.urandom(4).hex()
    with psycopg.connect(cluster.admin_url, autocommit=True) as c:
        c.execute("CREATE DATABASE %s" % db)
    migrate.migrate(cluster.admin_url.rsplit("/", 1)[0] + "/" + db)
    yield cluster.runtime_url(db)
    persistence._POOL.clear()


def instance(url):
    """A separate application instance: its own pool (= own connections), like another process or replica."""
    return SharedLimiter(persistence._Pool(url, 5, 10))


def test_exact_admission_under_concurrency_across_instances(url):
    a, b, c = instance(url), instance(url), instance(url)
    allowed, lock = [], threading.Lock()

    def worker(lim):
        for _ in range(20):
            ok = lim.hit("login:acct:victim", 25, window=600)
            with lock:
                allowed.append(ok)
    ts = [threading.Thread(target=worker, args=(l,)) for l in (a, b, c) for _ in range(3)]      # 9 threads x 20 = 180
    [t.start() for t in ts]; [t.join() for t in ts]
    assert sum(allowed) == 25 and len(allowed) == 180                    # never over-admits, never loses an update


def test_counters_survive_restart(url):
    a = instance(url)
    assert all(a.hit("authfail:ip:203.0.113.9", 5, window=600) for _ in range(5))
    a.pool.close_all()
    b = instance(url)                                                     # "restarted" process
    assert b.hit("authfail:ip:203.0.113.9", 5, window=600) is False
    assert b.hit("authfail:ip:203.0.113.10", 5, window=600) is True       # other buckets unaffected


def test_check_only_does_not_consume(url):
    a = instance(url)
    for _ in range(10):
        assert a.hit("reset:acct:x", 2, window=600, count=False)
    assert a.hit("reset:acct:x", 2, window=600) and a.hit("reset:acct:x", 2, window=600)
    assert a.hit("reset:acct:x", 2, window=600, count=False) is False


def test_sliding_window_counts_the_previous_window(url, monkeypatch):
    a = instance(url)
    t = [1_900_000_020.0]                                             # aligned to a 60 s window boundary
    monkeypatch.setattr(identity.time, "time", lambda: t[0])
    for _ in range(10):
        assert a.hit("req:key:k1", 10, window=60)
    t[0] += 60                                                          # start of the next window: previous counts fully
    assert a.hit("req:key:k1", 10, window=60) is False
    t[0] += 45                                                          # 3/4 into it: previous weighs 25 %
    assert sum(a.hit("req:key:k1", 10, window=60) for _ in range(10)) == 7


def test_keys_are_hashed_no_raw_identifiers_stored(url, cluster):
    a = instance(url)
    a.hit("login:ip:198.51.100.77", 5)
    a.hit("login:acct:" + "alice@example.com", 5)
    import psycopg
    with psycopg.connect(cluster.admin_url.rsplit("/", 1)[0] + "/" + url.rsplit("/", 1)[1]) as c:
        rows = " ".join(r[0] for r in c.execute("SELECT bucket FROM rate_limits").fetchall())
    assert "198.51.100.77" not in rows and "alice" not in rows and len(rows.split()[0]) == 64


def test_backend_outage_fails_closed_for_auth_and_degrades_for_general(url):
    dead = SharedLimiter(persistence._Pool("postgresql://qyrix_runtime@127.0.0.1:%d/x?connect_timeout=1" % _free_port(), 1, 2))
    for scope in identity.SECURITY_SCOPES:
        with pytest.raises(AuthError) as e:
            dead.hit(scope + ":ip:203.0.113.1", 5)
        assert e.value.status == 503                                     # brute-force protection never silently disappears
    assert [dead.hit("req:key:k", 2) for _ in range(3)] == [True, True, False]   # per-instance fallback still limits


def test_two_real_backend_processes_share_auth_failure_limits(url, tmp_path):
    """End to end: two uvicorn processes on one database. Failed authentications on process A count on process B."""
    key = tmp_path / "sig"; key.write_bytes(b"client-signing-key-for-tests-0123456789")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = {**os.environ, "QYRIX_DATABASE_URL": url, "QYRIX_AUTH_FAIL_PER_MIN": "4", "QYRIX_AUTH_FAIL_GLOBAL_PER_MIN": "1000",
           "QYRIX_CLIENT_SIG_KEY_FILE": str(key), "QYRIX_CHAIN_FILE": str(tmp_path / "c.jsonl"), "QYRIX_WORKSPACE": str(tmp_path)}
    ports, procs = [_free_port(), _free_port()], []
    try:
        for port in ports:
            procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)], cwd=here, env=env,
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        for port in ports:
            for _ in range(100):
                try:
                    urllib.request.urlopen("http://127.0.0.1:%d/api/v1/health" % port, timeout=1); break
                except Exception:
                    time.sleep(0.1)
        from app.auth import sign_client

        def call(port):
            req = urllib.request.Request("http://127.0.0.1:%d/api/v1/sentinel/status" % port, headers={
                "authorization": "Bearer qsk_guess", "x-qyrix-client": sign_client("203.0.113.50", key.read_bytes())})
            try:
                return urllib.request.urlopen(req, timeout=5).status
            except urllib.error.HTTPError as e:
                return e.code
        codes = [call(ports[i % 2]) for i in range(6)]                  # alternate between the two processes
        assert codes == [401, 401, 401, 401, 429, 429], codes
    finally:
        for p in procs:
            p.terminate(); p.wait(timeout=10)
