"""C4 dashboard relay: backend GET /api/v1/sentinel/observer/reconciliations -> observer GET /v1/reconciliations with a
tenant-scoped READ-ONLY key. Caller's tenant only, allow-listed fields, never ENFORCEMENT_VERIFIED, explicit
'not independent of the backend' labelling, clean failure when not configured / unreachable."""
import hashlib

import pytest
from fastapi.testclient import TestClient

from app import observer_feed
from tests.conftest import ADMIN
from tests.observer_support import HAVE_PG
from tests.test_observer_canary_pg import cluster, env, finish, live  # noqa: F401
from tests.test_observer_reconcile_pg import claim

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")
RT = "dashboard-read-token-for-tests-only"


@pytest.fixture
def relay(env, tmp_path, monkeypatch):
    from observer.app import create_app
    oc = TestClient(create_app(env["obs"], "op", env["svc"],
                               [{"sha256": hashlib.sha256(RT.encode()).hexdigest(), "tenants": ["default"]}]))
    tf = tmp_path / "rt"; tf.write_text(RT)
    monkeypatch.setenv("QYRIX_OBSERVER_URL", "http://observer.test")
    monkeypatch.setenv("QYRIX_OBSERVER_READ_TOKEN_FILE", str(tf))
    monkeypatch.setattr(observer_feed, "_read_http", lambda: oc)
    return oc


def test_relay_shows_callers_tenant_results(env, relay):
    from app.main import app
    live(env, "broken")
    r = env["svc"].start("default")
    claim(env, r["correlation_id"], "BLOCK")
    env["svc"].start("tenant-b")
    finish(env)
    j = TestClient(app, headers=ADMIN).get("/api/v1/sentinel/observer/reconciliations").json()
    assert j["configured"] and j["available"] and j["tenant"] == "default" and j["verified_possible"] is False
    assert [x["result"] for x in j["reconciliations"]] == ["BYPASS_DETECTED"]                # tenant-b not included
    assert "not independent of the backend" in j["source"] and RT not in str(j)


def test_relay_requires_auth_and_reports_unavailability(env, relay, monkeypatch, tmp_path):
    from app.main import app
    assert TestClient(app).get("/api/v1/sentinel/observer/reconciliations").status_code == 401
    import httpx
    monkeypatch.setattr(observer_feed, "_read_http",
                        lambda: httpx.Client(base_url="http://127.0.0.1:1", timeout=0.5, trust_env=False))
    j = TestClient(app, headers=ADMIN).get("/api/v1/sentinel/observer/reconciliations").json()
    assert j["available"] is False and j["error"].startswith("OBSERVER_UNREACHABLE") and j["reconciliations"] == []
    (tmp_path / "rt").write_text("wrong-token")
    monkeypatch.setattr(observer_feed, "_read_http", lambda: relay)
    j = TestClient(app, headers=ADMIN).get("/api/v1/sentinel/observer/reconciliations").json()
    assert j["available"] is False and j["error"] == "OBSERVER_HTTP_401"
    monkeypatch.delenv("QYRIX_OBSERVER_READ_TOKEN_FILE")
    assert TestClient(app, headers=ADMIN).get("/api/v1/sentinel/observer/reconciliations").json()["configured"] is False


def test_relay_never_forwards_an_unexpected_result_value():
    class Fake:
        def get(self, *a, **k):
            return type("R", (), {"status_code": 200, "json": lambda s: {"reconciliations": [
                {"result": "ENFORCEMENT_VERIFIED", "reasons": [], "extra": "x"}]}})()
    import os
    os.environ["QYRIX_OBSERVER_URL"] = "http://observer.test"
    import tempfile
    f = tempfile.NamedTemporaryFile("w", delete=False); f.write("t"); f.close()
    os.environ["QYRIX_OBSERVER_READ_TOKEN_FILE"] = f.name
    try:
        j = observer_feed.fetch_reconciliations("default", Fake())
        assert j["reconciliations"][0]["result"] == "INCONCLUSIVE" and "extra" not in j["reconciliations"][0]
        assert j["reconciliations"][0]["reasons"] == ["UNEXPECTED_RESULT_VALUE"]
    finally:
        del os.environ["QYRIX_OBSERVER_URL"], os.environ["QYRIX_OBSERVER_READ_TOKEN_FILE"]
        os.unlink(f.name)
