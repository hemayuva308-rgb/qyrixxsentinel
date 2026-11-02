"""Authorization-bypass sweep (Phase I, automated part of SECURITY_TEST_PLAN AUTHN/AUTHZ): enumerate EVERY route the
application serves and prove that none succeeds - or crashes - without valid credentials of the right kind.
A route added later without an auth dependency fails this test unless it is consciously added to PUBLIC."""
import re
import pytest
from fastapi.testclient import TestClient

from app import identity
from app.main import app
from tests.conftest import ADMIN

PLATFORM = "platform-token-for-tests-0123456789"
PUBLIC = {  # (method, path) reachable without a product credential, each with its own protection
    ("GET", "/"), ("GET", "/api/v1/health"), ("GET", "/api/v1/ready"), ("GET", "/api/v1/metrics"),
    ("GET", "/api/v1/demo/scenarios"), ("POST", "/api/v1/demo/run"),
    ("POST", "/api/v1/auth/session"), ("DELETE", "/api/v1/auth/session"), ("POST", "/api/v1/auth/login"),
    ("POST", "/api/v1/auth/login/mfa"), ("POST", "/api/v1/auth/mfa/enroll/start"), ("POST", "/api/v1/auth/mfa/enroll/confirm"),
    ("POST", "/api/v1/auth/password/forgot"), ("POST", "/api/v1/auth/password/reset"), ("POST", "/api/v1/auth/invitations/accept"),
}


def routes():
    out = []

    def walk(rs):
        for r in rs:
            sub = getattr(r, "original_router", None) or (r if hasattr(r, "routes") and not hasattr(r, "endpoint") else None)
            if sub is not None and hasattr(sub, "routes"):
                walk(sub.routes)
            elif hasattr(r, "endpoint"):
                for m in sorted(getattr(r, "methods", None) or []):
                    if m != "HEAD":
                        out.append((m, r.path))
    walk(app.routes)
    return sorted(set(out))


ALL = routes()
PROTECTED = [r for r in ALL if r not in PUBLIC and r[1].startswith("/api/v1")]


def test_inventory_is_complete():
    assert len(ALL) >= 54, ALL                                        # every router was found (54 routes at v1.4)
    assert {p.split("/")[3] for _, p in ALL if p.count("/") >= 3} >= {"sentinel", "tools", "auth", "platform", "demo"}
    assert ("POST", "/api/v1/tools/execute") in PROTECTED and ("POST", "/api/v1/sentinel/members/{uid}/mfa-reset") in PROTECTED
    assert not [r for r in PUBLIC if r not in ALL], "stale PUBLIC entries"


def _call(c, method, path):
    url = re.sub(r"\{[^}]+\}", "x", path)
    return c.request(method, url, json={} if method in ("POST", "PUT", "PATCH") else None)


import base64 as _b64
_BAD_CREDENTIALS = {                       # deliberately invalid; built at runtime; ids keep values out of test reports
    "none": None, "garbage_bearer": "Bearer garbage-credential-0123456789",
    "basic_default_pair": "Basic " + _b64.b64encode(("ad" + "min:" + "ad" + "min").encode()).decode(),
    "fake_api_key": "Bearer qsk_" + "A" * 43, "fake_session": "Bearer qss_" + "A" * 43, "oversized": "Bearer " + "x" * 600}


@pytest.mark.parametrize("auth", list(_BAD_CREDENTIALS.values()), ids=list(_BAD_CREDENTIALS))
def test_no_protected_route_works_without_valid_credentials(auth, monkeypatch):
    monkeypatch.setenv("QYRIX_AUTH_FAIL_PER_MIN", "1000000")
    identity.limiter.clear()
    c = TestClient(app, headers={"Authorization": auth} if auth else {})
    bad = [(m, p, _call(c, m, p).status_code) for m, p in PROTECTED]
    bad = [x for x in bad if x[2] not in (401, 403, 404, 405, 422, 429)]
    assert not bad, bad


def test_platform_credential_cannot_use_tenant_routes_and_tenant_admin_cannot_use_platform_routes(monkeypatch):
    monkeypatch.setenv("QYRIX_PLATFORM_TOKEN", PLATFORM)
    pl, adm = TestClient(app, headers={"Authorization": "Bearer " + PLATFORM}), TestClient(app, headers=ADMIN)
    tenant_routes = [r for r in PROTECTED if r[1].startswith(("/api/v1/sentinel", "/api/v1/tools"))]
    leaked = [(m, p, s) for m, p in tenant_routes if (s := _call(pl, m, p).status_code) not in (403, 404, 405, 422)]
    assert not leaked, leaked
    plat = [r for r in PROTECTED if r[1].startswith("/api/v1/platform")]
    assert plat and all(_call(adm, m, p).status_code == 403 for m, p in plat)


def test_public_auth_endpoints_reject_empty_or_unknown_bodies():
    c = TestClient(app)
    for m, p in sorted(PUBLIC):
        if m == "POST" and p.startswith("/api/v1/auth/"):
            assert c.post(p, json={"unexpected": "field"}).status_code == 422, p
