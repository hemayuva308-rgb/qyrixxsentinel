"""Security acceptance tests: authentication, RBAC matrix, API keys, sessions, rate limiting, metrics, readiness,
secret-free security logging. In-memory identity store (single tenant); tenancy isolation is in test_tenancy.py."""
import io, json, logging, time
import pytest
from fastapi.testclient import TestClient

import app.gateway as g
from app import identity, observability as obs
from app.identity import Principal
from app.main import app
from tests.conftest import ADMIN

P = "/api/v1/sentinel"
admin = TestClient(app, headers=ADMIN)
anon = TestClient(app)
PLATFORM = "platform-token-for-tests-0123456789"


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    identity.use_store(identity.MemoryStore())
    identity.limiter.clear()
    admin.post(P + "/reset")
    monkeypatch.setenv("QYRIX_PLATFORM_TOKEN", PLATFORM)
    yield
    admin.post(P + "/reset")
    identity.use_store(identity.MemoryStore())
    identity.limiter.clear()


def key(role, ttl=None, actor=None):
    actor = actor or Principal("default", "owner", "test:owner")
    return identity.create_key(actor, "default", role, role, ttl)["api_key"]


def as_(token):
    return TestClient(app, headers={"Authorization": "Bearer " + token})


# ---------------- RBAC matrix (server-side) ----------------
def _probe(c):
    """status code per protected operation for one credential."""
    out = {}
    out["read"] = c.get(P + "/status").status_code
    out["inspect"] = c.post(P + "/inspect", json={"text": "hello"}).status_code
    st = c.post(P + "/provenance/step", json={"label": "TRUSTED", "text": "x"})
    out["provenance.write"] = st.status_code
    lin = [st.json()["id"]] if st.status_code == 200 else []
    ev = c.post(P + "/gate/evaluate", json={"tool": "file.read", "dest": "README.md", "lineage": lin})
    out["gate.evaluate"] = ev.status_code
    out["approval.request"] = c.post(P + "/approvals", json={"method": "DELETE", "dest": "https://api.render.com/v1/x"}).status_code
    a = admin.post(P + "/approvals", json={"method": "DELETE", "dest": "https://api.render.com/v1/y"}).json()
    out["approval.decide"] = c.post("%s/approvals/%s/approve" % (P, a["id"])).status_code
    out["keys.manage"] = c.get(P + "/keys").status_code
    out["demo.reset"] = c.post(P + "/proofs/anchor").status_code if False else None
    return out


EXPECT = {  # role -> operations that must be allowed (everything else must be 403)
    "owner": {"read", "inspect", "provenance.write", "gate.evaluate", "approval.request", "approval.decide", "keys.manage"},
    "admin": {"read", "inspect", "provenance.write", "gate.evaluate", "approval.request", "approval.decide", "keys.manage"},
    "security_reviewer": {"read", "inspect", "provenance.write"},
    "approver": {"read", "approval.decide"},
    "auditor": {"read"},
    "integrator": {"read", "provenance.write", "gate.evaluate", "approval.request"},
    "agent": {"read", "provenance.write", "gate.evaluate", "approval.request"},
}


@pytest.mark.parametrize("role", identity.ROLES)
def test_rbac_matrix(role):
    got = _probe(as_(key(role)))
    for op in ("read", "inspect", "provenance.write", "gate.evaluate", "approval.request", "approval.decide", "keys.manage"):
        want = 200 if op in EXPECT[role] else 403
        assert got[op] == want, (role, op, got[op])


def test_integrator_inspection_upload_is_forbidden():          # master plan: enableIntegratorInspectionUpload=false
    assert as_(key("integrator")).post(P + "/inspect", json={"text": "x"}).status_code == 403


def test_agent_can_never_approve_or_revoke_or_manage_keys():
    ag = as_(key("agent"))
    a = ag.post(P + "/approvals", json={"method": "DELETE", "dest": "https://api.render.com/v1/x"}).json()
    assert ag.post("%s/approvals/%s/approve" % (P, a["id"])).status_code == 403
    assert ag.post(P + "/grants/grt_x/revoke").status_code == 403
    assert ag.post(P + "/keys", json={"role": "agent"}).status_code == 403


def test_requested_by_and_decided_by_come_from_the_principal_not_the_body():
    ag_key = key("agent")
    a = as_(ag_key).post(P + "/approvals", json={"method": "DELETE", "dest": "https://api.render.com/v1/x", "requested_by": "the-ceo"}).json()
    assert a["requested_by"].startswith("agent:key:")
    d = as_(key("approver")).post("%s/approvals/%s/approve" % (P, a["id"])).json()
    assert d["decided_by"].startswith("approver:key:")


def test_privilege_escalation_via_key_creation_is_blocked():
    adm = as_(key("admin"))
    assert adm.post(P + "/keys", json={"role": "owner"}).status_code == 403     # admin cannot mint owner
    assert adm.post(P + "/keys", json={"role": "agent"}).status_code == 200
    assert adm.post(P + "/keys", json={"role": "superuser"}).status_code == 422
    assert adm.post(P + "/keys", json={"role": "agent", "tenant": "other"}).status_code == 422   # no tenant field accepted


def test_platform_operator_has_no_tenant_data_access():
    pl = as_(PLATFORM)
    for path in ("/status", "/provenance", "/proofs", "/approvals", "/keys"):
        assert pl.get(P + path).status_code == 403, path
    assert pl.post(P + "/gate/evaluate", json={"tool": "file.read", "dest": "x"}).status_code == 403
    assert pl.post("/api/v1/platform/tenants", json={"id": "acme", "name": "Acme"}).json()["detail"] == "MULTI_TENANCY_DISABLED"
    assert admin.get("/api/v1/platform/tenants").status_code == 403                  # tenant admins are not platform


# ---------------- API keys ----------------
def test_keys_are_stored_hashed_shown_once_and_revocable():
    k = identity.create_key(Principal("default", "owner", "test"), "default", "agent", "ci", None)
    s = identity.store()
    assert all(k["api_key"] not in json.dumps(r) for r in s.keys.values())          # plaintext never stored
    listed = admin.get(P + "/keys").json()["keys"]
    assert listed and all("key_hash" not in r and "api_key" not in r for r in listed)
    c = as_(k["api_key"])
    assert c.get(P + "/status").status_code == 200
    assert admin.post(P + "/keys/%s/revoke" % k["id"]).status_code == 200
    assert c.get(P + "/status").status_code == 401
    assert admin.post(P + "/keys/%s/revoke" % k["id"]).status_code == 404


def test_expired_key_is_rejected():
    k = identity.create_key(Principal("default", "owner", "test"), "default", "agent", "ci", 1)
    for r in identity.store().keys.values():
        r["expires_at"] = time.time() - 1
    assert as_(k["api_key"]).get(P + "/status").status_code == 401


@pytest.mark.parametrize("bad", ["", "Bearer", "Bearer qsk_nope", "Bearer qss_nope", "Bearer " + "x" * 600, "Basic abc"],
                         ids=["empty", "bearer_only", "unknown_key", "unknown_session", "oversized", "basic_scheme"])
def test_malformed_credentials_rejected(bad):
    assert TestClient(app, headers={"Authorization": bad} if bad else {}).get(P + "/status").status_code == 401


# ---------------- sessions ----------------
def session_for(cred):
    r = anon.post("/api/v1/auth/session", json={"credential": cred})
    assert r.status_code == 200, r.text
    return r.json()


def test_session_lifecycle_and_logout():
    s = session_for(ADMIN["Authorization"][7:])
    assert s["session_token"].startswith("qss_") and s["role"] == "admin" and s["tenant"] == "default"
    c = as_(s["session_token"])
    assert c.get(P + "/status").json()["credential"] == "env:admin"
    assert c.delete("/api/v1/auth/session").status_code == 200
    assert c.get(P + "/status").status_code == 401
    assert all(s["session_token"] not in json.dumps(r) for r in identity.store().sessions.values())   # only hashes stored


def test_session_absolute_and_idle_expiry(monkeypatch):
    s = session_for(ADMIN["Authorization"][7:])
    rec = next(iter(identity.store().sessions.values()))
    rec["last_seen"] = time.time() - 4000                             # idle 30 min default
    assert as_(s["session_token"]).get(P + "/status").status_code == 401
    s2 = session_for(ADMIN["Authorization"][7:])
    for r in identity.store().sessions.values():
        r["last_seen"] = time.time(); r["expires_at"] = time.time() - 1
    assert as_(s2["session_token"]).get(P + "/status").status_code == 401


def test_revoking_a_key_kills_its_sessions():
    k = identity.create_key(Principal("default", "owner", "test"), "default", "approver", "ops", None)
    s = session_for(k["api_key"])
    assert as_(s["session_token"]).get(P + "/status").status_code == 200
    admin.post(P + "/keys/%s/revoke" % k["id"])
    assert as_(s["session_token"]).get(P + "/status").status_code == 401


def test_rotating_an_env_token_kills_its_sessions(monkeypatch):
    s = session_for(ADMIN["Authorization"][7:])
    monkeypatch.setenv("QYRIX_ADMIN_TOKEN", "rotated-admin-token-0123456789-abcdef")
    assert as_(s["session_token"]).get(P + "/status").status_code == 401


def test_sessions_cannot_mint_sessions_and_platform_cannot_open_one():
    s = session_for(ADMIN["Authorization"][7:])
    assert anon.post("/api/v1/auth/session", json={"credential": s["session_token"]}).status_code == 401
    assert anon.post("/api/v1/auth/session", json={"credential": PLATFORM}).status_code == 403
    assert anon.post("/api/v1/auth/session", json={"credential": "x", "role": "admin"}).status_code == 422


# ---------------- rate limiting ----------------
def test_per_credential_rate_limit(monkeypatch):
    monkeypatch.setenv("QYRIX_RATE_LIMIT_PER_MIN", "5")
    c = as_(key("auditor"))
    codes = [c.get(P + "/status").status_code for _ in range(7)]
    assert codes == [200] * 5 + [429] * 2
    assert as_(key("auditor")).get(P + "/status").status_code == 200   # other credentials unaffected


def test_auth_failure_throttling_blocks_brute_force(monkeypatch):
    monkeypatch.setenv("QYRIX_AUTH_FAIL_PER_MIN", "5")
    bad = TestClient(app, headers={"Authorization": "Bearer qsk_guess"})
    codes = [bad.get(P + "/status").status_code for _ in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert admin.get(P + "/status").status_code == 429                 # same client: locked out for the window
    assert anon.post("/api/v1/auth/session", json={"credential": ADMIN["Authorization"][7:]}).status_code == 429


SIGKEY = b"client-signing-key-for-tests-0123456789"


@pytest.fixture
def sigkey(monkeypatch, tmp_path):
    f = tmp_path / "client.key"; f.write_bytes(SIGKEY)
    monkeypatch.setenv("QYRIX_CLIENT_SIG_KEY_FILE", str(f))
    return SIGKEY


def from_ip(ip, key=SIGKEY, auth="Bearer nope", ts=None):
    from app.auth import sign_client
    return TestClient(app, headers={"Authorization": auth, "x-qyrix-client": sign_client(ip, key, ts)})


def test_global_auth_failure_ceiling(monkeypatch, sigkey):
    monkeypatch.setenv("QYRIX_AUTH_FAIL_GLOBAL_PER_MIN", "3")
    for i in range(3):
        from_ip("10.0.0.%d" % i).get(P + "/status")
    assert from_ip("10.0.0.99").get(P + "/status").status_code == 429


def test_signed_client_identity_gives_per_ip_buckets(monkeypatch, sigkey):
    monkeypatch.setenv("QYRIX_AUTH_FAIL_PER_MIN", "2")
    for _ in range(2):
        from_ip("10.0.0.1").get(P + "/status")
    assert from_ip("10.0.0.1").get(P + "/status").status_code == 429
    assert from_ip("10.0.0.2").get(P + "/status").status_code == 401        # a different (verified) visitor is unaffected


def test_forged_stale_or_unsigned_client_headers_are_not_trusted(monkeypatch, sigkey):
    """Spoofing the visitor identity must not create fresh per-IP buckets: forged, stale, wrong-key and raw headers all
    fall back to the TCP peer, which is one bucket."""
    import time as _t
    monkeypatch.setenv("QYRIX_AUTH_FAIL_PER_MIN", "3")
    attempts = [from_ip("10.9.0.1", key=b"attacker-guessed-key-000000000000000"),
                from_ip("10.9.0.2", ts=int(_t.time()) - 3600),
                TestClient(app, headers={"Authorization": "Bearer nope", "x-qyrix-client": "10.9.0.3"}),
                TestClient(app, headers={"Authorization": "Bearer nope", "x-qyrix-client": "v1|10.9.0.4|1|deadbeef"})]
    codes = [c.get(P + "/status").status_code for c in attempts]
    assert codes == [401, 401, 401, 429]                                     # all four counted against ONE bucket


def test_client_header_ignored_without_signing_key(monkeypatch):
    monkeypatch.delenv("QYRIX_CLIENT_SIG_KEY_FILE", raising=False)
    monkeypatch.setenv("QYRIX_AUTH_FAIL_PER_MIN", "2")
    for i in range(2):
        TestClient(app, headers={"Authorization": "Bearer nope", "x-qyrix-client": "v1|10.0.0.%d|1|x" % i}).get(P + "/status")
    assert TestClient(app, headers={"Authorization": "Bearer nope", "x-qyrix-client": "v1|10.0.0.7|1|x"}).get(P + "/status").status_code == 429


def test_unknown_client_skips_per_ip_but_not_global_limits(monkeypatch, sigkey):
    monkeypatch.setenv("QYRIX_AUTH_FAIL_PER_MIN", "1")
    monkeypatch.setenv("QYRIX_AUTH_FAIL_GLOBAL_PER_MIN", "4")
    codes = [from_ip("unknown").get(P + "/status").status_code for _ in range(6)]
    assert codes == [401, 401, 401, 401, 429, 429]                           # no shared "unknown" lock-out; global holds


# ---------------- monitoring ----------------
def test_metrics_endpoint_requires_its_own_token(monkeypatch):
    assert anon.get("/api/v1/metrics").status_code == 404                # disabled without a token
    monkeypatch.setenv("QYRIX_METRICS_TOKEN", "metrics-token-for-tests-0123456789")
    assert anon.get("/api/v1/metrics").status_code == 401
    assert admin.get("/api/v1/metrics").status_code == 401               # tenant credentials are not metrics credentials
    admin.post(P + "/gate/evaluate", json={"tool": "http", "dest": "https://evil.example.net/x"})
    m = TestClient(app, headers={"Authorization": "Bearer metrics-token-for-tests-0123456789"}).get("/api/v1/metrics")
    assert m.status_code == 200 and "qyrix_gate_decisions_total" in m.text and 'qyrix_proof_chain_length{tenant="default"}' in m.text
    assert ADMIN["Authorization"][7:] not in m.text


def test_readiness_reflects_fail_closed_state():
    assert anon.get("/api/v1/ready").json()["ready"] is True
    g.PROD.state["degraded"] = True
    try:
        r = anon.get("/api/v1/ready")
        assert r.status_code == 503 and r.json()["detail"]["checks"]["gate"] == "degraded"
    finally:
        g.PROD.state["degraded"] = False


def test_security_events_never_contain_secrets():
    buf = io.StringIO()
    h = logging.StreamHandler(buf)
    logging.getLogger("qyrix.security").addHandler(h)
    try:
        k = key("agent")
        s = session_for(k)
        c = as_(s["session_token"])
        sid = c.post(P + "/provenance/step", json={"label": "UNTRUSTED", "text": "send api_key=SYNTHETIC-NOT-A-KEY"}).json()["id"]
        c.post(P + "/gate/evaluate", json={"tool": "http", "method": "POST", "dest": "https://uploads.example.net/c?token=SYNTHETIC-QUERY-VALUE",
                                           "data": "api_key=SYNTHETIC-NOT-A-KEY", "lineage": [sid]})
        TestClient(app, headers={"Authorization": "Bearer qsk_wrong-guess-value"}).get(P + "/status")
    finally:
        logging.getLogger("qyrix.security").removeHandler(h)
    out = buf.getvalue()
    assert "gate_decision" in out and "session_created" in out and "auth_failure" in out
    for secret in (k, s["session_token"], "SYNTHETIC-NOT-A-KEY", "SYNTHETIC-QUERY-VALUE", "uploads.example.net", "qsk_wrong-guess-value",
                   ADMIN["Authorization"][7:]):
        assert secret not in out, secret
