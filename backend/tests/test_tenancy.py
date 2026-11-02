"""Tenant isolation acceptance tests.

Part 1 (no database): multi-tenancy stays OFF unless explicitly enabled AND durable persistence exists (fail closed).
Part 2 (real PostgreSQL): two tenants on one deployment; every cross-tenant read/execute/decide path is refused
(IDOR by id guessing, grants, approvals, proofs, provenance lineage, workspace, allowlist), and PostgreSQL row-level
security independently blocks cross-tenant rows for the application role even if application filtering were wrong."""
import os
import pytest
from fastapi.testclient import TestClient

import app.gateway as g
from app import identity, persistence, tenancy
from app.identity import Principal
from app.main import app
from tests.conftest import ADMIN
from tests.test_persistence import Cluster, HAVE_PG

P = "/api/v1/sentinel"
EX = "/api/v1/tools/execute"
PLATFORM = "platform-token-for-tests-0123456789"


def as_(token):
    return TestClient(app, headers={"Authorization": "Bearer " + token})


# ---------------- part 1: fail-closed enablement ----------------
@pytest.fixture
def memory(monkeypatch):
    monkeypatch.setenv("QYRIX_PLATFORM_TOKEN", PLATFORM)
    identity.use_store(identity.MemoryStore())
    identity.limiter.clear()
    yield
    identity.use_store(identity.MemoryStore())
    with tenancy._lock:
        tenancy._contexts.clear()


def test_tenant_principal_refused_when_multi_tenancy_disabled(memory, monkeypatch):
    monkeypatch.delenv("QYRIX_MULTI_TENANT", raising=False)
    identity.store().create_tenant("acme", "Acme", None)
    k = identity.create_key(Principal(None, "platform", "env:platform"), "acme", "owner", "x", None)["api_key"]
    r = as_(k).get(P + "/status")
    assert r.status_code == 403 and r.json()["detail"] == "MULTI_TENANCY_DISABLED"
    assert as_(PLATFORM).post("/api/v1/platform/tenants/acme/keys", json={}).status_code == 409


def test_multi_tenancy_requires_durable_persistence(memory, monkeypatch):
    monkeypatch.setenv("QYRIX_MULTI_TENANT", "1")
    r = as_(PLATFORM).post("/api/v1/platform/tenants", json={"id": "acme", "name": "Acme"})
    assert r.status_code == 409 and r.json()["detail"] == "PERSISTENCE_REQUIRED"


def test_tenant_context_refuses_without_database(memory, monkeypatch):
    monkeypatch.setenv("QYRIX_MULTI_TENANT", "1")
    for k in ("QYRIX_DATABASE_URL", "QYRIX_DB_HOST"):
        monkeypatch.delenv(k, raising=False)
    identity.store().create_tenant("acme", "Acme", None)
    k = identity.create_key(Principal(None, "platform", "env:platform"), "acme", "owner", "x", None)["api_key"]
    r = as_(k).get(P + "/status")
    assert r.status_code == 503 and r.json()["detail"] == "PERSISTENCE_REQUIRED"


# ---------------- part 2: two tenants on real PostgreSQL ----------------
pg = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = Cluster()
    yield c
    c.destroy()


@pytest.fixture
def mt(cluster, monkeypatch, tmp_path):
    db = "t" + os.urandom(4).hex()
    import psycopg
    with psycopg.connect(cluster.admin_url, autocommit=True) as c:
        c.execute("CREATE DATABASE %s" % db)
    admin = cluster.admin_url.rsplit("/", 1)[0] + "/" + db
    from app import migrate
    migrate.migrate(admin)
    url = cluster.runtime_url(db)
    monkeypatch.setenv("QYRIX_DATABASE_URL", url)
    monkeypatch.setenv("QYRIX_MULTI_TENANT", "1")
    monkeypatch.setenv("QYRIX_PLATFORM_TOKEN", PLATFORM)
    identity.use_store(identity.PgStore(persistence.shared_connection(url)))
    identity.limiter.clear()
    pl = as_(PLATFORM)
    assert pl.post("/api/v1/platform/tenants", json={"id": "acme", "name": "Acme", "approved_domains": ["api.acme.example"]}).status_code == 200
    assert pl.post("/api/v1/platform/tenants", json={"id": "globex", "name": "Globex"}).status_code == 200
    a = pl.post("/api/v1/platform/tenants/acme/keys", json={"role": "owner"}).json()["api_key"]
    b = pl.post("/api/v1/platform/tenants/globex/keys", json={"role": "owner"}).json()["api_key"]
    yield {"url": url, "admin": admin, "a": as_(a), "b": as_(b), "a_key": a, "b_key": b}
    with tenancy._lock:
        tenancy._contexts.clear()
    identity.use_store(identity.MemoryStore())


def _evaluate_file(c, name):
    return c.post(P + "/gate/evaluate", json={"tool": "file.read", "dest": name}).json()


@pg
def test_contexts_are_separate_objects_with_separate_state(mt):
    ra = _evaluate_file(mt["a"], "README.md")
    sa = mt["a"].get(P + "/status").json()
    sb = mt["b"].get(P + "/status").json()
    assert sa["tenant"] == "acme" and sb["tenant"] == "globex"
    assert sa["persistence"] == "postgres" and sb["persistence"] == "postgres"
    assert len(mt["b"].get(P + "/proofs").json()["chain"]) == 0 < len(mt["a"].get(P + "/proofs").json()["chain"])
    assert ra["gate_evaluation_id"] not in str(mt["b"].get(P + "/proofs").json())
    assert len(g.PROD.chain) == 0 or all(ra["gate_evaluation_id"] not in str(r) for r in g.PROD.chain)


@pg
def test_cross_tenant_grant_execution_is_refused(mt):
    ws_a = os.path.join(g.WORKSPACE, "tenants", "acme")
    os.makedirs(ws_a, exist_ok=True)
    with open(os.path.join(ws_a, "notes.txt"), "w") as f:
        f.write("acme only")
    ra = _evaluate_file(mt["a"], "notes.txt")
    assert ra["verdict"] == "ALLOW", ra
    body = {"gate_evaluation_id": ra["gate_evaluation_id"], "grant_id": ra["grant_id"]}
    rb = mt["b"].post(EX, json=body)
    assert rb.status_code in (403, 404, 409) and rb.json().get("executed") is not True
    ok = mt["a"].post(EX, json=body)                         # the stolen-and-tried grant is still the owner's, unused
    assert ok.status_code == 200 and "acme only" in str(ok.json())


@pg
def test_workspaces_are_isolated(mt):
    ws_b = os.path.join(g.WORKSPACE, "tenants", "globex")
    os.makedirs(ws_b, exist_ok=True)
    with open(os.path.join(ws_b, "secret-plan.txt"), "w") as f:
        f.write("globex only")
    ra = _evaluate_file(mt["a"], "secret-plan.txt")
    if ra.get("verdict") == "ALLOW":
        ex = mt["a"].post(EX, json={"gate_evaluation_id": ra["gate_evaluation_id"], "grant_id": ra["grant_id"]})
        assert "globex only" not in ex.text
    ra = _evaluate_file(mt["a"], "../globex/secret-plan.txt")
    assert ra["verdict"] != "ALLOW"


@pg
def test_cross_tenant_approvals_and_revocation_are_refused(mt):
    ap = mt["a"].post(P + "/approvals", json={"method": "DELETE", "dest": "https://api.acme.example/v1/x"}).json()
    assert mt["b"].post("%s/approvals/%s/approve" % (P, ap["id"])).status_code == 404
    assert all(x["id"] != ap["id"] for x in mt["b"].get(P + "/approvals").json()["approvals"])
    ra = _evaluate_file(mt["a"], "README.md")
    r = mt["b"].post("%s/grants/%s/revoke" % (P, ra["grant_id"]))     # same answer as for a non-existent grant
    assert r.status_code == 409 and r.json()["detail"] == "GRANT_NOT_REVOCABLE"
    assert mt["b"].post(P + "/grants/grt_doesnotexist/revoke").json()["detail"] == "GRANT_NOT_REVOCABLE"
    ex = mt["a"].post(EX, json={"gate_evaluation_id": ra["gate_evaluation_id"], "grant_id": ra["grant_id"]})
    assert ex.status_code == 200                                # the owner's grant was not revoked by the other tenant


@pg
def test_cross_tenant_provenance_lineage_is_refused(mt):
    sid = mt["a"].post(P + "/provenance/step", json={"label": "TRUSTED", "text": "acme instruction"}).json()["id"]
    assert mt["b"].get(P + "/provenance/%s" % sid).status_code == 404
    r = mt["b"].post(P + "/gate/evaluate", json={"tool": "file.read", "dest": "README.md", "lineage": [sid]}).json()
    assert r["verdict"] != "ALLOW"                          # another tenant's step is unknown lineage => blocked


@pg
def test_allowlists_are_per_tenant_and_default_deny(mt):
    a = mt["a"].post(P + "/gate/evaluate", json={"tool": "http", "method": "GET", "dest": "https://api.acme.example/v1/ping"}).json()
    b = mt["b"].post(P + "/gate/evaluate", json={"tool": "http", "method": "GET", "dest": "https://api.acme.example/v1/ping"}).json()
    c = mt["b"].post(P + "/gate/evaluate", json={"tool": "http", "method": "GET", "dest": "https://api.example.com/v1/ping"}).json()
    assert a["verdict"] == "ALLOW" and b["verdict"] != "ALLOW" and c["verdict"] != "ALLOW"


@pg
def test_keys_are_tenant_scoped(mt):
    assert all(k["tenant_id"] == "acme" for k in mt["a"].get(P + "/keys").json()["keys"])
    kid = mt["b"].get(P + "/keys").json()["keys"][0]["id"]
    assert mt["a"].post(P + "/keys/%s/revoke" % kid).status_code == 404
    assert mt["b"].get(P + "/status").status_code == 200


@pg
def test_disabling_a_tenant_cuts_keys_and_sessions(mt):
    s = TestClient(app).post("/api/v1/auth/session", json={"credential": mt["b_key"]}).json()["session_token"]
    assert as_(s).get(P + "/status").status_code == 200
    assert as_(PLATFORM).post("/api/v1/platform/tenants/globex/disable").status_code == 200
    assert mt["b"].get(P + "/status").status_code == 401
    assert as_(s).get(P + "/status").status_code == 401
    assert mt["a"].get(P + "/status").status_code == 200


@pg
def test_default_tenant_admin_cannot_reach_other_tenants(mt):
    adm = TestClient(app, headers=ADMIN)
    ra = _evaluate_file(mt["a"], "README.md")
    assert ra["gate_evaluation_id"] not in adm.get(P + "/proofs").text
    assert adm.get("/api/v1/platform/tenants").status_code == 403


@pg
def test_row_level_security_blocks_cross_tenant_rows_for_the_runtime_account(mt):
    """Through the API two tenants write data; then, connected as the backend's own runtime login (no role switch),
    the other tenant's rows are invisible and cannot be forged. Full adversarial suite: test_db_privileges.py."""
    _evaluate_file(mt["a"], "README.md")
    mt["a"].post(P + "/provenance/step", json={"label": "TRUSTED", "text": "acme"})
    import psycopg, uuid as _u
    with psycopg.connect(mt["url"]) as c:
        with c.transaction():
            c.execute("SELECT set_config('qyrix.tenant_id', 'globex', true)")
            for t in ("gate_evaluations", "provenance_steps", "proof_records", "api_keys", "sessions"):
                assert c.execute("SELECT count(tenant_id) FROM %s WHERE tenant_id = 'acme'" % t).fetchone()[0] == 0, t
        with c.transaction():
            c.execute("SELECT set_config('qyrix.tenant_id', 'acme', true)")
            assert c.execute("SELECT count(*) FROM gate_evaluations").fetchone()[0] >= 1      # positive control
        with c.transaction():
            assert c.execute("SELECT count(*) FROM gate_evaluations").fetchone()[0] == 0      # no tenant => nothing
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="row-level security"):
            with c.transaction():
                c.execute("SELECT set_config('qyrix.tenant_id', 'globex', true)")
                c.execute("INSERT INTO provenance_steps (tenant_id, id, source, declared_label, effective_label, created_at)"
                          " VALUES ('acme', %s, 'x', 'TRUSTED', 'TRUSTED', now())", (str(_u.uuid4()),))
    with psycopg.connect(mt["admin"]) as c:                    # ground truth (admin): both tenants really have data
        assert c.execute("SELECT count(DISTINCT tenant_id) FROM proof_records").fetchone()[0] >= 1


@pg
def test_unbuildable_tenant_context_fails_closed(mt, monkeypatch, tmp_path):
    """Regression (found on the read-only container): an unwritable tenant workspace must give 503, not 500 or a
    half-built context, and the next request retries cleanly once the cause is fixed."""
    blocker = tmp_path / "not-a-dir"; blocker.write_text("x")
    monkeypatch.setenv("QYRIX_TENANT_WORKSPACE_ROOT", str(blocker))
    r = mt["a"].get(P + "/status")
    assert r.status_code == 503 and r.json()["detail"] == "TENANT_CONTEXT_UNAVAILABLE"
    assert "acme" not in tenancy.loaded()
    monkeypatch.setenv("QYRIX_TENANT_WORKSPACE_ROOT", str(tmp_path / "ok"))
    assert mt["a"].get(P + "/status").status_code == 200


@pg
def test_duplicate_and_unknown_tenants_are_clean_errors(mt):
    """Regression (found on the live stack): duplicate tenant => 409 and unknown tenant disable => 404, never 500."""
    pl = as_(PLATFORM)
    r = pl.post("/api/v1/platform/tenants", json={"id": "acme", "name": "Again"})
    assert r.status_code == 409 and r.json()["detail"] == "TENANT_EXISTS"
    assert pl.post("/api/v1/platform/tenants/nope-tenant/disable").status_code == 404
    assert pl.post("/api/v1/platform/tenants/default/disable").status_code == 404
    assert mt["a"].get(P + "/status").json()["tenant"] == "acme"
    assert TestClient(app, headers=ADMIN).get(P + "/status").json()["tenant"] == "default"


@pg
def test_client_supplied_tenant_hints_are_ignored(mt):
    """The tenant comes only from the authenticated credential: headers, query strings and body fields cannot select it."""
    ra = _evaluate_file(mt["a"], "README.md")
    hints = {"X-Qyrix-Tenant": "acme", "X-Tenant-Id": "acme", "X-Forwarded-Tenant": "acme"}
    b = TestClient(app, headers={"Authorization": "Bearer " + mt["b_key"], **hints})
    assert b.get(P + "/status?tenant=acme&tenant_id=acme").json()["tenant"] == "globex"
    assert ra["gate_evaluation_id"] not in b.get(P + "/proofs?tenant=acme").text
    r = b.post(P + "/gate/evaluate", json={"tool": "file.read", "dest": "README.md", "tenant": "acme"})
    assert r.status_code == 422                                   # unknown body fields are refused, not ignored
