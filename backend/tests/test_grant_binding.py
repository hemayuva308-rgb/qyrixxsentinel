"""v1.5 P1: agent-, task- and policy-version-bound grants (in-memory + REST + MCP). PostgreSQL-level checks (migration 007,
atomic SQL binding, runtime privileges, restart) are in tests/test_grant_binding_pg.py."""
import json
import threading

import pytest
from fastapi.testclient import TestClient

from app import adapter, gateway as g, identity, mcp_proxy as mp, netguard
from app.main import app
from tests.conftest import ADMIN, AGENT

P = "/api/v1/sentinel"
EX, RD = "/api/v1/tools/execute", "/api/v1/tools/redeem"
admin = TestClient(app, headers=ADMIN)
agent = TestClient(app, headers=AGENT)
_second = {}


def agent2():
    """A second, distinct agent credential (API key) in the same tenant."""
    if "c" not in _second:
        k = admin.post(P + "/keys", json={"role": "agent", "name": "second-agent"}).json()["api_key"]
        _second["c"] = TestClient(app, headers={"Authorization": "Bearer " + k})
    return _second["c"]


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.delenv("QYRIX_REQUIRE_TASK_ID", raising=False)
    identity.limiter.clear()
    admin.post(P + "/reset")


def allow(client=agent, task=None, dest="https://github.com/qyrix"):
    body = {"tool": "http", "method": "GET", "dest": dest}
    if task:
        body["task_id"] = task
    r = client.post(P + "/gate/evaluate", json=body).json()
    assert r["verdict"] == "ALLOW", r
    return r


def red(r, client=agent, task=None, **extra):
    body = {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"], "params_digest": r["params_digest"], **extra}
    if task:
        body["task_id"] = task
    return client.post(RD, json=body)


def ex(r, client=agent, task=None):
    body = {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}
    if task:
        body["task_id"] = task
    return client.post(EX, json=body)


def code(resp):
    return resp.status_code, resp.json().get("detail")


# ---------------- binding is recorded ----------------
def test_decision_and_grant_record_agent_task_and_policy_version():
    r = allow(task="ticket-42")
    assert r["task_id"] == "ticket-42" and len(r["policy_version"]) == 64
    gr = g.PROD.grants[r["grant_id"]]
    assert gr["agent_id"] == "env:agent" and gr["task_id"] == "ticket-42" and gr["policy_version"] == r["policy_version"]
    assert r["proof"]["agent_id"] == "env:agent" and r["proof"]["task_id"] == "ticket-42" and r["proof"]["policy_version"] == r["policy_version"]


# ---------------- cross-agent ----------------
@pytest.mark.parametrize("path", ["redeem", "execute"])
def test_cross_agent_use_is_refused_and_does_not_consume(path):
    r = allow()
    for other in (agent2(), admin):                                   # another agent key, and even the admin token
        resp = red(r, other) if path == "redeem" else ex(r, other)
        assert code(resp) == (403, "GRANT_AGENT_MISMATCH")
    ok = red(r) if path == "redeem" else ex(r)                        # the rightful agent can still use it once
    assert ok.status_code == 200
    assert code(red(r) if path == "redeem" else ex(r)) == (409, "GRANT_REPLAY")


# ---------------- cross-task ----------------
def test_cross_task_and_task_presence_must_match():
    a = allow(task="task-A")
    assert code(red(a, task="task-B")) == (403, "GRANT_TASK_MISMATCH")
    assert code(red(a)) == (403, "GRANT_TASK_MISMATCH")                # task-bound grant without the task
    assert red(a, task="task-A").status_code == 200
    n = allow()                                                         # grant issued with no task
    assert code(red(n, task="task-A")) == (403, "GRANT_TASK_MISMATCH")
    assert red(n).status_code == 200


def test_cross_task_on_execute_path():
    a = allow(task="task-A")
    assert code(ex(a, task="task-B")) == (403, "GRANT_TASK_MISMATCH")
    assert code(ex(a)) == (403, "GRANT_TASK_MISMATCH")


@pytest.mark.parametrize("bad", ["", "has space", "x" * 65, "semi;colon", 5, ["a"]])
def test_invalid_task_ids_are_rejected(bad):
    assert agent.post(P + "/gate/evaluate", json={"tool": "http", "dest": "https://github.com", "task_id": bad}).status_code == 422
    r = allow()
    resp = agent.post(RD, json={"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"],
                                "params_digest": r["params_digest"], "task_id": bad})
    assert code(resp) == (400, "TASK_ID_INVALID")


# ---------------- REQUIRE_TASK_ID ----------------
def test_require_task_id_blocks_allow_without_task(monkeypatch):
    monkeypatch.setenv("QYRIX_REQUIRE_TASK_ID", "1")
    r = agent.post(P + "/gate/evaluate", json={"tool": "http", "method": "GET", "dest": "https://github.com/x"}).json()
    assert r["verdict"] == "BLOCK" and "R18_TASK_ID_REQUIRED" in r["rules"] and r["grant_id"] is None
    ok = allow(task="t-1")
    assert ok["verdict"] == "ALLOW" and red(ok, task="t-1").status_code == 200


def test_require_task_id_off_by_default():
    r = agent.post(P + "/gate/evaluate", json={"tool": "http", "method": "GET", "dest": "https://github.com/x"}).json()
    assert r["verdict"] == "ALLOW" and "R18_TASK_ID_REQUIRED" not in r["rules"]


# ---------------- policy version: canonical + every input invalidates ----------------
def test_policy_version_is_deterministic_and_canonical(monkeypatch):
    monkeypatch.setenv("QYRIX_APPROVED_DOMAINS", "b.example,a.example")
    v1 = g.policy_version(g.PROD)
    monkeypatch.setenv("QYRIX_APPROVED_DOMAINS", " A.example , b.example , a.example.")   # order/case/dupes/space/dot
    assert g.policy_version(g.PROD) == v1
    inputs = g.policy_inputs(g.PROD)
    assert json.loads(json.dumps(inputs, sort_keys=True)) == inputs
    assert set(inputs) == {"engine", "approved_domains", "workspace", "executable_tools", "adapters", "require_task_id",
                           "max_redirects", "max_file_bytes", "detectors", "state_changing_methods"}


def _change_domains(mp_):
    mp_.setenv("QYRIX_APPROVED_DOMAINS", ",".join(netguard.approved_domains() + ("newly-approved.example",)))


POLICY_CHANGES = {
    "approved_domains": _change_domains,
    "workspace": lambda m: m.setattr(g.PROD, "workspace", g.PROD.workspace + "-moved"),
    "executable_tools": lambda m: m.setattr(g, "TOOLS", g.TOOLS + ("file.write",)),
    "adapters": lambda m: m.setitem(g.PROD.adapters, "extra", adapter.HttpAdapter()),
    "require_task_id": lambda m: m.setenv("QYRIX_REQUIRE_TASK_ID", "1"),
    "max_redirects": lambda m: m.setattr(g, "MAX_REDIRECTS", g.MAX_REDIRECTS + 1),
    "max_file_bytes": lambda m: m.setattr(adapter, "MAX_FILE_BYTES", adapter.MAX_FILE_BYTES + 1),
    "engine": lambda m: m.setattr(g, "POLICY_ENGINE_VERSION", g.POLICY_ENGINE_VERSION + "-next"),
    "secret_detector": lambda m: m.setattr(g, "SECRET", g.re.compile(g.SECRET.pattern + "|newsecret", g.re.I)),
    "inject_detector": lambda m: m.setattr(g, "INJECT", g.re.compile(g.INJECT.pattern + "|x", g.re.I)),
    "cmds_detector": lambda m: m.setattr(g, "CMDS", g.re.compile(g.CMDS.pattern + "|y", g.re.I)),
    "tlds": lambda m: m.setattr(g, "_TLDS", g._TLDS | {"zz"}),
    "state_changing_methods": lambda m: m.setattr(g, "STATE_CHANGING", g.STATE_CHANGING - {"PATCH"}),
}


@pytest.mark.parametrize("name", list(POLICY_CHANGES))
def test_each_policy_input_change_invalidates_outstanding_grants(name, monkeypatch):
    r1, r2 = allow(task="t1"), allow(task="t2")
    before = g.policy_version(g.PROD)
    POLICY_CHANGES[name](monkeypatch)
    assert g.policy_version(g.PROD) != before, name
    assert code(red(r1, task="t1")) == (409, "GRANT_POLICY_CHANGED")
    assert code(ex(r2, task="t2")) == (409, "GRANT_POLICY_CHANGED")


def test_unchanged_policy_keeps_grant_valid():
    r = allow()
    assert g.policy_version(g.PROD) == r["policy_version"] and red(r).status_code == 200


# ---------------- replay, expiry, tampering ----------------
def test_replay_and_expiry_still_enforced():
    r = allow(task="t")
    assert red(r, task="t").status_code == 200
    assert code(red(r, task="t")) == (409, "GRANT_REPLAY")
    e = allow()
    g.PROD.grants[e["grant_id"]]["exp"] = 0
    assert code(red(e)) == (409, "GRANT_EXPIRED")


def test_argument_tampering_refused():
    r = allow()
    assert code(red(r, params_digest="f" * 64)) == (403, "PARAMS_DIGEST_MISMATCH")
    assert red(r).status_code == 200                                  # tampering attempt did not consume it


def test_foreign_agent_learns_nothing_about_grant_state():
    r = allow()
    assert red(r).status_code == 200
    assert code(red(r, agent2())) == (403, "GRANT_AGENT_MISMATCH")    # not GRANT_REPLAY


# ---------------- concurrency ----------------
def test_concurrent_mixed_callers_exactly_one_success():
    r = allow(task="race")
    other = agent2()
    results, barrier = [], threading.Barrier(12)

    def go(client, task):
        barrier.wait()
        resp = red(r, client, task=task)
        results.append((resp.status_code, resp.json().get("detail")))
    plan = [(agent, "race")] * 6 + [(other, "race")] * 3 + [(agent, "other-task")] * 3
    ts = [threading.Thread(target=go, args=p) for p in plan]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count((200, None)) == 1
    assert results.count((409, "GRANT_REPLAY")) == 5
    assert results.count((403, "GRANT_AGENT_MISMATCH")) == 3 and results.count((403, "GRANT_TASK_MISMATCH")) == 3


# ---------------- internal callers stay consistent ----------------
def test_internal_unbound_grant_cannot_be_used_by_an_api_caller():
    d = g.evaluate(g.Action(tool="http", method="GET", dest="https://github.com/internal"), g.PROD)   # no principal
    assert d["verdict"] == "ALLOW" and g.PROD.grants[d["grant_id"]]["agent_id"] is None
    assert code(red(d)) == (403, "GRANT_AGENT_MISMATCH")


# ---------------- MCP proxy ----------------
from tests.test_mcp_proxy import Harness  # noqa: E402  (reuses the real stdio MCP server fixture)


def test_mcp_proxy_binds_task_and_agent(tmp_path):
    h = Harness(tmp_path, task_id="mcp-task-1")
    try:
        r = h.call(1, "echo", {"url": "https://github.com/mcp", "text": "hi"})["result"]
        assert not r.get("isError") and h.server_calls() == [{"name": "echo", "arguments": {"url": "https://github.com/mcp", "text": "hi"}}]
        rec = [x for x in g.PROD.chain if x.get("verdict") == "EXECUTION_DELEGATED"][-1]
        assert rec["task_id"] == "mcp-task-1" and rec["agent_id"] == "env:agent"
        r2 = h.call(2, "echo", {"url": "https://github.com/mcp", "text": "per-call"}, meta={"qyrix/task_id": "override-7"})["result"]
        assert not r2.get("isError")
        assert [x for x in g.PROD.chain if x.get("verdict") == "EXECUTION_DELEGATED"][-1]["task_id"] == "override-7"
        bad = h.call(3, "echo", {"url": "https://github.com/mcp", "text": "x"}, meta={"qyrix/task_id": "bad task!"})["result"]
        assert bad["isError"] and bad["_meta"]["qyrix"]["rules"] == ["TASK_ID_INVALID"]
    finally:
        h.close()


def test_mcp_proxy_wrong_task_redemption_is_not_forwarded(tmp_path):
    class WrongTask(mp.SentinelClient):
        def redeem(self, d, corr, task=None):
            return super().redeem(d, corr, "some-other-task")        # a buggy/hostile adapter swapping the task
    h = Harness(tmp_path, sentinel=WrongTask(http=TestClient(app, headers=AGENT)), task_id="real-task")
    try:
        r = h.call(4, "echo", {"url": "https://github.com/mcp", "text": "x"})["result"]
        assert r["isError"] and r["_meta"]["qyrix"]["rules"] == ["GRANT_GRANT_TASK_MISMATCH"]
        assert h.server_calls() == []
    finally:
        h.close()


def test_mcp_proxy_with_require_task_id_and_no_task_blocks(tmp_path, monkeypatch):
    monkeypatch.setenv("QYRIX_REQUIRE_TASK_ID", "1")
    h = Harness(tmp_path)
    try:
        r = h.call(5, "echo", {"url": "https://github.com/mcp", "text": "x"})["result"]
        assert r["isError"] and "R18_TASK_ID_REQUIRED" in r["_meta"]["qyrix"]["rules"] and h.server_calls() == []
    finally:
        h.close()
