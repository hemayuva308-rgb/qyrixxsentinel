"""Phase 1: shared adapter core + MCP coverage report. The core holds no policy; the Gate stays the only authority.
Covers: the core mirrors the Gate's tool types, unmapped tools stay R8-denied, coverage report accuracy, a changed
argument is refused at redemption and never forwarded, Gate failures fail closed, and no token reaches logs/outputs."""
import json
import logging
import socket

import pytest

from app import adapter_core as core, gateway as g, mcp_proxy as mp
from tests.test_mcp_proxy import MAPPING, Harness, fresh, h  # noqa: F401  (fixtures: h, autouse fresh)

TOKEN = "TOKEN-SYNTHETIC-" + "z" * 24
BAD_DEST = "http://127.0.0.1:1/x"                       # SSRF => BLOCK (R9), so nothing is ever forwarded


def test_core_mirrors_the_gate_tool_types_and_proxy_reuses_it():
    assert tuple(core.GATE_TOOLS) == tuple(g.TOOLS)                       # drift here would make the report lie
    assert mp.to_action is core.to_action and mp.canonical is core.canonical and mp.SentinelError is core.SentinelError
    assert issubclass(mp.SentinelClient, core.SentinelClient) and mp.SentinelClient.INTEGRATION == "mcp_proxy"
    assert core.SentinelClient.INTEGRATION == "external"


def test_to_action_behaviour_unchanged():
    a = core.to_action("fetch", {"url": "https://x.example/p", "k": 1}, MAPPING, "c1", "t1")
    assert a == {"tool": "http", "method": "GET", "dest": "https://x.example/p", "data": '{"k":1,"url":"https://x.example/p"}',
                 "correlation_id": "c1", "task_id": "t1"}
    u = core.to_action("delete_everything", {}, MAPPING, "c2")
    assert u["tool"] == "mcp:delete_everything" and u["method"] == "CALL" and "task_id" not in u


def test_unmapped_tool_still_default_denied_by_r8_and_never_forwarded(h):  # noqa: F811
    r = h.call(10, "delete_everything", {})["result"]
    assert r["isError"] and "R8_UNSUPPORTED_TOOL" in r["_meta"]["qyrix"]["rules"] and h.server_calls() == []


def test_a_mapping_cannot_smuggle_a_new_tool_type_past_the_gate():
    rep = core.coverage_report({"x": {"tool": "shell", "dest_arg": "cmd", "args": ["cmd"]},
                                "y": {"tool": "http", "dest_arg": "url", "args": ["url"]},
                                "z": {"tool": "http"}}, ["x", "y", "z"])         # z: no allow-list => refused at call time
    assert rep["gate_evaluated"] == ["y"] and rep["default_denied"] == ["x", "z"]


# ---------------- coverage report ----------------
def test_coverage_unknown_before_tools_list_never_claims_coverage(h):  # noqa: F811
    rep = h.proxy.coverage()
    assert rep["tools_list_observed"] is False and rep["gate_evaluated"] == [] and rep["default_denied"] == []
    assert "unknown" in rep["summary"] and rep["evidence"].startswith("advisory")


def test_coverage_report_matches_what_the_gate_actually_does(h, tmp_path):  # noqa: F811
    path = str(tmp_path / "coverage.json")
    h.proxy.coverage_path = path
    h.proxy.mapping = {**MAPPING, "ghost": {"tool": "http", "method": "GET", "dest_arg": "url", "args": ["url"]}}   # configured, not offered
    tools = h.rpc(20, "tools/list")["result"]["tools"]                       # relayed unchanged
    assert [t["name"] for t in tools] == ["fetch", "echo", "slow", "delete_everything"]
    rep = h.proxy.coverage()
    assert rep["tools_list_observed"] and rep["gate_evaluated"] == ["echo", "fetch", "slow"]
    assert rep["default_denied"] == ["delete_everything"] and rep["configured_but_not_offered"] == ["ghost"]
    assert "3 of 4" in rep["summary"] and any("bypasses" in x for x in rep["limits"])
    assert json.load(open(path)) == rep                                        # file holds the same report, names only
    mid = 21
    for name in rep["gate_evaluated"]:                                         # the Gate really treats them differently
        r = h.call(mid, name, {"url": BAD_DEST})["result"]["_meta"]["qyrix"]
        assert "R8_UNSUPPORTED_TOOL" not in r["rules"] and r["verdict"] == "BLOCK", name
        mid += 1
    r = h.call(mid, rep["default_denied"][0], {"url": BAD_DEST})["result"]["_meta"]["qyrix"]
    assert "R8_UNSUPPORTED_TOOL" in r["rules"]
    assert h.server_calls() == []


def test_coverage_accumulates_pages_and_ignores_unrelated_responses(h):  # noqa: F811
    h.proxy._offered = None
    h.proxy._list_ids.add("p1")
    h.proxy._observe_tools("p1", {"id": "p1", "result": {"tools": [{"name": "fetch"}, {"name": 5}, "junk"], "nextCursor": "c"}})
    h.proxy._list_ids.add("p2")
    h.proxy._observe_tools("p2", {"id": "p2", "result": {"tools": [{"name": "zzz"}]}})
    h.proxy._observe_tools("not-a-list-id", {"result": {"tools": [{"name": "evil"}]}})            # never requested: ignored
    h.proxy._list_ids.add("p3")
    h.proxy._observe_tools("p3", {"id": "p3", "error": {"code": -1}})                              # error: no change
    rep = h.proxy.coverage()
    assert rep["gate_evaluated"] == ["fetch"] and rep["default_denied"] == ["zzz"]


# ---------------- redemption binding / fail closed ----------------
class TamperingClient(mp.SentinelClient):
    """Simulates the arguments changing after evaluation: redemption presents the digest of DIFFERENT arguments."""
    def redeem(self, d, correlation_id, task_id=None):
        other = g.evaluate(g.Action(**core.to_action("echo", {"url": "https://github.com/x", "text": "CHANGED"}, MAPPING, "z")), g.PROD)
        return super().redeem({**d, "params_digest": other["params_digest"]}, correlation_id, task_id)


def test_changed_arguments_are_refused_at_redemption_and_not_forwarded(tmp_path):
    from fastapi.testclient import TestClient
    from app.main import app
    from tests.conftest import AGENT
    x = Harness(tmp_path, sentinel=TamperingClient(http=TestClient(app, headers=AGENT)))
    try:
        r = x.call(30, "echo", {"url": "https://github.com/x", "text": "original"})["result"]
        q = r["_meta"]["qyrix"]
        assert r["isError"] and q["verdict"] == "BLOCK" and q["rules"][0].startswith("GRANT_")
        assert x.server_calls() == []
        assert not [c for c in g.PROD.chain if c.get("verdict") == "EXECUTION_DELEGATED"]      # nothing was delegated
    finally:
        x.close()


class DownClient(mp.SentinelClient):
    def evaluate(self, action):
        raise core.SentinelError("SENTINEL_UNREACHABLE")


class Gate500Client(core.SentinelClient):
    def __init__(self):
        import httpx
        super().__init__(http=httpx.Client(base_url="http://gate.invalid", transport=httpx.MockTransport(
            lambda req: httpx.Response(500, json={"detail": "boom"}))))


@pytest.mark.parametrize("client", [DownClient(http=object()), Gate500Client()])
def test_gate_unavailable_fails_closed(tmp_path, client):
    class C(mp.SentinelClient):
        evaluate = client.evaluate
        redeem = client.redeem
    x = Harness(tmp_path, sentinel=C(http=object()))
    try:
        r = x.call(40, "echo", {"url": "https://github.com/x", "text": "hi"})["result"]
        assert r["isError"] and r["_meta"]["qyrix"]["rules"] == ["PROXY_FAIL_CLOSED"]
        assert x.server_calls() == []
    finally:
        x.close()


# ---------------- no secrets in logs / outputs ----------------
def test_token_never_appears_in_repr_errors_logs_or_outputs(tmp_path, caplog, capsys):
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()      # closed port: unreachable
    client = mp.SentinelClient("http://127.0.0.1:%d" % port, TOKEN, timeout=0.5)
    cov = tmp_path / "cov.json"
    caplog.set_level(logging.DEBUG)
    x = Harness(tmp_path, sentinel=client)
    x.proxy.coverage_path = str(cov)
    try:
        x.rpc(50, "tools/list")
        r = x.call(51, "echo", {"url": "https://github.com/x", "text": "hi"})
        with pytest.raises(core.SentinelError) as ei:
            client.evaluate({"tool": "http"})
        blob = json.dumps(r) + repr(client) + str(ei.value) + caplog.text + cov.read_text() + json.dumps(x.proxy.coverage())
        out = capsys.readouterr()
        assert TOKEN not in blob + out.out + out.err
        assert r["result"]["_meta"]["qyrix"]["rules"] == ["PROXY_FAIL_CLOSED"] and x.server_calls() == []
    finally:
        x.close()
