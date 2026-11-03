"""v1.5 MCP proxy: tools/call interception -> Gate -> grant redemption -> forward, against a REAL stdio MCP server
process (tests/fixtures/mcp_server_fixture.py), plus one full end-to-end run of `python -m app.mcp_proxy` as its own
process talking to a live Sentinel HTTP server."""
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from app import alerts, cev, gateway as g, identity, mcp_proxy as mp
from app.main import app
from tests.conftest import ADMIN, AGENT

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = [sys.executable, os.path.join(HERE, "fixtures", "mcp_server_fixture.py")]
MAPPING = {"fetch": {"tool": "http", "method": "GET", "dest_arg": "url"},
           "echo": {"tool": "http", "method": "GET", "dest_arg": "url"},
           "slow": {"tool": "http", "method": "GET", "dest_arg": "url"}}
admin = TestClient(app, headers=ADMIN)


class Harness:
    def __init__(self, tmp_path, sentinel=None, timeout=10.0, mapping=MAPPING):
        self.log = str(tmp_path / "server-calls.jsonl")
        self.msgs, self.cv = [], threading.Condition()
        env = {**os.environ, "MCP_FIXTURE_LOG": self.log}
        self.proxy = mp.McpProxy(sentinel or mp.SentinelClient(http=TestClient(app, headers=AGENT)), SERVER, mapping,
                                 self._out, timeout, env).start()

    def _out(self, msg):
        with self.cv:
            self.msgs.append(msg)
            self.cv.notify_all()

    def wait(self, mid, t=10.0):
        end = time.time() + t
        with self.cv:
            while time.time() < end:
                for m in self.msgs:
                    if m.get("id") == mid:
                        return m
                self.cv.wait(0.05)
        return None

    def rpc(self, mid, method, params=None):
        self.proxy.handle_client({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        return self.wait(mid)

    def call(self, mid, name, args, meta=None):
        p = {"name": name, "arguments": args}
        if meta:
            p["_meta"] = meta
        return self.rpc(mid, "tools/call", p)

    def server_calls(self):
        return [json.loads(l) for l in open(self.log)] if os.path.exists(self.log) else []

    def close(self):
        self.proxy.close()


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("QYRIX_CEV_WINDOW_SECONDS", "0.1")
    alerts.reset_for_tests(); identity.limiter.clear()
    admin.post("/api/v1/sentinel/reset")


@pytest.fixture
def h(tmp_path):
    x = Harness(tmp_path)
    assert x.rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}})["result"]["serverInfo"]["name"] == "qyrix-mcp-fixture"
    yield x
    x.close()


def chain():
    with g.PROD.lock:
        return list(g.PROD.chain)


def test_tool_discovery_is_forwarded_unchanged(h):
    tools = h.rpc(2, "tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["fetch", "echo", "slow", "delete_everything"]
    assert h.server_calls() == []                                  # discovery is not a tool execution


def test_blocked_call_is_never_forwarded_and_observer_sees_nothing(h):
    http, _ = cev.observers()
    token = "mcptest" + "a" * 20
    r = h.call(3, "fetch", {"url": http.url_for(token)})["result"]
    q = r["_meta"]["qyrix"]
    assert r["isError"] and q["verdict"] == "BLOCK" and "R9_SSRF_BLOCKED" in q["rules"]
    assert h.server_calls() == [] and http.hits(token) == []          # not forwarded, no side effect
    rec = [x for x in chain() if x.get("kind") == "gate_decision" and x.get("correlation_id") == q["correlation_id"]]
    assert len(rec) == 1 and rec[0]["hash"] == q["decision_proof_hash"]


def test_unmapped_tool_is_default_denied(h):
    r = h.call(4, "delete_everything", {})["result"]
    assert r["isError"] and "R8_UNSUPPORTED_TOOL" in r["_meta"]["qyrix"]["rules"]
    assert h.server_calls() == []


def test_allowed_call_redeems_grant_once_then_forwards_exact_arguments(h):
    args = {"url": "https://github.com/qyrix", "text": "hello"}
    r = h.call(5, "echo", args, meta={"qyrix/correlation_id": "corr-mcp-1"})
    assert r["result"]["content"][0]["text"] == "echo:hello" and not r["result"].get("isError")
    assert h.server_calls() == [{"name": "echo", "arguments": args}]
    dele = [x for x in chain() if x.get("verdict") == "EXECUTION_DELEGATED"]
    assert len(dele) == 1 and dele[0]["integration"] == "mcp_proxy" and dele[0]["correlation_id"] == "corr-mcp-1"
    dec = [x for x in chain() if x.get("kind") == "gate_decision" and x.get("correlation_id") == "corr-mcp-1"]
    assert len(dec) == 1 and dec[0]["verdict"] == "ALLOW"


def test_argument_change_changes_the_evaluated_digest(h):
    a = mp.to_action("echo", {"url": "https://github.com/x", "text": "a"}, MAPPING, "c")
    b = mp.to_action("echo", {"url": "https://github.com/x", "text": "b"}, MAPPING, "c")
    da = g.evaluate(g.Action(**a), g.PROD)
    db = g.evaluate(g.Action(**b), g.PROD)
    assert da["params_digest"] != db["params_digest"]                # the grant binds the full argument object


def test_secret_looking_arguments_are_blocked(h):
    r = h.call(6, "echo", {"url": "https://github.com/x", "text": "api_key=SYNTHETIC-NOT-A-KEY"})["result"]
    assert r["isError"] and r["_meta"]["qyrix"]["verdict"] == "BLOCK"
    assert h.server_calls() == []


def test_sentinel_unreachable_fails_closed(tmp_path):
    class Down(mp.SentinelClient):
        def __init__(self):
            pass

        def evaluate(self, action):
            raise mp.SentinelError("SENTINEL_UNREACHABLE")
    x = Harness(tmp_path, sentinel=Down())
    try:
        r = x.call(7, "echo", {"url": "https://github.com/x", "text": "x"})["result"]
        assert r["isError"] and r["_meta"]["qyrix"]["rules"] == ["PROXY_FAIL_CLOSED"]
        assert x.server_calls() == []
    finally:
        x.close()


def test_failed_redemption_is_not_forwarded(tmp_path):
    class Replay(mp.SentinelClient):
        def redeem(self, d, corr):
            raise mp.SentinelError("GRANT_REPLAY")
    x = Harness(tmp_path, sentinel=Replay(http=TestClient(app, headers=AGENT)))
    try:
        r = x.call(8, "echo", {"url": "https://github.com/x", "text": "x"})["result"]
        assert r["isError"] and r["_meta"]["qyrix"]["rules"] == ["GRANT_GRANT_REPLAY"]
        assert x.server_calls() == []
    finally:
        x.close()


def test_server_timeout_returns_structured_error_and_drops_late_reply(tmp_path):
    x = Harness(tmp_path, timeout=0.3)
    try:
        r = x.call(9, "slow", {"url": "https://github.com/x", "seconds": 1.0})
        assert r["error"]["code"] == mp.TIMEOUT_CODE and x.proxy.stats["timeouts"] == 1
        time.sleep(1.2)
        assert len([m for m in x.msgs if m.get("id") == 9]) == 1      # the late server reply was dropped
    finally:
        x.close()


def test_invalid_params_and_requests(h):
    assert h.rpc(10, "tools/call", {"name": 5, "arguments": {}})["error"]["code"] == -32602
    h.proxy.handle_client({"id": 11, "method": "tools/call"})
    assert any(m.get("error", {}).get("code") == -32600 for m in h.msgs)


def test_cev_conformance_through_the_mcp_proxy_is_verified(h):
    ad = mp.McpProxyCanaryAdapter(h.proxy, h.wait)
    r = cev.run_canary(g.PROD, ad, "http")
    assert r["adapter"] == "mcp_proxy" and r["decision_verdict"] == "BLOCK" and r["result"] == cev.VERIFIED
    assert r["telemetry"]["positive_control"] and r["observed"] == []
    assert h.server_calls() == []


def test_load_mapping_rejects_unknown_target_tools(tmp_path):
    p = tmp_path / "t.json"
    p.write_text(json.dumps({"tools": {"x": {"tool": "shell"}}}))
    with pytest.raises(SystemExit):
        mp.load_mapping(str(p))


# ---------------- full end to end: proxy as its own process, live Sentinel HTTP server ----------------
def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    return port


def test_end_to_end_stdio_proxy_process(tmp_path):
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    cfg = tmp_path / "tools.json"
    cfg.write_text(json.dumps({"tools": MAPPING}))
    log = tmp_path / "calls.jsonl"
    env = {**os.environ, "QYRIX_URL": "http://127.0.0.1:%d" % port, "QYRIX_TOKEN": os.environ["QYRIX_AGENT_TOKEN"],
           "MCP_FIXTURE_LOG": str(log)}
    backend = os.path.dirname(HERE)
    p = subprocess.Popen([sys.executable, "-m", "app.mcp_proxy", "--config", str(cfg), "--timeout", "5", "--"] + SERVER,
                         cwd=backend, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
    try:
        http, _ = cev.observers()
        tok = "e2e" + "b" * 24
        lines = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}}},
                 {"jsonrpc": "2.0", "method": "notifications/initialized"},
                 {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                 {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "fetch", "arguments": {"url": http.url_for(tok)}}},
                 {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "echo", "arguments": {"url": "https://github.com/e2e", "text": "ok"}}}]
        for m in lines:
            p.stdin.write(json.dumps(m) + "\n")
        p.stdin.write("{not json\n")
        p.stdin.flush()
        got = {}
        end = time.time() + 20
        while time.time() < end and len(got) < 5:
            m = json.loads(p.stdout.readline())
            got[m.get("id")] = m
        assert got[1]["result"]["serverInfo"]["name"] == "qyrix-mcp-fixture"
        assert len(got[2]["result"]["tools"]) == 4
        assert got[3]["result"]["isError"] and got[3]["result"]["_meta"]["qyrix"]["verdict"] == "BLOCK"
        assert got[4]["result"]["content"][0]["text"] == "echo:ok"
        assert got[None]["error"]["code"] == -32700
        assert http.hits(tok) == []
        calls = [json.loads(l) for l in open(log)]
        assert [c["name"] for c in calls] == ["echo"]                 # the blocked fetch never reached the server
    finally:
        p.stdin.close()
        p.wait(timeout=5)
        server.should_exit = True
        t.join(timeout=5)
