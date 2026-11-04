"""Phase 2: MCP Streamable HTTP proxy (app/mcp_http_proxy.py, MCP 2025-11-25 POST-only subset) against a hand-written
HTTP upstream (tests/fixtures/mcp_http_server_fixture.py) and the REAL Gate. Tests that need a third-party MCP HTTP
server or SDK (interoperability) are NOT here - see docs/MCP_HTTP_PROXY.md."""
import json
import logging
import threading
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from app import adapter_core as core, gateway as g, mcp_http_proxy as mhp
from app.main import app
from tests.conftest import AGENT
from tests.fixtures.mcp_http_server_fixture import UpstreamFixture, free_port, serve
from tests.test_mcp_proxy import fresh  # noqa: F401  (autouse: resets Gate / alerts / limiter)

ALICE, BOB = "alice-token-SYNTHETIC-" + "a" * 20, "bob-token-SYNTHETIC-" + "b" * 20
UP_TOKEN = "upstream-token-SYNTHETIC-" + "u" * 16
GATE_TOKEN = AGENT["Authorization"].split(" ", 1)[1]
OK_URL, BAD_URL = "https://github.com/qyrix", "http://127.0.0.1:1/x"
MAPPING = {n: {"tool": "http", "method": "GET", "dest_arg": "url"}
           for n in ("echo", "stream_echo", "slow", "ask_sampling", "hang_stream", "die", "bigjson")}


class HttpClient(core.SentinelClient):
    INTEGRATION = mhp.INTEGRATION


def gate_client():
    return HttpClient(http=TestClient(app, headers=AGENT))


class Env:
    def __init__(self, sentinel=None, up_version="2025-11-25", upstream_url=None, **cfg):
        self.up = UpstreamFixture(up_version)
        self.up_port, self._stop_up = serve(self.up.app)
        self.port = free_port()
        c = mhp.HttpProxyConfig(upstream_url or "http://127.0.0.1:%d/mcp" % self.up_port,
                                {"alice": mhp.hash_token(ALICE), "bob": mhp.hash_token(BOB)},
                                {"127.0.0.1:%d" % self.port}, cfg.pop("mapping", MAPPING), **cfg)
        self.proxy = mhp.McpHttpProxy(c, sentinel or gate_client())
        _, self._stop = serve(self.proxy.app, self.port)
        self.http = httpx.Client(base_url="http://127.0.0.1:%d" % self.port, trust_env=False, timeout=30)

    def close(self):
        self.http.close()
        self._stop()
        self._stop_up()
        self.proxy.close()

    def headers(self, who="alice", sid=None, **extra):
        h = {"Authorization": "Bearer " + {"alice": ALICE, "bob": BOB}.get(who, who), "Accept": "application/json, text/event-stream",
             "Content-Type": "application/json", "MCP-Protocol-Version": "2025-11-25"}
        if sid:
            h["MCP-Session-Id"] = sid
        h.update(extra)
        return {k: v for k, v in h.items() if v is not None}

    def post(self, msg, who="alice", sid=None, raw=None, **extra):
        return self.http.post("/mcp", content=raw if raw is not None else json.dumps(msg), headers=self.headers(who, sid, **extra))

    def init(self, who="alice"):
        r = self.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}, who, MCP_PV=None)
        assert r.status_code == 200, r.text
        sid = r.headers["mcp-session-id"]
        assert self.post({"jsonrpc": "2.0", "method": "notifications/initialized"}, who, sid).status_code == 202
        return sid

    def call(self, sid, mid, name, args, who="alice", meta=None):
        p = {"name": name, "arguments": args}
        if meta:
            p["_meta"] = meta
        r = self.post({"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": p}, who, sid)
        assert r.status_code == 200, r.text
        return r.json()


@pytest.fixture
def env():
    e = Env()
    yield e
    e.close()


def delegated():
    with g.PROD.lock:
        return [x for x in g.PROD.chain if x.get("verdict") == "EXECUTION_DELEGATED"]


# ---------------- protocol flow ----------------
def test_initialize_session_list_ping_and_coverage(env):
    sid = env.init()
    assert sid != "up-session-1" and len(sid) >= 32                      # proxy-issued; upstream's id never leaves the proxy
    assert env.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid=sid).json()["result"] == {}
    assert env.up.methods() == ["initialize", "notifications/initialized"]  # ping answered locally
    tl = env.post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid=sid).json()
    assert [t["name"] for t in tl["result"]["tools"]][:2] == ["echo", "stream_echo"]
    rep = env.proxy.coverage()
    assert rep["default_denied"] == ["delete_everything"] and "echo" in rep["gate_evaluated"]


def test_allowed_call_redeems_then_forwards_exact_message_with_allow_listed_headers():
    e = Env(upstream_token=UP_TOKEN)
    try:
        sid = e.init()
        r = e.call(sid, 5, "echo", {"url": OK_URL, "text": "hi"}, meta={"qyrix/correlation_id": "corr-h-1"})
        assert r["result"]["content"][0]["text"] == "echo:hi" and r["id"] == 5
        assert [c["params"] for c in e.up.calls()] == [{"name": "echo", "arguments": {"url": OK_URL, "text": "hi"},
                                                         "_meta": {"qyrix/correlation_id": "corr-h-1"}}]
        d = delegated()
        assert len(d) == 1 and d[0]["integration"] == "mcp_proxy_http" and d[0]["correlation_id"] == "corr-h-1"
        h = [x for x in e.up.requests if x["body"].get("method") == "tools/call"][0]["headers"]
        assert h["authorization"] == "Bearer " + UP_TOKEN and h["mcp-session-id"] == "up-session-1"
        assert ALICE not in json.dumps(e.up.requests) and BOB not in json.dumps(e.up.requests)   # client auth never forwarded
        assert set(h) <= {"host", "content-type", "accept", "mcp-protocol-version", "mcp-session-id", "authorization",
                          "accept-encoding", "content-length", "user-agent", "connection"}
    finally:
        e.close()


def test_blocked_call_never_reaches_upstream(env):
    sid = env.init()
    r = env.call(sid, 6, "echo", {"url": BAD_URL})["result"]
    assert r["isError"] and r["_meta"]["qyrix"]["verdict"] == "BLOCK" and "R9_SSRF_BLOCKED" in r["_meta"]["qyrix"]["rules"]
    assert env.up.calls() == [] and delegated() == []


def test_unmapped_tool_is_r8_default_denied(env):
    sid = env.init()
    r = env.call(sid, 7, "delete_everything", {})["result"]
    assert r["isError"] and "R8_UNSUPPORTED_TOOL" in r["_meta"]["qyrix"]["rules"] and env.up.calls() == []


def test_secret_looking_arguments_blocked(env):
    sid = env.init()
    r = env.call(sid, 8, "echo", {"url": OK_URL, "text": "api_key=SYNTHETIC-NOT-A-KEY"})["result"]
    assert r["isError"] and env.up.calls() == []


def test_invalid_tools_call_params(env):
    sid = env.init()
    r = env.post({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": 5}}, sid=sid).json()
    assert r["error"]["code"] == -32602 and env.up.calls() == []


# ---------------- no forwarding before redemption / fail closed ----------------
class TamperingClient(HttpClient):
    def redeem(self, d, correlation_id, task_id=None):
        other = g.evaluate(g.Action(**core.to_action("echo", {"url": OK_URL, "text": "CHANGED"}, MAPPING, "z")), g.PROD)
        return super().redeem({**d, "params_digest": other["params_digest"]}, correlation_id, task_id)


def test_changed_arguments_refused_at_redemption_upstream_untouched():
    e = Env(sentinel=TamperingClient(http=TestClient(app, headers=AGENT)))
    try:
        sid = e.init()
        q = e.call(sid, 10, "echo", {"url": OK_URL, "text": "original"})["result"]["_meta"]["qyrix"]
        assert q["rules"][0].startswith("GRANT_") and e.up.calls() == [] and delegated() == []
    finally:
        e.close()


def test_grant_is_single_use_and_replay_is_refused():
    c = gate_client()
    d = c.evaluate(core.to_action("echo", {"url": OK_URL, "text": "x"}, MAPPING, "corr-replay"))
    assert d["verdict"] == "ALLOW"
    c.redeem(d, "corr-replay")
    with pytest.raises(core.SentinelError) as ei:
        c.redeem(d, "corr-replay")
    assert "GRANT_REPLAY" in str(ei.value)


class Down(HttpClient):
    def __init__(self, mode):
        super().__init__(http=httpx.Client(base_url="http://gate.invalid", transport=httpx.MockTransport(
            (lambda r: httpx.Response(500, json={"detail": "boom"})) if mode == "500" else self._raise)))

    @staticmethod
    def _raise(request):
        raise httpx.ConnectError("down")


@pytest.mark.parametrize("mode", ["500", "unreachable"])
def test_gate_unavailable_fails_closed(mode):
    e = Env(sentinel=Down(mode))
    try:
        sid = e.init()                                                   # initialize does not need the Gate
        r = e.call(sid, 11, "echo", {"url": OK_URL, "text": "hi"})["result"]
        assert r["isError"] and r["_meta"]["qyrix"]["rules"] == ["PROXY_FAIL_CLOSED"] and e.up.calls() == []
    finally:
        e.close()


# ---------------- authentication, Host, Origin ----------------
@pytest.mark.parametrize("auth", [None, "Bearer wrong", "Basic " + ALICE, "Bearer", ALICE])
def test_authentication_required_for_every_method(env, auth):
    h = env.headers()
    h.pop("Authorization")
    if auth is not None:
        h["Authorization"] = auth
    for method in ("POST", "GET", "DELETE"):
        r = env.http.request(method, "/mcp", headers=h, content=b"{}")
        assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer", method
    assert env.up.requests == []


def test_host_and_origin_validation(env):
    r = env.http.post("/mcp", headers=env.headers(Host="evil.example"), content=b"{}")
    assert r.status_code == 403
    r = env.http.post("/mcp", headers=env.headers(Origin="http://evil.example"), content=b"{}")
    assert r.status_code == 403
    env.proxy.cfg.allowed_origins.add("http://localhost:3000")
    sid = env.init()
    r = env.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid=sid, Origin="http://localhost:3000")
    assert r.status_code == 200


# ---------------- malformed input ----------------
@pytest.mark.parametrize("raw,status", [
    ('{"jsonrpc":"2.0",', 400), ("[]", 400), ('[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}]', 400),
    ('"str"', 400), ('{"id":1,"method":"ping"}', 400), ('{"jsonrpc":"2.0","id":1,"method":5}', 400),
    ('{"jsonrpc":"2.0","id":1,"result":{}}', 400), ('{"jsonrpc":"2.0","id":true,"method":"ping"}', 400),
    ('{"jsonrpc":"2.0","id":[1],"method":"ping"}', 400)])
def test_malformed_and_batch_requests_rejected_before_anything_else(env, raw, status):
    sid = env.init()
    n = len(env.up.requests)
    r = env.post(None, sid=sid, raw=raw)
    assert r.status_code == status and len(env.up.requests) == n and delegated() == []


def test_content_type_accept_and_size_limits():
    e = Env(max_request_bytes=2000)
    try:
        sid = e.init()
        assert e.post(None, sid=sid, raw="{}", **{"Content-Type": "text/plain"}).status_code == 415
        assert e.post(None, sid=sid, raw="{}", Accept="application/json").status_code == 406
        big = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {"x": "y" * 5000}})
        assert e.post(None, sid=sid, raw=big).status_code == 413
        gen = (b"x" * 500 for _ in range(10))                              # no Content-Length: chunked body
        assert e.http.post("/mcp", content=gen, headers=e.headers(sid=sid)).status_code == 413
    finally:
        e.close()


def test_unsupported_surface_is_refused(env):
    sid = env.init()
    n = len(env.up.requests)
    for m in ("resources/read", "prompts/get", "completion/complete", "logging/setLevel", "sampling/createMessage"):
        assert env.post({"jsonrpc": "2.0", "id": 3, "method": m, "params": {}}, sid=sid).json()["error"]["code"] == -32601
    assert env.post({"jsonrpc": "2.0", "method": "notifications/roots/list_changed"}, sid=sid).status_code == 400
    assert env.post({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}, sid=sid).status_code == 202
    assert [m for m in env.up.methods()[n:]] == ["notifications/cancelled"]
    for m in ("GET", "PUT", "PATCH"):
        r = env.http.request(m, "/mcp", headers=env.headers(sid=sid, **{"Last-Event-ID": "5"}))
        assert r.status_code == 405 and "POST" in r.headers["allow"]
    assert "GET" not in env.up.methods()                                    # nothing reached the upstream


def test_protocol_version_is_pinned():
    e = Env(up_version="2026-07-28")
    try:
        r = e.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}}, MCP_PV=None)
        assert r.json()["error"]["code"] == -32603 and "mcp-session-id" not in r.headers      # upstream version mismatch: no session
    finally:
        e.close()
    e = Env()
    try:
        r = e.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2026-07-28"}})
        assert r.json()["error"]["code"] == -32602 and e.up.requests == []
        sid = e.init()
        assert e.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid=sid, **{"MCP-Protocol-Version": "2026-07-28"}).status_code == 400
        assert e.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid=sid, **{"MCP-Protocol-Version": None}).status_code == 400
    finally:
        e.close()


# ---------------- sessions / tenant isolation ----------------
def test_session_isolation_between_clients(env):
    a, b = env.init("alice"), env.init("bob")
    assert a != b
    ping = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert env.post(ping, "bob", a).status_code == 404 and env.post(ping, "alice", b).status_code == 404
    assert env.post(ping, "alice", "nope").status_code == 404 and env.post(ping, "alice").status_code == 404
    n = len(env.up.requests)
    r = env.post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "echo", "arguments": {"url": OK_URL}}}, "bob", a)
    assert r.status_code == 404 and len(env.up.requests) == n and delegated() == []
    assert env.http.delete("/mcp", headers=env.headers("bob", a)).status_code == 404
    assert env.http.delete("/mcp", headers=env.headers("alice", a)).status_code == 204
    assert env.post(ping, "alice", a).status_code == 404                       # ended
    assert env.post(ping, "bob", b).status_code == 200                         # untouched


def test_session_limit_and_expiry():
    e = Env(max_sessions=2, session_idle_ttl=0.3)
    try:
        s1 = e.init(); e.init()
        r = e.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
        assert r.status_code == 503
        time.sleep(0.5)
        assert e.post({"jsonrpc": "2.0", "id": 1, "method": "ping"}, sid=s1).status_code == 404   # idle TTL
        e.init()                                                                                    # slot freed
    finally:
        e.close()


# ---------------- duplicates, concurrency, unknown outcomes ----------------
def test_completed_duplicate_is_answered_from_cache_without_reexecution(env):
    sid = env.init()
    args = {"url": OK_URL, "text": "once"}
    first = env.call(sid, 20, "echo", args)
    second = env.call(sid, 20, "echo", args)
    assert first == second and len(env.up.calls()) == 1 and len(delegated()) == 1 and env.proxy.stats["replays"] == 1
    r = env.call(sid, 20, "echo", {"url": OK_URL, "text": "different"})
    assert r["error"]["code"] == mhp.DUPLICATE_CODE and len(env.up.calls()) == 1
    env.call(sid, 21, "echo", args)                                           # a NEW request id is a new execution
    assert len(env.up.calls()) == 2


def test_concurrent_duplicate_in_flight_is_refused(env):
    sid = env.init()
    out = []
    def go():
        out.append(env.call(sid, 30, "slow", {"url": OK_URL, "seconds": 1.0}))
    ts = [threading.Thread(target=go) for _ in range(2)]
    ts[0].start(); time.sleep(0.4); ts[1].start()
    [t.join() for t in ts]
    kinds = sorted("error" if "error" in o else "result" for o in out)
    assert kinds == ["error", "result"] and [o for o in out if "error" in o][0]["error"]["code"] == mhp.DUPLICATE_CODE
    assert len(env.up.calls("slow")) == 1 and len(delegated()) == 1


def test_same_request_id_in_two_sessions_does_not_collide(env):
    a, b = env.init("alice"), env.init("bob")
    out = {}
    def go(who, sid, text):
        out[who] = env.call(sid, 1, "slow" if who == "alice" else "echo", {"url": OK_URL, "text": text, "seconds": 0.6}, who=who)
    ts = [threading.Thread(target=go, args=("alice", a, "A")), threading.Thread(target=go, args=("bob", b, "B"))]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert out["alice"]["result"]["content"][0]["text"] == "slow-done" and out["bob"]["result"]["content"][0]["text"] == "echo:B"
    assert len(env.up.calls()) == 2


def test_many_concurrent_distinct_calls_each_use_their_own_grant(env):
    sid = env.init()
    out = [None] * 8
    def go(i):
        out[i] = env.call(sid, 100 + i, "echo", {"url": OK_URL, "text": "n%d" % i})
    ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert [o["result"]["content"][0]["text"] for o in out] == ["echo:n%d" % i for i in range(8)]
    assert len(delegated()) == 8 and len({d["gate_evaluation_id"] for d in delegated()}) == 8


def test_timeout_is_unknown_outcome_and_retry_is_never_reexecuted():
    e = Env(request_timeout=1.0)
    try:
        sid = e.init()
        r = e.call(sid, 40, "slow", {"url": OK_URL, "seconds": 3})
        assert r["error"]["code"] == mhp.TIMEOUT_CODE and r["error"]["data"]["qyrix"]["unknown_outcome"] is True
        again = e.call(sid, 40, "slow", {"url": OK_URL, "seconds": 3})
        assert again["error"]["code"] == mhp.UNKNOWN_OUTCOME_CODE and again["error"]["data"]["qyrix"]["re_executed"] is False
        assert len(e.up.calls("slow")) == 1 and len(delegated()) == 1
    finally:
        e.close()


@pytest.mark.parametrize("tool", ["die", "hang_stream"])
def test_broken_or_stalled_stream_is_unknown_outcome(tool):
    e = Env(request_timeout=1.0)
    try:
        sid = e.init()
        r = e.call(sid, 41, tool, {"url": OK_URL})
        assert "error" in r and r["error"]["data"]["qyrix"]["unknown_outcome"] is True
        assert e.call(sid, 41, tool, {"url": OK_URL})["error"]["code"] == mhp.UNKNOWN_OUTCOME_CODE
        assert len(e.up.calls(tool)) == 1
    finally:
        e.close()


def test_oversize_upstream_response_is_unknown_outcome():
    e = Env(max_response_bytes=4096)
    try:
        sid = e.init()
        r = e.call(sid, 42, "bigjson", {"url": OK_URL})
        assert r["error"]["code"] == mhp.UNKNOWN_OUTCOME_CODE and len(e.up.calls("bigjson")) == 1
    finally:
        e.close()


def test_upstream_unavailable():
    e = Env(upstream_url="http://127.0.0.1:%d/mcp" % free_port())
    try:
        r = e.post({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-11-25"}})
        assert r.json()["error"]["code"] == -32603 and "mcp-session-id" not in r.headers
    finally:
        e.close()
    e = Env()
    try:
        sid = e.init()
        e.proxy.cfg.upstream_url = "http://127.0.0.1:%d/mcp" % free_port()      # goes away AFTER authorization is possible
        r = e.call(sid, 43, "echo", {"url": OK_URL, "text": "x"})
        assert r["error"]["code"] == mhp.UNKNOWN_OUTCOME_CODE and len(delegated()) == 1   # redeemed => never retried automatically
        assert e.call(sid, 43, "echo", {"url": OK_URL, "text": "x"})["error"]["code"] == mhp.UNKNOWN_OUTCOME_CODE
    finally:
        e.close()


# ---------------- JSON / SSE / server-initiated messages ----------------
def test_sse_response_is_correlated_and_returned_as_json(env):
    sid = env.init()
    r = env.post({"jsonrpc": "2.0", "id": 50, "method": "tools/call", "params": {"name": "stream_echo", "arguments": {"url": OK_URL, "text": "s"}}}, sid=sid)
    assert r.headers["content-type"].startswith("application/json")
    assert r.json() == {"jsonrpc": "2.0", "id": 50, "result": {"content": [{"type": "text", "text": "stream:s"}]}}
    assert env.proxy.stats["server_messages_dropped"] == 1                       # the progress notification


def test_server_initiated_request_is_refused_upstream_and_never_relayed(env):
    sid = env.init()
    r = env.post({"jsonrpc": "2.0", "id": 51, "method": "tools/call", "params": {"name": "ask_sampling", "arguments": {"url": OK_URL}}}, sid=sid)
    assert "sampling" not in r.text.replace("sampling-reply-code", "") and r.json()["result"]["content"][0]["text"] == "sampling-reply-code:-32601"
    assert env.up.client_responses[0]["error"]["code"] == -32601 and env.proxy.stats["server_requests_refused"] == 1


# ---------------- secrets ----------------
def test_no_secrets_in_responses_logs_reports_or_upstream_requests(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    e = Env(upstream_token=UP_TOKEN, coverage_path=str(tmp_path / "cov.json"))
    try:
        sid = e.init()
        outs = [e.http.post("/mcp", headers=e.headers("wrong-token"), content=b"{}").text]
        e.post({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, sid=sid)
        outs.append(json.dumps(e.call(sid, 2, "echo", {"url": OK_URL, "text": "x"})))
        outs.append(json.dumps(e.call(sid, 3, "echo", {"url": BAD_URL})))
        outs.append(json.dumps(e.proxy.stats) + json.dumps(e.proxy.coverage()) + (tmp_path / "cov.json").read_text())
        blob = "".join(outs) + caplog.text + "".join(capsys.readouterr())
        for secret in (ALICE, BOB, UP_TOKEN, GATE_TOKEN):
            assert secret not in blob
        up = json.dumps(e.up.requests)
        assert UP_TOKEN in up and ALICE not in up and GATE_TOKEN not in up       # only the configured upstream credential
    finally:
        e.close()


# ---------------- SSE parser, config, CLI ----------------
def _events(chunks, **kw):
    p, out = mhp.SseParser(**kw), []
    for c in chunks:
        out += p.feed(c)
    return out + p.finish()


def test_sse_parser_line_endings_chunking_and_fields():
    assert _events([b"data: a\n\n"]) == ["a"] and _events([b"data: a\r\n\r\n"]) == ["a"] and _events([b"data: a\r\r"]) == ["a"]
    assert _events([b"data: a\r", b"\n\r", b"\n"]) == ["a"]                          # CR/LF split across chunks
    assert _events([b"data: x\ndata: y\n\n"]) == ["x\ny"] and _events([b": c\nid: 1\nretry: 5\nevent: m\ndata:z\n\n"]) == ["z"]
    assert _events([b"\xef\xbb\xbfdata: bom\n\n"]) == ["bom"]
    assert _events([b"d", b"ata: sp", b"lit\n", b"\n"]) == ["split"]
    assert _events([b"data: partial"]) == [] and _events([b"data: a\n\ndata: b"]) == ["a"]   # unterminated event discarded


def test_sse_parser_limits_and_invalid_utf8():
    with pytest.raises(mhp.SseError):
        _events([b"data: " + b"x" * 200], max_line=100)
    with pytest.raises(mhp.SseError):
        _events([b"data: " + b"x" * 60 + b"\n" + b"data: " + b"x" * 60 + b"\n\n"], max_line=100, max_event=100)
    with pytest.raises(mhp.SseError):
        _events([b"data: \xff\xfe\n\n"])


def test_config_validation(tmp_path):
    g1 = gate_client()
    ok = dict(upstream_url="https://mcp.example/mcp", allowed_hosts={"h"})
    with pytest.raises(ValueError):
        mhp.McpHttpProxy(mhp.HttpProxyConfig(client_token_hashes={}, **ok), g1)                 # never unauthenticated
    for bad in ("http://mcp.example/mcp", "ftp://x/y", "https:///nohost"):
        with pytest.raises(ValueError):
            mhp.McpHttpProxy(mhp.HttpProxyConfig(upstream_url=bad, client_token_hashes={"a": "0" * 64}, allowed_hosts={"h"}), g1)
    mhp.McpHttpProxy(mhp.HttpProxyConfig(client_token_hashes={"a": "0" * 64}, **ok), g1).close()
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"a": ALICE}))                                                       # plaintext token: refused
    with pytest.raises(SystemExit):
        mhp.load_client_tokens(str(f))
    f.write_text(json.dumps({"a": mhp.hash_token(ALICE)}))
    assert mhp.load_client_tokens(str(f)) == {"a": mhp.hash_token(ALICE)}
    assert mhp.main(["--upstream", "http://127.0.0.1:1/mcp", "--client-tokens-file", str(f), "--listen", "0.0.0.0:9"]) == 2


def test_upstream_receives_no_authorization_unless_an_upstream_credential_is_configured(env):
    sid = env.init()
    env.call(sid, 1, "echo", {"url": OK_URL, "text": "x"})
    assert env.up.requests and all("authorization" not in r["headers"] for r in env.up.requests)
    assert all("cookie" not in r["headers"] and "origin" not in r["headers"] for r in env.up.requests)
