"""Audit F-02: the Gate evaluates ONE destination (mapping.dest_arg) and ONE method (mapping.method). A mapped tool must
declare an explicit `args` allow-list; anything else is refused BEFORE the Gate is asked and never reaches the upstream.
Same shared guard for the stdio and the HTTP proxy - every rejection case is run through both transports."""
import json

import pytest

from app import adapter_core as core, gateway as g, mcp_http_proxy as mhp, mcp_proxy as mp
from tests.test_mcp_http_proxy import Env, delegated, gate_client, OK_URL  # noqa: F401
from tests.test_mcp_proxy import ARGS, MAPPING, Harness, fresh  # noqa: F401  (autouse: resets Gate / alerts / limiter)

BAD = "http://127.0.0.1:1/x"                      # SSRF target: R9 would BLOCK it IF the Gate were shown it
M = {"tool": "http", "method": "GET", "dest_arg": "url", "args": ["url", "text"]}


# ---------------- mapping validation ----------------
@pytest.mark.parametrize("entry,why", [
    ({"tool": "http", "method": "GET", "dest_arg": "url"}, "no allow-list"),
    ({"tool": "http", "dest_arg": "url", "args": []}, "empty allow-list"),
    ({"tool": "http", "dest_arg": "url", "args": ["text"]}, "allow-list lacks dest_arg"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "endpoint"]}, "second destination (endpoint)"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "callback_url"]}, "second destination (callback_url)"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "Webhook-URL"]}, "second destination (normalised name)"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "host"]}, "second destination (host)"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "method"]}, "method-like argument"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "HTTP_Method"]}, "method-like argument (normalised)"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", "URL"]}, "names differing only by case"),
    ({"tool": "http", "dest_arg": "url", "args": ["url", 5]}, "non-string name"),
    ({"tool": "shell", "dest_arg": "cmd", "args": ["cmd"]}, "tool type the Gate does not support"),
    ({"tool": "http", "args": ["url"]}, "no dest_arg"),
    ("not-a-dict", "not an object"),
])
def test_validate_mapping_rejects_ambiguous_or_allowlist_less_entries(entry, why):
    with pytest.raises(ValueError):
        core.validate_mapping({"t": entry})


def test_validate_mapping_accepts_supported_shapes_and_every_loader_enforces_it(tmp_path):
    core.validate_mapping({"a": M, "r": {"tool": "file.read", "dest_arg": "path", "args": ["path"]}})
    bad = tmp_path / "t.json"
    bad.write_text(json.dumps({"tools": {"fetch": {"tool": "http", "dest_arg": "url", "args": ["url", "endpoint"]}}}))
    with pytest.raises(SystemExit):
        mp.load_mapping(str(bad))                                              # stdio CLI config
    good = tmp_path / "g.json"
    good.write_text(json.dumps({"tools": {"fetch": M}}))
    assert mp.load_mapping(str(good)) == {"fetch": M}
    cfg = mhp.HttpProxyConfig("https://mcp.example/mcp", {"a": "0" * 64}, {"h"}, {"fetch": {"tool": "http", "dest_arg": "url"}})
    with pytest.raises(ValueError):
        mhp.McpHttpProxy(cfg, gate_client())                                   # HTTP proxy construction


# ---------------- per-call argument checks ----------------
@pytest.mark.parametrize("args,code", [
    ({"url": OK_URL, "endpoint": BAD}, "ARG_NOT_ALLOWED_endpoint"),            # the audit's attack
    ({"url": OK_URL, "text": "x", "note": "y"}, "ARG_NOT_ALLOWED_note"),        # unknown extra argument
    ({"url": OK_URL, "URL": BAD}, "ARG_NOT_ALLOWED_URL"),                      # case variant of the destination
    ({"url": OK_URL, "uri": BAD, "host": "evil.example"}, "ARG_NOT_ALLOWED_uri"),   # several destination-like arguments
    ({"url": OK_URL, "method": "DELETE"}, "ARG_NOT_ALLOWED_method"),           # method override / ambiguity
    ({"url": OK_URL, "http_method": "POST"}, "ARG_NOT_ALLOWED_http_method"),
    ({"url": OK_URL, "text": {"url": BAD}}, "ARG_NOT_SCALAR_text"),            # nested value hiding a second destination
    ({"url": OK_URL, "text": [BAD]}, "ARG_NOT_SCALAR_text"),
    ({"text": "x"}, "DESTINATION_MISSING_OR_NOT_A_STRING"),
    ({"url": {"a": 1}}, "DESTINATION_MISSING_OR_NOT_A_STRING"),
    ({"url": 5}, "DESTINATION_MISSING_OR_NOT_A_STRING"),
    ({"url": "   "}, "DESTINATION_MISSING_OR_NOT_A_STRING"),
    ({"url": OK_URL, "bad\nname": 1}, "ARG_NOT_ALLOWED_bad?name"),             # reason codes are sanitised
])
def test_check_arguments_rejects(args, code):
    assert core.check_arguments("t", args, {"t": M}) == code


def test_check_arguments_accepts_the_supported_structure_and_leaves_unmapped_tools_to_the_gate():
    assert core.check_arguments("t", {"url": OK_URL, "text": "hello"}, {"t": M}) is None
    assert core.check_arguments("t", {"url": OK_URL}, {"t": M}) is None
    assert core.check_arguments("other", {"endpoint": BAD, "anything": {"x": 1}}, {"t": M}) is None   # unmapped: Gate says R8
    assert core.check_arguments("t", {"url": OK_URL}, {"t": {"tool": "http", "dest_arg": "url"}}) == "ARGS_POLICY_INVALID"


class Counting(core.SentinelClient):
    def __init__(self, inner):
        super().__init__(http=inner.http)
        self.evaluated, self.redeemed = [], 0

    def evaluate(self, action):
        self.evaluated.append(action)
        return super().evaluate(action)

    def redeem(self, d, corr, task=None):
        self.redeemed += 1
        return super().redeem(d, corr, task)


def test_guard_never_asks_the_gate_about_a_rejected_call_and_evaluates_exactly_what_runs():
    c = Counting(gate_client())
    guard = core.ToolCallGuard(c, {"fetch": M})
    out = guard.authorize({"name": "fetch", "arguments": {"url": OK_URL, "endpoint": BAD}})
    assert out["kind"] == "blocked" and out["meta"]["rules"] == ["ARGS_POLICY_ARG_NOT_ALLOWED_endpoint"]
    assert c.evaluated == [] and c.redeemed == 0
    args = {"url": OK_URL, "text": "hello"}
    out = guard.authorize({"name": "fetch", "arguments": args})
    assert out["kind"] == "forward" and c.redeemed == 1
    a = c.evaluated[0]                                                        # what the Gate saw == what will run
    assert (a["tool"], a["method"], a["dest"], a["data"]) == ("http", "GET", OK_URL, core.canonical(args))


# ---------------- both proxies: rejected before the upstream ----------------
CASES = [({"url": OK_URL, "endpoint": BAD}, "ARG_NOT_ALLOWED_endpoint"),
         ({"url": OK_URL, "text": "x", "note": "y"}, "ARG_NOT_ALLOWED_note"),
         ({"url": OK_URL, "uri": BAD, "host": "evil.example"}, "ARG_NOT_ALLOWED_uri"),
         ({"url": OK_URL, "method": "DELETE"}, "ARG_NOT_ALLOWED_method"),
         ({"url": OK_URL, "text": {"url": BAD}}, "ARG_NOT_SCALAR_text")]


def chain_len():
    with g.PROD.lock:
        return len(g.PROD.chain)


@pytest.mark.parametrize("args,code", CASES)
def test_stdio_proxy_rejects_before_gate_and_upstream(tmp_path, args, code):
    x = Harness(tmp_path)
    try:
        n = chain_len()
        r = x.call(1, "echo", args)["result"]
        q = r["_meta"]["qyrix"]
        assert r["isError"] and q["verdict"] == "BLOCK" and q["rules"] == ["ARGS_POLICY_" + code]
        assert x.server_calls() == [] and chain_len() == n                     # not forwarded, Gate never consulted
    finally:
        x.close()


@pytest.mark.parametrize("args,code", CASES)
def test_http_proxy_rejects_before_gate_and_upstream(args, code):
    e = Env()
    try:
        sid = e.init()
        n = chain_len()
        r = e.call(sid, 1, "echo", args)["result"]
        q = r["_meta"]["qyrix"]
        assert r["isError"] and q["verdict"] == "BLOCK" and q["rules"] == ["ARGS_POLICY_" + code]
        assert e.up.calls() == [] and delegated() == [] and chain_len() == n
    finally:
        e.close()


def test_valid_structure_still_works_and_upstream_receives_exactly_the_authorized_arguments(tmp_path):
    args = {"url": OK_URL, "text": "hello"}
    x = Harness(tmp_path)
    try:
        assert x.call(2, "echo", args)["result"]["content"][0]["text"] == "echo:hello"
        assert x.server_calls() == [{"name": "echo", "arguments": args}]       # stdio: byte-for-byte the evaluated arguments
    finally:
        x.close()
    e = Env()
    try:
        sid = e.init()
        d0 = len(delegated())
        assert e.call(sid, 2, "echo", args)["result"]["content"][0]["text"] == "echo:hello"
        assert [c["params"]["arguments"] for c in e.up.calls()] == [args] and len(delegated()) == d0 + 1
        with g.PROD.lock:
            decided = [r for r in g.PROD.chain if r.get("kind") == "gate_decision"][-1]
        assert decided["verdict"] == "ALLOW"
    finally:
        e.close()


def test_a_mapping_without_allowlist_is_rejected_by_both_constructors_and_blocked_if_swapped_in_later(tmp_path):
    bare = {"echo": {"tool": "http", "method": "GET", "dest_arg": "url"}}
    with pytest.raises(ValueError):
        Harness(tmp_path, mapping=bare)                                           # stdio McpProxy constructor (programmatic callers)
    cfg = mhp.HttpProxyConfig("https://mcp.example/mcp", {"a": "0" * 64}, {"h"}, bare)
    with pytest.raises(ValueError):
        mhp.McpHttpProxy(cfg, gate_client())                                      # HTTP proxy constructor
    ok = {"echo": M}
    x = Harness(tmp_path, mapping=ok)
    try:
        x.proxy.mapping = bare                                                    # swapped in after construction: still fails closed
        n = chain_len()
        r = x.call(3, "echo", {"url": OK_URL})["result"]["_meta"]["qyrix"]
        assert r["rules"] == ["ARGS_POLICY_INVALID"] and x.server_calls() == [] and chain_len() == n   # single prefix; Gate not asked
        x.proxy.mapping = {"echo": {**M, "args": ["url", "endpoint"]}}            # ambiguous mapping swapped in later
        assert x.call(4, "echo", {"url": OK_URL})["result"]["_meta"]["qyrix"]["rules"] == ["ARGS_POLICY_INVALID"]
    finally:
        x.close()


def test_every_args_policy_rule_has_exactly_one_prefix():
    c = core.ToolCallGuard(Counting(gate_client()), {"t": M})
    for args in ({"url": OK_URL, "x": 1}, {"text": "a"}, {"url": OK_URL, "text": {"a": 1}}):
        rules = c.authorize({"name": "t", "arguments": args})["meta"]["rules"]
        assert len(rules) == 1 and rules[0].startswith("ARGS_POLICY_") and not rules[0].startswith("ARGS_POLICY_ARGS_POLICY_")
    bad = core.ToolCallGuard(Counting(gate_client()), {"t": {"tool": "http", "dest_arg": "url"}})
    assert bad.authorize({"name": "t", "arguments": {"url": OK_URL}})["meta"]["rules"] == ["ARGS_POLICY_INVALID"]
