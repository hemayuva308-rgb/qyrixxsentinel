"""Minimal stdio MCP server used as the downstream server in MCP proxy tests (JSON-RPC 2.0, newline-delimited, MCP
initialize / tools/list / tools/call). It is a separate process speaking the protocol, so the proxy is tested end to end.
Every tools/call it RECEIVES is appended to $MCP_FIXTURE_LOG, which lets tests prove a blocked call never arrived.
`fetch` performs a real HTTP GET, but only to loopback (CEV canary listener) - it can never reach the internet."""
import json
import os
import sys
import time
import urllib.request

TOOLS = [
    {"name": "fetch", "description": "HTTP GET a URL (fixture: loopback only)",
     "inputSchema": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
    {"name": "echo", "description": "Echo text",
     "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}, "url": {"type": "string"}}}},
    {"name": "slow", "description": "Sleep then answer",
     "inputSchema": {"type": "object", "properties": {"seconds": {"type": "number"}}}},
    {"name": "delete_everything", "description": "Dangerous tool that must never be forwarded unmapped",
     "inputSchema": {"type": "object", "properties": {}}},
]
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def log(entry):
    p = os.getenv("MCP_FIXTURE_LOG")
    if p:
        with open(p, "a") as f:
            f.write(json.dumps(entry) + "\n")


def reply(mid, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": mid}
    msg["error" if error else "result"] = error or result
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def call(name, args):
    if name == "fetch":
        url = args.get("url", "")
        if not url.startswith("http://127.0.0.1:"):
            return {"content": [{"type": "text", "text": "fixture refuses non-loopback URL"}], "isError": True}
        _NO_PROXY.open(urllib.request.Request(url, method="GET"), timeout=3).close()
        return {"content": [{"type": "text", "text": "fetched"}]}
    if name == "echo":
        return {"content": [{"type": "text", "text": "echo:" + str(args.get("text", ""))}]}
    if name == "slow":
        time.sleep(float(args.get("seconds", 1)))
        return {"content": [{"type": "text", "text": "slow done"}]}
    if name == "delete_everything":
        return {"content": [{"type": "text", "text": "DELETED EVERYTHING"}]}
    return None


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    msg = json.loads(line)
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        reply(mid, {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "qyrix-mcp-fixture", "version": "1.0"}})
    elif method == "tools/list":
        reply(mid, {"tools": TOOLS})
    elif method == "tools/call":
        p = msg.get("params") or {}
        log({"name": p.get("name"), "arguments": p.get("arguments")})
        r = call(p.get("name"), p.get("arguments") or {})
        reply(mid, r) if r is not None else reply(mid, error={"code": -32602, "message": "unknown tool"})
    elif method == "ping":
        reply(mid, {})
    elif mid is not None:
        reply(mid, error={"code": -32601, "message": "Method not found"})
