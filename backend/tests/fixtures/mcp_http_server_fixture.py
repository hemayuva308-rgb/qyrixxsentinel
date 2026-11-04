"""Hand-written Streamable-HTTP MCP upstream used to test app/mcp_http_proxy.py (MCP 2025-11-25, POST-only). It speaks
just enough protocol, records EVERY request it receives (headers + body) so tests can prove what did / did not reach it,
and has tools that exercise JSON replies, SSE replies, server-initiated requests, slow, truncated and oversize replies."""
import asyncio
import json
import socket
import threading
import time

import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

TOOLS = [{"name": n, "description": n, "inputSchema": {"type": "object"}} for n in
         ("echo", "stream_echo", "slow", "ask_sampling", "hang_stream", "die", "bigjson", "delete_everything",
          "prime_echo", "prime_after", "prime_multi", "prime_bad", "prime_only", "empty_stream", "garbage_stream")]


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class UpstreamFixture:
    def __init__(self, version: str = "2025-11-25"):
        self.version, self.requests, self.client_responses = version, [], []
        self.lock = threading.Lock()
        self.app = Starlette(routes=[Route("/mcp", self.handle, methods=["POST", "GET", "DELETE"])])

    def calls(self, name=None):
        with self.lock:
            return [r["body"] for r in self.requests if r["body"].get("method") == "tools/call"
                    and (name is None or r["body"]["params"]["name"] == name)]

    def methods(self):
        with self.lock:
            return [r["body"].get("method") for r in self.requests]

    async def handle(self, request: Request) -> Response:
        if request.method != "POST":
            with self.lock:
                self.requests.append({"headers": dict(request.headers), "body": {"method": request.method}})
            return Response(status_code=405)
        body = json.loads(await request.body())
        with self.lock:
            self.requests.append({"headers": dict(request.headers), "body": body})
        if "method" not in body:                                    # a client RESPONSE to a server-initiated request
            with self.lock:
                self.client_responses.append(body)
            return Response(status_code=202)
        m, mid = body["method"], body.get("id")
        if mid is None:
            return Response(status_code=202)
        if m == "initialize":
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": self.version, "capabilities": {"tools": {}}, "serverInfo": {"name": "http-fixture", "version": "1"}}},
                headers={"MCP-Session-Id": "up-session-1"})
        if m == "tools/list":
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
        if m == "tools/call":
            return await self.call(mid, body["params"])
        return JSONResponse({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "nope"}})

    def result(self, mid, text):
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}]}}

    async def call(self, mid, p):
        name, args = p["name"], p.get("arguments") or {}
        if name == "echo":
            return JSONResponse(self.result(mid, "echo:%s" % args.get("text")))
        if name == "slow":
            await asyncio.sleep(float(args.get("seconds", 1)))
            return JSONResponse(self.result(mid, "slow-done"))
        if name == "bigjson":
            return JSONResponse(self.result(mid, "x" * 20000))
        sse = {"Content-Type": "text/event-stream"}

        async def stream_echo():
            yield b": keep-alive comment\r\n\r\n"
            yield ("data: " + json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}) + "\n\n").encode()
            payload = json.dumps(self.result(mid, "stream:%s" % args.get("text")))
            yield ("id: 7\r\ndata: " + payload[:20]).encode()          # split mid-event, CRLF line endings
            yield (payload[20:] + "\r\n\r\n").encode()

        async def ask_sampling():
            yield ("data: " + json.dumps({"jsonrpc": "2.0", "id": "srv-1", "method": "sampling/createMessage", "params": {}}) + "\n\n").encode()
            for _ in range(60):
                with self.lock:
                    got = [r for r in self.client_responses if r.get("id") == "srv-1"]
                if got:
                    break
                await asyncio.sleep(0.05)
            code = got[0].get("error", {}).get("code") if got else "none"
            yield ("data: " + json.dumps(self.result(mid, "sampling-reply-code:%s" % code)) + "\n\n").encode()

        async def hang_stream():
            yield b"data: " + json.dumps({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}).encode() + b"\n\n"
            await asyncio.sleep(10)

        async def die():                                              # response event never terminated by a blank line
            yield ("data: " + json.dumps(self.result(mid, "unterminated"))).encode()

        def ev(msg):
            return ("data: " + json.dumps(msg) + "\n\n").encode()

        async def prime_echo():                                       # 2025-11-25 priming event, then the response
            yield b"id: 0\nretry: 100\ndata:\n\n"
            yield ev(self.result(mid, "primed"))

        async def prime_after():                                      # response first, a priming event after it
            yield ev(self.result(mid, "primed-after"))
            yield b"id: 9\ndata:\n\n"

        async def prime_multi():
            yield b"id: 0\ndata:\n\n"
            yield b"id: 1\r\ndata:\r\n\r\n"
            yield b"id: 2\ndata: \n\n"
            yield b"id: 3\n\n"                                         # id-only block: no data field at all
            yield ev(self.result(mid, "multi-primed"))

        async def prime_bad():                                        # priming, then malformed JSON
            yield b"id: 0\ndata:\n\n"
            yield b"data: {not json\n\n"

        async def prime_only():                                       # priming, then the server closes (polling style)
            yield b"id: 0\ndata:\n\n"

        async def empty_stream():
            return
            yield

        async def garbage_stream():
            yield b"data: \xff\xfe\n\n"                               # invalid UTF-8

        gens = {"prime_echo": prime_echo, "prime_after": prime_after, "prime_multi": prime_multi, "prime_bad": prime_bad,
                "prime_only": prime_only, "empty_stream": empty_stream, "garbage_stream": garbage_stream,
                "stream_echo": stream_echo, "ask_sampling": ask_sampling, "hang_stream": hang_stream, "die": die}
        if name in gens:
            return StreamingResponse(gens[name](), headers=sse)
        return JSONResponse({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "unknown tool"}})


def serve(app, port: int = 0):
    """Run an ASGI app on 127.0.0.1 in a daemon thread. Returns (port, stop())."""
    port = port or free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", access_log=False))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    end = time.time() + 10
    while not server.started and time.time() < end:
        time.sleep(0.02)

    def stop():
        server.should_exit = True
        t.join(5)
    return port, stop
