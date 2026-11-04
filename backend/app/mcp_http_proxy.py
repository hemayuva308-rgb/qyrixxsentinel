"""Qyrix Sentinel MCP proxy - Streamable HTTP transport (POST-only subset of MCP revision 2025-11-25).

    MCP client --HTTPS/HTTP POST--> this proxy --> Gate evaluate --> grant redeem --> POST upstream MCP server

PINNED REVISION: 2025-11-25 (https://modelcontextprotocol.io/specification/2025-11-25/basic/transports). The 2026-07-28
revision (no sessions, no initialize) is NOT interchangeable and is not supported: any other protocol version is refused.

SECURITY MODEL (all enforced here, none of it is authorization - the Gate alone authorizes):
  * every request is authenticated (Bearer token, compared by SHA-256 digest in constant time); Host and Origin are
    validated; a proxy instance holds ONE Sentinel agent credential (its SentinelClient);
  * sessions are issued by THIS proxy (random, unguessable), bound to the authenticating client, and an unknown or
    foreign session is indistinguishable (404). The upstream session id never leaves the proxy;
  * `tools/call` goes through core.ToolCallGuard (evaluate -> single-use, params_digest-bound redeem). The upstream is
    contacted only after a successful redemption; BLOCK, Gate error or refused redemption never reach it (fail closed);
  * duplicate / retried calls are tracked per session (bounded, IN MEMORY - lost on restart): a duplicate in flight is
    refused, a completed call is answered from the cache, and a call whose outcome is unknown (timeout, broken stream,
    upstream error after redemption) is NEVER re-executed automatically. This is NOT exactly-once execution;
  * the upstream request is built from an explicit header allow-list; the client's Authorization is never forwarded;
    redirects are not followed; request and response sizes are capped;
  * JSON-RPC batches, GET (no server-initiated stream), resumability (Last-Event-ID), and every method other than
    initialize / ping / tools/list / tools/call (+ notifications/initialized, notifications/cancelled) are refused.
    resources/*, prompts/*, completion, logging, sampling and elicitation are NOT proxied. A server-initiated request
    inside a response stream is refused toward the upstream (JSON-RPC error) and never relayed to the client;
  * the response is always buffered and returned as one application/json message (no incremental streaming);
  SSE priming events (an event id with an empty data field) are skipped; resumability / polling (GET + Last-Event-ID)
  remains UNSUPPORTED, so a server that closes the stream before sending the response yields an unknown outcome.
Adapter reports are E1 self-reports, never independent evidence. Direct access to the upstream URL bypasses this proxy.
Nothing in this module logs headers, bodies or tokens."""
import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, NamedTuple, Optional, Set, Tuple
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from app import adapter_core as core

PROTOCOL_VERSION = "2025-11-25"
INTEGRATION = "mcp_proxy_http"
TIMEOUT_CODE = -32001            # same code as the stdio proxy
UNKNOWN_OUTCOME_CODE = -32003
DUPLICATE_CODE = -32002
ALLOWED_REQUESTS = ("initialize", "ping", "tools/list", "tools/call")
ALLOWED_NOTIFICATIONS = ("notifications/initialized", "notifications/cancelled")
_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SseError(Exception):
    pass


class SseEvent(NamedTuple):
    data: str                      # "" for a priming event (2025-11-25: an event id with an empty data field)
    event_id: Optional[str]        # the stream's last-event-id when the event was dispatched (WHATWG semantics)


class SseParser:
    """Strict, bounded Server-Sent-Events parser (WHATWG rules we rely on): lines end in CRLF, LF or CR; blank line
    dispatches; `data:` lines are joined with LF; comments and other fields are ignored; an event that is not
    terminated by a blank line when the stream ends is DISCARDED. Oversize lines/events and invalid UTF-8 raise."""
    _EOL = re.compile(rb"\r\n|\n|\r(?=.)", re.S)

    def __init__(self, max_line: int = 1 << 20, max_event: int = 1 << 20):
        self.buf, self.data, self.size, self.max_line, self.max_event, self.first = b"", [], 0, max_line, max_event, True
        self.last_event_id: Optional[str] = None

    def finish(self) -> List[SseEvent]:
        """End of stream: a trailing lone CR was waiting for a possible LF; it is a line terminator now."""
        return self.feed(b"\n") if self.buf.endswith(b"\r") else []

    def feed(self, chunk: bytes) -> List[SseEvent]:
        self.buf += chunk
        out: List[SseEvent] = []
        while True:
            m = self._EOL.search(self.buf)
            if not m:
                if len(self.buf) > self.max_line:
                    raise SseError("line too long")
                return out
            line, self.buf = self.buf[:m.start()], self.buf[m.end():]
            if len(line) > self.max_line:
                raise SseError("line too long")
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError as e:
                raise SseError("invalid utf-8") from e
            if self.first:
                text, self.first = text.lstrip("﻿"), False
            if text == "":
                if self.data:                                    # an `id:`-only block carries no data field: nothing to dispatch
                    out.append(SseEvent("\n".join(self.data), self.last_event_id))
                self.data, self.size = [], 0
            elif text.startswith(":"):
                continue
            else:
                field_, _, value = text.partition(":")
                if field_ == "id":
                    v = value[1:] if value.startswith(" ") else value
                    if "\x00" not in v:                          # WHATWG: an id containing NUL is ignored
                        self.last_event_id = v
                elif field_ == "data":
                    value = value[1:] if value.startswith(" ") else value
                    self.size += len(value) + 1
                    if self.size > self.max_event:
                        raise SseError("event too large")
                    self.data.append(value)


@dataclass
class HttpProxyConfig:
    upstream_url: str
    client_token_hashes: Dict[str, str]                       # client_id -> sha256 hex of the client's bearer token
    allowed_hosts: Set[str]                                   # exact Host header values, e.g. {"127.0.0.1:8765"}
    mapping: Dict[str, Dict] = field(default_factory=dict)
    allowed_origins: Set[str] = field(default_factory=set)    # empty: any request carrying an Origin header is refused
    task_id: Optional[str] = None
    upstream_token: Optional[str] = None                      # proxy -> upstream credential (never the client's)
    path: str = "/mcp"
    max_request_bytes: int = 1 << 20
    max_response_bytes: int = 1 << 20
    request_timeout: float = 30.0
    max_sessions: int = 256
    session_idle_ttl: float = 1800.0
    cache_per_session: int = 64
    cache_ttl: float = 600.0
    coverage_path: Optional[str] = None


class _Session:
    def __init__(self, sid: str, client_id: str, upstream_sid: Optional[str]):
        self.id, self.client_id, self.upstream_sid = sid, client_id, upstream_sid
        self.last_used = time.time()
        self.lock = threading.Lock()
        self.inflight: Dict[str, str] = {}                    # request key -> params digest
        self.done: "OrderedDict[str, Tuple[str, Dict, float]]" = OrderedDict()   # key -> (digest, response, ts)
        self.unknown: "OrderedDict[str, Tuple[str, float]]" = OrderedDict()      # key -> (digest, ts)


def _err(mid: Any, code: int, message: str, data: Optional[Dict] = None) -> Dict:
    e: Dict[str, Any] = {"code": code, "message": message}
    if data:
        e["data"] = {"qyrix": data}
    return {"jsonrpc": "2.0", "id": mid, "error": e}


def _digest(msg: Dict) -> str:
    return hashlib.sha256(core.canonical({"m": msg.get("method"), "p": msg.get("params")}).encode()).hexdigest()


class McpHttpProxy:
    def __init__(self, cfg: HttpProxyConfig, sentinel: core.SentinelClient, upstream: Optional[httpx.Client] = None,
                 reporter=None):
        if not cfg.client_token_hashes:
            raise ValueError("at least one client token hash is required: the listener is never unauthenticated")
        u = urlsplit(cfg.upstream_url)
        if u.scheme not in ("http", "https") or not u.hostname or (u.scheme == "http" and u.hostname not in _LOOPBACK):
            raise ValueError("upstream must be https:// (http:// only for loopback)")
        core.validate_mapping(cfg.mapping)                         # ValueError: ambiguous / allow-list-less mapping (audit F-02)
        self.cfg, self.sentinel, self.reporter = cfg, sentinel, reporter
        self.upstream = upstream or httpx.Client(
            timeout=httpx.Timeout(cfg.request_timeout, connect=5.0), follow_redirects=False,
            trust_env=u.hostname not in _LOOPBACK)
        self._sessions: Dict[str, _Session] = {}
        self._lock = threading.Lock()
        self._offered: Optional[Set[str]] = None
        self.stats = {"forwarded_calls": 0, "blocked_calls": 0, "duplicates_refused": 0, "replays": 0,
                      "unknown_outcomes": 0, "timeouts": 0, "server_requests_refused": 0, "server_messages_dropped": 0,
                      "sse_priming_events": 0}
        self.app = Starlette(routes=[Route(cfg.path, self.endpoint, methods=["GET", "POST", "DELETE", "PUT", "PATCH", "OPTIONS", "HEAD"])])

    # ---------------- plumbing ----------------
    def close(self) -> None:
        self.upstream.close()

    def coverage(self) -> Dict:
        with self._lock:
            offered = None if self._offered is None else set(self._offered)
        return core.coverage_report(self.cfg.mapping, offered)

    def _reject(self, status: int, code: int, message: str, headers: Optional[Dict] = None) -> Response:
        return JSONResponse(_err(None, code, message), status_code=status, headers=headers)

    def _authenticate(self, request: Request) -> Optional[str]:
        h = request.headers.get("authorization", "")
        tok = h[7:].strip() if h[:7].lower() == "bearer " else ""
        d, found = hash_token(tok), None
        for cid, want in self.cfg.client_token_hashes.items():     # no early exit: constant work per configured client
            if hmac.compare_digest(d, want) and tok:
                found = cid
        return found

    def _purge(self) -> None:
        now = time.time()
        with self._lock:
            for sid in [k for k, s in self._sessions.items() if now - s.last_used > self.cfg.session_idle_ttl]:
                del self._sessions[sid]

    def _session(self, request: Request, client_id: str) -> Optional[_Session]:
        sid = request.headers.get("mcp-session-id", "")
        with self._lock:
            s = self._sessions.get(sid)
            if s is None or s.client_id != client_id:               # foreign and unknown sessions look identical
                return None
            s.last_used = time.time()
            return s

    # ---------------- endpoint ----------------
    async def endpoint(self, request: Request) -> Response:
        host, origin = request.headers.get("host", ""), request.headers.get("origin")
        if host not in self.cfg.allowed_hosts:
            return self._reject(403, -32600, "Forbidden host")
        if origin is not None and origin not in self.cfg.allowed_origins:
            return self._reject(403, -32600, "Forbidden origin")
        client_id = self._authenticate(request)
        if client_id is None:
            return self._reject(401, -32600, "Unauthorized", {"WWW-Authenticate": "Bearer"})
        self._purge()
        if request.method == "DELETE":
            return await run_in_threadpool(self._delete, request, client_id)
        if request.method != "POST":
            return self._reject(405, -32600, "Method not allowed (POST only; no server-initiated stream)", {"Allow": "POST, DELETE"})
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        accept = request.headers.get("accept", "").lower()
        if ctype != "application/json":
            return self._reject(415, -32600, "Content-Type must be application/json")
        if "application/json" not in accept or "text/event-stream" not in accept:
            return self._reject(406, -32600, "Accept must list application/json and text/event-stream")
        try:
            cl = int(request.headers.get("content-length", "0"))
        except ValueError:
            return self._reject(400, -32700, "Bad Content-Length")
        if cl > self.cfg.max_request_bytes:
            return self._reject(413, -32600, "Request too large")
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > self.cfg.max_request_bytes:
                return self._reject(413, -32600, "Request too large")
        try:
            msg = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._reject(400, -32700, "Parse error")
        if isinstance(msg, list):
            return self._reject(400, -32600, "JSON-RPC batches are not supported")
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
            return self._reject(400, -32600, "Invalid Request (responses to server requests are not accepted)")
        return await run_in_threadpool(self._dispatch, request, client_id, msg)

    def _delete(self, request: Request, client_id: str) -> Response:
        s = self._session(request, client_id)
        if s is None:
            return self._reject(404, -32600, "Unknown session")
        with self._lock:
            self._sessions.pop(s.id, None)
        if s.upstream_sid:                                           # best effort; failures are irrelevant
            try:
                self.upstream.delete(self.cfg.upstream_url, headers=self._up_headers(s))
            except Exception:  # nosec B110
                pass
        return Response(status_code=204)

    def _dispatch(self, request: Request, client_id: str, msg: Dict) -> Response:
        method, mid = msg["method"], msg.get("id")
        has_id = "id" in msg
        if has_id and (isinstance(mid, bool) or not isinstance(mid, (str, int))):
            return self._reject(400, -32600, "Invalid id")
        if method == "initialize":
            if not has_id:
                return self._reject(400, -32600, "initialize must be a request")
            return self._initialize(client_id, msg)
        if request.headers.get("mcp-protocol-version") != PROTOCOL_VERSION:
            return self._reject(400, -32600, "MCP-Protocol-Version must be %s" % PROTOCOL_VERSION)
        s = self._session(request, client_id)
        if s is None:
            return self._reject(404, -32600, "Unknown session")
        if not has_id:
            if method not in ALLOWED_NOTIFICATIONS:
                return self._reject(400, -32600, "Unsupported notification")
            ex = self._exchange(s, json.dumps(msg, separators=(",", ":")), None)
            return Response(status_code=202) if ex["kind"] in ("accepted", "ok") else self._reject(502, -32603, "Upstream error")
        if method not in ALLOWED_REQUESTS:
            return JSONResponse(_err(mid, -32601, "Method not supported by this proxy"))
        if method == "ping":
            return JSONResponse({"jsonrpc": "2.0", "id": mid, "result": {}})
        if method == "tools/list":
            return self._tools_list(s, msg)
        return JSONResponse(self._tools_call(s, msg))

    # ---------------- initialize / tools/list ----------------
    def _initialize(self, client_id: str, msg: Dict) -> Response:
        params = msg.get("params")
        if not isinstance(params, dict) or params.get("protocolVersion") != PROTOCOL_VERSION:
            return JSONResponse(_err(msg["id"], -32602, "Unsupported protocol version",
                                     {"supported": [PROTOCOL_VERSION]}))
        with self._lock:
            if len(self._sessions) >= self.cfg.max_sessions:
                return self._reject(503, -32603, "Too many sessions")
        tmp = _Session("", client_id, None)
        ex = self._exchange(tmp, json.dumps(msg, separators=(",", ":")), msg["id"])
        if ex["kind"] != "ok" or "result" not in ex["message"] or \
                (ex["message"]["result"] or {}).get("protocolVersion") != PROTOCOL_VERSION:
            return JSONResponse(_err(msg["id"], -32603, "Upstream initialize failed or version mismatch"))
        sid = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[sid] = _Session(sid, client_id, ex.get("sid"))
        return JSONResponse(ex["message"], headers={"MCP-Session-Id": sid})

    def _tools_list(self, s: _Session, msg: Dict) -> Response:
        ex = self._exchange(s, json.dumps(msg, separators=(",", ":")), msg["id"])
        if ex["kind"] != "ok":
            return JSONResponse(_err(msg["id"], -32603, "Upstream error", {"reason": ex["kind"]}))
        res = ex["message"].get("result")
        tools = res.get("tools") if isinstance(res, dict) else None
        if isinstance(tools, list):
            names = {t.get("name") for t in tools[:5000] if isinstance(t, dict) and isinstance(t.get("name"), str)}
            with self._lock:
                self._offered = (self._offered or set()) | names
            self._write_coverage()
        return JSONResponse(ex["message"])

    def _write_coverage(self) -> None:
        if not self.cfg.coverage_path:
            return
        try:
            tmp = self.cfg.coverage_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.coverage(), f, indent=1)
            os.replace(tmp, self.cfg.coverage_path)
        except OSError:
            pass

    # ---------------- tools/call ----------------
    def _report(self, corr: str, forwarded: bool, execution_id: Optional[str] = None) -> None:
        if self.reporter is not None:
            try:
                self.reporter.report(corr, forwarded, execution_id)     # E1 self-report; never blocks or changes the call
            except Exception:  # nosec B110
                pass

    def _tools_call(self, s: _Session, msg: Dict) -> Dict:
        mid, key, dg, now = msg["id"], json.dumps(msg["id"]), _digest(msg), time.time()
        with s.lock:
            for tbl in (s.done, s.unknown):                         # bounded, TTL'd
                for k in [k for k, v in tbl.items() if now - v[-1] > self.cfg.cache_ttl]:
                    del tbl[k]
            if key in s.inflight:
                self.stats["duplicates_refused"] += 1
                return _err(mid, DUPLICATE_CODE, "Duplicate request in flight", {"duplicate": True})
            if key in s.unknown:
                if s.unknown[key][0] != dg:
                    return _err(mid, DUPLICATE_CODE, "Request id reused with different parameters")
                self.stats["unknown_outcomes"] += 1
                return _err(mid, UNKNOWN_OUTCOME_CODE, "Outcome of the earlier execution is unknown; not re-executed",
                            {"unknown_outcome": True, "re_executed": False})
            if key in s.done:
                if s.done[key][0] != dg:
                    return _err(mid, DUPLICATE_CODE, "Request id reused with different parameters")
                self.stats["replays"] += 1
                return s.done[key][1]                                 # cached response; the tool is NOT run again
            s.inflight[key] = dg
        terminal: Optional[str] = None                                # None: nothing executed, safe to retry
        resp: Dict
        try:
            out = core.ToolCallGuard(self.sentinel, self.cfg.mapping, self.cfg.task_id).authorize(msg.get("params"))
            if out["kind"] == "invalid":
                return _err(mid, -32602, "Invalid params")
            if out["kind"] == "blocked":
                self.stats["blocked_calls"] += 1
                if out["meta"].get("correlation_id"):
                    self._report(out["meta"]["correlation_id"], False)
                return core.blocked_result(mid, out["text"], out["meta"])
            # grant redeemed: from here on the upstream MAY execute, so a failure is an UNKNOWN outcome, never a retry
            self.stats["forwarded_calls"] += 1
            terminal = "unknown"                                      # even an unexpected exception below is never retried
            ex = self._exchange(s, json.dumps(msg, separators=(",", ":")), mid)
            self._report(out["corr"], True, out["execution_id"])
            if ex["kind"] == "ok":
                terminal, resp = "done", ex["message"]
            else:
                self.stats["timeouts" if ex["kind"] == "timeout" else "unknown_outcomes"] += 1
                resp = _err(mid, TIMEOUT_CODE if ex["kind"] == "timeout" else UNKNOWN_OUTCOME_CODE,
                            "MCP server timeout; outcome unknown" if ex["kind"] == "timeout" else
                            "Upstream failed after authorization; outcome unknown",
                            {"unknown_outcome": True, "reason": ex["kind"], "re_executed": False,
                             "correlation_id": out["corr"]})
            return resp
        finally:
            with s.lock:
                s.inflight.pop(key, None)
                if terminal == "done":
                    s.done[key] = (dg, resp, time.time())
                    while len(s.done) > self.cfg.cache_per_session:
                        s.done.popitem(last=False)
                elif terminal == "unknown":
                    s.unknown[key] = (dg, time.time())
                    while len(s.unknown) > self.cfg.cache_per_session:
                        s.unknown.popitem(last=False)

    # ---------------- upstream ----------------
    def _up_headers(self, s: _Session) -> Dict[str, str]:
        """EXPLICIT allow-list. Nothing from the client request is copied, in particular not its Authorization."""
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "MCP-Protocol-Version": PROTOCOL_VERSION, "Accept-Encoding": "identity"}
        if s.upstream_sid:
            h["MCP-Session-Id"] = s.upstream_sid
        if self.cfg.upstream_token:
            h["Authorization"] = "Bearer " + self.cfg.upstream_token
        return h

    def _refuse_server_request(self, s: _Session, mid: Any) -> None:
        """A server-initiated request (sampling / elicitation / roots ...) is never relayed to the client: answer the
        upstream with a JSON-RPC error instead."""
        self.stats["server_requests_refused"] += 1
        try:
            self.upstream.post(self.cfg.upstream_url, headers=self._up_headers(s), content=json.dumps(
                _err(mid, -32601, "Server-initiated requests are not supported by this proxy")))
        except Exception:  # nosec B110
            pass

    def _exchange(self, s: _Session, payload: str, expect_id: Any) -> Dict:
        """POST one message upstream. expect_id None: a notification (202 expected). Otherwise returns the JSON-RPC
        response whose id matches, from a JSON body or an SSE stream. kind: ok | accepted | timeout | error."""
        deadline, cap = time.monotonic() + self.cfg.request_timeout, self.cfg.max_response_bytes
        try:
            with self.upstream.stream("POST", self.cfg.upstream_url, content=payload, headers=self._up_headers(s)) as r:
                sid = r.headers.get("mcp-session-id")
                if expect_id is None:
                    return {"kind": "accepted" if r.status_code in (200, 202) else "error"}
                if r.status_code != 200:
                    return {"kind": "error", "status": r.status_code}
                ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
                if ctype not in ("application/json", "text/event-stream"):
                    return {"kind": "error", "reason": "content-type"}
                total, buf, sse = 0, [], SseParser(cap, cap)
                for chunk in r.iter_bytes():
                    total += len(chunk)
                    if total > cap:
                        return {"kind": "error", "reason": "response too large"}
                    if time.monotonic() > deadline:
                        return {"kind": "timeout"}
                    if ctype == "application/json":
                        buf.append(chunk)
                        continue
                    for ev in sse.feed(chunk):
                        m = self._sse_message(s, ev, expect_id)
                        if m is not None:
                            return {"kind": "ok", "message": m, "sid": sid, "last_event_id": sse.last_event_id}
                if ctype != "application/json":
                    for ev in sse.finish():
                        m = self._sse_message(s, ev, expect_id)
                        if m is not None:
                            return {"kind": "ok", "message": m, "sid": sid, "last_event_id": sse.last_event_id}
                if ctype == "application/json":
                    m = self._classify(s, b"".join(buf).decode("utf-8", "strict"), expect_id)
                    if m is not None:
                        return {"kind": "ok", "message": m, "sid": sid}
                return {"kind": "error", "reason": "no matching response"}
        except httpx.TimeoutException:
            return {"kind": "timeout"}
        except (httpx.HTTPError, SseError, ValueError, UnicodeDecodeError):
            return {"kind": "error", "reason": "transport"}

    def _sse_message(self, s: _Session, ev: SseEvent, expect_id: Any) -> Optional[Dict]:
        """An SSE event with an EMPTY data field is a priming event (event id only, per 2025-11-25): it carries no JSON-RPC
        message, is counted and skipped, and can never be a response. Any non-empty data goes through full JSON-RPC
        validation in _classify, so malformed data (including whitespace-only) still fails the exchange."""
        if ev.data == "":
            self.stats["sse_priming_events"] += 1
            return None
        return self._classify(s, ev.data, expect_id)

    def _classify(self, s: _Session, text: str, expect_id: Any) -> Optional[Dict]:
        """The final response for expect_id, or None to keep reading. Notifications are dropped; server requests are
        refused toward the upstream; responses for other ids are ignored."""
        try:
            m = json.loads(text)
        except ValueError:
            raise SseError("bad json")
        if not isinstance(m, dict) or m.get("jsonrpc") != "2.0":
            raise SseError("not a json-rpc message")
        if "method" in m:
            if "id" in m:
                self._refuse_server_request(s, m["id"])
            else:
                self.stats["server_messages_dropped"] += 1
            return None
        if m.get("id") == expect_id and type(m.get("id")) is type(expect_id) and ("result" in m) != ("error" in m):
            return m
        return None


# ---------------- CLI ----------------
def load_client_tokens(path: str) -> Dict[str, str]:
    with open(path) as f:
        d = json.load(f)
    if not isinstance(d, dict) or not d or not all(isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                                                    for k, v in d.items()):
        raise SystemExit("client tokens file must be {client_id: sha256-hex-of-token}")
    return d


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Qyrix Sentinel MCP proxy (Streamable HTTP, POST-only subset, MCP 2025-11-25)")
    ap.add_argument("--upstream", required=True, help="upstream MCP endpoint (https://, or http:// on loopback)")
    ap.add_argument("--client-tokens-file", required=True, help='JSON {client_id: sha256 hex of the client bearer token}')
    ap.add_argument("--config", help="tools.json mapping MCP tools to Sentinel actions (unmapped => blocked)")
    ap.add_argument("--listen", default="127.0.0.1:8765")
    ap.add_argument("--allow-non-loopback", action="store_true", help="bind a non-loopback address (put TLS in front!)")
    ap.add_argument("--allowed-host", action="append", default=[], help="extra accepted Host header value (repeatable)")
    ap.add_argument("--allowed-origin", action="append", default=[], help="accepted Origin (repeatable; default none)")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--task-id")
    ap.add_argument("--coverage-file")
    a = ap.parse_args(argv)
    host, _, port = a.listen.rpartition(":")
    if host not in _LOOPBACK and not a.allow_non_loopback:
        print("refusing to listen on a non-loopback address without --allow-non-loopback", file=sys.stderr)
        return 2
    token = os.getenv("QYRIX_TOKEN") or ""
    if not token and os.getenv("QYRIX_TOKEN_FILE"):
        with open(os.environ["QYRIX_TOKEN_FILE"]) as f:
            token = f.read().strip()
    if not token:
        print("QYRIX_TOKEN or QYRIX_TOKEN_FILE is required", file=sys.stderr)
        return 2
    up = os.getenv("QYRIX_MCP_UPSTREAM_TOKEN")
    if not up and os.getenv("QYRIX_MCP_UPSTREAM_TOKEN_FILE"):
        with open(os.environ["QYRIX_MCP_UPSTREAM_TOKEN_FILE"]) as f:
            up = f.read().strip()
    from app.mcp_proxy import load_mapping
    from app.observer_feed import AdapterReporter
    cfg = HttpProxyConfig(a.upstream, load_client_tokens(a.client_tokens_file), {a.listen, *a.allowed_host},
                          load_mapping(a.config), set(a.allowed_origin), a.task_id, up or None, request_timeout=a.timeout,
                          coverage_path=a.coverage_file)
    class _Client(core.SentinelClient):
        INTEGRATION = INTEGRATION
    proxy = McpHttpProxy(cfg, _Client(os.getenv("QYRIX_URL"), token), reporter=AdapterReporter.from_env())
    import uvicorn
    uvicorn.run(proxy.app, host=host, port=int(port), log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
