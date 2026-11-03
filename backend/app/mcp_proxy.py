"""Qyrix Sentinel MCP proxy (stdio), v1.5 - the first platform integration built on the universal adapter contract.

    MCP client  <-stdio->  python -m app.mcp_proxy --config tools.json -- <real MCP server command...>  <-stdio->  MCP server

Every JSON-RPC message is passed through unchanged EXCEPT `tools/call`, which is intercepted:
  1. map the MCP tool + arguments to a Sentinel action (tools.json). Unmapped tools become `mcp:<name>`, which the Gate
     refuses (R8, default deny). The FULL arguments object is the action payload, so the grant's params_digest binds
     the exact arguments.
  2. POST /api/v1/sentinel/gate/evaluate with a correlation id (client may supply params._meta["qyrix/correlation_id"]).
  3. BLOCK, Sentinel unreachable, or any error  -> the call is NOT forwarded; the client gets an MCP tool result with
     isError=true and the decision (verdict, rules, correlation id) in _meta.qyrix. Fail closed.
  4. ALLOW -> POST /api/v1/tools/redeem (single-use grant, exact params_digest). Only after a successful redemption is
     the ORIGINAL message forwarded, so the server executes exactly what was evaluated.
  5. Responses are relayed; a call that exceeds --timeout gets a JSON-RPC error and its late response is dropped.

Configuration: QYRIX_URL (default http://127.0.0.1:8000), QYRIX_TOKEN or QYRIX_TOKEN_FILE (an agent/integrator API key).
tools.json: {"tools": {"fetch": {"tool": "http", "method": "GET", "dest_arg": "url"},
                       "read_file": {"tool": "file.read", "dest_arg": "path"}}}
Scope: stdio transport only. Tested against a stdio MCP server fixture (tests/fixtures/mcp_server_fixture.py);
compatibility with other MCP servers is claimed only where a test demonstrates it.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

import httpx

INTEGRATION = "mcp_proxy"
_CORR = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
TIMEOUT_CODE = -32001


def canonical(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SentinelError(Exception):
    pass


class SentinelClient:
    """Talks to the Sentinel REST API. `http` may be any httpx.Client (tests pass FastAPI's TestClient)."""

    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None, http: Optional[httpx.Client] = None,
                 timeout: float = 10.0):
        if http is None:
            base_url = (base_url or "http://127.0.0.1:8000").rstrip("/")
            host = urlsplit(base_url).hostname or ""
            http = httpx.Client(base_url=base_url, timeout=timeout, headers={"Authorization": "Bearer " + (token or "")},
                                trust_env=host not in ("127.0.0.1", "localhost", "::1"))
        self.http = http

    def _post(self, path: str, body: Dict, headers: Optional[Dict] = None) -> Dict:
        try:
            r = self.http.post(path, json=body, headers=headers or {})
        except Exception as e:
            raise SentinelError("SENTINEL_UNREACHABLE") from e
        try:
            j = r.json()
        except ValueError:
            j = {}
        if r.status_code != 200:
            raise SentinelError(str(j.get("detail") or "HTTP_%d" % r.status_code)[:120])
        return j

    def evaluate(self, action: Dict) -> Dict:
        return self._post("/api/v1/sentinel/gate/evaluate", action)

    def redeem(self, d: Dict, correlation_id: str, task_id: Optional[str] = None) -> Dict:
        body = {"gate_evaluation_id": d["gate_evaluation_id"], "grant_id": d["grant_id"],
                "params_digest": d["params_digest"], "correlation_id": correlation_id}
        if task_id:
            body["task_id"] = task_id                          # must equal the task the grant was issued for
        return self._post("/api/v1/tools/redeem", body, {"X-Qyrix-Integration": INTEGRATION})


def to_action(name: str, args: Dict, mapping: Dict[str, Dict], correlation_id: str, task_id: Optional[str] = None) -> Dict:
    m = mapping.get(name)
    if m is None:
        a = {"tool": ("mcp:" + name)[:32], "method": "CALL", "dest": "", "data": canonical(args)[:65536],
             "correlation_id": correlation_id}
    else:
        dest = args.get(m.get("dest_arg", ""), "")
        a = {"tool": m["tool"], "method": str(m.get("method", "GET"))[:10], "dest": dest if isinstance(dest, str) else "",
             "data": canonical(args)[:65536], "correlation_id": correlation_id}
    if task_id:
        a["task_id"] = task_id
    return a


class McpProxy:
    def __init__(self, sentinel: SentinelClient, server_cmd: List[str], mapping: Dict[str, Dict],
                 write_client: Callable[[Dict], None], timeout: float = 30.0, env: Optional[Dict[str, str]] = None,
                 task_id: Optional[str] = None, reporter=None):
        self.sentinel, self.cmd, self.mapping, self.write_client = sentinel, server_cmd, mapping, write_client
        self.reporter = reporter                              # optional observer_feed.AdapterReporter (E1 self-reports)
        if task_id is not None and not _CORR.match(task_id):
            raise ValueError("invalid task_id")
        self.task_id = task_id                                # default task context; a call may override it
        self.timeout, self.env = timeout, env
        self._pending: Dict[Any, float] = {}
        self._timed_out: set = set()
        self._lock = threading.Lock()
        self._wlock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None
        self.stats = {"forwarded_calls": 0, "blocked_calls": 0, "timeouts": 0}

    # ---- lifecycle ----
    def start(self) -> "McpProxy":
        self.proc = subprocess.Popen(self.cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
                                     env=self.env)
        threading.Thread(target=self._read_server, name="mcp-proxy-server-reader", daemon=True).start()
        threading.Thread(target=self._watchdog, name="mcp-proxy-watchdog", daemon=True).start()
        return self

    def close(self) -> None:
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.stdin.close()
            except Exception:
                pass
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    # ---- server side ----
    def _to_server(self, msg: Dict) -> None:
        self.proc.stdin.write(json.dumps(msg, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def _read_server(self) -> None:
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue                                       # never relay non-protocol output
            mid = msg.get("id") if isinstance(msg, dict) else None
            if isinstance(msg, dict) and "method" not in msg and mid is not None:
                with self._lock:
                    if mid in self._pending:
                        self._pending.pop(mid)
                    elif self._late(mid):
                        continue                               # response to a call we already timed out: drop it
            self._emit(msg)

    def _late(self, mid) -> bool:
        return mid in self._timed_out

    def _watchdog(self) -> None:
        while self.proc and self.proc.poll() is None:
            now = time.time()
            with self._lock:
                expired = [i for i, dl in self._pending.items() if dl < now]
                for i in expired:
                    self._pending.pop(i)
                    self._timed_out.add(i)
            for i in expired:
                self.stats["timeouts"] += 1
                self._emit({"jsonrpc": "2.0", "id": i, "error": {"code": TIMEOUT_CODE, "message": "MCP server timeout",
                                                                  "data": {"qyrix": {"timeout_s": self.timeout}}}})
            time.sleep(0.05)

    def _emit(self, msg: Dict) -> None:
        with self._wlock:
            self.write_client(msg)

    # ---- client side ----
    def handle_client(self, msg: Any) -> None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
            self._emit({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
            return
        if msg.get("method") == "tools/call" and "id" in msg:
            self._intercept(msg)
        else:
            self._to_server(msg)                               # initialize, tools/list, notifications, pings...

    def _report(self, corr: str, forwarded: bool, execution_id: Optional[str] = None) -> None:
        """Phase C2: signed adapter_report to the observer (E1: a self-report, never evidence). Never blocks the call."""
        if self.reporter is not None:
            try:
                self.reporter.report(corr, forwarded, execution_id)
            except Exception:
                pass

    def _blocked(self, mid, text: str, meta: Dict) -> None:
        self.stats["blocked_calls"] += 1
        if meta.get("correlation_id"):
            self._report(meta["correlation_id"], False)
        self._emit({"jsonrpc": "2.0", "id": mid, "result": {
            "content": [{"type": "text", "text": text}], "isError": True, "_meta": {"qyrix": meta}}})

    def _intercept(self, msg: Dict) -> None:
        mid, params = msg["id"], msg.get("params") or {}
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            self._emit({"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "Invalid params"}})
            return
        meta_in = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        supplied = meta_in.get("qyrix/correlation_id")
        corr = supplied if isinstance(supplied, str) and _CORR.match(supplied) else "mcp_" + uuid.uuid4().hex
        task = meta_in.get("qyrix/task_id", self.task_id)       # caller-provided context, NOT a verified task identity
        if task is not None and not (isinstance(task, str) and _CORR.match(task)):
            self._blocked(mid, "Blocked by Qyrix Sentinel: invalid task_id. correlation_id=%s" % corr,
                          {"verdict": "BLOCK", "rules": ["TASK_ID_INVALID"], "correlation_id": corr})
            return
        try:
            d = self.sentinel.evaluate(to_action(name, args, self.mapping, corr, task))
        except SentinelError as e:
            self._blocked(mid, "Blocked by Qyrix Sentinel (fail closed): %s. correlation_id=%s" % (e, corr),
                          {"verdict": "BLOCK", "rules": ["PROXY_FAIL_CLOSED"], "reason": str(e), "correlation_id": corr})
            return
        meta = {"verdict": d.get("verdict"), "rules": d.get("rules", []), "correlation_id": corr, "task_id": task,
                "gate_evaluation_id": d.get("gate_evaluation_id"), "decision_proof_hash": (d.get("proof") or {}).get("hash")}
        if d.get("verdict") != "ALLOW" or not d.get("grant_id"):
            self._blocked(mid, "Blocked by Qyrix Sentinel before execution: %s. correlation_id=%s"
                          % (", ".join(d.get("rules") or ["UNKNOWN"]), corr), {**meta, "verdict": "BLOCK"})
            return
        try:
            red = self.sentinel.redeem(d, corr, task)          # single-use, exact params_digest, same agent + task
        except SentinelError as e:
            self._blocked(mid, "Blocked by Qyrix Sentinel: grant redemption refused (%s). correlation_id=%s" % (e, corr),
                          {**meta, "verdict": "BLOCK", "rules": ["GRANT_" + str(e)[:40]]})
            return
        with self._lock:
            self._pending[mid] = time.time() + self.timeout
        self.stats["forwarded_calls"] += 1
        self._to_server(msg)                                   # the exact arguments that were evaluated
        self._report(corr, True, (red or {}).get("execution_id"))


class McpProxyCanaryAdapter:
    """Adapter-contract wrapper so CEV can send must-block canaries THROUGH a running proxy (conformance tests)."""
    id, label, test_fixture = INTEGRATION, "MCP proxy (stdio)", False

    def __init__(self, proxy: McpProxy, responses, tool: str = "fetch", url_arg: str = "url"):
        self.proxy, self.responses, self.tool, self.url_arg = proxy, responses, tool, url_arg

    def submit(self, action, ctx) -> Dict:
        mid = "cev-" + uuid.uuid4().hex[:12]
        self.proxy.handle_client({"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {
            "name": self.tool, "arguments": {self.url_arg: action.dest}, "_meta": {"qyrix/correlation_id": action.correlation_id}}})
        resp = self.responses(mid)
        meta = ((resp or {}).get("result") or {}).get("_meta", {}).get("qyrix") or {}
        with ctx.lock:                                         # the decision as RECORDED in the chain, not as reported
            rec = next((r for r in reversed(ctx.chain) if r.get("kind") == "gate_decision"
                        and r.get("gate_evaluation_id") == meta.get("gate_evaluation_id")), None)
        dec = {"verdict": rec["verdict"], "rules": rec["rule_ids"], "gate_evaluation_id": rec["gate_evaluation_id"],
               "proof": rec} if rec else None
        return {"decision": dec, "forwarded": not (resp or {}).get("result", {}).get("isError", False)}


def load_mapping(path: Optional[str]) -> Dict[str, Dict]:
    if not path:
        return {}
    with open(path) as f:
        cfg = json.load(f)
    tools = cfg.get("tools", {})
    for k, v in tools.items():
        if not isinstance(v, dict) or v.get("tool") not in ("http", "file.read"):
            raise SystemExit("tools.json: %s must map to tool 'http' or 'file.read'" % k)
    return tools


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Qyrix Sentinel MCP proxy (stdio)")
    ap.add_argument("--config", help="tools.json mapping MCP tools to Sentinel actions (unmapped => blocked)")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--task-id", help="default task context for every call (caller-provided, not verified)")
    ap.add_argument("server", nargs=argparse.REMAINDER, help="-- <MCP server command>")
    a = ap.parse_args(argv)
    cmd = a.server[1:] if a.server[:1] == ["--"] else a.server
    if not cmd:
        ap.error("missing MCP server command after --")
    token = os.getenv("QYRIX_TOKEN") or ""
    if not token and os.getenv("QYRIX_TOKEN_FILE"):
        with open(os.environ["QYRIX_TOKEN_FILE"]) as f:
            token = f.read().strip()
    if not token:
        print("QYRIX_TOKEN or QYRIX_TOKEN_FILE is required", file=sys.stderr)
        return 2
    out_lock = threading.Lock()

    def write(msg: Dict) -> None:
        with out_lock:
            sys.stdout.write(json.dumps(msg, separators=(",", ":")) + "\n")
            sys.stdout.flush()

    from app.observer_feed import AdapterReporter
    proxy = McpProxy(SentinelClient(os.getenv("QYRIX_URL"), token), cmd, load_mapping(a.config), write, a.timeout,
                     task_id=a.task_id, reporter=AdapterReporter.from_env()).start()
    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                write({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            proxy.handle_client(msg)
    finally:
        proxy.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
