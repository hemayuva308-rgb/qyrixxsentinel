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
Coverage: `--coverage-file` / McpProxy.coverage() report which offered tools reach the Gate and which are default-denied (advisory).
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

from app import adapter_core as core

INTEGRATION = "mcp_proxy"
_CORR = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
TIMEOUT_CODE = -32001


class SentinelClient(core.SentinelClient):
    """The shared client, scoped to this integration on redemption (`X-Qyrix-Integration: mcp_proxy`)."""
    INTEGRATION = INTEGRATION


canonical, SentinelError, to_action = core.canonical, core.SentinelError, core.to_action   # public names kept for importers


class McpProxy:
    def __init__(self, sentinel: SentinelClient, server_cmd: List[str], mapping: Dict[str, Dict],
                 write_client: Callable[[Dict], None], timeout: float = 30.0, env: Optional[Dict[str, str]] = None,
                 task_id: Optional[str] = None, reporter=None, coverage_path: Optional[str] = None):
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
        self.coverage_path = coverage_path
        self._list_ids: set = set()                           # ids of tools/list requests we forwarded
        self._offered: Optional[set] = None                   # tool names the server has offered (None = not seen yet)

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
                self._observe_tools(mid, msg)
            self._emit(msg)

    def _observe_tools(self, mid, msg: Dict) -> None:
        """Record tool NAMES from a tools/list response for the coverage report. Read-only: the message is relayed
        unchanged and nothing here influences any decision."""
        with self._lock:
            if not isinstance(mid, (str, int)) or mid not in self._list_ids:
                return
            self._list_ids.discard(mid)
            tools = (msg.get("result") or {}).get("tools") if isinstance(msg.get("result"), dict) else None
            if not isinstance(tools, list):
                return
            names = {t.get("name") for t in tools[:5000] if isinstance(t, dict) and isinstance(t.get("name"), str)}
            self._offered = (self._offered or set()) | names     # accumulates across pages
        self._write_coverage()

    def coverage(self) -> Dict:
        with self._lock:
            offered = None if self._offered is None else set(self._offered)
        return core.coverage_report(self.mapping, offered)

    def _write_coverage(self) -> None:
        if not self.coverage_path:
            return
        try:
            tmp = self.coverage_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.coverage(), f, indent=1)
            os.replace(tmp, self.coverage_path)
        except OSError:
            pass                                               # advisory output only: never affects the call path

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
            if msg.get("method") == "tools/list" and isinstance(msg.get("id"), (str, int)):
                with self._lock:
                    self._list_ids.add(msg["id"])
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
    ap.add_argument("--coverage-file", help="write the tool coverage report (JSON, tool names only) here after tools/list")
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
                     task_id=a.task_id, reporter=AdapterReporter.from_env(), coverage_path=a.coverage_file).start()
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
