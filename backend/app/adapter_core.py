"""Shared adapter core (Phase 1). Platform adapters (today: the MCP proxy) translate platform events into Sentinel actions
and talk to the Sentinel REST API through this module. It contains NO policy: every allow / deny decision is made by the
deterministic Gate (`POST /api/v1/sentinel/gate/evaluate`), and execution is delegated only after the Gate's single-use,
params_digest-bound grant is redeemed (`POST /api/v1/tools/redeem`). Nothing here can authorize an action.

Kept dependency-light on purpose (httpx only): the proxy runs as its own process and must not import the server."""
import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import httpx

CORR = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")             # correlation / task id shape (same as the Gate's Action fields)

# Gate tool types an adapter may target. A MIRROR of gateway.TOOLS used only to label the coverage report; the Gate stays
# the authority (tests/test_adapter_core.py fails if the two ever diverge). Anything else is refused by R8_UNSUPPORTED_TOOL.
GATE_TOOLS = ("http", "file.read")


def canonical(o: Any) -> str:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class SentinelError(Exception):
    pass


class SentinelClient:
    """Talks to the Sentinel REST API. `http` may be any httpx.Client (tests pass FastAPI's TestClient).
    INTEGRATION is the `X-Qyrix-Integration` scope sent on redemption; adapters override it."""
    INTEGRATION = "external"

    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None, http: Optional[httpx.Client] = None,
                 timeout: float = 10.0):
        if http is None:
            base_url = (base_url or "http://127.0.0.1:8000").rstrip("/")
            host = urlsplit(base_url).hostname or ""
            http = httpx.Client(base_url=base_url, timeout=timeout, headers={"Authorization": "Bearer " + (token or "")},
                                trust_env=host not in ("127.0.0.1", "localhost", "::1"))
        self.http = http

    def __repr__(self) -> str:                                # never expose the bearer token through repr / logging
        return "<%s>" % type(self).__name__

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
        return self._post("/api/v1/tools/redeem", body, {"X-Qyrix-Integration": self.INTEGRATION})


def to_action(name: str, args: Dict, mapping: Dict[str, Dict], correlation_id: str, task_id: Optional[str] = None) -> Dict:
    """Unmapped tools become `mcp:<name>`, which the Gate refuses (R8, default deny). The FULL arguments object is the
    action payload, so the grant's params_digest binds the exact arguments."""
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


# ---------------- argument policy (Phase 2.2, audit F-02) ----------------
# The Gate evaluates ONE destination (mapping.dest_arg) and ONE method (mapping.method). If the upstream tool also accepts
# another destination-bearing or method-bearing argument, the Gate would authorize something other than what runs. So a
# mapped tool must declare an explicit allow-list `args`; anything outside it is refused BEFORE the Gate is asked.
_SEP = re.compile(r"[-_.\s]")
_DEST_SUBSTR = ("url", "uri", "endpoint", "webhook", "callback", "redirect", "hostname", "domain", "address", "download", "upload")
_DEST_EXACT = frozenset(("host", "dest", "destination", "target", "path", "file", "filename", "filepath", "directory", "dir",
                         "link", "href", "src", "proxy", "server", "origin", "location", "remote", "ip", "site", "bucket"))
_METHOD_NAMES = frozenset(("method", "httpmethod", "verb", "requestmethod", "reqmethod", "httpverb"))
_SCALARS = (str, int, float, bool, type(None))


def _norm(name: str) -> str:
    return _SEP.sub("", name.lower())


def is_destination_like(name: str) -> bool:
    n = _norm(name)
    return n in _DEST_EXACT or any(x in n for x in _DEST_SUBSTR)


def is_method_like(name: str) -> bool:
    return _norm(name) in _METHOD_NAMES


def _safe(name: Any) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "?", str(name))[:40]


def validate_mapping(mapping: Dict[str, Dict]) -> None:
    """Raises ValueError for a mapping the proxies must not run. Each entry needs tool (a Gate tool type), dest_arg and an
    explicit `args` allow-list containing dest_arg and NO other destination-like or method-like name (ambiguous)."""
    if not isinstance(mapping, dict):
        raise ValueError("mapping must be an object")
    for name, m in mapping.items():
        if not isinstance(m, dict) or m.get("tool") not in GATE_TOOLS:
            raise ValueError("%s: tool must be one of %s" % (_safe(name), ", ".join(GATE_TOOLS)))
        dest, args = m.get("dest_arg"), m.get("args")
        if not isinstance(dest, str) or not dest:
            raise ValueError("%s: dest_arg is required" % _safe(name))
        if not isinstance(args, list) or not args or not all(isinstance(a, str) and a for a in args):
            raise ValueError("%s: an explicit non-empty 'args' allow-list is required" % _safe(name))
        if dest not in args:
            raise ValueError("%s: 'args' must contain dest_arg" % _safe(name))
        if len({_norm(a) for a in args}) != len(args):
            raise ValueError("%s: 'args' contains names that differ only by case/separators" % _safe(name))
        for a in args:
            if is_method_like(a):
                raise ValueError("%s: method-like argument %r is ambiguous with the mapped method" % (_safe(name), _safe(a)))
            if a != dest and is_destination_like(a):
                raise ValueError("%s: destination-like argument %r is ambiguous with dest_arg" % (_safe(name), _safe(a)))


def check_arguments(name: str, args: Dict, mapping: Dict[str, Dict]) -> Optional[str]:
    """None when the call may go to the Gate; otherwise a short reason code. Unmapped tools return None: the Gate refuses
    them (R8) and their arguments are never interpreted. Nothing is ever dropped or rewritten: the exact arguments the
    checks passed are the ones the Gate digests and the upstream later receives."""
    m = mapping.get(name)
    if m is None:
        return None
    try:
        validate_mapping({name: m})
    except ValueError:
        return "ARGS_POLICY_INVALID"
    for k in args:
        if k not in m["args"]:
            return "ARG_NOT_ALLOWED_" + _safe(k)
    if not isinstance(args.get(m["dest_arg"]), str) or not args[m["dest_arg"]].strip():
        return "DESTINATION_MISSING_OR_NOT_A_STRING"
    for k, v in args.items():
        if not isinstance(v, _SCALARS) or (isinstance(v, float) and v != v):
            return "ARG_NOT_SCALAR_" + _safe(k)                       # nested values could hide a second destination
    return None


def coverage_report(mapping: Dict[str, Dict], offered: Optional[Iterable[str]]) -> Dict:
    """Which tools the MCP server offers are sent to the Gate as a supported tool type, and which are default-denied.
    This is CONFIGURATION ANALYSIS, an advisory E1-style report: it is not evidence that enforcement happened, and a
    'gate_evaluated' tool is still BLOCKed whenever the Gate's rules say so. `offered=None` means no tools/list was seen."""
    mapped_ok = set()
    for n, m in mapping.items():
        try:
            validate_mapping({n: m})
            mapped_ok.add(n)
        except ValueError:
            pass                                                   # would be refused at call time => not Gate-evaluated
    if offered is None:
        return {"tools_list_observed": False, "gate_evaluated": [], "default_denied": [],
                "configured_but_not_offered": sorted(mapped_ok),
                "summary": "no tools/list response observed yet: coverage unknown",
                "limits": _LIMITS, "evidence": "advisory_configuration_analysis_not_enforcement_proof"}
    names: List[str] = sorted({n for n in offered if isinstance(n, str)})
    ev = [n for n in names if n in mapped_ok]
    den = [n for n in names if n not in mapped_ok]
    return {"tools_list_observed": True, "gate_evaluated": ev, "default_denied": den,
            "configured_but_not_offered": sorted(mapped_ok - set(names)),
            "summary": "%d of %d offered tools are evaluated by the Gate; %d are default-denied (R8)" % (len(ev), len(names), len(den)),
            "limits": _LIMITS, "evidence": "advisory_configuration_analysis_not_enforcement_proof"}


_LIMITS = ["gate_evaluated means the call is sent to the Gate, which can still BLOCK it; it does not mean the call is allowed",
           "the Gate sees the destination argument and the arguments text; other arguments are digest-bound but not interpreted",
           "tools the server adds after the observed tools/list are not reflected until the next tools/list",
           "covers only traffic through this proxy: a client that launches the MCP server directly bypasses it"]


def blocked_result(mid: Any, text: str, meta: Dict) -> Dict:
    """The MCP tool result a client gets when a call is NOT forwarded (isError=true, decision in _meta.qyrix)."""
    return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": text}], "isError": True,
                                                    "_meta": {"qyrix": meta}}}


class ToolCallGuard:
    """Transport-neutral per-call authorization for MCP `tools/call` (shared by the stdio and HTTP proxies).
    authorize() does evaluate -> redeem and returns what the TRANSPORT must do; it never forwards anything itself and
    holds no policy: only the Gate's verdict plus a successfully redeemed single-use grant yields kind == "forward".
      {"kind": "invalid"}                                  -> JSON-RPC -32602, nothing evaluated
      {"kind": "blocked", "text", "meta"}                  -> do NOT forward (BLOCK, Gate error, refused redemption)
      {"kind": "forward", "corr", "execution_id", "meta"}  -> grant redeemed: forward the ORIGINAL message, exactly once"""

    def __init__(self, sentinel: "SentinelClient", mapping: Dict[str, Dict], task_id: Optional[str] = None):
        self.sentinel, self.mapping, self.task_id = sentinel, mapping, task_id

    def authorize(self, params: Any) -> Dict:
        params = params if isinstance(params, dict) else {}
        name, args = params.get("name"), params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(args, dict):
            return {"kind": "invalid"}
        meta_in = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
        supplied = meta_in.get("qyrix/correlation_id")
        corr = supplied if isinstance(supplied, str) and CORR.match(supplied) else "mcp_" + uuid.uuid4().hex
        task = meta_in.get("qyrix/task_id", self.task_id)       # caller-provided context, NOT a verified task identity
        if task is not None and not (isinstance(task, str) and CORR.match(task)):
            return {"kind": "blocked", "text": "Blocked by Qyrix Sentinel: invalid task_id. correlation_id=%s" % corr,
                    "meta": {"verdict": "BLOCK", "rules": ["TASK_ID_INVALID"], "correlation_id": corr}}
        bad = check_arguments(name, args, self.mapping)
        if bad:                                                     # refused BEFORE the Gate: nothing is evaluated or forwarded
            rule = bad if bad.startswith("ARGS_POLICY_") else "ARGS_POLICY_" + bad     # one prefix, never two
            return {"kind": "blocked", "text": "Blocked by Qyrix Sentinel before evaluation: argument policy (%s). correlation_id=%s" % (rule, corr),
                    "meta": {"verdict": "BLOCK", "rules": [rule], "correlation_id": corr}}
        try:
            d = self.sentinel.evaluate(to_action(name, args, self.mapping, corr, task))
        except SentinelError as e:
            return {"kind": "blocked", "text": "Blocked by Qyrix Sentinel (fail closed): %s. correlation_id=%s" % (e, corr),
                    "meta": {"verdict": "BLOCK", "rules": ["PROXY_FAIL_CLOSED"], "reason": str(e), "correlation_id": corr}}
        meta = {"verdict": d.get("verdict"), "rules": d.get("rules", []), "correlation_id": corr, "task_id": task,
                "gate_evaluation_id": d.get("gate_evaluation_id"), "decision_proof_hash": (d.get("proof") or {}).get("hash")}
        if d.get("verdict") != "ALLOW" or not d.get("grant_id"):
            return {"kind": "blocked", "text": "Blocked by Qyrix Sentinel before execution: %s. correlation_id=%s"
                    % (", ".join(d.get("rules") or ["UNKNOWN"]), corr), "meta": {**meta, "verdict": "BLOCK"}}
        try:
            red = self.sentinel.redeem(d, corr, task)           # single-use, exact params_digest, same agent + task
        except SentinelError as e:
            return {"kind": "blocked", "text": "Blocked by Qyrix Sentinel: grant redemption refused (%s). correlation_id=%s" % (e, corr),
                    "meta": {**meta, "verdict": "BLOCK", "rules": ["GRANT_" + str(e)[:40]]}}
        return {"kind": "forward", "corr": corr, "execution_id": (red or {}).get("execution_id"), "meta": meta}
