"""Shared adapter core (Phase 1). Platform adapters (today: the MCP proxy) translate platform events into Sentinel actions
and talk to the Sentinel REST API through this module. It contains NO policy: every allow / deny decision is made by the
deterministic Gate (`POST /api/v1/sentinel/gate/evaluate`), and execution is delegated only after the Gate's single-use,
params_digest-bound grant is redeemed (`POST /api/v1/tools/redeem`). Nothing here can authorize an action.

Kept dependency-light on purpose (httpx only): the proxy runs as its own process and must not import the server."""
import json
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlsplit

import httpx

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


def coverage_report(mapping: Dict[str, Dict], offered: Optional[Iterable[str]]) -> Dict:
    """Which tools the MCP server offers are sent to the Gate as a supported tool type, and which are default-denied.
    This is CONFIGURATION ANALYSIS, an advisory E1-style report: it is not evidence that enforcement happened, and a
    'gate_evaluated' tool is still BLOCKed whenever the Gate's rules say so. `offered=None` means no tools/list was seen."""
    mapped_ok = {n for n, m in mapping.items() if isinstance(m, dict) and m.get("tool") in GATE_TOOLS}
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
