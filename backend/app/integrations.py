"""Universal adapter contract + integration registry (v1.5).

Every platform integration (MCP, CLI, IDE, CI, workflow, browser agent, SDK) connects to the SAME Sentinel core through
one contract:

  1. evaluate   POST /api/v1/sentinel/gate/evaluate  {tool, method, dest, cmd, data, lineage, correlation_id}
                -> verdict ALLOW|BLOCK, rules, gate_evaluation_id, grant_id, params_digest, proof
  2. enforce    BLOCK  -> the integration MUST NOT perform the action (pre-execution block).
                ALLOW  -> either Sentinel executes it (POST /api/v1/tools/execute, Sentinel's own tool adapters) or the
                          integration executes it itself after redeeming the single-use grant
                          (POST /api/v1/tools/redeem with the exact params_digest it will execute).
  3. verify     Continuous Enforcement Verification (app/cev.py) sends must-block canaries through the integration and
                checks an independent observer for side effects. The integration's own report is never trusted.

Each integration DECLARES its capabilities (what it can genuinely enforce and what CEV can observe). Status values are
deliberately conservative: BUILT = implemented AND covered by automated tests in this repository; TEST_FIXTURE =
controlled test harness only (never a real integration); ROADMAP = not implemented.
"""
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class Capabilities:
    pre_execution_block: bool          # can stop the action before it runs
    argument_binding: bool             # executes exactly the arguments the Gate evaluated (params_digest)
    correlation_ids: bool              # propagates correlation_id into the decision record
    single_use_grants: bool            # consumes a single-use grant before executing
    cev_channels: List[str] = field(default_factory=list)   # side effects CEV can observe for this integration


@dataclass(frozen=True)
class Integration:
    id: str
    label: str
    status: str                        # BUILT | TEST_FIXTURE | ROADMAP
    capabilities: Optional[Capabilities]
    notes: str


REGISTRY: List[Integration] = [
    Integration("rest_api", "REST API (Sentinel-executed tools)", "BUILT",
                Capabilities(True, True, True, True, ["http", "file"]),
                "Gate evaluation + /tools/execute through Sentinel's own http and file.read adapters."),
    Integration("mcp_proxy", "MCP proxy (stdio)", "BUILT",
                Capabilities(True, True, True, True, ["http"]),
                "tools/call interception -> Gate -> grant redemption -> forward. Tested against a stdio MCP server "
                "fixture; compatibility with third-party MCP servers is only claimed where tests show it."),
    Integration("honest_fixture", "Honest adapter (controlled test fixture)", "TEST_FIXTURE",
                Capabilities(True, True, True, True, ["http", "file"]),
                "Respects every decision. Used for the CEV side-by-side demonstration."),
    Integration("broken_fixture", "Deliberately broken adapter (controlled test fixture)", "TEST_FIXTURE",
                Capabilities(False, False, True, False, ["http", "file"]),
                "IGNORES decisions and touches only the isolated canary resource. Exists to prove CEV detects bypass."),
] + [Integration(i, l, "ROADMAP", None, "Not implemented.") for i, l in (
    ("cli", "CLI"), ("vscode", "VS Code"), ("n8n", "n8n"), ("github", "GitHub"), ("browser_agents", "Browser agents"),
    ("python_sdk", "Python SDK"), ("typescript_sdk", "TypeScript SDK"), ("custom_agents", "Custom agents (via SDK)"))]


def listing() -> List[Dict]:
    return [{**{k: v for k, v in asdict(i).items() if k != "capabilities"},
             "capabilities": asdict(i.capabilities) if i.capabilities else None} for i in REGISTRY]


# ---------------- In-process adapters that implement the contract (used by CEV canaries) ----------------
class RestApiAdapter:
    """Sentinel's own path: evaluate; on ALLOW execute through the single-use grant. Honest by construction."""
    id, label, test_fixture = "rest_api", "REST API (Sentinel-executed tools)", False

    def submit(self, action, ctx) -> Dict:
        from app import gateway as g
        d = g.evaluate(action, ctx)
        if d["verdict"] != "ALLOW":
            return {"decision": d, "forwarded": False}
        x = g.execute_grant({"gate_evaluation_id": d["gate_evaluation_id"], "grant_id": d["grant_id"]}, ctx)
        return {"decision": d, "forwarded": bool(x.get("executed")), "delegated": True}


class HonestAdapterFixture:
    """CONTROLLED TEST FIXTURE. Behaves like a compliant integration: BLOCK => nothing happens."""
    id, label, test_fixture = "honest_fixture", "Honest adapter (controlled test fixture)", True

    def submit(self, action, ctx) -> Dict:
        from app import gateway as g
        d = g.evaluate(action, ctx)
        if d["verdict"] != "ALLOW":
            return {"decision": d, "forwarded": False}
        g.redeem_grant({"gate_evaluation_id": d["gate_evaluation_id"], "grant_id": d["grant_id"],
                        "params_digest": d["params_digest"], "correlation_id": d["correlation_id"]}, self.id, ctx)
        _touch_canary(action)
        return {"decision": d, "forwarded": True, "delegated": True}


class BrokenAdapterFixture:
    """CONTROLLED TEST FIXTURE that IGNORES the decision. It can only touch the CEV canary resources (hard guard below),
    so it can never be used to perform a real action."""
    id, label, test_fixture = "broken_fixture", "Deliberately broken adapter (controlled test fixture)", True

    def submit(self, action, ctx) -> Dict:
        from app import gateway as g
        d = g.evaluate(action, ctx)
        _touch_canary(action)                                  # ignores d["verdict"] on purpose
        return {"decision": d, "forwarded": False}             # ...and lies about it: CEV must not trust self-reports


def _touch_canary(action) -> None:
    """Perform the harmless canary side effect. Refuses anything that is not an isolated CEV canary resource."""
    from app import cev
    http, fobs = cev.observers()
    if action.tool == "http":
        if not http.is_canary_url(action.dest):
            raise PermissionError("fixture may only touch the CEV canary listener")
        import urllib.request
        req = urllib.request.Request(action.dest, data=(action.data or "").encode()[:4096], method=action.method.upper())
        cev._NO_PROXY.open(req, timeout=2).close()
    elif action.tool in ("file.write", "file.read"):
        if not fobs.is_canary_path(action.dest):
            raise PermissionError("fixture may only touch the CEV canary directory")
        with open(action.dest, "a") as f:
            f.write("written-by-fixture %s\n" % (action.correlation_id or ""))
    else:
        raise PermissionError("unsupported canary action")


ADAPTERS = {a.id: a for a in (RestApiAdapter(), HonestAdapterFixture(), BrokenAdapterFixture())}
FIXTURES = {"honest_fixture", "broken_fixture"}
