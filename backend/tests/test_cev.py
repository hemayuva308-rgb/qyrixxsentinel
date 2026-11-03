"""v1.5 Continuous Enforcement Verification + universal adapter contract + delegated grant redemption.
Every claim the dashboard/deck makes about CEV is asserted here: same BLOCK for both fixtures, honest => VERIFIED,
broken => BYPASS_DETECTED + critical alert, missing telemetry never verified, evidence in the hash chain."""
import os

import pytest
from fastapi.testclient import TestClient

from app import alerts, cev, gateway as g, identity, integrations, observability as obs, proof
from app.main import app
from tests.conftest import ADMIN, AGENT

P = "/api/v1/sentinel"
admin = TestClient(app, headers=ADMIN)
agent = TestClient(app, headers=AGENT)


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    monkeypatch.setenv("QYRIX_CEV_WINDOW_SECONDS", "0.1")
    alerts.reset_for_tests(); identity.limiter.clear()
    admin.post(P + "/reset")
    yield
    alerts.reset_for_tests()


# ---------------- reconciler truth table (pure) ----------------
OK = {"armed": True, "positive_control": True, "window_closed": True}
BLK, ALW = {"verdict": "BLOCK"}, {"verdict": "ALLOW"}
EV = [{"channel": "http"}]


@pytest.mark.parametrize("decision,events,tel,delegated,expected", [
    (BLK, [], OK, False, cev.VERIFIED),
    (BLK, EV, OK, False, cev.BYPASS),
    (BLK, EV, {"armed": False}, False, cev.BYPASS),                        # observed side effect beats missing telemetry
    (BLK, [], {**OK, "positive_control": False}, False, cev.INCONCLUSIVE),  # observer not proven => never verified
    (BLK, [], {**OK, "armed": False}, False, cev.INCONCLUSIVE),
    (BLK, [], {**OK, "window_closed": False}, False, cev.INCONCLUSIVE),
    (BLK, [], {}, False, cev.INCONCLUSIVE),                                # no telemetry at all
    (None, EV, OK, False, cev.UNAUTHORIZED),
    (None, [], OK, False, cev.INCONCLUSIVE),
    ({"verdict": "WEIRD"}, [], OK, False, cev.INCONCLUSIVE),
    (ALW, EV, OK, True, cev.VERIFIED),
    (ALW, EV, OK, False, cev.UNAUTHORIZED),                                 # executed outside the grant path
    (ALW, [], OK, True, cev.INCONCLUSIVE),
], ids=["block-held", "bypass", "bypass-no-telemetry", "no-positive-control", "not-armed", "window-open", "empty-telemetry",
        "effect-without-decision", "nothing-at-all", "unknown-verdict", "allow-through-grant", "allow-without-grant",
        "allow-not-observed"])
def test_reconciler_truth_table(decision, events, tel, delegated, expected):
    assert cev.reconcile(decision, events, tel, delegated)["result"] == expected


def test_missing_telemetry_is_never_verified_exhaustively():
    for armed in (False, True):
        for ctl in (False, True):
            for closed in (False, True):
                if armed and ctl and closed:
                    continue
                r = cev.reconcile(BLK, [], {"armed": armed, "positive_control": ctl, "window_closed": closed})
                assert r["result"] == cev.INCONCLUSIVE, (armed, ctl, closed)


# ---------------- signature demo (acceptance criteria) ----------------
@pytest.mark.parametrize("channel", ["http", "file"])
def test_side_by_side_demo_honest_verified_broken_bypass(channel):
    r = admin.post(P + "/cev/demo", json={"channel": channel})
    assert r.status_code == 200, r.text
    j = r.json()
    h, b = j["honest"], j["broken"]
    # 1. the SAME must-block decision for both
    assert h["decision_verdict"] == b["decision_verdict"] == "BLOCK" and h["decision_rules"] == b["decision_rules"]
    # 2./3./4./5. honest respected it, broken did not, the independent observer saw it, reconciler says so
    assert h["result"] == cev.VERIFIED and h["observed"] == []
    assert b["result"] == cev.BYPASS and len(b["observed"]) == 1 and b["observed"][0]["channel"] == channel
    assert b["adapter_reported_forwarded"] is False                       # broken fixture lies; CEV ignored the lie
    assert h["test_fixture"] and b["test_fixture"]
    assert h["correlation_id"] != b["correlation_id"] and h["correlation_id"].startswith("cev_")
    # 6. evidence: the hash chain verifies and contains both decisions (with correlation ids) and both reconciliations
    assert j["chain_verify"]["valid"] is True
    chain = admin.get(P + "/proofs").json()["chain"]
    assert proof.verify_records(chain)["valid"]
    for x in (h, b):
        dec = [r for r in chain if r.get("kind") == "gate_decision" and r.get("correlation_id") == x["correlation_id"]]
        rec = [r for r in chain if r.get("kind") == "cev_reconciliation" and r.get("correlation_id") == x["correlation_id"]]
        assert len(dec) == 1 and dec[0]["hash"] == x["decision_proof_hash"] and dec[0]["verdict"] == "BLOCK"
        assert len(rec) == 1 and rec[0]["result"] == x["result"] and rec[0]["hash"] == x["proof"]["hash"]
    # 7. the broken outcome is a critical alert; the honest one raises nothing
    crit = [a for a in alerts.recent if a["alert"] == "enforcement_bypass_detected"]
    assert len(crit) == 1 and crit[0]["severity"] == "critical" and crit[0]["scope"] == "broken_fixture"


def test_results_and_conformance_come_from_the_proof_chain():
    admin.post(P + "/cev/demo", json={"channel": "http"})
    j = admin.get(P + "/cev/results").json()
    assert {r["adapter"] for r in j["results"]} == {"honest_fixture", "broken_fixture"}
    assert j["conformance"]["honest_fixture"]["conformance_rate"] == 100.0
    assert j["conformance"]["broken_fixture"]["conformance_rate"] == 0.0
    snap = obs.snapshot()
    assert snap.get('qyrix_cev_results_total{adapter="broken_fixture",channel="http",result="BYPASS_DETECTED"}', 0) >= 1
    assert snap.get('qyrix_cev_results_total{adapter="honest_fixture",channel="http",result="ENFORCEMENT_VERIFIED"}', 0) >= 1


def test_observer_without_positive_control_makes_honest_result_inconclusive(monkeypatch):
    monkeypatch.setattr(cev, "positive_control", lambda ch: False)
    h = admin.post(P + "/cev/canary", json={"adapter": "honest_fixture", "channel": "http"}).json()
    assert h["result"] == cev.INCONCLUSIVE and "OBSERVER_POSITIVE_CONTROL_FAILED" in h["reasons"]
    b = admin.post(P + "/cev/canary", json={"adapter": "broken_fixture", "channel": "http"}).json()
    assert b["result"] == cev.BYPASS                                       # positive evidence still wins
    s = admin.get(P + "/cev/results").json()["conformance"]
    assert s["honest_fixture"]["conformance_rate"] is None                 # inconclusive is never counted as success


def test_adapter_crash_is_inconclusive_not_verified():
    class Crashing:
        id, label, test_fixture = "crash", "crash", True

        def submit(self, action, ctx):
            raise RuntimeError("boom")
    r = cev.run_canary(g.PROD, Crashing(), "http")
    assert r["result"] == cev.INCONCLUSIVE and r["reasons"] == ["NO_DECISION_RECORDED"]


def test_side_effect_without_decision_is_unauthorized_execution():
    class Rogue:                                                           # executes without ever asking the Gate
        id, label, test_fixture = "rogue", "rogue", True

        def submit(self, action, ctx):
            integrations._touch_canary(action)
            return {"decision": None}
    r = cev.run_canary(g.PROD, Rogue(), "http")
    assert r["result"] == cev.UNAUTHORIZED
    assert any(a["alert"] == "enforcement_bypass_detected" for a in alerts.recent)


def test_rest_api_adapter_canary_is_verified():
    r = admin.post(P + "/cev/canary", json={"adapter": "rest_api", "channel": "http"}).json()
    assert r["decision_verdict"] == "BLOCK" and r["result"] == cev.VERIFIED and not r["test_fixture"]


def test_fixtures_are_disabled_outside_demo_or_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("QYRIX_ENABLE_DEMO_RESET", "0")
    monkeypatch.delenv("QYRIX_CEV_TEST_FIXTURES", raising=False)
    assert admin.post(P + "/cev/demo", json={}).status_code == 403
    assert admin.post(P + "/cev/canary", json={"adapter": "broken_fixture"}).status_code == 403
    assert admin.post(P + "/cev/canary", json={"adapter": "rest_api"}).status_code == 200   # real path stays available
    monkeypatch.setenv("QYRIX_CEV_TEST_FIXTURES", "1")
    assert admin.post(P + "/cev/demo", json={}).status_code == 200


def test_cev_permissions_and_validation():
    assert agent.post(P + "/cev/demo", json={}).status_code == 403
    assert agent.post(P + "/cev/canary", json={"adapter": "rest_api"}).status_code == 403
    assert admin.post(P + "/cev/canary", json={"adapter": "nope"}).status_code == 404
    assert admin.post(P + "/cev/canary", json={"adapter": "rest_api", "channel": "ftp"}).status_code == 422
    assert admin.post(P + "/cev/canary", json={"adapter": "rest_api", "extra": 1}).status_code == 422
    assert TestClient(app).get(P + "/cev/results").status_code == 401


def test_broken_fixture_can_only_touch_canary_resources():
    for a in (g.Action(tool="http", method="GET", dest="https://github.com/x"),
              g.Action(tool="http", method="GET", dest="http://127.0.0.1:1/canary/abcdefgh"),
              g.Action(tool="file.write", dest="/etc/passwd"),
              g.Action(tool="file.write", dest=os.path.join(cev.observers()[1].dir, "..", "x.canary")),
              g.Action(tool="shell", cmd="id")):
        with pytest.raises(PermissionError):
            integrations._touch_canary(a)


def test_canary_actions_are_must_block_under_current_policy():
    for ch in cev.CHANNELS:
        a = cev.canary_action(ch, "cev_test", "t" * 32)
        d = g.evaluate(a, g.PROD)
        assert d["verdict"] == "BLOCK" and d["correlation_id"] == "cev_test" and d["proof"]["correlation_id"] == "cev_test"


def test_integration_registry_status_is_conservative():
    j = admin.get(P + "/integrations").json()
    by = {i["id"]: i for i in j["integrations"]}
    assert by["rest_api"]["status"] == "BUILT" and by["mcp_proxy"]["status"] == "BUILT"
    assert by["broken_fixture"]["status"] == "TEST_FIXTURE" and not by["broken_fixture"]["capabilities"]["pre_execution_block"]
    for rid in ("cli", "vscode", "n8n", "github", "browser_agents", "python_sdk", "typescript_sdk", "custom_agents"):
        assert by[rid]["status"] == "ROADMAP" and by[rid]["capabilities"] is None


# ---------------- correlation ids + delegated redemption ----------------
def _allow(corr=None):
    body = {"tool": "http", "method": "GET", "dest": "https://github.com/qyrix"}
    if corr:
        body["correlation_id"] = corr
    r = agent.post(P + "/gate/evaluate", json=body).json()
    assert r["verdict"] == "ALLOW", r
    return r


def test_correlation_id_is_recorded_and_does_not_change_the_digest():
    a, b = _allow("corr-1"), _allow()
    assert a["params_digest"] == b["params_digest"] and a["correlation_id"] == "corr-1" and b["correlation_id"] == b["gate_evaluation_id"]
    assert a["proof"]["correlation_id"] == "corr-1"
    assert agent.post(P + "/gate/evaluate", json={"tool": "http", "dest": "https://github.com", "correlation_id": "bad id!"}).status_code == 422


def test_redeem_is_single_use_digest_bound_and_audited():
    r = _allow("corr-2")
    body = {"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"], "params_digest": r["params_digest"]}
    ok = agent.post("/api/v1/tools/redeem", json=body, headers={"X-Qyrix-Integration": "mcp_proxy"})
    assert ok.status_code == 200 and ok.json()["redeemed"] and ok.json()["proof"]["verdict"] == "EXECUTION_DELEGATED"
    assert ok.json()["proof"]["integration"] == "mcp_proxy"
    again = agent.post("/api/v1/tools/redeem", json=body)
    assert again.status_code == 409 and again.json()["detail"] == "GRANT_REPLAY"
    r2 = _allow()
    tampered = agent.post("/api/v1/tools/redeem", json={"gate_evaluation_id": r2["gate_evaluation_id"], "grant_id": r2["grant_id"],
                                                        "params_digest": "0" * 64})
    assert tampered.status_code == 403 and tampered.json()["detail"] == "PARAMS_DIGEST_MISMATCH"
    # a redeemed grant can no longer be executed by Sentinel either (one grant, one execution, any path)
    x = agent.post("/api/v1/tools/execute", json={"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]})
    assert x.status_code == 409 and x.json()["detail"] == "GRANT_REPLAY"


def test_redeem_refuses_blocked_unknown_and_extra_fields():
    blk = agent.post(P + "/gate/evaluate", json={"tool": "http", "method": "GET", "dest": "https://evil.example.net/x"}).json()
    assert blk["verdict"] == "BLOCK" and blk["grant_id"] is None
    r = agent.post("/api/v1/tools/redeem", json={"gate_evaluation_id": blk["gate_evaluation_id"], "grant_id": "grt_x",
                                                 "params_digest": blk["params_digest"]})
    assert r.status_code == 403 and r.json()["detail"] == "GRANT_INVALID"
    a = _allow()
    assert agent.post("/api/v1/tools/redeem", json={"gate_evaluation_id": a["gate_evaluation_id"], "grant_id": a["grant_id"],
                                                    "params_digest": a["params_digest"], "dest": "https://evil.example"}).status_code == 400
    assert agent.post("/api/v1/tools/redeem", json={"gate_evaluation_id": a["gate_evaluation_id"]}).status_code == 400
    assert agent.post("/api/v1/tools/redeem", content=b"{nope").status_code == 400


def test_expired_grant_cannot_be_redeemed(monkeypatch):
    a = _allow()
    g.PROD.grants[a["grant_id"]]["exp"] = 0
    r = agent.post("/api/v1/tools/redeem", json={"gate_evaluation_id": a["gate_evaluation_id"], "grant_id": a["grant_id"],
                                                 "params_digest": a["params_digest"]})
    assert r.status_code == 409 and r.json()["detail"] == "GRANT_EXPIRED"


def test_concurrent_redemption_of_one_grant_succeeds_exactly_once():
    import threading
    a = _allow()
    body = {"gate_evaluation_id": a["gate_evaluation_id"], "grant_id": a["grant_id"], "params_digest": a["params_digest"]}
    codes, start = [], threading.Barrier(8)

    def go():
        start.wait()
        codes.append(TestClient(app, headers=AGENT).post("/api/v1/tools/redeem", json=body).status_code)
    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sorted(codes) == [200] + [409] * 7


def test_reconciliation_reports_its_proof_sequence_number():
    r = admin.post(P + "/cev/canary", json={"adapter": "rest_api"}).json()
    chain = admin.get(P + "/proofs").json()["chain"]
    assert isinstance(r["proof"]["seq"], int) and chain[r["proof"]["seq"] - 1]["hash"] == r["proof"]["hash"]
