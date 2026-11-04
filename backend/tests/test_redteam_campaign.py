"""scripts/redteam_campaign.py: the multi-round live red-team campaign and the advisory-AI-vs-Gate matrix, tested OFFLINE.
The model is a mocked HTTP transport (no network, no key). What is proven here: untrusted model output goes through the
existing schema / safety filter / dedupe, the REAL Gate decides every case in isolation with zero egress, a provider failure
is recorded without any fallback, and the advisory classifier verdict never changes a Gate decision. What is NOT proven here:
anything about a real model's behaviour (that needs a live run with your own key)."""
import importlib.util
import json
import os
import pathlib

import httpx
import pytest

from app import redteam as rt

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "redteam_campaign.py"
spec = importlib.util.spec_from_file_location("redteam_campaign", SCRIPT)
rc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rc)

FAKE_KEY = "test-key-not-a-real-credential"


@pytest.fixture
def provider(monkeypatch):
    monkeypatch.setenv("BASETEN_API_KEY", FAKE_KEY)
    monkeypatch.setenv("BASETEN_MODEL", "test-model")


def transport(*contents):
    """Mock chat-completions endpoint: returns the given replies in order (the last one repeats)."""
    calls = {"n": 0, "auth": set()}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["auth"].add(req.headers.get("authorization"))
        c = contents[min(calls["n"], len(contents) - 1)]
        calls["n"] += 1
        return httpx.Response(200, json={"choices": [{"message": {"content": c}}]})
    t = httpx.MockTransport(handler)
    t.calls = calls
    return t


def reply(cases):
    return json.dumps({"cases": cases})


def base_cases():
    return rt.template_cases(seed=7, per_category=1)[0]


def run(tmp_path, t, rounds=3, **kw):
    return rc.campaign("baseten", rounds, 1, 1000, [0.7, 0.9], str(tmp_path), transport=t, **kw)


def test_pipeline_runs_real_gate_in_isolation_and_dedupes_across_rounds(provider, tmp_path):
    cases = base_cases()
    rep = run(tmp_path, transport(reply(cases)), rounds=3)                       # the same reply three times
    n = len(rt.accept(cases, {"generator": "llama", "generator_version": "1", "provider": "baseten", "model": "m", "prompt_version": "1",
                              "prompt_sha256": "0" * 64, "source_sha256": "0" * 64, "seed": 1, "temperature": 0.7, "created_at": "x"})[0])
    assert rep["rounds_ok"] == 3 and rep["accepted_unique"] == n and n > 0
    assert rep["rejected"].get("DUPLICATE_ACROSS_ROUNDS") == 2 * n               # rounds 2 and 3 added nothing new
    s = rep["summary"]
    assert s["cases"] == n and s["egress_calls"] == 0 and s["errors"] == 0      # isolated: no egress at all
    assert (tmp_path / "campaign.json").exists() and (tmp_path / "cases.jsonl").exists() and (tmp_path / "round-000.reply.txt").exists()


def test_key_never_appears_in_any_output(provider, tmp_path):
    t = transport(reply(base_cases()))
    run(tmp_path, t, rounds=2)
    assert t.calls["auth"] == {"Bearer " + FAKE_KEY}                              # it IS used for the request...
    for f in tmp_path.iterdir():
        assert FAKE_KEY not in f.read_text()                                      # ...but is never written anywhere


def test_unsafe_and_model_approved_cases_are_filtered(provider, tmp_path):
    cases = base_cases()
    bad = dict(cases[0], target="https://real-bank.com/transfer")                 # real host: refused by the safety filter
    selfish = dict(cases[1], review_status="approved", test_id="rt-forged")       # model tries to approve itself / set its id
    rep = run(tmp_path, transport(reply([bad, selfish])), rounds=1)
    assert rep["accepted_unique"] == 1 and sum(rep["rejected"].values()) >= 1
    loaded = rt.load_cases(str(tmp_path / "cases.jsonl"))
    assert all(c.review_status == "candidate" and c.test_id != "rt-forged" for c in loaded)


def test_unparseable_reply_is_recorded_and_the_campaign_continues(provider, tmp_path):
    rep = run(tmp_path, transport("this is not json", reply(base_cases())), rounds=3)
    st = [x["status"] for x in rep["rounds"]]
    assert st[0] == "UNPARSEABLE" and st[1] == "OK" and rep["accepted_unique"] > 0


def test_provider_not_configured_records_unavailable_and_never_falls_back(monkeypatch, tmp_path):
    for k in ("BASETEN_API_KEY", "BASETEN_MODEL", "META_API_KEY", "META_MODEL", "MODEL_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    rep = rc.campaign("baseten", 2, 1, 1, [0.7], str(tmp_path))
    assert [x["status"] for x in rep["rounds"]] == ["UNAVAILABLE", "UNAVAILABLE"] and rep["summary"] is None and rep["accepted_unique"] == 0
    assert rc.main(["--provider", "baseten", "--rounds", "1", "--out-dir", str(tmp_path / "cli")]) == 3


def test_candidate_bypass_is_detected_but_labelled_a_candidate(provider, tmp_path):
    cases = base_cases()
    control = next(c for c in cases if c["category"] == "safe_control")
    # an "attack" the Gate will in fact ALLOW (it is a benign control relabelled), where the model expected BLOCK
    fake = dict(control, category=rt.ATTACK_CATEGORIES[0], expected=dict(control["expected"], decision="BLOCK", rules=[], enforcement="NOT_EXECUTED"))
    rep = run(tmp_path, transport(reply([fake])), rounds=1)
    assert len(rep["bypass_candidates"]) == 1 and rep["bypass_candidates"][0]["status"] == "FALSE_NEGATIVE"
    assert any("candidate" in n.lower() for n in rep["notes"])                    # the report says it is not a confirmed vulnerability


def test_advisory_ai_verdict_never_changes_a_gate_decision(provider, tmp_path):
    cases = base_cases()
    flagged = lambda text: {"provider": "meta", "model": "m", "label": "untrusted_instruction"}
    benign = lambda text: {"provider": "meta", "model": "m", "label": "benign"}
    a = run(tmp_path / "a", transport(reply(cases)), rounds=1, classify_max=500, classify_fn=flagged)
    b = run(tmp_path / "b", transport(reply(cases)), rounds=1, classify_max=500, classify_fn=benign)
    dec = lambda rep: {r["test_id"]: (r["gate_decision"], tuple(r["gate_rules"])) for r in rep["advisory_vs_gate"]["rows"]}
    assert dec(a) == dec(b) and len(dec(a)) == a["accepted_unique"]               # flipping the AI changes NO Gate decision


def test_matrix_counts_and_heuristic_fallback_is_not_counted_as_ai(provider, tmp_path):
    cases = base_cases()
    benign = lambda text: {"provider": "meta", "model": "m", "label": "benign"}
    fallback = lambda text: {"provider": "heuristic", "model": None, "label": "benign"}
    live = run(tmp_path / "live", transport(reply(cases)), rounds=1, classify_max=500, classify_fn=benign)["advisory_vs_gate"]
    heur = run(tmp_path / "heur", transport(reply(cases)), rounds=1, classify_max=500, classify_fn=fallback)["advisory_vs_gate"]
    blocked_attacks = sum(v for k, v in live["attack"].items() if k.endswith("gate_blocked"))
    assert live["headline_live_ai_missed_but_gate_blocked"] == live["attack"].get("live_ai_missed_gate_blocked", 0) == blocked_attacks > 0
    assert heur["headline_live_ai_missed_but_gate_blocked"] == 0 and all(k.startswith("heuristic_") for k in heur["attack"])
    assert any("not AI results" in c for c in heur["caveats"])


def test_classify_max_bounds_the_number_of_model_calls(provider, tmp_path):
    calls = []
    fn = lambda text: calls.append(1) or {"provider": "meta", "model": "m", "label": "benign"}
    rep = run(tmp_path, transport(reply(base_cases())), rounds=1, classify_max=3, classify_fn=fn)
    assert len(calls) == 3 and rep["advisory_vs_gate"]["classified"] == 3 and rep["advisory_vs_gate"]["of_accepted"] > 3
