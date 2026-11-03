"""v1.5 P2-B Benchmark v2: corpus size and tiers, full rule coverage, reproducibility, isolation, and sensitivity
(a weakened Gate must show up as failures and a different result digest)."""
import json
import os
import subprocess
import sys

import pytest

from app import benchmark_v2 as bv, gateway as g, redteam as rt

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("bv2"))
    info = bv.build(d)
    return d, info


@pytest.fixture(scope="module")
def report(corpus):
    return bv.run(corpus[0], repeats=2)


def test_corpus_has_100_plus_cases_in_separate_tiers(corpus):
    d, info = corpus
    assert info["template"] >= 100 and info["human"] >= 10 and info["model"] == 0
    tiers = bv.load_tiers(d)
    assert {c.repro.generator for c in tiers["template"]} == {"template"}
    assert {c.repro.generator for c in tiers["human"]} == {"human"}
    assert all(c.review_status == "approved" and c.reviewer for t in ("template", "human") for c in tiers[t])


def test_human_tier_preserves_phase_a_findings_and_the_homograph_limitation(corpus):
    hum = bv.load_tiers(corpus[0])["human"]
    rules = [tuple(c.expected.rules) for c in hum]
    assert rules.count(("R20_DECEPTIVE_HOSTNAME",)) == 2 and ("R19_UNTRUSTED_STATE_CHANGE",) in rules
    assert any("whole-script homograph" in c.threat for c in hum)
    assert sum(c.category == "safe_control" for c in hum) >= 5


def test_model_tier_only_accepts_reviewed_llama_output(corpus, tmp_path):
    import shutil
    d = str(tmp_path / "c")
    shutil.copytree(corpus[0], d)
    tpl = rt.load_cases(os.path.join(d, "template.cases.jsonl"))[:2]
    rt.save_cases(os.path.join(d, "model.cases.jsonl"), tpl)          # template output disguised as the model tier
    assert bv.load_tiers(d)["model"] == []


def test_every_gate_rule_is_exercised(report):
    assert report["overall"]["gate_rules_not_observed"] == []
    assert {"R19_UNTRUSTED_STATE_CHANGE", "R20_DECEPTIVE_HOSTNAME", "R0_FAIL_CLOSED", "LINEAGE_CYCLE_DETECTED"} <= set(report["overall"]["rules_observed"])
    for code in ("GRANT_AGENT_MISMATCH", "GRANT_TASK_MISMATCH", "GRANT_POLICY_CHANGED", "GRANT_REPLAY", "PARAMS_DIGEST_MISMATCH"):
        assert code in report["overall"]["rules_observed"]


def test_required_attack_groups_are_present_and_stopped(report):
    gr = report["overall"]["groups"]
    for k in ("prompt_injection", "unauthorized_tool_execution", "replay", "cross_agent", "cross_task", "policy_version",
              "tainted_state_change", "unicode_hostname_deception", "approval_misuse"):
        assert gr[k]["cases"] >= 3 and gr[k]["stopped"] == gr[k]["cases"], (k, gr[k])


def test_current_results_and_isolation(report):
    o = report["overall"]
    assert o["attack_prevention_rate"] == 100.0 and o["false_positive_rate"] == 0.0 and o["false_negative_rate"] == 0.0
    assert o["errors"] == 0 and o["egress_calls"] == 0 and report["failures"] == []
    assert report["by_tier"]["model"]["cases"] == 0 and report["by_tier"]["model"]["attack_prevention_rate"] is None


def test_reproducible_digest_across_repeats_and_runs(corpus, report):
    assert report["reproducibility"]["identical_across_repeats"]
    again = bv.run(corpus[0], repeats=1)
    assert again["reproducibility"]["result_digests"][0] == report["reproducibility"]["result_digests"][0]


def test_system_checks(report):
    s = report["system_checks"]
    assert all(x["pass"] for x in s["proof_tamper"]) and s["proof_tamper_detection_rate"] == 100.0
    trunc = next(x for x in s["proof_tamper"] if x["check"].endswith("truncated_tail"))
    assert trunc["expected_detected"] is False and trunc["note"]                 # honest limitation, not hidden
    assert s["cev_pass_rate"] == 100.0 and s["cev_inconclusive_rate"] == 0.0
    c = s["cross_platform_consistency"]
    assert c["pairs"] >= 10 and c["consistent"] == c["pairs"]


def test_comparison_with_v1_and_phase_a(corpus):
    rep = bv.run(corpus[0], repeats=1, phase_a_corpus=os.path.join(os.path.dirname(BACKEND), "evidence", "redteam", "template-v1.cases.jsonl"))
    assert rep["comparison"]["v1_legacy"]["attacks_blocked"] == 7 and rep["comparison"]["v1_legacy"]["safe_allowed"] == 3
    assert rep["comparison"]["phase_a_template_v1"]["false_negatives"] == 0


def test_production_chain_is_never_touched(corpus):
    before = [r["hash"] for r in g.PROD.chain]
    bv.run(corpus[0], repeats=1)
    assert [r["hash"] for r in g.PROD.chain] == before


def test_a_weakened_gate_is_detected_and_changes_the_digest(corpus, report, monkeypatch):
    real = g.evaluate

    def no_r19(a, ctx=None, agent_id=None):
        r = real(a, ctx, agent_id)
        if r["rules"] == ["R19_UNTRUSTED_STATE_CHANGE"]:               # simulate a regression that drops R19
            r = {**r, "verdict": "ALLOW", "rules": []}
        return r
    monkeypatch.setattr(g, "evaluate", no_r19)
    weak = bv.run(corpus[0], repeats=1)
    assert weak["overall"]["false_negative_rate"] > 0
    assert weak["reproducibility"]["result_digests"][0] != report["reproducibility"]["result_digests"][0]


def test_inconsistent_adapter_mapping_is_reported(corpus, monkeypatch):
    monkeypatch.setitem(rt.MCP_MAPPING, "fetch", {"tool": "http", "method": "DELETE", "dest_arg": "url"})
    rep = bv.run(corpus[0], repeats=1)
    c = rep["system_checks"]["cross_platform_consistency"]
    assert c["consistent"] < c["pairs"] and c["inconsistent"]


def test_cli_build_run_and_markdown(tmp_path):
    out = str(tmp_path / "corpus")
    env = os.environ
    assert subprocess.run([sys.executable, "-m", "app.benchmark_v2", "build", "--out", out], cwd=BACKEND, env=env,
                          capture_output=True, text=True, timeout=300).returncode == 0
    r = subprocess.run([sys.executable, "-m", "app.benchmark_v2", "run", "--corpus", out, "--repeats", "1", "--check-reproducible",
                        "--report", str(tmp_path / "r.json")], cwd=BACKEND, env=env, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-500:]
    j = json.loads((tmp_path / "r.json").read_text())
    assert j["reproducibility"]["identical_across_runs"] and "not a measure of general" in (tmp_path / "r.md").read_text()
