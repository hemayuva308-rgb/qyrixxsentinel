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
    assert info["template"] >= 100 and info["human"] >= 5 and info["model"] == 0
    tiers = bv.load_tiers(d)
    assert {c.repro.generator for c in tiers["template"]} == {"template"}
    assert {c.repro.generator for c in tiers["human"]} == {"human"}
    assert all(c.review_status == "approved" and c.reviewer for t in ("template", "human") for c in tiers[t])


def test_every_case_is_in_exactly_one_tier_and_findings_are_present_once(corpus):
    t = bv.load_tiers(corpus[0])
    ids = [c.test_id for cs in t.values() for c in cs]
    assert len(ids) == len(set(ids))                                   # no case counted in two tiers
    from tests.test_gate_hardening import ORIGINAL_FINDINGS
    ok, _ = rt.accept(ORIGINAL_FINDINGS, {"generator": "x", "created_at": "x"})
    tpl = {c.test_id for c in t["template"]}
    assert all(c.test_id in tpl for c in ok)                           # Phase A findings: in the template tier, once
    hum = t["human"]
    assert any("whole-script homograph" in c.threat for c in hum) and sum(c.category == "safe_control" for c in hum) >= 5


def test_build_refuses_cross_tier_duplicates(tmp_path, monkeypatch):
    import json as _j
    src = _j.load(open(bv.HUMAN_SOURCE))
    raw, _ = rt.template_cases(bv.TEMPLATE_SEED, bv.TEMPLATE_PER_CATEGORY)
    src["cases"].append(raw[0])                                        # a template case re-added to the human tier
    p = tmp_path / "h.json"
    p.write_text(_j.dumps(src))
    monkeypatch.setattr(bv, "HUMAN_SOURCE", str(p))
    with pytest.raises(SystemExit, match="more than one tier"):
        bv.build(str(tmp_path / "out"))


def test_totals_reconcile_with_the_corpus_files(corpus, report):
    t = bv.corpus_totals(corpus[0])
    o = report["overall"]
    assert (t["overall"]["cases"], t["overall"]["attack_cases"], t["overall"]["safe_controls"]) == (o["cases"], o["attack_cases"], o["safe_controls"])
    assert sum(v["cases"] for v in o["attack_categories"].values()) == o["attack_cases"]   # primary categories sum exactly
    assert sum(v for k, v in t["template"]["by_category"].items() if k != "safe_control") == t["template"]["attack_cases"]


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
    gr = report["overall"]["cross_cutting_views"]
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
    assert again["reproducibility"]["digest"] == report["reproducibility"]["digest"]


def test_system_checks(report):
    s = report["system_checks"]
    assert all(x["pass"] for x in s["proof_tamper"]) and s["proof_tamper_detection_rate"] == 100.0
    trunc = next(x for x in s["proof_tamper"] if x["check"].endswith("truncated_tail"))
    assert trunc["expected_detected"] is False and trunc["detected"] is False and "durable mode only" in trunc["note"]
    below = next(x for x in s["proof_tamper"] if x["check"] == "proof_anchor:truncated_below_anchor")
    after = next(x for x in s["proof_tamper"] if x["check"] == "proof_anchor:truncated_after_latest_anchor")
    assert below["detected"] and not after["detected"]
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
    assert weak["reproducibility"]["digest"] != report["reproducibility"]["digest"]


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


# ---------------- digest sensitivity (item 4) ----------------
@pytest.fixture(scope="module")
def parts(corpus):
    """Rows + system checks + v1 from one run, to recompute the digest under single controlled mutations."""
    d = corpus[0]
    tiers = bv.load_tiers(d)
    import tempfile, shutil
    ws = tempfile.mkdtemp()
    for rel, body in rt.WORKSPACE_FILES.items():
        os.makedirs(os.path.dirname(os.path.join(ws, rel)), exist_ok=True)
        open(os.path.join(ws, rel), "w").write(body)
    rows = []
    for tier, cs in tiers.items():
        for c in cs:
            r = rt.run_case(c, ws)
            r["tier"] = tier
            rows.append(r)
    system = {"proof_tamper": bv.proof_tamper_checks(), "cev": bv.cev_checks(),
              "cross_platform_consistency": bv.consistency_checks(tiers["template"] + tiers["human"], ws)}
    shutil.rmtree(ws, ignore_errors=True)
    return bv.config_for_digest(d), rows, system, bv.legacy_v1()


def test_digest_matches_the_full_run(parts, report):
    assert bv.full_digest(*parts) == report["reproducibility"]["digest"]


@pytest.mark.parametrize("mutation", ["attack_decision", "rule_code", "safe_control_outcome", "enforcement", "case_id",
                                      "proof_check", "cev_result", "consistency", "v1_result", "engine_config", "corpus_hash"])
def test_any_single_change_changes_the_digest(parts, mutation):
    import copy as _c
    cfg, rows, system, v1 = _c.deepcopy(parts)
    base = bv.full_digest(*parts)
    att = next(r for r in rows if r["category"] != "safe_control")
    safe = next(r for r in rows if r["category"] == "safe_control")
    if mutation == "attack_decision":
        att["actual"]["decision"] = "ALLOW"
    elif mutation == "rule_code":
        att["actual"]["rules"] = att["actual"]["rules"][:-1] + ["R1_DEST_NOT_APPROVED" if att["actual"]["rules"][-1:] != ["R1_DEST_NOT_APPROVED"] else "R9_SSRF_BLOCKED"]
    elif mutation == "safe_control_outcome":
        safe["actual"]["decision"], safe["status"] = "BLOCK", "FALSE_POSITIVE"
    elif mutation == "enforcement":
        att["actual"]["enforcement"] = "GRANT_ISSUED"
    elif mutation == "case_id":
        att["test_id"] = "rt-" + "0" * 20
    elif mutation == "proof_check":
        system["proof_tamper"][0]["detected"] = not system["proof_tamper"][0]["detected"]
    elif mutation == "cev_result":
        system["cev"][0]["result"] = "INCONCLUSIVE"
    elif mutation == "consistency":
        system["cross_platform_consistency"]["consistent"] -= 1
    elif mutation == "v1_result":
        v1["rows"][0]["verdict"] = "BLOCK" if v1["rows"][0]["verdict"] == "ALLOW" else "ALLOW"
    elif mutation == "engine_config":
        cfg["gate_engine"] += "-x"
    elif mutation == "corpus_hash":
        cfg["corpus_sha256"]["template"] = "0" * 64
    assert bv.full_digest(cfg, rows, system, v1) != base, mutation


def test_fresh_process_reproduces_the_digest(corpus, report, tmp_path):
    r = subprocess.run([sys.executable, "-m", "app.benchmark_v2", "run", "--corpus", corpus[0], "--repeats", "1",
                        "--report", str(tmp_path / "fresh.json")], cwd=BACKEND, env=os.environ, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr[-400:]
    assert json.loads((tmp_path / "fresh.json").read_text())["reproducibility"]["digest"] == report["reproducibility"]["digest"]


# ---------------- evidence and documentation agree (item 5) ----------------
ROOT = os.path.dirname(BACKEND)


def test_committed_evidence_matches_corpus_and_docs():
    ev = os.path.join(ROOT, "evidence", "benchmark-v2")
    rep = json.loads(open(os.path.join(ev, "report.json")).read())
    t = bv.corpus_totals(ev)
    assert rep["corpus_totals"] == t
    for tier in bv.TIERS:
        assert rep["corpus"][tier]["sha256"] == bv._sha_file(os.path.join(ev, "%s.cases.jsonl" % tier))
    o = t["overall"]
    doc = open(os.path.join(ROOT, "docs", "BENCHMARK_V2.md")).read()
    md = open(os.path.join(ev, "report.md")).read()
    row = "| **overall** | **%d** | **%d** | **%d** | **%d** | **%d** |" % (o["cases"], o["attack_cases"], o["attack_cases"], o["safe_controls"], o["safe_controls"])
    assert row in md and row in doc
    assert rep["reproducibility"]["digest"][:16] in doc
    assert "runs inside the backend process" in doc and "do NOT show protection against a compromise" in doc


def test_original_v1_benchmark_and_phase_a_evidence_are_preserved():
    from app import gateway as g
    assert len(g.benchmark_cases(lambda *a, **k: "x")) == 10
    pa = os.path.join(ROOT, "evidence", "redteam", "template-v1.cases.jsonl")
    assert len(rt.load_cases(pa)) == 40 and os.path.exists(os.path.join(ROOT, "evidence", "benchmark-results.json"))


def test_corpus_build_is_byte_identical(tmp_path):
    a, b = str(tmp_path / "a"), str(tmp_path / "b")
    bv.build(a)
    bv.build(b)
    for t in bv.TIERS:
        assert bv._sha_file(os.path.join(a, "%s.cases.jsonl" % t)) == bv._sha_file(os.path.join(b, "%s.cases.jsonl" % t))
