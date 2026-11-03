"""Qyrix Sentinel Benchmark v2 (v1.5 P2 phase B). Synthetic, isolated, reproducible.

    python -m app.benchmark_v2 build --out ../evidence/benchmark-v2            # write the tiered corpus files
    python -m app.benchmark_v2 run --corpus ../evidence/benchmark-v2 --repeats 5 --check-reproducible \
                                   --report ../evidence/benchmark-v2/report.json

Tiers are kept separate everywhere: template (seeded generator), human (hand-written, reviewed), model (Llama-written
and human-approved; empty unless such a file exists), v1-legacy (the original 10 cases, unchanged). Every case runs in
a fresh isolated GateContext (sandbox adapters, synthetic workspace, no chain file): the production proof chain is
never touched and the run fails if any egress happens. Results describe this synthetic corpus only.
"""
import argparse
import copy
import hashlib
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app import redteam as rt

BENCHMARK_VERSION = "qyrix-benchmark/2.0"
TEMPLATE_SEED, TEMPLATE_PER_CATEGORY = 7, 7
HERE = os.path.dirname(os.path.abspath(__file__))
HUMAN_SOURCE = os.path.join(os.path.dirname(HERE), "benchmark", "human-v1.cases.json")
TIERS = ("template", "human", "model")
GROUPS = {
    "prompt_injection": lambda c: c.category in ("direct_injection", "indirect_injection", "delayed_multistep", "encoded_obfuscated"),
    "unauthorized_tool_execution": lambda c: c.category in ("tool_misuse", "mcp_tool_manipulation") or c.tool not in ("http", "file.read"),
    "replay": lambda c: (c.misuse and c.misuse.mode == "replay") or (c.approval and c.approval.mode == "replay"),
    "cross_agent": lambda c: bool(c.misuse and c.misuse.mode in ("cross_agent", "delegation")),
    "cross_task": lambda c: bool(c.misuse and c.misuse.mode == "cross_task"),
    "policy_version": lambda c: bool(c.misuse and c.misuse.mode == "policy_change"),
    "tainted_state_change": lambda c: "R19_UNTRUSTED_STATE_CHANGE" in c.expected.rules,
    "unicode_hostname_deception": lambda c: c.category == "unicode_manipulation",
    "approval_misuse": lambda c: c.category == "approval_misuse",
    "fail_closed_environment": lambda c: c.category == "fail_closed_environment",
    "ssrf_and_destination": lambda c: c.category == "ssrf_destination",
    "data_exfiltration": lambda c: c.category in ("unauthorized_data_transfer",),
    "argument_tampering": lambda c: c.category == "argument_tampering" or bool(c.misuse and c.misuse.mode == "digest_tamper"),
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha_file(p: str) -> str:
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


# ---------------- corpus build ----------------
def build(out_dir: str) -> Dict:
    os.makedirs(out_dir, exist_ok=True)
    raw, repro = rt.template_cases(TEMPLATE_SEED, TEMPLATE_PER_CATEGORY)
    tpl, rej_t = rt.accept(raw, repro, "approved")
    for c in tpl:
        c.reviewer = "template-authors"
    with open(HUMAN_SOURCE) as f:
        hsrc = json.load(f)
    hum, rej_h = rt.accept(hsrc["cases"], {"generator": "human", "generator_version": hsrc["version"],
                                           "source_sha256": _sha_file(HUMAN_SOURCE), "created_at": "2026-11-03T00:00:00Z"},
                           "approved")
    for c in hum:
        c.reviewer = hsrc["reviewer"]
    if any(r["reasons"] != ["DUPLICATE"] for r in rej_t + rej_h):
        raise SystemExit("corpus build rejected cases: %s" % [r for r in rej_t + rej_h if r["reasons"] != ["DUPLICATE"]])
    rt.save_cases(os.path.join(out_dir, "template.cases.jsonl"), tpl)
    rt.save_cases(os.path.join(out_dir, "human.cases.jsonl"), hum)
    model = os.path.join(out_dir, "model.cases.jsonl")
    if not os.path.exists(model):
        open(model, "w").close()                         # tier exists, deliberately empty (no reviewed model cases)
    return {"template": len(tpl), "template_duplicates_dropped": len(rej_t), "human": len(hum),
            "model": sum(1 for _ in open(model) if _.strip())}


def load_tiers(corpus_dir: str) -> Dict[str, List[rt.RedTeamCase]]:
    out = {}
    for t in TIERS:
        p = os.path.join(corpus_dir, "%s.cases.jsonl" % t)
        cases = rt.load_cases(p) if os.path.exists(p) else []
        if t == "model":
            cases = [c for c in cases if c.repro.generator == "llama"]       # only reviewed model output belongs here
        out[t] = cases
    return out


# ---------------- system checks (isolated) ----------------
def _ctx(workspace: Optional[str] = None, approved=rt.APPROVED):
    from app import adapter, gateway as g, provenance as prov
    sb = adapter.SandboxAdapter()
    return g.GateContext("bench-v2", prov.ProvenanceStore(), None, lambda: approved, {"http": sb, "file.read": sb}, workspace)


def proof_tamper_checks() -> List[Dict]:
    """Build a small isolated chain, then tamper with copies. Tail truncation is listed honestly: a hash chain alone
    cannot detect it (the witness / external anchoring does, not this check)."""
    from app import gateway as g, proof
    ctx = _ctx()
    for i in range(5):
        g.evaluate(g.Action(tool="http", method="GET", dest="https://api.partner.example.com/v1/t%d" % i), ctx)
    base = [dict(r) for r in ctx.chain]
    variants = {
        "modified_verdict": lambda c: c[2].__setitem__("verdict", "ALLOW" if c[2]["verdict"] == "BLOCK" else "BLOCK"),
        "deleted_middle_record": lambda c: c.pop(2),
        "reordered_records": lambda c: c.__setitem__(slice(1, 3), [c[2], c[1]]),
        "modified_hash": lambda c: c[3].__setitem__("hash", "0" * 64),
        "truncated_tail": lambda c: c.pop(),
    }
    out = []
    for name, f in variants.items():
        c = copy.deepcopy(base)
        f(c)
        detected = not proof.verify_records(c)["valid"]
        expected = name != "truncated_tail"
        out.append({"check": "proof_tamper:" + name, "expected_detected": expected, "detected": detected,
                    "pass": detected == expected,
                    "note": "hash chain alone cannot detect tail truncation (state witness / anchoring required)" if not expected else None})
    out.append({"check": "proof_tamper:untampered_chain_valid", "expected_detected": False,
                "detected": not proof.verify_records(base)["valid"], "pass": proof.verify_records(base)["valid"], "note": None})
    return out


def cev_checks() -> List[Dict]:
    from app import cev, integrations
    out = []
    for ch in cev.CHANNELS:
        for ad, want in ((integrations.HonestAdapterFixture(), cev.VERIFIED), (integrations.BrokenAdapterFixture(), cev.BYPASS)):
            r = cev.run_canary(_ctx(), ad, ch)
            out.append({"check": "cev:%s:%s" % (ad.id, ch), "expected": want, "result": r["result"], "pass": r["result"] == want})
    return out


def consistency_checks(cases: List[rt.RedTeamCase], workspace: str) -> Dict:
    """Same action through the direct path and through the MCP proxy mapping must get the same verdict and rules."""
    rows = []
    for c in cases:
        if c.mcp or c.misuse or c.approval or c.environment or c.redirect or c.task_id:
            continue
        if c.tool == "http" and c.action.upper() == "GET" and not c.command and not c.payload:
            mcp = {"name": "fetch", "arguments": {"url": c.target}}
        elif c.tool == "file.read" and not c.payload:
            mcp = {"name": "read_file", "arguments": {"path": c.target}}
        else:
            continue
        twin = c.model_copy(update={"mcp": rt.McpCall(**mcp)})
        a, b = rt.run_case(c, workspace), rt.run_case(twin, workspace)
        same = a["actual"]["decision"] == b["actual"]["decision"] and a["actual"]["rules"] == b["actual"]["rules"]
        rows.append({"test_id": c.test_id, "direct": a["actual"], "mcp": b["actual"], "consistent": same})
    n = len(rows)
    return {"pairs": n, "consistent": sum(r["consistent"] for r in rows),
            "rate": round(100.0 * sum(r["consistent"] for r in rows) / n, 2) if n else None,
            "inconsistent": [r for r in rows if not r["consistent"]]}


def legacy_v1() -> Dict:
    """The unchanged 10-case v1 benchmark, run in an isolated context (its own default allowlist)."""
    from app import gateway as g, netguard
    ws = tempfile.mkdtemp(prefix="qyrix-bv2-v1-")
    try:
        open(os.path.join(ws, "README.md"), "w").write("synthetic readme\n")
        r = g.run_benchmark(_ctx(ws, netguard.approved_domains()))
    finally:
        shutil.rmtree(ws, ignore_errors=True)
    return {"cases": len(r["cases"]), **r["counts"], "rows": [{"name": x["name"], "verdict": x["verdict"], "rules": x["rules"],
                                                              "ok": x["ok"]} for x in r["cases"]]}


# ---------------- metrics ----------------
def _rate(n: int, d: int) -> Optional[float]:
    return round(100.0 * n / d, 2) if d else None


def _pct(values: List[float], q: float) -> Optional[float]:
    if not values:
        return None
    v = sorted(values)
    return v[min(len(v) - 1, max(0, int(round(q / 100.0 * len(v) + 0.5)) - 1))]


def metrics(rows: List[Dict], cases: Dict[str, rt.RedTeamCase]) -> Dict:
    att = [r for r in rows if r["category"] != "safe_control"]
    safe = [r for r in rows if r["category"] == "safe_control"]
    stopped = lambda r: r["status"] in ("PASS", "RULE_MISMATCH", "ENFORCEMENT_MISMATCH")
    fn = [r for r in att if r["status"] == "FALSE_NEGATIVE"]
    fp = [r for r in safe if r["status"] == "FALSE_POSITIVE"]
    groups = {}
    for name, pred in GROUPS.items():
        g_rows = [r for r in att if pred(cases[r["test_id"]])]
        groups[name] = {"cases": len(g_rows), "stopped": sum(stopped(r) for r in g_rows), "rate": _rate(sum(stopped(r) for r in g_rows), len(g_rows))}
    observed = set()
    for r in rows:
        observed.update(r["actual"]["rules"])
        if r["actual"]["enforcement"].startswith("REFUSED:"):
            observed.add(r["actual"]["enforcement"][8:])
    return {"cases": len(rows), "attack_cases": len(att), "safe_controls": len(safe),
            "attack_prevention_rate": _rate(sum(stopped(r) for r in att), len(att)),
            "false_negative_rate": _rate(len(fn), len(att)), "false_positive_rate": _rate(len(fp), len(safe)),
            "rule_mismatches": sum(r["status"] == "RULE_MISMATCH" for r in rows),
            "expectation_reviews": sum(r["status"] == "EXPECTATION_REVIEW" for r in rows),
            "errors": sum(r["status"].startswith("ERROR") for r in rows), "egress_calls": sum(r["egress_calls"] for r in rows),
            "groups": groups, "rules_observed": sorted(observed),
            "gate_rules_not_observed": [x for x in rt.GATE_RULES if x not in observed],
            "by_category": {c: {"cases": sum(r["category"] == c for r in rows),
                                "pass": sum(r["category"] == c and r["status"] == "PASS" for r in rows)}
                            for c in sorted({r["category"] for r in rows})},
            "failures": [r for r in rows if r["status"] != "PASS"]}


def result_digest(rows: List[Dict]) -> str:
    proj = sorted((r["tier"], r["test_id"], r["actual"]["decision"], tuple(r["actual"]["rules"]), r["actual"]["enforcement"],
                   r["status"]) for r in rows)
    return hashlib.sha256(json.dumps(proj, separators=(",", ":")).encode()).hexdigest()


def environment() -> Dict:
    from app import gateway as g
    env = rt.environment()
    ctx = _ctx()
    return {**env, "benchmark_version": BENCHMARK_VERSION, "isolated_policy_version": g.policy_version(ctx),
            "template_seed": TEMPLATE_SEED, "template_per_category": TEMPLATE_PER_CATEGORY,
            "prompt_version": rt.PROMPT_VERSION, "model_cases": "none (no reviewed model output in this release)"}


# ---------------- run ----------------
def run(corpus_dir: str, repeats: int = 3, phase_a_corpus: Optional[str] = None) -> Dict:
    from app import gateway as g
    prod_before = len(g.PROD.chain)
    tiers = load_tiers(corpus_dir)
    by_id = {c.test_id: c for cs in tiers.values() for c in cs}
    ws = tempfile.mkdtemp(prefix="qyrix-bv2-ws-")
    digests, all_rows, lat = [], [], []
    try:
        for rel, body in rt.WORKSPACE_FILES.items():
            p = os.path.join(ws, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            open(p, "w").write(body)
        t0 = time.time()
        for rep in range(max(1, repeats)):
            rows = []
            for tier, cs in tiers.items():
                for c in cs:
                    r = rt.run_case(c, ws)
                    r["tier"] = tier
                    rows.append(r)
            digests.append(result_digest(rows))
            lat.extend(r["latency_ms"] for r in rows)
            if rep == 0:
                all_rows = rows
        consistency = consistency_checks(tiers["template"] + tiers["human"], ws)
        wall = round(time.time() - t0, 2)
    finally:
        shutil.rmtree(ws, ignore_errors=True)
    tamper, cevr = proof_tamper_checks(), cev_checks()
    phase_a = None
    if phase_a_corpus and os.path.exists(phase_a_corpus):
        pa = rt.run_suite(rt.load_cases(phase_a_corpus))["summary"]
        phase_a = {k: pa[k] for k in ("cases", "attack_cases", "safe_cases", "attacks_stopped", "false_negatives", "false_positives", "egress_calls")}
    v1 = legacy_v1()
    if len(g.PROD.chain) != prod_before:
        raise RuntimeError("benchmark touched the production proof chain")
    cev_runs = [x for x in cevr]
    report = {
        "report_version": BENCHMARK_VERSION, "generated_at": _now(), "environment": environment(),
        "corpus": {t: {"cases": len(cs), "file": "%s.cases.jsonl" % t,
                       "sha256": _sha_file(os.path.join(corpus_dir, "%s.cases.jsonl" % t)) if os.path.exists(os.path.join(corpus_dir, "%s.cases.jsonl" % t)) else None}
                   for t, cs in tiers.items()},
        "repeats": max(1, repeats), "wall_seconds": wall,
        "reproducibility": {"result_digests": digests, "identical_across_repeats": len(set(digests)) == 1},
        "overall": {k: v for k, v in metrics(all_rows, by_id).items() if k != "failures"},
        "by_tier": {t: {k: v for k, v in metrics([r for r in all_rows if r["tier"] == t], by_id).items()
                        if k in ("cases", "attack_cases", "safe_controls", "attack_prevention_rate", "false_negative_rate",
                                 "false_positive_rate", "errors")} for t in TIERS},
        "latency_ms": {"samples": len(lat), "p50": _pct(lat, 50), "p95": _pct(lat, 95), "p99": _pct(lat, 99),
                       "note": "in-process Gate evaluation only (no network, no persistence); machine-dependent"},
        "system_checks": {
            "proof_tamper": tamper, "proof_tamper_detection_rate": _rate(sum(x["detected"] for x in tamper if x["expected_detected"]),
                                                                         sum(1 for x in tamper if x["expected_detected"])),
            "cev": cevr, "cev_pass_rate": _rate(sum(x["pass"] for x in cev_runs), len(cev_runs)),
            "cev_inconclusive_rate": _rate(sum(x["result"] == "INCONCLUSIVE" for x in cev_runs), len(cev_runs)),
            "cross_platform_consistency": consistency},
        "comparison": {"v1_legacy": {k: v1[k] for k in ("cases", "attacks", "attacks_blocked", "safe", "safe_allowed", "safe_blocked")},
                       "phase_a_template_v1": phase_a},
        "failures": metrics(all_rows, by_id)["failures"],
        "unsupported": [
            "Public benchmarks (AgentDojo: MIT, needs a live LLM agent; InjecAgent: no licence found) - not run",
            "Live model-generated cases - none (no provider credentials)",
            "Whole-script homograph detection (UTS #39 confusables) - not implemented; such hosts never match ASCII allowlists",
            "Real egress, real persistence/PostgreSQL behaviour and multi-process races - covered by unit/integration tests, not this benchmark",
            "Proof tail truncation - not detectable by the hash chain alone (state witness / anchoring cover it)"],
        "disclaimer": "Synthetic, isolated corpus written for this project. Results describe this corpus only and are not a "
                      "measure of general or real-world security.",
    }
    return report


def markdown(rep: Dict) -> str:
    o, s = rep["overall"], rep["system_checks"]
    L = ["# Benchmark v2 report (%s)" % rep["report_version"], "", "> " + rep["disclaimer"], "",
         "Generated %s, commit `%s`, engine `%s`, isolated policy `%s`." % (rep["generated_at"], rep["environment"]["commit"],
                                                                            rep["environment"]["gate_engine"], rep["environment"]["isolated_policy_version"][:16]), "",
         "| Tier | Cases | Attack cases | Prevention | False negatives | Safe controls | False positives |", "|---|---|---|---|---|---|---|"]
    for t, m in rep["by_tier"].items():
        L.append("| %s | %d | %d | %s | %s | %d | %s |" % (t, m["cases"], m["attack_cases"], m["attack_prevention_rate"],
                                                          m["false_negative_rate"], m["safe_controls"], m["false_positive_rate"]))
    L += ["| **overall** | %d | %d | %s%% | %s%% | %d | %s%% |" % (o["cases"], o["attack_cases"], o["attack_prevention_rate"],
                                                                   o["false_negative_rate"], o["safe_controls"], o["false_positive_rate"]), "",
          "| Group | Cases | Stopped |", "|---|---|---|"]
    L += ["| %s | %d | %d |" % (k, v["cases"], v["stopped"]) for k, v in o["groups"].items()]
    L += ["", "System checks: proof tamper detection %s%% (tail truncation not detectable by hash chain, listed); CEV pass %s%%, "
          "INCONCLUSIVE %s%%; cross-platform consistency %s/%s." % (s["proof_tamper_detection_rate"], s["cev_pass_rate"],
                                                                  s["cev_inconclusive_rate"], s["cross_platform_consistency"]["consistent"],
                                                                  s["cross_platform_consistency"]["pairs"]),
          "", "Latency (ms, %d samples): p50 %s, p95 %s, p99 %s - %s." % (rep["latency_ms"]["samples"], rep["latency_ms"]["p50"],
                                                                         rep["latency_ms"]["p95"], rep["latency_ms"]["p99"], rep["latency_ms"]["note"]),
          "", "Reproducible: %s across %d repeats (digest `%s`)." % (rep["reproducibility"]["identical_across_repeats"], rep["repeats"],
                                                                     rep["reproducibility"]["result_digests"][0][:16]),
          "", "Rules observed: %d of %d Gate rules; not observed: %s." % (len([r for r in o["rules_observed"] if r in rt.GATE_RULES]),
                                                                        len(rt.GATE_RULES), ", ".join(o["gate_rules_not_observed"]) or "none"),
          "", "Not covered: " + "; ".join(rep["unsupported"]) + ".", ""]
    return "\n".join(L)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.benchmark_v2")
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--out", required=True)
    r = sub.add_parser("run")
    r.add_argument("--corpus", required=True)
    r.add_argument("--repeats", type=int, default=3)
    r.add_argument("--report", required=True)
    r.add_argument("--phase-a-corpus")
    r.add_argument("--check-reproducible", action="store_true", help="run twice more and require identical result digests")
    a = ap.parse_args(argv)
    if a.cmd == "build":
        print(json.dumps(build(a.out)))
        return 0
    rep = run(a.corpus, a.repeats, a.phase_a_corpus)
    if a.check_reproducible:
        again = run(a.corpus, 1, None)
        rep["reproducibility"]["separate_run_digest"] = again["reproducibility"]["result_digests"][0]
        rep["reproducibility"]["identical_across_runs"] = again["reproducibility"]["result_digests"][0] == rep["reproducibility"]["result_digests"][0]
    with open(a.report, "w") as f:
        json.dump(rep, f, indent=1, ensure_ascii=True)
    with open(os.path.splitext(a.report)[0] + ".md", "w") as f:
        f.write(markdown(rep))
    print(markdown(rep))
    ok = (rep["reproducibility"]["identical_across_repeats"] and rep["reproducibility"].get("identical_across_runs", True)
          and rep["overall"]["errors"] == 0 and rep["overall"]["egress_calls"] == 0)
    return 0 if ok else 6


if __name__ == "__main__":
    sys.exit(main())
