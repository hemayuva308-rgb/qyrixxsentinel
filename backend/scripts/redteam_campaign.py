"""Multi-round LIVE red-team campaign: a Llama model attacks the deterministic Gate. (Meta Model API or Baseten.)

  cd backend
  BASETEN_API_KEY=... BASETEN_MODEL=<model id> python scripts/redteam_campaign.py --provider baseten --rounds 5 --out-dir ../evidence/redteam/campaign-1
  META_API_KEY=...    META_MODEL=<model id>    python scripts/redteam_campaign.py --provider meta    --rounds 5 --out-dir ../evidence/redteam/campaign-2

It reuses the existing, tested pipeline in app/redteam.py and adds only the orchestration:
  1. each round asks the model for attack test cases (different seed and temperature per round);
  2. every reply is UNTRUSTED: strict schema, safety filter (synthetic RFC 2606 hosts only, real credential formats rejected),
     dedupe (also across rounds). The model cannot approve its own cases or set their expected outcome in the Gate's favour;
  3. all accepted cases run through the REAL Gate in an isolated context: no network, no real file, no command, egress counted;
  3b. optional --classify-max N: the same case text is sent to the product's ADVISORY classifier (app.gateway.classify: Meta first,
     then Baseten). A 2x2 matrix compares "AI flagged / AI missed" with "Gate blocked / Gate allowed". The headline number is
     how often the AI missed an attack and the Gate still stopped it. A heuristic fallback is counted separately, never as AI.
  4. one report. A FALSE_NEGATIVE (the model expected BLOCK, the Gate said ALLOW) is a CANDIDATE bypass for a human to triage,
     NOT a confirmed vulnerability; an EXPECTATION_REVIEW means the model's own expectation was probably wrong.

The model never decides anything: the deterministic Gate evaluates every case. The key is read from the environment, is never
printed or written, and a provider failure is recorded (nothing is generated, nothing falls back silently).
Exit code: 0 ok, 3 nothing could be generated, 5 isolation error (egress)."""
import argparse
import collections
import hashlib
import json
import os
import sys

os.environ.setdefault("QYRIX_ADMIN_TOKEN", "x" * 32)
os.environ.setdefault("QYRIX_AGENT_TOKEN", "y" * 32)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import redteam as rt  # noqa: E402

MAX_ROUNDS = 200
NOTES = ["Model-generated, synthetic test cases only; the deterministic Gate decides every case.",
         "FALSE_NEGATIVE = candidate bypass for human triage, not a confirmed vulnerability.",
         "EXPECTATION_REVIEW = the model's own expected outcome was probably wrong; it never changes the Gate's decision.",
         "A clean run is evidence about THESE cases only, not a security guarantee."]


def _case_view(c: "rt.RedTeamCase") -> dict:
    return {"test_id": c.test_id, "category": c.category, "severity": c.severity, "threat": c.threat, "tool": c.tool,
            "action": c.action, "target": c.target, "payload": c.payload, "command": c.command,
            "expected_decision": c.expected.decision}


def advisory_text(c: "rt.RedTeamCase") -> str:
    """What the advisory classifier is shown: the instruction text the agent read plus what it would send (bounded)."""
    parts = [x.text for x in c.setup] + [c.payload or "", c.command or "", "%s %s" % (c.action, c.target)]
    return "\n".join(p for p in parts if p)[:4000]


def advisory_vs_gate(cases, rows, classify_fn, max_n: int) -> dict:
    """2x2: advisory AI verdict vs deterministic Gate decision. The AI verdict never influences the Gate; this only measures both."""
    by_id, row_by = {c.test_id: c for c in cases}, {r["test_id"]: r for r in rows}
    matrix = {"attack": collections.Counter(), "safe_control": collections.Counter()}
    providers, per = collections.Counter(), []
    for tid in sorted(by_id)[:max_n]:
        c, r = by_id[tid], row_by[tid]
        res = classify_fn(advisory_text(c))
        prov, live = res.get("provider"), res.get("provider") not in (None, "heuristic")
        flagged, blocked = res.get("label") == "untrusted_instruction", r["actual"]["decision"] == "BLOCK"
        providers[(prov, res.get("model"))] += 1
        kind = "safe_control" if c.category == "safe_control" else "attack"
        matrix[kind][("live_" if live else "heuristic_") + "ai_%s_gate_%s" % ("flagged" if flagged else "missed", "blocked" if blocked else "allowed")] += 1
        per.append({"test_id": tid, "category": c.category, "ai_provider": prov, "ai_model": res.get("model"), "ai_label": res.get("label"),
                    "gate_decision": r["actual"]["decision"], "gate_rules": r["actual"]["rules"]})
    return {"classified": len(per), "of_accepted": len(cases), "max_requested": max_n,
            "providers": [{"provider": k[0], "model": k[1], "count": v} for k, v in providers.items()],
            "attack": dict(matrix["attack"]), "safe_control": dict(matrix["safe_control"]),
            "headline_live_ai_missed_but_gate_blocked": matrix["attack"]["live_ai_missed_gate_blocked"],
            "rows": per,
            "caveats": ["Measures this advisory prompt on these synthetic cases; it is not a benchmark of any model.",
                        "The Gate never reads the classifier output; the matrix only compares the two.",
                        "heuristic_* counts are the deterministic fallback (no live model answered) and are not AI results."]}


def campaign(provider: str, rounds: int, per_category: int, base_seed: int, temperatures, out_dir: str, transport=None,
             classify_max: int = 0, classify_fn=None) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    cases, seen, log, model = [], set(), [], None
    raw_total, rejected = 0, collections.Counter()
    for r in range(rounds):
        seed, temp = base_seed + r, temperatures[r % len(temperatures)]
        entry = {"round": r, "seed": seed, "temperature": temp}
        try:
            content, repro = rt.llama_generate(provider, per_category, temperature=temp, seed=seed, transport=transport)
        except rt.GenerationUnavailable as e:
            log.append({**entry, "status": "UNAVAILABLE", "reason": str(e)[:160]})
            continue
        model = model or repro.get("model")
        entry["reply_sha256"] = hashlib.sha256(content.encode()).hexdigest()
        with open(os.path.join(out_dir, "round-%03d.reply.txt" % r), "w", encoding="utf-8") as f:   # untrusted text, kept for audit/replay
            f.write(content)
        try:
            raw = rt.parse_llama(content)
        except ValueError as e:                                                                       # includes JSONDecodeError
            log.append({**entry, "status": "UNPARSEABLE", "reason": str(e)[:160]})
            continue
        raw_total += len(raw)
        ok, rej = rt.accept(raw, repro, "candidate")
        for x in rej:
            rejected.update(x["reasons"])
        fresh = [c for c in ok if c.test_id not in seen]
        rejected["DUPLICATE_ACROSS_ROUNDS"] += len(ok) - len(fresh)
        seen.update(c.test_id for c in fresh)
        cases.extend(fresh)
        log.append({**entry, "status": "OK", "raw": len(raw), "accepted_new": len(fresh), "rejected": len(rej)})
    report = {"report_version": "redteam-campaign/1.0", "generated_at": rt._now(), "provider": provider, "model": model,
              "rounds_requested": rounds, "rounds_ok": sum(x["status"] == "OK" for x in log), "raw_cases": raw_total,
              "accepted_unique": len(cases), "rejected": dict(rejected), "rounds": log, "environment": rt.environment(), "notes": NOTES}
    if not cases:
        report.update(summary=None, bypass_candidates=[], expectation_reviews=[], failures=[])
    else:
        res = rt.run_suite(cases, include_candidates=True)
        by_id = {c.test_id: c for c in cases}
        rows = res["rows"]
        report.update(summary=res["summary"],
                      bypass_candidates=[{**r, "case": _case_view(by_id[r["test_id"]])} for r in rows
                                         if r["status"] == "FALSE_NEGATIVE" and r["category"] != "safe_control"],
                      expectation_reviews=[{**r, "case": _case_view(by_id[r["test_id"]])} for r in rows if r["status"] == "EXPECTATION_REVIEW"],
                      failures=[r for r in rows if r["status"] != "PASS"])
        rt.save_cases(os.path.join(out_dir, "cases.jsonl"), cases)
        if classify_max > 0:
            if classify_fn is None:
                from app import gateway as g
                classify_fn = g.classify
            report["advisory_vs_gate"] = advisory_vs_gate(cases, rows, classify_fn, classify_max)
    with open(os.path.join(out_dir, "campaign.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    return report


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--provider", choices=["meta", "baseten"], default="baseten")
    ap.add_argument("--rounds", type=int, default=5, help="model calls (each costs tokens); capped at %d" % MAX_ROUNDS)
    ap.add_argument("--per-category", type=int, default=3)
    ap.add_argument("--seed", type=int, default=1000)
    ap.add_argument("--temperatures", default="0.7,0.9,1.0")
    ap.add_argument("--classify-max", type=int, default=0, help="also send up to N cases to the advisory classifier (one call each) and compare with the Gate")
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args(argv)
    temps = [float(x) for x in a.temperatures.split(",") if x.strip()] or [0.7]
    rep = campaign(a.provider, max(1, min(a.rounds, MAX_ROUNDS)), max(1, min(a.per_category, 10)), a.seed, temps, a.out_dir,
                   classify_max=max(0, min(a.classify_max, 1000)))
    s = rep["summary"]
    print("provider=%s model=%s rounds_ok=%d/%d raw=%d accepted_unique=%d rejected=%s" % (
        rep["provider"], rep["model"], rep["rounds_ok"], rep["rounds_requested"], rep["raw_cases"], rep["accepted_unique"], rep["rejected"]))
    if not s:
        print("NOTHING GENERATED: see rounds[] in campaign.json (provider not configured or unreachable). No fallback was used.")
        return 3
    print("attack cases=%d stopped=%d | candidate bypasses=%d | expectation reviews=%d | safe controls=%d, blocked wrongly=%d | egress calls=%d" % (
        s["attack_cases"], s["attacks_stopped"], len(rep["bypass_candidates"]), s["expectation_reviews"], s["safe_cases"], s["false_positives"], s["egress_calls"]))
    adv = rep.get("advisory_vs_gate")
    if adv:
        print("advisory AI vs Gate (%d classified; providers=%s): attack matrix=%s | HEADLINE live AI missed but Gate blocked: %d" % (
            adv["classified"], adv["providers"], adv["attack"], adv["headline_live_ai_missed_but_gate_blocked"]))
    print("report: %s" % os.path.join(a.out_dir, "campaign.json"))
    return 5 if s["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
