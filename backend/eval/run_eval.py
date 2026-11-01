"""Measure the classifiers on eval/instructions.json.   Run from backend/:  python -m eval.run_eval
The heuristic is always measured. The LLM is measured ONLY if a provider answered live (source meta:/baseten:);
otherwise the result says so explicitly - nothing is estimated or filled in."""
import json, os, sys, time
os.environ.setdefault("QYRIX_ADMIN_TOKEN", "x" * 32)
os.environ.setdefault("QYRIX_AGENT_TOKEN", "y" * 32)
HERE = os.path.dirname(os.path.abspath(__file__))
POS = "untrusted_instruction"


def load():
    return json.load(open(os.path.join(HERE, "instructions.json")))["items"]


def metrics(rows):
    """rows: [(truth, pred, category)]"""
    tp = sum(t == POS and p == POS for t, p, _ in rows); fn = sum(t == POS and p != POS for t, p, _ in rows)
    fp = sum(t != POS and p == POS for t, p, _ in rows); tn = sum(t != POS and p != POS for t, p, _ in rows)
    cat = {}
    for t, p, c in rows:
        d = cat.setdefault(c, {"n": 0, "correct": 0}); d["n"] += 1; d["correct"] += int(t == p)
    pct = lambda a, b: round(100 * a / b, 1) if b else None
    return {"n": len(rows), "accuracy_pct": pct(tp + tn, len(rows)), "recall_pct": pct(tp, tp + fn), "false_positive_pct": pct(fp, fp + tn),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn, "by_category": cat}


def run(use_llm=True):
    from app import gateway as g
    items, h_rows, l_rows, lat, miss = load(), [], [], [], []
    for it in items:
        h_rows.append((it["label"], g.heuristic_classify(it["text"])["label"], it["category"]))
        if use_llm and g._configured():
            r = g.classify(it["text"])
            if r["provider"] != "heuristic":
                l_rows.append((it["label"], r["label"], it["category"])); lat.append(r["latency_ms"])
            else:
                miss.append(it["id"])
    out = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "cases": len(items), "heuristic": metrics(h_rows)}
    if l_rows:
        out["llm"] = {**metrics(l_rows), "answered": len(l_rows), "unanswered_ids": miss, "avg_latency_ms": round(sum(lat) / len(lat), 1),
                      "providers": g._configured()}
    else:
        out["llm"] = {"measured": False, "reason": "no provider configured or no live answer" if not g._configured() else "providers configured but none answered: " + ",".join(miss)}
    return out


if __name__ == "__main__":
    res = run()
    json.dump(res, open(os.path.join(HERE, "results.json"), "w"), indent=1)
    for k in ("heuristic", "llm"):
        v = res[k]
        print(k.upper(), "->", v if v.get("measured") is False else {x: v[x] for x in ("n", "accuracy_pct", "recall_pct", "false_positive_pct", "tp", "fn", "fp", "tn")})
    print("saved eval/results.json")
