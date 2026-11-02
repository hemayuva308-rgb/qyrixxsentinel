"""Reproducible 10-case benchmark with retained evidence (no server, no network, no production state touched).
  cd backend && python scripts/run_benchmark.py [--out ../evidence]
Runs the exact plan composition (3 SAFE, 3 DIRECT, 2 TRANSFORMED, 2 DELAYED) through the real evaluate() in a fresh,
isolated GateContext whose proof chain is written to <out>/benchmark-proof-chain.jsonl, then writes:
  benchmark-results.json   cases, expected vs actual, rule ids, latency, counts, metrics, hypotheses, environment
  benchmark-proof-bundle.json   exported chain + verification result
and prints the SHA-256 of each artifact. Exit code 0 only if every case matched its expectation."""
import argparse, hashlib, json, os, platform, subprocess, sys, tempfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("QYRIX_ADMIN_TOKEN", "x" * 32)
os.environ.setdefault("QYRIX_AGENT_TOKEN", "y" * 32)
os.environ.setdefault("QYRIX_CHAIN_FILE", os.path.join(tempfile.mkdtemp(prefix="qyrix-bench-"), "unused.jsonl"))
from app import gateway as g, netguard, proof, provenance as prov   # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--out", default=os.path.join(HERE, "..", "evidence"))
args = ap.parse_args()
out = os.path.abspath(args.out)
os.makedirs(out, exist_ok=True)
chain_file = os.path.join(out, "benchmark-proof-chain.jsonl")
open(chain_file, "w").close()
ws = tempfile.mkdtemp(prefix="qyrix-bench-ws-")
ctx = g.GateContext("benchmark", prov.ProvenanceStore(), chain_file, netguard.approved_domains,
                    {}, ws)                                    # no adapters: nothing can execute

res = g.run_benchmark(ctx)
try:
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=HERE, capture_output=True, text=True).stdout.strip() or None
except OSError:
    commit = None
res["environment"] = {"generated_utc": datetime.now(timezone.utc).isoformat(), "git_commit": commit,
                      "python": platform.python_version(), "platform": platform.platform(),
                      "approved_domains": list(netguard.approved_domains()), "network": "no adapters configured; no egress possible"}
paths = {"benchmark-results.json": res,
         "benchmark-proof-bundle.json": {"format": "qyrix-proof-bundle/v2", "chain": ctx.chain, "verify": proof.verify_records(ctx.chain)}}
for name, obj in paths.items():
    with open(os.path.join(out, name), "w") as f:
        json.dump(obj, f, indent=1)
for name in list(paths) + ["benchmark-proof-chain.jsonl"]:
    print("%s  sha256=%s" % (name, hashlib.sha256(open(os.path.join(out, name), "rb").read()).hexdigest()))
c = res["counts"]
print("attacks blocked %d/%d | safe allowed %d/%d | false positives %d/%d | avg %.3f ms | max %.3f ms | chain %s"
      % (c["attacks_blocked"], c["attacks"], c["safe_allowed"], c["safe"], c["safe_blocked"], c["safe"],
         res["metrics"]["avg_latency_ms"], res["metrics"]["max_latency_ms"], res["verify"]["status"]))
sys.exit(0 if all(x["ok"] for x in res["cases"]) else 1)
