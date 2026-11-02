"""Disaster-recovery drill: measures encrypted backup and restore times on a synthetic dataset against throw-away
PostgreSQL clusters (needs local PostgreSQL binaries + age). Produces evidence, not a guarantee:

    python scripts/dr_drill.py --decisions 2000 --out ../evidence/dr-drill.json

Steps: source cluster -> N Gate decisions (DB rows + proof chain) -> encrypted backup -> source destroyed ->
fresh cluster -> verified restore -> backend boot -> chain verification -> RECOVERY_REQUIRED expected? (witness off
in this drill) -> timings. RTO here = restore + boot on this hardware; it excludes detection, people and provisioning.
"""
import argparse, json, os, platform, shutil, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "scripts"))
os.environ.setdefault("QYRIX_STATE_WITNESS", "disabled")    # the drill measures DB+chain restore; witness tested elsewhere


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--decisions", type=int, default=2000)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    tmp = tempfile.mkdtemp(prefix="qyrix-dr-")
    ident = os.path.join(tmp, "id")
    subprocess.run(["age-keygen", "-o", ident], check=True, capture_output=True)
    open(os.path.join(tmp, "rec"), "w").write(subprocess.run(["age-keygen", "-y", ident], check=True, capture_output=True, text=True).stdout)
    open(os.path.join(tmp, "sig"), "w").write(os.urandom(32).hex())
    os.environ.update(QYRIX_BACKUP_IDENTITY_FILE=ident, QYRIX_BACKUP_RECIPIENTS_FILE=os.path.join(tmp, "rec"),
                      QYRIX_BACKUP_SIGNING_KEY_FILE=os.path.join(tmp, "sig"))
    from tests.test_persistence import Cluster
    import app.gateway as g
    from app import adapter, persistence, provenance as prov
    import backup as bk
    ws = os.path.join(tmp, "ws"); os.makedirs(ws); open(os.path.join(ws, "README.md"), "w").write("x")
    chain_dir = os.path.join(tmp, "chain"); os.makedirs(chain_dir)

    def boot(url):
        ctx = g.GateContext("t", prov.ProvenanceStore(), os.path.join(chain_dir, "chain.jsonl"), lambda: ("api.example.com",),
                            {"file.read": adapter.FileAdapter(ws, g._redact)}, ws)
        g._load_chain(ctx)
        g.attach_persistence(ctx, persistence.PgPersistence(url))
        return ctx

    src, dst = Cluster(), Cluster()
    try:
        c = boot(src.url)
        t = c.prov.add_step("ticket", "TRUSTED", "read")
        t0 = time.time()
        for i in range(a.decisions):
            g.evaluate(g.Action(tool="file.read", dest="README.md", lineage=[t["id"]]) if i % 2 else
                       g.Action(tool="http", method="POST", dest="https://evil.example.net/x", lineage=[t["id"]]), c)
        populate_s = time.time() - t0
        bdir = os.path.join(tmp, "bk")
        t0 = time.time(); m = bk.backup(src.admin_url, chain_dir, bdir); backup_s = time.time() - t0
        shutil.rmtree(chain_dir); os.makedirs(chain_dir); src.destroy(); persistence._POOL.clear()
        t0 = time.time(); bk.restore(dst.admin_url, chain_dir, bdir); restore_s = time.time() - t0
        t0 = time.time(); r = boot(dst.url); boot_s = time.time() - t0
        ok = g.verify_chain(r)["valid"] and len(r.chain) == len(c.chain) and r.state["persistence"] == "postgres"
        ev = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": platform.platform(), "cpus": os.cpu_count(),
              "decisions": a.decisions, "chain_records": len(c.chain),
              "backup_bytes": {k: v["bytes"] for k, v in m["files"].items()},
              "seconds": {"populate": round(populate_s, 2), "backup": round(backup_s, 2), "restore": round(restore_s, 2),
                          "boot_and_verify": round(boot_s, 2)},
              "restored_state_verified": ok,
              "notes": "Single host, synthetic data, no network transfer. RTO excludes detection, decision and provisioning; "
                       "RPO equals the backup interval (no PITR / WAL archiving)."}
        json.dump(ev, open(a.out, "w"), indent=2)
        print(json.dumps(ev, indent=2))
        return 0 if ok else 1
    finally:
        dst.destroy()
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
