"""Operator recovery for the data-loss detector (app/integrity.py). Run with the BACKEND STOPPED.

    python -m app.recovery status
    python -m app.recovery accept --reason "restored backup 2026-11-02T06:00Z after disk failure (INC-42)"
    python -m app.recovery accept --reason "..." --new-installation      # DB intentionally empty/new
    python -m app.recovery accept --reason "..." --reinitialize-witness  # witness key rotated / witness lost

`accept` re-seals the witness to the CURRENT state of the database and chain files. It never deletes data. Every
acceptance is appended to the witness's `recoveries` log and queued as a RECOVERY_ACCEPTED proof record that the
backend writes into the affected tenant's chain on its next start - the discontinuity becomes part of the evidence.
Chains that do not verify (tampering, not loss) are refused: investigate with scripts/verify_proof.py instead.
"""
import argparse
import glob
import json
import os
import sys
import time

from app import integrity, persistence, proof


def _chains() -> dict:
    base = os.getenv("QYRIX_CHAIN_FILE", "")
    if not base:
        raise SystemExit("QYRIX_CHAIN_FILE not set")
    out = {"default": base}
    for p in sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(base)), "tenants", "*.jsonl"))):
        if not p.endswith(".anchors.jsonl"):
            out[os.path.basename(p)[:-6]] = p
    return out


def _load(path: str):
    if not os.path.exists(path):
        return []
    return [json.loads(l) for l in open(path) if l.strip()]


def status() -> dict:
    out = {"witness": None, "witness_error": None, "database_install_id": None, "chains": {}}
    try:
        w = integrity.read_witness()
        out["witness"] = None if w is None else {"install_id": w["install_id"], "tenants": w.get("tenants", {}),
                                                 "recoveries": len(w.get("recoveries", [])), "pending_records": len(w.get("pending_records", []))}
    except integrity.WitnessError as e:
        out["witness_error"] = integrity.reason_of(e)
    dsn = persistence.dsn_from_env()
    if dsn:
        out["database_install_id"] = persistence.PgPersistence(dsn).install_id()
    for tid, path in _chains().items():
        recs = _load(path)
        v = proof.verify_records(recs)
        out["chains"][tid] = {"records": len(recs), "head": recs[-1]["hash"] if recs else None, "valid": v["valid"]}
    return out


def accept(reason: str, new_installation: bool = False, reinitialize_witness: bool = False) -> dict:
    if len(reason.strip()) < 10:
        raise SystemExit("--reason must describe the incident (>= 10 characters); it is kept in the audit trail")
    try:
        w = integrity.read_witness()
    except integrity.WitnessError as e:
        if not reinitialize_witness:
            raise SystemExit("witness unusable (%s); pass --reinitialize-witness after investigating" % e)
        w = None
    dsn = persistence.dsn_from_env()
    if not dsn:
        raise SystemExit("no database configured")
    db = persistence.PgPersistence(dsn)
    db_id = db.install_id()
    if db_id is None:
        if not new_installation:
            raise SystemExit("the database has no installation identity (wiped or new). If that is intended, pass --new-installation")
        import uuid
        db_id = db.init_install(str(uuid.uuid4()))
    old = w or {"install_id": None, "tenants": {}, "recoveries": [], "pending_records": []}
    marks, pending = {}, list(old.get("pending_records", []))
    now = time.time()
    for tid, path in _chains().items():
        recs = _load(path)
        if not proof.verify_records(recs)["valid"]:
            raise SystemExit("chain for tenant %s does not verify: this is tampering, not data loss - not accepting" % tid)
        # seal at the point BOTH stores provably hold: a correct restore (DB first, chain second) may leave the chain
        # ahead of the DB mirror; the backend back-fills the mirror on start and then advances the mark itself
        n_db = len(persistence.PgPersistence(dsn, tid).load_proof_index())
        if n_db > len(recs):
            raise SystemExit("tenant %s: database mirror (%d) is AHEAD of the chain file (%d) - restore order is wrong "
                             "(restore the chain from the same backup); not accepting" % (tid, n_db, len(recs)))
        n = min(len(recs), n_db)
        if n:
            marks[tid] = {"n": n, "head": recs[n - 1]["hash"], "at": now}
        prev = old.get("tenants", {}).get(tid)
        if prev != marks.get(tid) or old.get("install_id") != db_id:
            pending.append({"tenant": tid, "reason": reason.strip()[:200], "previous_mark": prev, "accepted_at": now})
    body = {"install_id": db_id, "created_at": old.get("created_at", now), "tenants": marks, "seq": old.get("seq", 0),
            "recoveries": old.get("recoveries", []) + [{"at": now, "reason": reason.strip()[:500], "from_install": old.get("install_id"),
                                                        "to_install": db_id, "previous_marks": old.get("tenants", {})}],
            "pending_records": pending}
    integrity.write_witness(body)
    return {"accepted": True, "install_id": db_id, "tenants": marks, "pending_proof_records": len(pending)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["status", "accept"])
    ap.add_argument("--reason", default="")
    ap.add_argument("--new-installation", action="store_true")
    ap.add_argument("--reinitialize-witness", action="store_true")
    a = ap.parse_args(argv)
    out = status() if a.cmd == "status" else accept(a.reason, a.new_installation, a.reinitialize_witness)
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
