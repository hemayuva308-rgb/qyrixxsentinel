"""Operator recovery for the data-loss detector (app/integrity.py). Run with the BACKEND STOPPED.

    python -m app.recovery status
    python -m app.recovery accept --reason "restored backup 2026-11-02T06:00Z after disk failure (INC-42)"
    python -m app.recovery accept --reason "..." --new-installation      # DB intentionally empty/new
    python -m app.recovery accept --reason "..." --reinitialize-witness  # witness key rotated / witness lost

    python -m app.recovery observer-epoch --recovery-key /path/operator-recovery.pem --reason "..." --out epoch.json [--send]
    python -m app.recovery observer-epoch-send --file epoch.json

`observer-epoch` (Phase C2, design §5.4) is the ONLY way to restart the observer feed's sequence numbers after a
restore: with the ADMIN database account it records the last trusted seq per tenant of the current epoch, moves the
producer to epoch+1 (seq restarts at 1, heartbeat counter at 0) and writes an `epoch_change` record signed with the
OPERATOR RECOVERY key (offline / operator-held; never the GATE key - the observer refuses a GATE-signed one). The
record is written to --out BEFORE the database commit. With --send the epoch bump is committed ONLY if the observer
accepts the record (a refused record - wrong key, wrong epoch - leaves the database unchanged); without --send the
bump is committed and the record must be delivered with observer-epoch-send.

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


class _NotAccepted(Exception):
    pass


def observer_epoch(recovery_key: str, reason: str, out: str, send: bool = False, http=None) -> dict:
    if len(reason.strip()) < 10:
        raise SystemExit("--reason must describe the incident (>= 10 characters)")
    import psycopg
    from app import observer_feed
    dsn = persistence.admin_dsn_from_env()
    if not dsn:
        raise SystemExit("administrative database connection not configured (QYRIX_ADMIN_DATABASE_URL / QYRIX_DB_*)")
    key = observer_feed.load_key(recovery_key)
    sent = None
    try:
      with psycopg.connect(dsn, autocommit=False) as c:
        with c.transaction():
            r = c.execute("SELECT install_id FROM installation WHERE id = 1").fetchone()
            if not r:
                raise SystemExit("no installation identity: run `accept` first")
            producer = "gate:" + str(r[0])
            c.execute("INSERT INTO observer_hb_seq (producer_id) VALUES (%s) ON CONFLICT DO NOTHING", (producer,))
            epoch = c.execute("SELECT epoch FROM observer_hb_seq WHERE producer_id=%s FOR UPDATE", (producer,)).fetchone()[0]
            last = {t: int(n) for t, n in c.execute("SELECT tenant_id, n FROM observer_seq WHERE epoch=%s ORDER BY 1", (epoch,))}
            env = observer_feed.sign_envelope(observer_feed.envelope(
                producer, "epoch_change", {"new_epoch": epoch + 1, "last_trusted_seq_per_tenant": last,
                                           "reason": reason.strip()[:500]}, None, epoch + 1), key)
            with open(out, "w") as f:
                json.dump(env, f, sort_keys=True)
            if send:
                sent = observer_epoch_send(out, http)
                if sent["status"] != 200:
                    raise _NotAccepted()                     # roll back: the database keeps its current epoch
            c.execute("UPDATE observer_hb_seq SET epoch = epoch + 1, n = 0 WHERE producer_id=%s", (producer,))
    except _NotAccepted:
        return {"producer_id": producer, "committed": False, "from_epoch": epoch, "observer": sent, "record": out}
    return {"producer_id": producer, "committed": True, "from_epoch": epoch, "to_epoch": epoch + 1,
            "last_trusted_seq_per_tenant": last, "record": out, "recovery_key_id": env["key_id"], "observer": sent}


def observer_epoch_send(path: str, http=None) -> dict:
    from app.observer_feed import canonical
    env = json.load(open(path))
    if http is None:
        if not os.getenv("QYRIX_OBSERVER_URL", "").strip():
            raise SystemExit("QYRIX_OBSERVER_URL not set")
        from app.observer_feed import observer_client
        http = observer_client(timeout=10)                # F2: mTLS (or loopback http)
    r = http.post("/v1/events", content=canonical(env), headers={"Content-Type": "application/json"})
    try:
        body = r.json()
    except ValueError:
        body = {}
    return {"status": r.status_code, "result": body.get("status") or body.get("error")}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["status", "accept", "observer-epoch", "observer-epoch-send"])
    ap.add_argument("--reason", default="")
    ap.add_argument("--new-installation", action="store_true")
    ap.add_argument("--reinitialize-witness", action="store_true")
    ap.add_argument("--recovery-key", help="operator recovery key (Ed25519 PEM) for observer-epoch")
    ap.add_argument("--out", help="where observer-epoch writes the signed epoch_change record")
    ap.add_argument("--file", help="epoch_change record for observer-epoch-send")
    ap.add_argument("--send", action="store_true", help="also POST the record to QYRIX_OBSERVER_URL")
    a = ap.parse_args(argv)
    if a.cmd == "observer-epoch":
        if not a.recovery_key or not a.out:
            ap.error("observer-epoch needs --recovery-key and --out")
        out = observer_epoch(a.recovery_key, a.reason, a.out, a.send)
    elif a.cmd == "observer-epoch-send":
        if not a.file:
            ap.error("observer-epoch-send needs --file")
        out = observer_epoch_send(a.file)
    else:
        out = status() if a.cmd == "status" else accept(a.reason, a.new_installation, a.reinitialize_witness)
    print(json.dumps(out, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
