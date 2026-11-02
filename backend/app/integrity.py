"""Silent data-loss detection (v1.4).

Problem: if the database AND the proof chain are wiped (or replaced by an older/different copy), an installation would
otherwise start as a healthy, empty "new install" and nobody would notice that customer evidence disappeared.

Trust model - three independent records, any disagreement => RECOVERY_REQUIRED (Gate blocks everything):
  1. PostgreSQL: `installation.install_id` (insert-once) + the per-tenant proof mirror.
  2. Proof chain files (one per tenant) on the chain volume.
  3. The STATE WITNESS: a small JSON file on a SEPARATE volume (QYRIX_STATE_WITNESS_DIR), authenticated with
     HMAC-SHA256 under a key held in a separate secret (QYRIX_STATE_WITNESS_KEY_FILE). It stores the install id and,
     per tenant, the high-water mark (record count + head hash) of the proof chain. Marks only ever move forward,
     except through an explicit, audited operator recovery (`python -m app.recovery accept`).
  4. Optional, strongest: QYRIX_EXPECTED_INSTALL_ID in the deployment configuration (outside every data store).

What this detects: database wiped or replaced; proof chain deleted, truncated, rolled back or forked; witness deleted
or forged without the key; restore of an older backup (until an operator accepts it); data present without a witness.
What it cannot detect (documented): an attacker who controls the database, the chain volume, the witness volume AND
the witness key, and no QYRIX_EXPECTED_INSTALL_ID is set - all evidence of the old installation is then gone.
"""
import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from typing import Dict, Optional

from app import observability as obs

FORMAT = "qyrix-witness/1"
OK, FRESH, ADOPTED, RECOVERY, DISABLED, NOT_APPLICABLE = "OK", "FRESH_INSTALL", "ADOPTED_EXISTING", "RECOVERY_REQUIRED", "DISABLED", "NOT_APPLICABLE"

_lock = threading.RLock()
_install: Dict = {"status": None, "reason": None, "install_id": None}


class WitnessError(Exception):
    pass


# ---------------- configuration ----------------
def disabled() -> bool:
    return os.getenv("QYRIX_STATE_WITNESS", "").strip().lower() == "disabled"


def witness_path() -> Optional[str]:
    d = os.getenv("QYRIX_STATE_WITNESS_DIR", "").strip()
    return os.path.join(d, "witness.json") if d else None


def _key() -> bytes:
    path = os.getenv("QYRIX_STATE_WITNESS_KEY_FILE", "").strip()
    if not path:
        raise WitnessError("WITNESS_KEY_NOT_CONFIGURED")
    try:
        k = open(path, "rb").read().strip()
    except OSError:
        raise WitnessError("WITNESS_KEY_UNAVAILABLE") from None
    if len(k) < 32 or b"CHANGE_ME" in k:
        raise WitnessError("WITNESS_KEY_UNAVAILABLE")
    return k


# ---------------- witness file ----------------
def _canon(body: Dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def read_witness() -> Optional[Dict]:
    """None if absent. Raises WitnessError if present but unreadable, malformed or not authentic."""
    p = witness_path()
    if not p:
        raise WitnessError("WITNESS_NOT_CONFIGURED")
    if not os.path.exists(p):
        return None
    try:
        doc = json.load(open(p))
        body, mac = doc["body"], doc["mac"]
    except Exception:
        raise WitnessError("WITNESS_UNREADABLE") from None
    if not hmac.compare_digest(hmac.new(_key(), _canon(body), hashlib.sha256).hexdigest(), str(mac)):
        raise WitnessError("WITNESS_FORGED_OR_WRONG_KEY")
    if body.get("format") != FORMAT:
        raise WitnessError("WITNESS_UNKNOWN_FORMAT")
    return body


def write_witness(body: Dict) -> None:
    p = witness_path()
    if not p:
        raise WitnessError("WITNESS_NOT_CONFIGURED")
    body = {**body, "format": FORMAT, "updated_at": time.time(), "seq": int(body.get("seq", 0)) + 1}
    doc = {"body": body, "mac": hmac.new(_key(), _canon(body), hashlib.sha256).hexdigest()}
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, p)                      # atomic: a crash leaves the old or the new witness, never half of one
    try:
        dfd = os.open(os.path.dirname(p), os.O_RDONLY)
        os.fsync(dfd)
        os.close(dfd)
    except OSError:
        pass


# ---------------- decisions ----------------
def _fail(ctx, reason: str, scope: str) -> None:
    ctx.state["integrity"] = {"status": RECOVERY, "reason": reason, "scope": scope}
    ctx.state["degraded"] = True            # Gate blocks everything (R11) until an operator recovers
    obs.inc("qyrix_integrity_failures_total", reason=reason)
    obs.event("data_integrity_failure", severity="critical", reason=reason, scope=scope, tenant=getattr(ctx.db, "t", ctx.name))


def check_installation(ctx, db) -> Dict:
    """Run once per process with the default tenant's context. Decides FRESH / ADOPTED / OK / RECOVERY."""
    with _lock:
        if disabled():
            _install.update(status=DISABLED, reason="QYRIX_STATE_WITNESS=disabled", install_id=None)
            obs.event("state_witness_disabled", severity="warning")
            return dict(_install)
        try:
            w = read_witness()
            db_id = db.install_id()
            census = db.proof_census()
            expected = os.getenv("QYRIX_EXPECTED_INSTALL_ID", "").strip() or None
            chain_has_data = bool(ctx.chain)
            if w is None and db_id is None:
                if expected:
                    raise WitnessError("EXPECTED_INSTALLATION_MISSING")       # config says data must exist: total loss
                iid = db.init_install(str(uuid.uuid4()))
                if census["records"] or chain_has_data:
                    status, ev = ADOPTED, "installation_adopted"               # upgrade from <= v1.3 (no identity yet)
                else:
                    status, ev = FRESH, "installation_initialized"             # a genuinely new, empty installation
                write_witness({"install_id": iid, "created_at": time.time(), "tenants": {}, "recoveries": []})
                obs.event(ev, severity="warning", install_id=iid, existing_records=census["records"])
                _install.update(status=status, reason=None, install_id=iid)
                return dict(_install)
            if w is None:
                raise WitnessError("WITNESS_MISSING")                          # witness volume lost or swapped
            if db_id is None:
                raise WitnessError("DATABASE_LOST_OR_REPLACED")                # DB wiped / recreated / pointed elsewhere
            if w["install_id"] != db_id:
                raise WitnessError("INSTALLATION_MISMATCH")                    # DB from another installation
            if expected and expected != db_id:
                raise WitnessError("INSTALLATION_MISMATCH_EXPECTED")
            if census["records"] == 0 and any(m.get("n", 0) > 0 for m in w.get("tenants", {}).values()):
                raise WitnessError("DATABASE_EVIDENCE_EMPTIED")                # rows deleted from a known installation
            _install.update(status=OK, reason=None, install_id=db_id)
        except WitnessError as e:
            _install.update(status=RECOVERY, reason=str(e), install_id=None)
            _fail(ctx, str(e), "installation")
        except Exception as e:                                                 # DB error etc: cannot establish => block
            _install.update(status=RECOVERY, reason="CHECK_FAILED:" + type(e).__name__, install_id=None)
            _fail(ctx, _install["reason"], "installation")
        return dict(_install)


def check_tenant(ctx, db) -> None:
    """Per tenant, BEFORE the DB proof mirror is back-filled: chain and DB must not be behind the witness mark."""
    tid = db.t
    with _lock:
        st = _install["status"]
        if st == DISABLED:
            ctx.state["integrity"] = {"status": DISABLED, "reason": _install["reason"]}
            return
        if st not in (OK, FRESH, ADOPTED):
            if ctx.state.get("integrity", {}).get("status") != RECOVERY:   # not already reported for this context
                _fail(ctx, str(_install["reason"] or "INSTALLATION_UNCHECKED"), "installation")
            return
        try:
            w = read_witness()
            if w is None or w["install_id"] != _install["install_id"]:
                raise WitnessError("WITNESS_CHANGED_SINCE_START")
            mark = w.get("tenants", {}).get(tid)
            n_chain, n_db = len(ctx.chain), len(db.load_proof_index())
            if mark:
                if n_chain < mark["n"]:
                    raise WitnessError("PROOF_CHAIN_REGRESSED")               # deleted, truncated or older restore
                if ctx.chain[mark["n"] - 1]["hash"] != mark["head"]:
                    raise WitnessError("PROOF_CHAIN_DIVERGED")                # replaced by a different history
                if n_db < mark["n"]:
                    raise WitnessError("DATABASE_EVIDENCE_REGRESSED")         # proof rows lost from PostgreSQL
            elif n_chain or n_db:
                pass                                                          # first sight of existing data: sealed below
            pending = [p for p in w.get("pending_records", []) if p.get("tenant") == tid]
            ctx.state["integrity"] = {"status": OK, "reason": None, "pending_recovery_records": len(pending)}
            if pending:
                ctx.state["integrity"]["pending"] = pending
        except WitnessError as e:
            _fail(ctx, str(e), "tenant")
        except Exception as e:
            _fail(ctx, "CHECK_FAILED:" + type(e).__name__, "tenant")


def seal(ctx) -> None:
    """Advance this tenant's high-water mark after a record is durable in BOTH the chain file and the DB mirror."""
    if ctx.db is None or not ctx.chain or ctx.state.get("integrity", {}).get("status") != OK:
        return
    with _lock:
        try:
            w = read_witness()
            if w is None or w["install_id"] != _install["install_id"]:
                raise WitnessError("WITNESS_CHANGED_AT_RUNTIME")
            tid, n = ctx.db.t, len(ctx.chain)
            cur = w.setdefault("tenants", {}).get(tid, {"n": 0})
            if n <= cur.get("n", 0):
                return
            w["tenants"][tid] = {"n": n, "head": ctx.chain[-1]["hash"], "at": time.time()}
            write_witness(w)
        except Exception as e:
            reason = str(e) if isinstance(e, WitnessError) else "WITNESS_WRITE_FAILED:" + type(e).__name__
            _fail(ctx, reason, "tenant")


def acknowledge_pending(ctx, record_fn) -> None:
    """Append one RECOVERY_ACCEPTED proof record per operator acceptance, so the discontinuity is part of the evidence."""
    pend = ctx.state.get("integrity", {}).get("pending") or []
    if not pend:
        return
    for p in pend:
        record_fn(ctx, {"kind": "integrity", "verdict": "RECOVERY_ACCEPTED", "gate_evaluation_id": None, "tool": None, "rule_ids": [],
                        "reason": str(p.get("reason", ""))[:200], "previous_mark": p.get("previous_mark"), "accepted_at": p.get("accepted_at")})
    with _lock:
        w = read_witness()
        w["pending_records"] = [p for p in w.get("pending_records", []) if p.get("tenant") != ctx.db.t]
        write_witness(w)
    ctx.state["integrity"].pop("pending", None)
    ctx.state["integrity"]["pending_recovery_records"] = 0


def reset_tenant_mark(ctx) -> None:
    """Demo/eval reset (already authorised by the API guard AND the database grant): lower this tenant's mark to 0."""
    if ctx.db is None or ctx.state.get("integrity", {}).get("status") != OK:
        return
    with _lock:
        w = read_witness()
        if w is None:
            return
        old = w.get("tenants", {}).pop(ctx.db.t, None)
        w.setdefault("recoveries", []).append({"at": time.time(), "tenant": ctx.db.t, "reason": "demo/eval evidence reset",
                                               "previous_mark": old})
        write_witness(w)
    obs.event("evidence_reset", severity="warning", tenant=ctx.db.t, previous_records=(old or {}).get("n", 0))


def snapshot() -> Dict:
    with _lock:
        return dict(_install)


def reset_for_tests() -> None:
    with _lock:
        _install.update(status=None, reason=None, install_id=None)
