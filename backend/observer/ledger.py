"""Observer ledger (design §2, §9): one hash chain, each record signed by the observer signing key listed in the
manifest. The observer refuses to sign (and therefore to ingest) with a key that the current manifest does not list as
valid now (§14 'Observer key revoked / manifest invalid')."""
import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from observer import crypto
from observer.canonical import canonical, sha256_hex

GENESIS = "0" * 64


class LedgerError(Exception):
    observer_passthrough = True          # a signing refusal, not a database outage


def _body(n, prev, recorded_at: str, kind, code, producer_id, tenant_id, ref, detail) -> Dict:
    return {"n": n, "prev": prev, "recorded_at": recorded_at, "kind": kind, "code": code, "producer_id": producer_id,
            "tenant_id": tenant_id, "ref": ref, "detail": detail}


def append(cur, signer, now: float, kind: str, code: str, producer_id: Optional[str] = None,
           tenant_id: Optional[str] = None, ref: Optional[str] = None, detail: Optional[Dict] = None) -> Dict:
    """Must run inside the ingest transaction (global advisory lock held), so n/prev are race-free."""
    key, key_id = signer()                       # raises LedgerError when no valid observer key
    cur.execute("SELECT n, hash FROM ledger ORDER BY n DESC LIMIT 1")
    r = cur.fetchone()
    n, prev = (r[0] + 1, r[1].strip()) if r else (1, GENESIS)
    at = datetime.fromtimestamp(now, timezone.utc).isoformat()
    body = _body(n, prev, at, kind, code, producer_id, tenant_id, ref, detail or {})
    h = sha256_hex(canonical(body))
    sig = crypto.sign(key, h.encode("ascii"))
    cur.execute("INSERT INTO ledger (n, prev, hash, recorded_at, kind, code, producer_id, tenant_id, ref, detail, observer_key_id, sig)"
                " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (n, prev, h, datetime.fromtimestamp(now, timezone.utc), kind, code, producer_id, tenant_id, ref,
                 json.dumps(body["detail"]), key_id, sig))
    return {"n": n, "hash": h}


def verify(rows: List[tuple], observer_keys: Dict) -> Dict:
    """rows: (n, prev, hash, recorded_at, kind, code, producer_id, tenant_id, ref, detail, observer_key_id, sig) by n.
    Checks linkage, recomputed hash, and the signature under a manifest observer key valid at recorded_at."""
    prev, n_exp = GENESIS, 1
    for r in rows:
        n, rprev, h, at, kind, code, pid, tid, ref, detail, kid, sig = r
        at_s = at.isoformat() if hasattr(at, "isoformat") else str(at)
        if n != n_exp or rprev.strip() != prev:
            return {"valid": False, "n": n, "reason": "LINK_BROKEN"}
        if sha256_hex(canonical(_body(n, prev, at_s, kind, code, pid, tid, ref, detail))) != h.strip():
            return {"valid": False, "n": n, "reason": "HASH_MISMATCH"}
        k = observer_keys.get(kid)
        if k is None or not k.valid_at(at.timestamp()) or not crypto.verify(k.public, sig, h.strip().encode("ascii")):
            return {"valid": False, "n": n, "reason": "SIGNATURE_INVALID"}
        prev, n_exp = h.strip(), n + 1
    return {"valid": True, "records": n_exp - 1, "head": prev}
