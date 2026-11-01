"""Verifiable Proof Engine: canonical JSON, SHA-256 hash chaining, offline verification.

Record format v2:  hash = SHA-256( prev_hash || canonical_json(record without "hash") )
canonical_json = UTF-8 JSON, keys sorted, no insignificant whitespace, ASCII-escaped (deterministic across platforms).

v1 records (written by v1.1, no "v" field) are still verified with their original body so existing evidence files
remain checkable after the upgrade; every new record is v2.

Verification outcomes (master plan 9.4 / 11):
- FAIL                 : any link, hash, sequence number or format check fails (missing, modified, reordered records).
- PARTIAL_UNANCHORED   : the chain is internally consistent but has NO trusted external anchor. This is the best
                         outcome this build can produce, because external anchoring is not implemented.
- PASS                 : reserved for an internally valid chain whose head is confirmed by a trusted external anchor.
                         Never returned without an anchor.
- An EMPTY bundle is a validation error (EMPTY_PROOF_BUNDLE), never a pass.
"""
import hashlib
import json
import re
from typing import Any, Dict, List, Optional

GENESIS = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PASS, FAIL, PARTIAL_UNANCHORED = "PASS", "FAIL", "PARTIAL_UNANCHORED"


class EmptyBundle(ValueError):
    code = "EMPTY_PROOF_BUNDLE"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _body_v1(r: Dict) -> str:
    return json.dumps([r["n"], r["ts"], r["tool"], r["verdict"], r["rule_ids"], r["blocked_dest"],
                       r["lineage"], r["data"], r["ext_calls"]], separators=(",", ":"))


def record_hash(r: Dict) -> str:
    if r.get("v") == 2:
        return sha256(r["prev"] + canonical({k: v for k, v in r.items() if k != "hash"}))
    return sha256(r["prev"] + _body_v1(r))


def make_record(prev: str, n: int, fields: Dict) -> Dict:
    r = {"v": 2, "n": n, **fields, "prev": prev}
    r["hash"] = record_hash(r)
    return r


def verify_records(chain: List[Dict], anchor_head: Optional[str] = None) -> Dict:
    """Pure function; safe to run offline on an exported bundle."""
    prev = GENESIS
    for i, r in enumerate(chain, start=1):
        try:
            ok = (isinstance(r, dict) and r.get("n") == i and r.get("prev") == prev and isinstance(r.get("hash"), str)
                  and HEX64.match(r["hash"]) is not None and r["hash"] == record_hash(r))
        except (KeyError, TypeError):
            ok = False
        if not ok:
            return {"valid": False, "status": FAIL, "broken_at": i, "length": len(chain), "head": None,
                    "anchor_status": "UNANCHORED"}
        prev = r["hash"]
    anchored = bool(chain) and anchor_head is not None and anchor_head == prev
    return {"valid": True, "status": PASS if anchored else PARTIAL_UNANCHORED, "length": len(chain),
            "head": prev if chain else None, "anchor_status": "ANCHORED" if anchored else "UNANCHORED"}


def verify_bundle(bundle: Any) -> Dict:
    """Verify an exported bundle {"chain": [...]} (or a bare list). Empty => EmptyBundle. Malformed => FAIL."""
    chain = bundle.get("chain") if isinstance(bundle, dict) else bundle
    if not isinstance(chain, list):
        return {"valid": False, "status": FAIL, "broken_at": None, "length": 0, "head": None,
                "anchor_status": "UNANCHORED", "error": "MALFORMED_BUNDLE"}
    if not chain:
        raise EmptyBundle("proof bundle contains no records")
    # No external anchor is implemented in this build, so a client-provided anchor value is never trusted.
    return verify_records(chain, anchor_head=None)
