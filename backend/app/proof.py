"""Verifiable Proof Engine: canonical JSON, SHA-256 hash chaining, offline verification.

Record format v2:  hash = SHA-256( prev_hash || canonical_json(record without "hash") )
canonical_json = UTF-8 JSON, keys sorted, no insignificant whitespace, ASCII-escaped (deterministic across platforms).

v1 records (written by v1.1, no "v" field) are still verified with their original body so existing evidence files
remain checkable after the upgrade; every new record is v2.

Verification outcomes (master plan 9.4 / 11):
- FAIL                 : any link, hash, sequence number or format check fails (missing, modified, reordered records).
- PARTIAL_UNANCHORED   : the chain is internally consistent but its current head is not covered by a verified external
                         anchor (none configured, anchor covers only a prefix, or no TSA trust anchor to verify with).
- PASS                 : internally valid chain whose CURRENT head is covered by an RFC 3161 anchor whose token verifies
                         against the configured TSA trust anchor (app/anchor.py). Never returned without a verified anchor.
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


def evaluate_anchors(chain: List[Dict], anchors: List[Dict], verify_token=None) -> Dict:
    """Combine internal chain verification with external anchors.
    PASS only if: chain valid AND latest anchor's token verifies (verify_token supplied) AND it covers the current head.
    FAIL if any anchor contradicts the chain (hash mismatch / beyond the end) or a token fails verification.
    Otherwise PARTIAL_UNANCHORED (no anchor, anchor covers only a prefix, or no way to verify tokens)."""
    base = verify_records(chain)
    out = {**base, "anchors": len(anchors), "anchored_through": None, "anchor_detail": None}
    if not base["valid"] or not chain:
        return out
    for a in anchors:
        n = a.get("n")
        if not isinstance(n, int) or n < 1 or n > len(chain) or chain[n - 1]["hash"] != a.get("head_hash"):
            return {**out, "valid": False, "status": FAIL, "anchor_status": "ANCHOR_MISMATCH", "broken_at": n,
                    "anchor_detail": "anchor %s does not match the chain" % str(a.get("id"))[:8]}
    if not anchors:
        return out
    latest = max(anchors, key=lambda a: a["n"])
    if verify_token is None:
        return {**out, "anchor_status": "ANCHOR_UNVERIFIABLE", "anchor_detail": "no TSA trust anchor configured"}
    ok, detail = verify_token(latest["head_hash"], latest["token_b64"])
    if not ok:
        return {**out, "valid": False, "status": FAIL, "anchor_status": "ANCHOR_INVALID", "anchor_detail": detail}
    full = latest["n"] == len(chain)
    return {**out, "status": PASS if full else PARTIAL_UNANCHORED, "anchor_status": "ANCHORED" if full else "ANCHORED_PREFIX",
            "anchored_through": latest["n"], "anchor_detail": "%s · %s · %s" % (latest.get("tsa_url"), latest.get("gen_time"), detail)}


def verify_bundle(bundle: Any) -> Dict:
    """Verify an exported bundle {"chain": [...]} (or a bare list). Empty => EmptyBundle. Malformed => FAIL."""
    chain = bundle.get("chain") if isinstance(bundle, dict) else bundle
    if not isinstance(chain, list):
        return {"valid": False, "status": FAIL, "broken_at": None, "length": 0, "head": None,
                "anchor_status": "UNANCHORED", "error": "MALFORMED_BUNDLE"}
    if not chain:
        raise EmptyBundle("proof bundle contains no records")
    return verify_records(chain, anchor_head=None)


def verify_bundle_with_anchors(bundle: Any, verify_token=None) -> Dict:
    """Like verify_bundle, plus anchors carried in the bundle. Anchor tokens are self-authenticating: they are only
    accepted if they verify against the VERIFIER's own TSA trust anchor (verify_token), never on the bundle's say-so."""
    base = verify_bundle(bundle)
    anchors = bundle.get("anchors") if isinstance(bundle, dict) else None
    if not base["valid"] or not isinstance(anchors, list) or not anchors:
        return base
    if not all(isinstance(a, dict) for a in anchors):
        return {**base, "valid": False, "status": FAIL, "anchor_status": "ANCHOR_MALFORMED"}
    return evaluate_anchors(bundle["chain"], anchors, verify_token)
