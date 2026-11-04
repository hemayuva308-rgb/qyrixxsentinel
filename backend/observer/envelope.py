"""Event envelope (design §12): canonical JSON, sorted keys, UTF-8, at most 64 KiB, Ed25519 over canonical(envelope
without sig). Structural validation only; authorization (producer, key, scope, tenant) is in observer/ingest.py."""
import json
import math
import re
import uuid
from typing import Dict, Tuple

from observer import FORMAT_EVENT
from observer.canonical import canonical, sha256_hex
from observer.manifest import parse_time

MAX_BYTES = 64 * 1024
TYPES = ("decision", "grant", "heartbeat", "adapter_report", "epoch_change",
         "observation")                    # internal-only: no producer scope can ever include it => SCOPE_DENIED
SEQ_TYPES = ("decision", "grant")                 # gap-free per (producer, epoch, tenant) stream (§5.1)
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")
FIELDS = {"schema", "event_id", "producer_id", "key_id", "epoch", "seq", "hb_seq", "issued_at", "tenant", "type", "body", "sig"}


class Refused(Exception):
    """A refusal with a fixed public code (design §12 error codes, plus the codes documented in docs/OBSERVER.md)."""
    observer_passthrough = True                    # not a database outage: propagate through Database.run unchanged

    def __init__(self, code: str, status: int, detail: str = ""):
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail[:200]


def _no_constant(name):
    raise ValueError("non-finite number")           # NaN / Infinity / -Infinity are not JSON (audit F7)


def _finite(s: str) -> float:
    f = float(s)
    if not math.isfinite(f):                         # e.g. 1e400 parses to inf
        raise ValueError("non-finite number")
    return f


def _int(v, lo: int) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and lo <= v < 2 ** 63


def parse(raw: bytes) -> Dict:
    if len(raw) > MAX_BYTES:
        raise Refused("OVERSIZE", 413)
    try:
        env = json.loads(raw.decode("utf-8"), parse_constant=_no_constant, parse_float=_finite)
    except (UnicodeDecodeError, ValueError, RecursionError):   # incl. >4300-digit integers and absurd nesting
        raise Refused("MALFORMED", 400, "not UTF-8 JSON") from None
    if not isinstance(env, dict) or set(env) != FIELDS:
        raise Refused("MALFORMED", 400, "envelope fields")
    if env["schema"] != FORMAT_EVENT or env["type"] not in TYPES:
        raise Refused("MALFORMED", 400, "schema/type")
    try:
        if str(uuid.UUID(env["event_id"], version=4)) != env["event_id"]:
            raise ValueError
        env["_issued"] = parse_time(env["issued_at"])
    except (TypeError, ValueError, AttributeError):
        raise Refused("MALFORMED", 400, "event_id/issued_at") from None
    if not (isinstance(env["producer_id"], str) and 0 < len(env["producer_id"]) <= 128
            and isinstance(env["key_id"], str) and len(env["key_id"]) <= 64 and isinstance(env["sig"], str)
            and isinstance(env["body"], dict) and _int(env["epoch"], 1)):
        raise Refused("MALFORMED", 400, "field types")
    t = env["type"]
    if t in SEQ_TYPES:
        ok = _int(env["seq"], 1) and env["hb_seq"] is None and isinstance(env["tenant"], str)
    elif t == "heartbeat":
        ok = env["seq"] is None and _int(env["hb_seq"], 1) and env["tenant"] is None
    elif t in ("adapter_report", "observation"):
        ok = env["seq"] is None and env["hb_seq"] is None and isinstance(env["tenant"], str)
    else:                                          # epoch_change: producer-level, no counters
        ok = env["seq"] is None and env["hb_seq"] is None and env["tenant"] is None
    if not ok:
        raise Refused("MALFORMED", 400, "counters/tenant for type")
    if env["tenant"] is not None and not TENANT_RE.match(env["tenant"]):
        raise Refused("TENANT_MISMATCH", 403, "invalid tenant id")
    return env


def signed_bytes(env: Dict) -> bytes:
    return canonical({k: v for k, v in env.items() if k in FIELDS and k != "sig"})


def content_digest(env: Dict) -> str:
    """Identity of an event's CONTENT for duplicate/conflict decisions: everything except the signature and the signing
    key id, so a re-send signed by a rotated (still valid) key is a duplicate, while any change of content is a conflict."""
    return sha256_hex(canonical({k: v for k, v in env.items() if k in FIELDS and k not in ("sig", "key_id")}))


def stored(env: Dict) -> Tuple[Dict, str]:
    clean = {k: v for k, v in env.items() if k in FIELDS}
    return clean, content_digest(env)
