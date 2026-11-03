"""Observer key manifest (design §9, §12). Installed from a FILE signed offline by the operator's root key; never set
through an API call and never fetched from the backend.

    {"format": "qyrix-observer-manifest/1", "manifest_version": 3, "issued_at": "<ISO-8601 UTC>",
     "observer_keys":  [{"key_id", "public_key", "valid_from", "valid_to"?, "revoked_at"?}],
     "producers": [{"producer_id": "gate:<install_id>" | "adapter:<integration_id>", "tenants": ["*"] | ["t1", ...],
                    "keys": [{"key_id", "public_key", "scopes": [...], "valid_from", "valid_to"?, "revoked_at"?}]}],
     "recovery_keys":  [{"key_id", "public_key", "valid_from", "valid_to"?, "revoked_at"?}],
     "root_key_id": "<id of the root key>", "sig": "<Ed25519 by the root key over canonical(manifest without sig)>"}

Rules enforced here (any violation => the whole manifest is refused, fail closed):
- signature by the PINNED root public key (configuration of the observer, outside every data store);
- key_id must be the id derived from the public key (no aliasing);
- scopes are limited by producer kind: gate => decision | grant | heartbeat; adapter => adapter_report;
- epoch changes (§5.4) verify ONLY against recovery_keys - never a producer (GATE) key;
- one key, one role: a key may not appear as observer, producer and/or recovery key at the same time.
"""
from datetime import datetime, timezone
from typing import Dict, List, Optional

from observer import crypto
from observer.canonical import canonical, sha256_hex

FORMAT = "qyrix-observer-manifest/1"
GATE_SCOPES = frozenset({"decision", "grant", "heartbeat"})
ADAPTER_SCOPES = frozenset({"adapter_report"})


class ManifestError(Exception):
    """Reason codes only (never key material)."""


def parse_time(v) -> Optional[float]:
    if v is None:
        return None
    if not isinstance(v, str) or len(v) > 40:
        raise ValueError("time must be an ISO-8601 string")
    d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    if d.tzinfo is None:
        raise ValueError("time must carry a UTC offset")
    return d.timestamp()


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, timezone.utc).isoformat()


class Key:
    __slots__ = ("key_id", "public", "valid_from", "valid_to", "revoked_at", "scopes")

    def __init__(self, d: Dict, scopes=frozenset()):
        if not isinstance(d, dict):
            raise ManifestError("KEY_ENTRY_INVALID")
        try:
            raw = crypto.unb64(d["public_key"])
            self.public = crypto.public_from_b64(d["public_key"])
            self.valid_from = parse_time(d["valid_from"])
            self.valid_to = parse_time(d.get("valid_to"))
            self.revoked_at = parse_time(d.get("revoked_at"))
        except (KeyError, ValueError, crypto.KeyError_):
            raise ManifestError("KEY_ENTRY_INVALID") from None
        if d.get("key_id") != crypto.key_id_of_raw(raw):
            raise ManifestError("KEY_ID_MISMATCH")
        self.key_id, self.scopes = d["key_id"], frozenset(scopes)

    def valid_at(self, t: float) -> bool:
        return (self.valid_from <= t and (self.valid_to is None or t < self.valid_to)
                and (self.revoked_at is None or t < self.revoked_at))


class Producer:
    __slots__ = ("producer_id", "kind", "tenants", "keys")

    def __init__(self, d: Dict):
        pid = d.get("producer_id") if isinstance(d, dict) else None
        if not isinstance(pid, str) or len(pid) > 128 or ":" not in pid:
            raise ManifestError("PRODUCER_INVALID")
        kind = pid.split(":", 1)[0]
        if kind not in ("gate", "adapter"):
            raise ManifestError("PRODUCER_KIND_INVALID")
        allowed = GATE_SCOPES if kind == "gate" else ADAPTER_SCOPES
        tenants = d.get("tenants")
        if not isinstance(tenants, list) or not tenants or not all(isinstance(t, str) and len(t) <= 40 for t in tenants):
            raise ManifestError("PRODUCER_TENANTS_INVALID")
        keys = {}
        for k in d.get("keys") or []:
            scopes = k.get("scopes") if isinstance(k, dict) else None
            if not isinstance(scopes, list) or not scopes or not set(scopes) <= allowed:
                raise ManifestError("SCOPE_NOT_ALLOWED_FOR_PRODUCER_KIND")
            key = Key(k, scopes)
            keys[key.key_id] = key
        if not keys:
            raise ManifestError("PRODUCER_WITHOUT_KEYS")
        self.producer_id, self.kind, self.tenants, self.keys = pid, kind, frozenset(tenants), keys

    def allows_tenant(self, t: str) -> bool:
        return "*" in self.tenants or t in self.tenants


class Manifest:
    def __init__(self, doc: Dict, root_public_b64: str):
        if not isinstance(doc, dict) or doc.get("format") != FORMAT:
            raise ManifestError("MANIFEST_FORMAT_INVALID")
        try:
            root = crypto.public_from_b64(root_public_b64)
            root_id = crypto.key_id_of_raw(crypto.unb64(root_public_b64))
        except crypto.KeyError_:
            raise ManifestError("ROOT_KEY_INVALID") from None
        body = {k: v for k, v in doc.items() if k != "sig"}
        if doc.get("root_key_id") != root_id or not crypto.verify(root, doc.get("sig") or "", canonical(body)):
            raise ManifestError("MANIFEST_SIGNATURE_INVALID")
        v = doc.get("manifest_version")
        if not isinstance(v, int) or isinstance(v, bool) or v < 1:
            raise ManifestError("MANIFEST_VERSION_INVALID")
        self.version, self.doc = v, doc
        self.digest = sha256_hex(canonical(doc))
        self.observer_keys = {k.key_id: k for k in (Key(x) for x in doc.get("observer_keys") or [])}
        self.recovery_keys = {k.key_id: k for k in (Key(x, {"epoch_change"}) for x in doc.get("recovery_keys") or [])}
        self.producers: Dict[str, Producer] = {}
        for p in doc.get("producers") or []:
            pr = Producer(p)
            if pr.producer_id in self.producers:
                raise ManifestError("PRODUCER_DUPLICATE")
            self.producers[pr.producer_id] = pr
        ids: List[str] = list(self.observer_keys) + list(self.recovery_keys) + [
            kid for p in self.producers.values() for kid in p.keys]
        if len(ids) != len(set(ids)) or root_id in ids:
            raise ManifestError("KEY_REUSED_ACROSS_ROLES")

    def producer(self, pid: str) -> Optional[Producer]:
        return self.producers.get(pid)


def sign_manifest(doc: Dict, root_key) -> Dict:
    """Operator tooling (offline): returns the signed manifest. `root_key` is an Ed25519 private key object."""
    rid, _ = crypto.describe(root_key)
    body = {k: v for k, v in doc.items() if k not in ("sig",)}
    body["format"], body["root_key_id"] = FORMAT, rid
    return {**body, "sig": crypto.sign(root_key, canonical(body))}
