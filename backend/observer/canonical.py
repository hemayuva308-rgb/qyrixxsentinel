"""Canonical JSON + SHA-256 (vendored; must stay byte-identical with app/observer_feed.py, enforced by a test)."""
import hashlib
import json
from typing import Any


def canonical(o: Any) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
