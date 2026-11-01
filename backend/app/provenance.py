"""Trust Provenance: labels every instruction source and keeps a 50-step memory.
Taint propagates through parent links (stored at creation), so transformed/delayed use stays traceable
even after the source step leaves the 50-step window. NOTE: single global memory (single-tenant MVP)."""
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

LABELS = ("approved", "untrusted", "unverified")
MEMORY_LIMIT = 50
_mem = deque(maxlen=MEMORY_LIMIT)
_seq = 0
_lock = threading.RLock()


def add_step(source: str, label: str, text: str, parents: Optional[List[int]] = None) -> Dict:
    global _seq
    if label not in LABELS:
        label = "unverified"          # unknown label never becomes trusted
    parents = parents or []
    with _lock:
        tainted = label != "approved" or any(get(p) and get(p)["tainted"] for p in parents)
        _seq += 1
        step = {"id": _seq, "source": source, "label": label, "text": text[:500], "parents": parents,
                "tainted": tainted, "ts": datetime.now(timezone.utc).isoformat()}
        _mem.append(step)
        return step


def get(step_id: int) -> Optional[Dict]:
    with _lock:
        return next((s for s in _mem if s["id"] == step_id), None)


def lineage(ids: List[int]) -> List[Dict]:
    seen, stack = set(), list(ids)
    while stack:
        i = stack.pop()
        if i in seen:
            continue
        seen.add(i)
        s = get(i)
        if s:
            stack.extend(s["parents"])
    return [s for s in (get(i) for i in sorted(seen)) if s]


def all_steps() -> List[Dict]:
    with _lock:
        return list(_mem)


def reset() -> None:
    global _seq
    with _lock:
        _mem.clear()
        _seq = 0
