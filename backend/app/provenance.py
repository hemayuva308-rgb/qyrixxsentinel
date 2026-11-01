"""Trust Provenance Engine.

Every instruction source becomes a *step* with a UUID v4 id, a declared label and an EFFECTIVE trust:

    TRUSTED > UNVERIFIED > UNTRUSTED

Rules (master plan 9.2):
- A session starts UNVERIFIED: unknown / missing labels are never upgraded.
- A child's effective trust = min(own declared label, effective trust of every parent). Trust can only go DOWN through
  summarisation, transformation or delay; it can never be raised.
- Parents must be known. An unknown parent (never seen, or malformed id) makes the child UNVERIFIED and is recorded.
- The working memory holds the last 50 steps (delayed-instruction window). Effective trust of evicted steps is kept in a
  bounded index, so a delayed child that references an evicted ancestor still inherits its taint.
- Lineage traversal detects cycles (LINEAGE_CYCLE_DETECTED). Ids are server-generated, so a cycle cannot be created
  through the API; the check is defence in depth against corrupted state.
- Trust is NOT authorisation: a TRUSTED step still has to pass the Execution Gate.

`ProvenanceStore` is instantiable so the public demo gets its own isolated store. The module-level functions operate on
the default (production) store and keep the original API.
"""
import threading
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

TRUSTED, UNVERIFIED, UNTRUSTED = "TRUSTED", "UNVERIFIED", "UNTRUSTED"
LABELS = (TRUSTED, UNTRUSTED, UNVERIFIED)
RANK = {UNTRUSTED: 0, UNVERIFIED: 1, TRUSTED: 2}
# Accepted spellings. "approved" is the v1.1 name for TRUSTED and is kept so existing clients keep working.
ALIASES = {"trusted": TRUSTED, "approved": TRUSTED, "untrusted": UNTRUSTED, "unverified": UNVERIFIED}
MEMORY_LIMIT = 50
INDEX_LIMIT = 10000          # bounded trust index for evicted steps (memory-safe)


class LineageCycle(Exception):
    """Raised when lineage traversal revisits a step on the current path."""
    code = "LINEAGE_CYCLE_DETECTED"


def normalize_label(label: Optional[str]) -> str:
    return ALIASES.get(str(label or "").strip().lower(), UNVERIFIED)   # unknown label never becomes trusted


def is_uuid4(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        u = uuid.UUID(value)
    except ValueError:
        return False
    return u.version == 4 and str(u) == value.lower()


def lowest(labels: Iterable[str]) -> str:
    out = TRUSTED
    for lab in labels:
        if RANK[lab] < RANK[out]:
            out = lab
    return out


class ProvenanceStore:
    def __init__(self, memory_limit: int = MEMORY_LIMIT, index_limit: int = INDEX_LIMIT):
        self.memory_limit = memory_limit
        self._mem: deque = deque(maxlen=memory_limit)
        self._index: "OrderedDict[str, str]" = OrderedDict()     # step id -> effective trust (survives eviction)
        self._lock = threading.RLock()

    # ---- writes
    def add_step(self, source: str, label: str, text: str, parents: Optional[List[str]] = None) -> Dict:
        declared = normalize_label(label)
        parents = list(dict.fromkeys(str(p) for p in (parents or [])))          # de-duplicate, keep order
        with self._lock:
            unknown = [p for p in parents if self.trust_of(p) is None]
            inherited = [self.trust_of(p) for p in parents if self.trust_of(p) is not None]
            effective = lowest([declared] + inherited + ([UNVERIFIED] if unknown else []))
            step = {"id": str(uuid.uuid4()), "source": str(source)[:64], "label": effective, "declared_label": declared,
                    "text": str(text)[:500], "parents": parents, "unknown_parents": unknown,
                    "tainted": effective != TRUSTED, "ts": datetime.now(timezone.utc).isoformat()}
            self._mem.append(step)
            self._index[step["id"]] = effective
            while len(self._index) > INDEX_LIMIT:          # oldest ids leave the index; a child naming one => UNVERIFIED
                self._index.popitem(last=False)
            return step

    # ---- reads
    def get(self, step_id: str) -> Optional[Dict]:
        with self._lock:
            return next((s for s in self._mem if s["id"] == step_id), None)

    def trust_of(self, step_id: str) -> Optional[str]:
        with self._lock:
            return self._index.get(step_id)

    def known(self, step_id: str) -> bool:
        return self.trust_of(step_id) is not None

    def lineage(self, ids: List[str]) -> List[Dict]:
        """All ancestors still in memory (plus stubs for evicted ones). Raises LineageCycle on a cycle."""
        out: Dict[str, Dict] = {}
        with self._lock:
            def walk(i: str, path: frozenset) -> None:
                if i in path:
                    raise LineageCycle(i)
                if i in out:
                    return
                s = self.get(i)
                if s is None:
                    t = self.trust_of(i)
                    if t is not None:        # evicted from the 50-step window: trust retained, text is not
                        out[i] = {"id": i, "label": t, "tainted": t != TRUSTED, "parents": [], "evicted": True}
                    return
                out[i] = s
                for p in s["parents"]:
                    walk(p, path | {i})
            for i in ids:
                walk(str(i), frozenset())
        return list(out.values())

    def all_steps(self) -> List[Dict]:
        with self._lock:
            return list(self._mem)

    def reset(self) -> None:
        with self._lock:
            self._mem.clear()
            self._index.clear()


_default = ProvenanceStore()


def default_store() -> ProvenanceStore:
    return _default


def add_step(source: str, label: str, text: str, parents: Optional[List[str]] = None) -> Dict:
    return _default.add_step(source, label, text, parents)


def get(step_id: str) -> Optional[Dict]:
    return _default.get(step_id)


def lineage(ids: List[str]) -> List[Dict]:
    return _default.lineage(ids)


def all_steps() -> List[Dict]:
    return _default.all_steps()


def reset() -> None:
    _default.reset()
