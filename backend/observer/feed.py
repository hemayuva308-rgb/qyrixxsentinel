"""Watermarks, feed conditions and window closure (design §5.3-§5.6). PURE functions: no I/O, observer clock passed in.

Heartbeats and sequence numbers are signed producer CLAIMS (E0). They only decide WHEN something may be concluded;
nothing in this module can make a result ENFORCEMENT_VERIFIED. Window closure is a necessary precondition that C4's
reconciler will add to (§11); in C1-C2 no sensor exists, so condition 3 can never hold and every window ends
NOT_CLOSABLE (=> INCONCLUSIVE), by construction."""
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass(frozen=True)
class Config:
    H: float = 10.0          # heartbeat interval
    G: float = 30.0          # grace
    W: float = 2.0           # observation window (canaries)
    T_decision: float = 10.0
    S: float = 120.0         # max clock skew

    @property
    def silent_after(self) -> float:
        return 3 * self.H


def advance(contiguous: int, received: Iterable[int]) -> int:
    """Highest n such that every seq 1..n has been received (given the current contiguous watermark)."""
    have = set(received)
    while contiguous + 1 in have:
        contiguous += 1
    return contiguous


def feed_conditions(now: float, stream: Dict, wms: List[Dict], cfg: Config) -> List[str]:
    """Conditions that make every dependent window INCONCLUSIVE. stream: {status, last_hb_received_at (epoch s|None)};
    wm: {tenant_id, contiguous_seq, max_seq, attested_seq, gap_since, behind_since} (times in epoch seconds|None)."""
    out = []
    if stream.get("status") == "quarantined":
        out.append("PRODUCER_REGRESSION")
    elif stream.get("status") == "closed":
        out.append("EPOCH_CLOSED")
    last = stream.get("last_hb_received_at")
    if last is None or now - last > cfg.silent_after:
        out.append("PRODUCER_SILENT")
    for w in wms:
        if w.get("gap_since") is not None and now - w["gap_since"] > cfg.G:
            out.append("DECISION_FEED_GAP:%s" % w["tenant_id"])
        if w.get("behind_since") is not None and now - w["behind_since"] > cfg.G:
            out.append("DECISION_FEED_GAP_TAIL:%s" % w["tenant_id"])
    return out


@dataclass
class Window:
    t0: float                         # observer time the window opened
    tenant: str
    channel: str = "http"


@dataclass
class Closure:
    state: str                        # OPEN | CLOSED | NOT_CLOSABLE
    reasons: List[str] = field(default_factory=list)


def window_closure(win: Window, now: float, cfg: Config, stream: Dict, wm: Optional[Dict],
                   heartbeats: List[Dict], sensors: Optional[Dict] = None, open_tunnels: int = 0) -> Closure:
    """§5.6. heartbeats: accepted ones for the stream, each {issued_at, received_at, tenants: {t: allocated_through_seq}}.
    sensors: {channel: {"healthy": bool, "positive_control_at": float|None}} - None in C1-C2 (no sensors exist).
    A window is CLOSED only if ALL conditions hold; otherwise OPEN until t0+W+G, then NOT_CLOSABLE."""
    reasons: List[str] = []
    end = win.t0 + cfg.W
    if now <= end:
        reasons.append("WINDOW_STILL_RUNNING")
    if stream.get("status") != "active":
        reasons.append("STREAM_NOT_ACTIVE")
    # 2. a heartbeat issued AND received after t0+W, whose claimed allocation the contiguous watermark has reached
    hb_ok = False
    for hb in heartbeats:
        if hb["issued_at"] > end and hb["received_at"] > end:
            alloc = hb.get("tenants", {}).get(win.tenant)
            if alloc is not None and wm is not None and wm["contiguous_seq"] >= alloc:
                hb_ok = True
                break
    if not hb_ok:
        reasons.append("NO_CLOSING_HEARTBEAT")
    # 3. healthy sensors with a positive control inside [t0, t0+W]
    s = (sensors or {}).get(win.channel)
    if not s:
        reasons.append("SENSORS_NOT_AVAILABLE")
    elif not s.get("healthy") or s.get("positive_control_at") is None or not (win.t0 <= s["positive_control_at"] <= end):
        reasons.append("POSITIVE_CONTROL_MISSING")
    # 4. no relevant tunnel still open
    if open_tunnels:
        reasons.append("TUNNEL_STILL_OPEN")
    if not reasons:
        return Closure("CLOSED")
    if now > end + cfg.G:
        return Closure("NOT_CLOSABLE", ["WINDOW_NOT_CLOSABLE"] + reasons)
    return Closure("OPEN", reasons)
