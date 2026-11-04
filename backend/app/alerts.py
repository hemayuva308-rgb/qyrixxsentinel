"""Security alerting (v1.4). Every structured security event passes through observe(); rules turn them into alerts.

* IMMEDIATE rules: things that must never happen silently (tenant-isolation violation, over-privileged DB account,
  data-integrity / proof-chain failure, rate-limit store outage, MFA reset).
* THRESHOLD rules: per tenant (or global) counts in a sliding 5-minute window (repeated execution blocks, refused
  executions = replay/forgery attempts, authentication / login / MFA failure spikes, throttling).
An alert is emitted at most once per (rule, tenant) per window (no alert storms).

Delivery: always as a JSON `alert` event on stdout + `qyrix_alerts_total{name,severity}` (scraped by Prometheus, see
ops/prometheus/qyrix-alerts.yml). Optionally to an operator webhook (QYRIX_ALERT_WEBHOOK_URL), HMAC-SHA256 signed with
QYRIX_ALERT_WEBHOOK_SECRET_FILE, from a bounded background queue so a slow receiver never blocks a request.
Payloads contain only rule names, severities, counts, tenant ids and reasons - never request data, destinations,
identities' secrets or customer payloads.
"""
import hashlib
import hmac
import json
import os
import queue
import threading
import time
from collections import defaultdict, deque
from typing import Dict, Optional

from app import observability as obs

WINDOW = 300.0

IMMEDIATE = {
    "tenant_isolation_violation": "critical",
    "db_privilege_violation": "critical",
    "data_integrity_failure": "critical",
    "proof_integrity_failure": "critical",
    "rate_limit_backend_unavailable": "critical",
    "mfa_reset": "high",
    "persistence_unavailable": "high",
    "recovery_code_used": "medium",
    "state_witness_disabled": "high",
    "evidence_reset": "medium",
    "enforcement_bypass_detected": "critical",   # v1.5 CEV: a BLOCKED action was executed / execution without a grant
}


def _thr(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _threshold_rules():
    # (event kind, predicate on fields, alert name, severity, env var, default count, per tenant?)
    return [
        ("gate_decision", lambda f: f.get("verdict") == "BLOCK", "repeated_execution_blocks", "high", "QYRIX_ALERT_BLOCKS_PER_5MIN", 20, True),
        ("execution_refused", lambda f: True, "repeated_execution_refusals", "high", "QYRIX_ALERT_REFUSALS_PER_5MIN", 10, True),
        ("auth_failure", lambda f: True, "auth_failure_spike", "high", "QYRIX_ALERT_AUTH_FAILURES_PER_5MIN", 50, False),
        ("login_failed", lambda f: True, "login_failure_spike", "high", "QYRIX_ALERT_LOGIN_FAILURES_PER_5MIN", 20, True),
        ("mfa_failed", lambda f: True, "mfa_failure_spike", "high", "QYRIX_ALERT_MFA_FAILURES_PER_5MIN", 10, True),
        ("login_throttled", lambda f: True, "login_throttling_active", "medium", "QYRIX_ALERT_THROTTLES_PER_5MIN", 5, False),
        ("auth_throttled", lambda f: True, "auth_throttling_active", "medium", "QYRIX_ALERT_THROTTLES_PER_5MIN", 5, False),
    ]


_lock = threading.Lock()
_hits: Dict[str, deque] = defaultdict(deque)
_last: Dict[str, float] = {}
_q: "queue.Queue" = queue.Queue(maxsize=1000)
_worker: Optional[threading.Thread] = None
recent: deque = deque(maxlen=200)                 # for tests / an admin view; contains alert payloads only


def observe(kind: str, fields: Dict) -> None:
    now = time.time()
    if kind in IMMEDIATE:
        _raise(kind, IMMEDIATE[kind], fields.get("tenant"), 1, {"reason": fields.get("reason"), "scope": fields.get("scope")}, now)
    for ev, pred, name, sev, env, default, per_tenant in _threshold_rules():
        if ev != kind or not pred(fields):
            continue
        key = name + "|" + (str(fields.get("tenant")) if per_tenant else "*")
        with _lock:
            q = _hits[key]
            q.append(now)
            while q and now - q[0] > WINDOW:
                q.popleft()
            n = len(q)
        if n >= _thr(env, default):
            _raise(name, sev, fields.get("tenant") if per_tenant else None, n, {}, now)


def _raise(name: str, severity: str, tenant, count: int, extra: Dict, now: float) -> None:
    key = name + "|" + str(tenant)
    with _lock:
        if now - _last.get(key, 0) < WINDOW:
            return                                # de-duplicated within the window
        _last[key] = now
    payload = {"alert": name, "severity": severity, "tenant": tenant, "count": count, "window_seconds": int(WINDOW),
               "at": round(now, 3), **{k: v for k, v in extra.items() if v is not None}}
    recent.append(payload)
    obs.inc("qyrix_alerts_total", alert=name, severity=severity)
    obs.event("alert", **payload)
    _dispatch(payload)


def _secret() -> bytes:
    p = os.getenv("QYRIX_ALERT_WEBHOOK_SECRET_FILE", "").strip()
    try:
        s = open(p, "rb").read().strip() if p else b""
    except OSError:
        return b""
    return s if len(s) >= 32 else b""


def _transport(url: str, body: bytes, headers: Dict[str, str]) -> int:
    import httpx
    return httpx.post(url, content=body, headers=headers, timeout=5.0).status_code


def _run():
    while True:
        payload = _q.get()
        url, key = os.getenv("QYRIX_ALERT_WEBHOOK_URL", "").strip(), _secret()
        if not url or not key:
            continue
        body = json.dumps(payload, sort_keys=True).encode()
        sig = hmac.new(key, body, hashlib.sha256).hexdigest()
        ok = False
        for attempt in range(3):
            try:
                ok = 200 <= _transport(url, body, {"content-type": "application/json", "x-qyrix-signature": sig}) < 300
            except Exception:
                ok = False
            if ok:
                break
            time.sleep(0.5 * (attempt + 1))
        obs.inc("qyrix_alert_deliveries_total", ok=str(ok).lower())


def _dispatch(payload: Dict) -> None:
    global _worker
    if not os.getenv("QYRIX_ALERT_WEBHOOK_URL", "").strip():
        return
    if _worker is None or not _worker.is_alive():
        _worker = threading.Thread(target=_run, name="qyrix-alerts", daemon=True)
        _worker.start()
    try:
        _q.put_nowait(payload)
    except queue.Full:
        obs.inc("qyrix_alert_deliveries_total", ok="dropped")


def reset_for_tests() -> None:
    with _lock:
        _hits.clear(); _last.clear()
    recent.clear()
