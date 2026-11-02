"""Metrics (Prometheus text format) and structured security events (JSON lines on stdout).

Rules: events never carry credentials, session tokens, request data, destinations or provenance text - only ids,
verdicts, rule ids, roles and tenant ids. Metrics are process-local counters (one backend process per database is the
supported deployment; a multi-replica deployment must scrape every replica).
"""
import json
import logging
import re
import sys
import threading
import time
from collections import defaultdict
from typing import Dict, Tuple

_lock = threading.Lock()
_counters: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = defaultdict(float)
_HELP = {
    "qyrix_gate_decisions_total": "Gate decisions by tenant and verdict",
    "qyrix_gate_rule_hits_total": "Rule ids that caused a BLOCK",
    "qyrix_executions_total": "Controlled executions by tenant and outcome",
    "qyrix_auth_failures_total": "Rejected authentication attempts by reason",
    "qyrix_rate_limited_total": "Requests refused by a rate limit",
    "qyrix_sessions_total": "Session lifecycle events",
    "qyrix_persistence_down_total": "Transitions of a tenant context to persistence=down",
    "qyrix_anchor_attempts_total": "RFC 3161 anchoring attempts by outcome",
    "qyrix_alerts_total": "Alerts raised by name and severity",
    "qyrix_integrity_failures_total": "Data-loss / integrity detections by reason",
    "qyrix_tenant_isolation_violations_total": "Row-level-security violations observed (never expected)",
    "qyrix_db_privilege_violations_total": "Startup refusals because the runtime DB account was over-privileged",
    "qyrix_login_failures_total": "Human login failures by reason",
    "qyrix_mfa_failures_total": "MFA failures by reason",
    "qyrix_rate_limit_denials_total": "Requests denied by the shared limiter by scope",
    "qyrix_rate_limit_backend_errors_total": "Shared rate-limit store errors by scope",
}
_FORBIDDEN = {"token", "credential", "password", "secret", "data", "dest", "text", "authorization", "session_token", "key",
              "code", "recovery_code", "otp", "totp", "email", "challenge", "cookie"}
# defence in depth: even an allowed field never carries something that LOOKS like a credential
_SCRUB = re.compile(r"(q(sk|ss|si|pr|ch)_[A-Za-z0-9_\-]{8,}|AGE-SECRET-KEY-[A-Z0-9]+|(?i:bearer)\s+[A-Za-z0-9._\-]{8,}|"
                    r"sk-[A-Za-z0-9_\-]{8,}|(?i:password|passwd|secret|api[_-]?key)\s*[=:]\s*\S+)")


def _clean(v):
    if isinstance(v, str):
        return _SCRUB.sub("[REDACTED]", v)[:500]
    if isinstance(v, (list, tuple)):
        return [_clean(x) for x in v][:50]
    if isinstance(v, dict):
        return {k: _clean(x) for k, x in v.items() if str(k).lower() not in _FORBIDDEN}
    return v

_log = logging.getLogger("qyrix.security")
if not _log.handlers:
    _h = logging.StreamHandler(sys.stdout)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(_h)
    _log.setLevel(logging.INFO)
    _log.propagate = False


def inc(name: str, value: float = 1.0, **labels: str) -> None:
    key = (name, tuple(sorted((k, str(v)) for k, v in labels.items())))
    with _lock:
        _counters[key] += value


def event(kind: str, **fields) -> None:
    """Structured security event. Fields that could carry secrets are dropped by name, never logged."""
    safe = {k: _clean(v) for k, v in fields.items() if k.lower() not in _FORBIDDEN}
    _log.info(json.dumps({"ts": round(time.time(), 3), "event": kind, **safe}, default=str, separators=(",", ":")))
    if kind != "alert":
        try:
            from app import alerts
            alerts.observe(kind, safe)
        except Exception:                         # alerting must never break the request path (the event is logged above)
            inc("qyrix_alert_engine_errors_total")    # ... but a broken alert engine must be visible, not silent


def snapshot() -> Dict[str, float]:
    with _lock:
        return {name + ("{" + ",".join('%s="%s"' % kv for kv in labels) + "}" if labels else ""): v
                for (name, labels), v in _counters.items()}


def render(gauges: Dict[str, float]) -> str:
    lines = []
    with _lock:
        items = sorted(_counters.items())
    seen = set()
    for (name, labels), v in items:
        if name not in seen:
            seen.add(name)
            lines += ["# HELP %s %s" % (name, _HELP.get(name, name)), "# TYPE %s counter" % name]
        lab = "{" + ",".join('%s="%s"' % (k, str(val).replace('"', "")) for k, val in labels) + "}" if labels else ""
        lines.append("%s%s %s" % (name, lab, v))
    for name, v in sorted(gauges.items()):
        base = name.split("{")[0]
        if base not in seen:
            seen.add(base)
            lines += ["# TYPE %s gauge" % base]
        lines.append("%s %s" % (name, v))
    return "\n".join(lines) + "\n"


def reset_for_tests() -> None:
    with _lock:
        _counters.clear()
