"""Continuous Enforcement Verification (CEV), v1.5.

A Gate decision says what SHOULD happen. CEV checks what DID happen, using evidence that does not come from the Gate or
from the integration that was told to enforce the decision:

  Decision ledger   the existing SHA-256 hash-linked proof chain; every decision carries a correlation_id.
  Execution observer  canary resources that record their own side effects:
                      * HTTP canary: a separate stdlib HTTP listener on 127.0.0.1 (its own thread and socket, never
                        routed through the API or the Gate); every request to /canary/<token> is recorded.
                      * File canary: a file per run in a dedicated directory; creation, modification and deletion are
                        detected by content/metadata snapshot. READS ARE NOT OBSERVABLE without OS hooks, so this
                        channel only claims writes/deletes.
  Reconciler        a pure, deterministic function from (decision, observations, telemetry health) to one of
                    ENFORCEMENT_VERIFIED, BYPASS_DETECTED, UNAUTHORIZED_EXECUTION, INCONCLUSIVE.
  Canaries          a must-block synthetic action (harmless payload, isolated canary resource) sent through an
                    integration adapter; the result is reconciled and written to the proof chain.

Safety rules (enforced below, tested in tests/test_cev.py):
  * Missing or unproven telemetry is NEVER reported as verified: the observer must pass a positive control in the same
    run (it must see a known side effect), and the observation window must have closed, otherwise INCONCLUSIVE.
  * An observed side effect is positive evidence and always wins over missing telemetry.
  * Observer and canaries only ever touch their own loopback listener and their own canary directory.
Scope note: in this release the observer runs in the backend process (separate thread/socket). That makes it independent
of the Gate's code path, not of the host; a fully independent deployment runs the observer as its own service.
"""
import hashlib
import os
import secrets
import tempfile
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

VERIFIED, BYPASS, UNAUTHORIZED, INCONCLUSIVE = ("ENFORCEMENT_VERIFIED", "BYPASS_DETECTED", "UNAUTHORIZED_EXECUTION",
                                                "INCONCLUSIVE")
RESULTS = (VERIFIED, BYPASS, UNAUTHORIZED, INCONCLUSIVE)
CHANNELS = ("http", "file")
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # loopback only: never via an egress proxy


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def window_seconds() -> float:
    try:
        return min(max(float(os.getenv("QYRIX_CEV_WINDOW_SECONDS", "0.5")), 0.05), 30.0)
    except ValueError:
        return 0.5


# ---------------- Execution observer: HTTP canary ----------------
class CanaryHttpObserver:
    """Loopback listener that records every request to /canary/<token>. Independent of FastAPI and the Gate."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self._hits: Dict[str, List[Dict]] = {}
        self._lock = threading.Lock()
        obs = self

        class H(BaseHTTPRequestHandler):
            def _hit(self):
                parts = self.path.split("?")[0].strip("/").split("/")
                if len(parts) == 2 and parts[0] == "canary" and 8 <= len(parts[1]) <= 64:
                    n = int(self.headers.get("content-length") or 0)
                    body = self.rfile.read(min(n, 4096)) if n > 0 else b""
                    with obs._lock:
                        obs._hits.setdefault(parts[1], []).append({
                            "channel": "http", "ts": _now(), "method": self.command, "path": "/canary/" + parts[1],
                            "body_sha256": hashlib.sha256(body).hexdigest()})
                    self.send_response(204)
                else:
                    self.send_response(404)
                self.end_headers()

            do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _hit

            def log_message(self, *a):          # no request logging (payloads are synthetic, but keep logs clean)
                pass

        self._srv = ThreadingHTTPServer((host, port), H)
        self._srv.daemon_threads = True
        self.host, self.port = self._srv.server_address[0], self._srv.server_address[1]
        self._t = threading.Thread(target=self._srv.serve_forever, name="qyrix-cev-http-observer", daemon=True)
        self._t.start()

    def url_for(self, token: str) -> str:
        return "http://%s:%d/canary/%s" % (self.host, self.port, token)

    def is_canary_url(self, url: str) -> bool:
        return url.startswith("http://%s:%d/canary/" % (self.host, self.port))

    def hits(self, token: str) -> List[Dict]:
        with self._lock:
            return list(self._hits.get(token, []))

    def forget(self, token: str) -> None:
        with self._lock:
            self._hits.pop(token, None)

    def alive(self) -> bool:
        return self._t.is_alive()

    def close(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()


# ---------------- Execution observer: file canary ----------------
class CanaryFileObserver:
    """Detects creation/modification/deletion of per-run canary files (reads are NOT observable)."""

    def __init__(self, directory: Optional[str] = None):
        self.dir = os.path.realpath(directory or os.getenv("QYRIX_CEV_CANARY_DIR") or tempfile.mkdtemp(prefix="qyrix-cev-"))
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        self._snap: Dict[str, Optional[tuple]] = {}

    def path_for(self, token: str) -> str:
        return os.path.join(self.dir, token + ".canary")

    def is_canary_path(self, path: str) -> bool:
        return os.path.realpath(path).startswith(self.dir + os.sep) and path.endswith(".canary")

    def _state(self, token: str) -> Optional[tuple]:
        p = self.path_for(token)
        try:
            st = os.stat(p)
            with open(p, "rb") as f:
                return (hashlib.sha256(f.read(65536)).hexdigest(), st.st_size, st.st_mtime_ns)
        except FileNotFoundError:
            return None

    def arm(self, token: str) -> None:
        with open(self.path_for(token), "w") as f:
            f.write("QYRIX CANARY %s (synthetic, harmless)\n" % token)
        self._snap[token] = self._state(token)

    def events(self, token: str) -> List[Dict]:
        if token not in self._snap:
            return []
        before, after = self._snap[token], self._state(token)
        if before == after:
            return []
        kind = "deleted" if after is None else "created" if before is None else "modified"
        return [{"channel": "file", "ts": _now(), "change": kind, "path": os.path.basename(self.path_for(token)),
                 "sha256_after": after[0] if after else None}]

    def disarm(self, token: str) -> None:
        self._snap.pop(token, None)
        try:
            os.remove(self.path_for(token))
        except FileNotFoundError:
            pass


_obs_lock = threading.Lock()
_http: Optional[CanaryHttpObserver] = None
_file: Optional[CanaryFileObserver] = None


def observers():
    """Process-wide observers, started lazily (the HTTP listener binds an ephemeral loopback port unless configured)."""
    global _http, _file
    with _obs_lock:
        if _http is None or not _http.alive():
            _http = CanaryHttpObserver("127.0.0.1", int(os.getenv("QYRIX_CEV_CANARY_PORT", "0") or 0))
        if _file is None:
            _file = CanaryFileObserver()
        return _http, _file


def positive_control(channel: str) -> bool:
    """Prove the observer can see a side effect RIGHT NOW. Without this, 'no event' would mean nothing."""
    http, fobs = observers()
    tok = "ctl" + secrets.token_hex(12)
    try:
        if channel == "http":
            _NO_PROXY.open(urllib.request.Request(http.url_for(tok), method="GET"), timeout=2).close()
            ok = len(http.hits(tok)) == 1
            http.forget(tok)
            return ok
        if channel == "file":
            fobs.arm(tok)
            with open(fobs.path_for(tok), "a") as f:
                f.write("control\n")
            ok = len(fobs.events(tok)) == 1
            fobs.disarm(tok)
            return ok
    except Exception:
        return False
    return False


def collect(channel: str, token: str) -> List[Dict]:
    http, fobs = observers()
    return http.hits(token) if channel == "http" else fobs.events(token)


# ---------------- Reconciler (pure, deterministic) ----------------
def reconcile(decision: Optional[Dict], observations: List[Dict], telemetry: Dict, delegated: bool = False) -> Dict:
    """decision: {"verdict": "ALLOW"|"BLOCK", ...} or None (no decision found for this correlation id).
    observations: side effects recorded by the observer for this correlation id.
    telemetry: {"armed": bool, "positive_control": bool, "window_closed": bool}.
    delegated: True when the grant for an ALLOW decision was consumed through Sentinel (execute or redeem).
    Missing/unproven telemetry never yields ENFORCEMENT_VERIFIED; an observed side effect always counts."""
    seen = bool(observations)
    telemetry_ok = bool(telemetry.get("armed") and telemetry.get("positive_control") and telemetry.get("window_closed"))
    verdict = (decision or {}).get("verdict")
    if verdict not in ("ALLOW", "BLOCK"):
        if seen:
            return {"result": UNAUTHORIZED, "reasons": ["SIDE_EFFECT_WITHOUT_DECISION"]}
        return {"result": INCONCLUSIVE, "reasons": ["NO_DECISION_RECORDED"]}
    if verdict == "BLOCK":
        if seen:
            return {"result": BYPASS, "reasons": ["BLOCKED_ACTION_WAS_EXECUTED"]}
        if not telemetry_ok:
            return {"result": INCONCLUSIVE, "reasons": _telemetry_reasons(telemetry)}
        return {"result": VERIFIED, "reasons": ["BLOCK_HELD_NO_SIDE_EFFECT_OBSERVED"]}
    if seen:
        if delegated:
            return {"result": VERIFIED, "reasons": ["ALLOWED_ACTION_EXECUTED_THROUGH_GRANT"]}
        return {"result": UNAUTHORIZED, "reasons": ["EXECUTED_WITHOUT_CONSUMING_GRANT"]}
    return {"result": INCONCLUSIVE, "reasons": ["ALLOWED_ACTION_NOT_OBSERVED"] + ([] if telemetry_ok else _telemetry_reasons(telemetry))}


def _telemetry_reasons(t: Dict) -> List[str]:
    out = []
    if not t.get("armed"):
        out.append("OBSERVER_NOT_ARMED")
    if not t.get("positive_control"):
        out.append("OBSERVER_POSITIVE_CONTROL_FAILED")
    if not t.get("window_closed"):
        out.append("OBSERVATION_WINDOW_OPEN")
    return out or ["TELEMETRY_UNAVAILABLE"]


# ---------------- Canary runs ----------------
def canary_action(channel: str, correlation_id: str, token: str):
    """A must-block, harmless action aimed at an isolated canary resource. Blocked by the CURRENT deterministic policy:
    http -> loopback destination (R9 SSRF); file -> 'file.write' is not an executable tool (R8)."""
    from app import gateway as g
    http, fobs = observers()
    if channel == "http":
        return g.Action(tool="http", method="POST", dest=http.url_for(token), data="qyrix-canary=" + correlation_id,
                        correlation_id=correlation_id)
    return g.Action(tool="file.write", method="PUT", dest=fobs.path_for(token), data="qyrix-canary=" + correlation_id,
                    correlation_id=correlation_id)


def run_canary(ctx, adapter, channel: str = "http") -> Dict:
    """Send one must-block canary through `adapter` (see app/integrations.py), observe, reconcile, prove, alert."""
    from app import gateway as g, observability as obs
    if channel not in CHANNELS:
        raise ValueError("unknown channel")
    corr = "cev_" + uuid.uuid4().hex
    token = secrets.token_hex(16)
    started = time.time()
    http, fobs = observers()
    control = positive_control(channel)
    if channel == "file":
        fobs.arm(token)
    armed = True
    action = canary_action(channel, corr, token)
    outcome: Dict = {}
    try:
        outcome = adapter.submit(action, ctx) or {}
    except Exception as e:                                   # an adapter crash is reported, never treated as enforcement
        outcome = {"decision": None, "error": type(e).__name__}
    deadline = started + window_seconds()
    while time.time() < deadline:
        time.sleep(0.02)
    events = collect(channel, token)
    if channel == "file":
        fobs.disarm(token)
    else:
        http.forget(token)
    decision = outcome.get("decision")
    telemetry = {"armed": armed, "positive_control": control, "window_closed": True}
    rec = reconcile(decision, events, telemetry, delegated=bool(outcome.get("delegated")))
    entry = {
        "kind": "cev_reconciliation", "correlation_id": corr, "adapter": adapter.id, "adapter_label": adapter.label,
        "test_fixture": bool(getattr(adapter, "test_fixture", False)), "channel": channel, "expected": "BLOCK",
        "decision_verdict": (decision or {}).get("verdict"), "decision_rules": (decision or {}).get("rules"),
        "gate_evaluation_id": (decision or {}).get("gate_evaluation_id"),
        "decision_proof_hash": ((decision or {}).get("proof") or {}).get("hash"),
        "adapter_reported_forwarded": outcome.get("forwarded"),   # self-report: shown, never trusted
        "observed": [{"channel": e["channel"], "ts": e["ts"], "evidence": e.get("body_sha256") or e.get("sha256_after") or e.get("change")} for e in events],
        "telemetry": telemetry, "window_ms": int(window_seconds() * 1000),
        "result": rec["result"], "reasons": rec["reasons"]}
    with ctx.lock:
        proof_rec = g._record(ctx, entry)
    obs.inc("qyrix_cev_results_total", adapter=adapter.id, channel=channel, result=rec["result"])
    tenant = getattr(ctx.db, "t", None) or ctx.name
    if rec["result"] in (BYPASS, UNAUTHORIZED):
        obs.event("enforcement_bypass_detected", severity="critical", tenant=tenant, reason=rec["result"],
                  scope=adapter.id, correlation=corr)
    elif rec["result"] == INCONCLUSIVE:
        obs.event("enforcement_inconclusive", severity="warning", tenant=tenant, reason=",".join(rec["reasons"]),
                  scope=adapter.id, correlation=corr)
    return {**entry, "proof": {"seq": proof_rec["n"], "hash": proof_rec["hash"]}, "observed_at": _now(),
            "duration_ms": int((time.time() - started) * 1000)}


def results(ctx, limit: int = 100) -> List[Dict]:
    """Reconciliation results read back from the proof chain (durable evidence, not an in-memory cache)."""
    with ctx.lock:
        recs = [r for r in ctx.chain if r.get("kind") == "cev_reconciliation"]
    return [dict(r) for r in recs[-limit:]][::-1]


def conformance(ctx) -> Dict[str, Dict]:
    out: Dict[str, Dict] = {}
    for r in results(ctx, limit=10000):
        a = out.setdefault(r.get("adapter"), {"runs": 0, **{k: 0 for k in RESULTS}})
        a["runs"] += 1
        a[r.get("result")] = a.get(r.get("result"), 0) + 1
    for a in out.values():
        decided = a["runs"] - a[INCONCLUSIVE]
        a["conformance_rate"] = round(100.0 * a[VERIFIED] / decided, 1) if decided else None   # None, never 100%
    return out


# ---------------- Periodic canaries (opt-in) ----------------
_sched: Optional[threading.Thread] = None


def start_scheduler(ctx_fn, adapters_fn) -> bool:
    """QYRIX_CEV_CANARY_INTERVAL_SECONDS > 0 runs every adapter in QYRIX_CEV_CANARY_ADAPTERS on both channels."""
    global _sched
    try:
        every = float(os.getenv("QYRIX_CEV_CANARY_INTERVAL_SECONDS", "0"))
    except ValueError:
        every = 0
    if every <= 0 or (_sched and _sched.is_alive()):
        return False
    every = max(every, 10.0)

    def loop():
        while True:
            time.sleep(every)
            try:
                ctx = ctx_fn()
                for ad in adapters_fn():
                    for ch in CHANNELS:
                        run_canary(ctx, ad, ch)
            except Exception as e:                           # never silent: a failed canary run is itself an alert
                from app import observability as obs
                obs.event("enforcement_inconclusive", severity="warning", reason="CANARY_RUN_FAILED", error_class=type(e).__name__)

    _sched = threading.Thread(target=loop, name="qyrix-cev-canaries", daemon=True)
    _sched.start()
    return True
