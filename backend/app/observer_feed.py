"""Backend side of the Observer feed (Phase C2; design §4, §5.1-§5.3, §10, §12).

Everything produced here is a PRODUCER CLAIM signed with the GATE key (E0) - or, for the MCP proxy, an adapter
self-report (E1). Nothing here is evidence of enforcement, and nothing here takes part in authorization: the Gate's
verdicts, rules (R0-R20), grant binding and atomic consumption are unchanged. The only coupling is deliberate and
fail closed (§10): when the feed is ENABLED, the outbox row is written in the same database transaction as the
decision / grant consumption, so if that write fails the decision is not recorded and the Gate blocks (R17).

  QYRIX_OBSERVER_URL            enables the feed (unset => nothing is written, publisher not started)
  QYRIX_OBSERVER_GATE_KEY_FILE  GATE signing key (Ed25519 PEM; scope decision|grant|heartbeat in the observer manifest)
  QYRIX_OBSERVER_HEARTBEAT_SECONDS (default 10)

Memory mode (no PostgreSQL) is unsupported: no outbox exists, so nothing is emitted (colocated CEV stays as before).
"""
import json
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

SCHEMA = "qyrix.event/v1"
_lock = threading.Lock()
_producer_cache: Dict[str, str] = {}
_status: Dict[str, Any] = {"state": "disabled"}


def canonical(o: Any) -> bytes:
    """Byte-identical with observer/canonical.py (enforced by tests/test_observer_unit.py)."""
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def observer_client(base_url: Optional[str] = None, timeout: float = 5.0):
    """httpx client to the observer (audit F2). https:// => pinned CA (QYRIX_OBSERVER_CA_FILE) + client certificate
    (QYRIX_OBSERVER_CLIENT_CERT_FILE / _KEY_FILE): mutual TLS. Plain http:// is refused unless the host is loopback.
    Raises RuntimeError on any misconfiguration (callers fail closed: nothing is sent)."""
    import ipaddress
    import ssl
    from urllib.parse import urlsplit
    import httpx
    url = (base_url or os.getenv("QYRIX_OBSERVER_URL", "")).strip().rstrip("/")
    p = urlsplit(url)
    host = p.hostname or ""
    try:
        is_lo = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_lo = host == "localhost"
    if p.scheme == "http":
        if not is_lo:
            raise RuntimeError("plain HTTP to a non-loopback observer is refused (use https:// with mTLS)")
        return httpx.Client(base_url=url, timeout=timeout, trust_env=False)
    if p.scheme != "https":
        raise RuntimeError("QYRIX_OBSERVER_URL must be https:// (or http:// on loopback)")
    ca, cert, key = (os.getenv("QYRIX_OBSERVER_CA_FILE", ""), os.getenv("QYRIX_OBSERVER_CLIENT_CERT_FILE", ""),
                     os.getenv("QYRIX_OBSERVER_CLIENT_KEY_FILE", ""))
    if not (ca and cert and key):
        raise RuntimeError("mTLS to the observer needs QYRIX_OBSERVER_CA_FILE, _CLIENT_CERT_FILE and _CLIENT_KEY_FILE")
    ctx = ssl.create_default_context(cafile=ca)       # verifies the observer's certificate and hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return httpx.Client(base_url=url, timeout=timeout, trust_env=False, verify=ctx)


def enabled() -> bool:
    return bool(os.getenv("QYRIX_OBSERVER_URL", "").strip())


def heartbeat_seconds() -> float:
    try:
        return max(1.0, float(os.getenv("QYRIX_OBSERVER_HEARTBEAT_SECONDS", "10")))
    except ValueError:
        return 10.0


def iso(t) -> str:
    if isinstance(t, (int, float)):
        t = datetime.fromtimestamp(t, timezone.utc)
    return t.astimezone(timezone.utc).isoformat()


# ---------------- keys ----------------
def load_key(path: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    try:
        with open(path, "rb") as f:
            k = serialization.load_pem_private_key(f.read(), password=None)
    except Exception:
        raise RuntimeError("observer signing key not readable") from None      # never echo key material
    if not isinstance(k, Ed25519PrivateKey):
        raise RuntimeError("observer signing key is not Ed25519")
    return k


def key_id(k) -> str:
    import hashlib
    from cryptography.hazmat.primitives import serialization
    raw = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:32]


def sign_envelope(env: Dict, key) -> Dict:
    import base64
    env = dict(env, key_id=key_id(key))
    env.pop("sig", None)
    env["sig"] = base64.b64encode(key.sign(canonical(env))).decode("ascii")
    return env


def envelope(producer_id: str, type_: str, body: Dict, tenant: Optional[str], epoch: int, seq: Optional[int] = None,
             hb_seq: Optional[int] = None, issued_at: Optional[str] = None, event_id: Optional[str] = None) -> Dict:
    return {"schema": SCHEMA, "event_id": event_id or str(uuid.uuid4()), "producer_id": producer_id, "key_id": "",
            "epoch": epoch, "seq": seq, "hb_seq": hb_seq, "issued_at": issued_at or iso(time.time()), "tenant": tenant,
            "type": type_, "body": body}


# ---------------- producer identity (§5.1) ----------------
def producer_id(db) -> str:
    """gate:<installation.install_id> - the insert-once installation identity (app/integrity.py), stable across
    restarts and shared by every tenant of this installation. No identity => raise (=> the write fails closed)."""
    with _lock:
        pid = _producer_cache.get(db.dsn)
    if pid:
        return pid
    iid = db.install_id()
    if not iid:
        raise RuntimeError("installation identity missing: observer feed cannot name its producer")
    pid = "gate:" + str(uuid.UUID(iid))
    with _lock:
        _producer_cache[db.dsn] = pid
    return pid


# ---------------- event bodies (§12). No raw parameters, data, paths or secrets: digests, ids and A-label hosts. ----
def decision_events(ctx, ev: Dict, grant: Optional[Dict] = None, proof: Optional[Dict] = None) -> List[Dict]:
    """Outbox events for one Gate evaluation (+ the grant it issued). [] when the feed is disabled or memory mode.
    `proof` is the decision's proof record when it already exists (BLOCK path); for ALLOW the evaluation is persisted
    BEFORE its proof record (unchanged Gate order), so proof is null and the heartbeat's proof head covers it."""
    if not enabled() or ctx.db is None:
        return []
    pid = producer_id(ctx.db)
    p = ev.get("params") or {}
    out = [{"producer_id": pid, "type": "decision", "event_id": str(uuid.uuid4()), "body": {
        "gate_evaluation_id": ev["id"], "correlation_id": ev.get("correlation_id"), "agent_id": ev.get("agent_id"),
        "task_id": ev.get("task_id"), "policy_version": ev.get("policy_version"), "verdict": ev["verdict"],
        "rule_ids": list(ev.get("rules") or []), "tool": p.get("tool"), "method": p.get("method"),
        "dest_host": ev.get("host"), "params_digest": ev.get("digest"),
        "proof": {"n": proof["n"], "hash": proof["hash"]} if proof else None}}]
    if grant is not None:
        out.append(grant_event(pid, ev["id"], grant, "issued"))
    return out


def grant_event(pid: str, eval_id: str, g: Dict, kind: str, integration: Optional[str] = None,
                refusal_code: Optional[str] = None) -> Dict:
    return {"producer_id": pid, "type": "grant", "event_id": str(uuid.uuid4()), "body": {
        "gate_evaluation_id": eval_id, "grant_id": g["id"], "execution_id": g.get("execution_id"), "kind": kind,
        "integration": integration, "refusal_code": refusal_code, "params_digest": g.get("digest"),
        "agent_id": g.get("agent_id"), "task_id": g.get("task_id"), "proof": None}}


def revocation_events(ctx, g: Dict, reason: str, reversed_ev: Optional[Dict] = None) -> List[Dict]:
    """C4 / audit F4: claims for a revoked grant (`grant` kind=revoked, refusal_code=<reason>) and, when the Gate reversed
    an ALLOW it had already written (proof write failed), a superseding decision claim with `reversed_from: ALLOW`.
    The reconciler never treats a reversed decision as a clean claim. [] when the feed is disabled / memory mode."""
    if not enabled() or ctx.db is None:
        return []
    pid = producer_id(ctx.db)
    out = []
    if reversed_ev is not None:
        d = decision_events(ctx, dict(reversed_ev, verdict="BLOCK", rules=["R0_FAIL_CLOSED"]))[0]
        d["body"]["reversed_from"] = "ALLOW"
        out.append(d)
    out.append(grant_event(pid, g["gate_evaluation_id"], g, "revoked", refusal_code=reason))
    return out


def consume_event(ctx, eval_id: str, g: Dict, kind: str, integration: Optional[str] = None) -> Optional[Dict]:
    if not enabled() or ctx.db is None:
        return None
    return grant_event(producer_id(ctx.db), eval_id, g, kind, integration)


def emit_refusal(ctx, eval_id: str, g: Optional[Dict], code: str, integration: Optional[str] = None) -> None:
    """Best effort, own transaction: a refusal is already safe (nothing executes). Only for grants that exist."""
    if not enabled() or ctx.db is None or g is None or ctx.state.get("persistence") != "postgres":
        return
    try:
        ctx.db.emit_event(grant_event(producer_id(ctx.db), eval_id, g, "refused", integration, code))
    except Exception:
        from app import observability as obs
        obs.inc("qyrix_observer_emit_failures_total", kind="grant_refused")


# ---------------- publisher (§5.3, §10) ----------------
RETRY_LATER = {"UNKNOWN_EPOCH", "OBSERVER_DB_UNAVAILABLE", "OBSERVER_KEY_INVALID", "LEDGER_INVALID", "RATE_LIMITED"}


class Publisher:
    """Sends unsent outbox rows in (tenant, seq) order and signed heartbeats. Exactly one active publisher per producer:
    it must hold the session advisory lock hash(producer_id) on its own connection; others stay on standby."""

    def __init__(self, db_factory: Callable[[str], Any], dsn: str, key, url: Optional[str] = None, http=None,
                 hb_seconds: Optional[float] = None, clock: Callable[[], float] = time.time):
        self.db_factory, self.dsn, self.key, self.clock = db_factory, dsn, key, clock
        self.url = (url or os.getenv("QYRIX_OBSERVER_URL", "")).rstrip("/")
        self.hb_seconds = hb_seconds or heartbeat_seconds()
        if http is None:
            http = observer_client(self.url)             # F2: mTLS (or loopback http); misconfig => raise
        self.http = http
        self._lock_conn = None
        self.backoff, self.next_try, self.last_hb = 0.0, 0.0, 0.0
        self.stats = {"state": "standby", "sent": 0, "duplicates": 0, "refused": 0, "heartbeats": 0, "last_error": None,
                      "outbox_depth": None, "stale_epoch_unsent": 0}
        self.root = db_factory("default")
        self.producer = None

    # -- single active publisher
    def acquire(self) -> bool:
        if self._lock_conn is not None:
            return True
        import psycopg
        self.producer = self.producer or producer_id(self.root)
        c = psycopg.connect(self.dsn, autocommit=True, connect_timeout=5)
        got = c.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))", ("qyrix-observer-publisher:" + self.producer,)).fetchone()[0]
        if not got:
            c.close()
            self.stats["state"] = "standby"
            return False
        self._lock_conn = c
        self.stats["state"] = "active"
        return True

    def release(self) -> None:
        if self._lock_conn is not None:
            try:
                self._lock_conn.close()                       # session end releases the advisory lock
            finally:
                self._lock_conn = None
                self.stats["state"] = "standby"

    def _post(self, env: Dict):
        try:
            r = self.http.post("/v1/events", content=canonical(env), headers={"Content-Type": "application/json"})
        except Exception as e:
            return None, "OBSERVER_UNREACHABLE:" + type(e).__name__
        try:
            j = r.json()
        except ValueError:
            j = {}
        return r.status_code, (j.get("error") or j.get("status") or "")

    def _fail(self, code: str) -> None:
        self.stats["last_error"] = code
        self.backoff = min(60.0, max(1.0, self.backoff * 2 or 1.0))
        self.next_try = self.clock() + self.backoff

    def publish_once(self) -> Dict:
        """One pass over all tenants. Stops a tenant at its first undelivered row: order is never skipped."""
        if not self.acquire():
            return self.stats
        feed = self.root.observer_feed(self.producer)
        self.stats["outbox_depth"] = sum(f["unsent"] for f in feed)
        self.stats["stale_epoch_unsent"] = sum(f["stale_unsent"] for f in feed)
        from app import observability as obs
        delivered = 0
        for f in feed:
            if not f["unsent"]:
                continue
            db = self.db_factory(f["tenant"])
            for row in db.outbox_unsent(f["epoch"]):
                env = sign_envelope(envelope(row["producer_id"], row["type"], row["body"], f["tenant"], f["epoch"],
                                             seq=row["seq"], issued_at=iso(row["created_at"]), event_id=row["event_id"]),
                                    self.key)
                status, code = self._post(env)
                if status == 200:
                    db.outbox_mark(f["epoch"], row["seq"], True)
                    self.stats["duplicates" if code == "duplicate" else "sent"] += 1
                    self.backoff = 0.0
                    delivered += 1
                    continue
                db.outbox_mark(f["epoch"], row["seq"], False)
                if status is None or status >= 500 or code in RETRY_LATER:
                    self._fail(code or "HTTP_%s" % status)
                else:                                      # refused for cause: a security condition, never skipped
                    self.stats["refused"] += 1
                    self._fail(code or "HTTP_%s" % status)
                    obs.event("observer_feed_refused", severity="critical", code=code or str(status), tenant=f["tenant"])
                break
        if delivered:
            # audit F13: attest the new allocation immediately (not only on the H timer), shrinking the window in which
            # allocated-but-unattested numbers could vanish in a restore without any regression signal
            self.heartbeat_once()
        return self.stats

    def heartbeat_once(self) -> Optional[str]:
        if not self.acquire():
            return None
        epoch, hb_seq = self.root.observer_next_hb(self.producer)
        feed = self.root.observer_feed(self.producer)
        tenants = {}
        for f in feed:
            n, h = self.db_factory(f["tenant"]).proof_head()
            tenants[f["tenant"]] = {"allocated_through_seq": f["allocated"], "proof_n": n, "proof_head": h}
        now = self.clock()
        cid = os.getenv("HOSTNAME", "")
        cid = cid if 12 <= len(cid) <= 64 and all(c in "0123456789abcdef" for c in cid) else None
        env = sign_envelope(envelope(self.producer, "heartbeat", {
            "gate_clock": iso(now), "outbox_depth": sum(f["unsent"] for f in feed), "tenants": tenants,
            "container_id": cid},                        # C5: a CLAIM; the observer uses it only to invalidate coverage
            None, epoch, hb_seq=hb_seq, issued_at=iso(now)), self.key)
        status, code = self._post(env)
        self.last_hb = now
        if status == 200:
            self.stats["heartbeats"] += 1
        else:
            self.stats["last_error"] = code or "HTTP_%s" % status
        return code

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                if not self.acquire():
                    stop.wait(self.hb_seconds)
                    continue
                now = self.clock()
                if now - self.last_hb >= self.hb_seconds:
                    self.heartbeat_once()
                if now >= self.next_try:
                    self.publish_once()
            except Exception as e:                          # DB / network trouble: visible in status, retried
                self.stats["last_error"] = "PUBLISHER_ERROR:" + type(e).__name__
                self.release()
            stop.wait(1.0)


_publisher: Dict[str, Any] = {}


def start(ctx_getter: Callable[[], Any]) -> Optional[threading.Event]:
    """Start the publisher thread (only when enabled and in durable mode). Returns its stop event."""
    if not enabled():
        _status.update(state="disabled")
        return None
    path = os.getenv("QYRIX_OBSERVER_GATE_KEY_FILE", "").strip()
    if not path:
        _status.update(state="misconfigured", reason="QYRIX_OBSERVER_GATE_KEY_FILE not set")
        return None
    stop = threading.Event()

    def boot():
        from app import persistence
        while not stop.is_set():
            ctx = ctx_getter()
            if ctx.db is not None and ctx.state.get("persistence") == "postgres":
                break
            if ctx.db is None and persistence.dsn_from_env() is None:
                _status.update(state="unsupported", reason="memory mode: no outbox")
                return
            stop.wait(2.0)
        try:
            pub = Publisher(lambda t: persistence.PgPersistence(ctx.db.dsn, t), ctx.db.dsn, load_key(path))
        except Exception as e:
            _status.update(state="misconfigured", reason=str(e)[:120])
            return
        _publisher["p"] = pub
        pub.run_forever(stop)
    threading.Thread(target=boot, name="observer-publisher", daemon=True).start()
    _status.update(state="starting")
    return stop


def status() -> Dict:
    p = _publisher.get("p")
    out = dict(_status)
    if p is not None:
        out.update({k: v for k, v in p.stats.items()}, producer_id=p.producer)
    return out


# ---------------- MCP proxy adapter reports (E1, §12) ----------------
class AdapterReporter:
    """Signed `adapter_report` self-reports from the MCP proxy, posted directly to the observer. Fire-and-forget on a
    background thread: a report can never delay, block or change a tools/call, and it is E1 (never evidence)."""

    def __init__(self, url: str, key, integration: str = "mcp_proxy", tenant: str = "default", http=None):
        self.url, self.key, self.integration, self.tenant = url.rstrip("/"), key, integration, tenant
        self.producer = "adapter:" + integration
        if http is None:
            http = observer_client(self.url, timeout=3.0)  # F2
        self.http = http
        self.stats = {"sent": 0, "failed": 0}

    def build(self, correlation_id: str, forwarded: bool, execution_id: Optional[str]) -> Dict:
        return sign_envelope(envelope(self.producer, "adapter_report", {
            "integration": self.integration, "correlation_id": correlation_id, "execution_id": execution_id,
            "claims": {"forwarded": bool(forwarded)}}, self.tenant, 1), self.key)

    def report(self, correlation_id: str, forwarded: bool, execution_id: Optional[str] = None, wait: bool = False):
        env = self.build(correlation_id, forwarded, execution_id)

        def go():
            try:
                r = self.http.post("/v1/events", content=canonical(env), headers={"Content-Type": "application/json"})
                self.stats["sent" if r.status_code == 200 else "failed"] += 1
            except Exception:
                self.stats["failed"] += 1
        t = threading.Thread(target=go, name="mcp-adapter-report", daemon=True)
        t.start()
        if wait:
            t.join(5)
        return env

    @classmethod
    def from_env(cls) -> Optional["AdapterReporter"]:
        url, path = os.getenv("QYRIX_OBSERVER_URL", "").strip(), os.getenv("QYRIX_OBSERVER_ADAPTER_KEY_FILE", "").strip()
        if not url or not path:
            return None
        return cls(url, load_key(path), os.getenv("QYRIX_OBSERVER_ADAPTER_ID", "mcp_proxy"),
                   os.getenv("QYRIX_OBSERVER_TENANT", "default"))


# ---------------- C4: dashboard read path (observer -> backend -> UI), READ-ONLY ----------------
RESULTS = ("ENFORCEMENT_VERIFIED", "BYPASS_DETECTED", "UNAUTHORIZED_EXECUTION", "INCONCLUSIVE")
_REC_FIELDS = ("recon_id", "run_id", "version", "result", "reasons", "evidence_level", "decided_at", "ledger", "channel",
               "run_created_at", "expected_condition", "expected_basis", "scope")


def _read_http():
    return observer_client(timeout=3.0)                  # F2: mTLS (or loopback http)


def fetch_reconciliations(tenant: str, http=None) -> Dict:
    """GET the observer's canary reconciliations for ONE tenant (the caller's) with a tenant-scoped READ-ONLY key
    (QYRIX_OBSERVER_READ_TOKEN_FILE). Only allow-listed fields are relayed; anything unexpected becomes INCONCLUSIVE.
    The relay passes through the backend, so the UI view is NOT independent of the backend (stated in `source`)."""
    base = {"source": "observer, relayed by the Sentinel backend (not independent of the backend; verify against the "
                      "observer API / signed ledger)", "verified_possible": False}
    # (verified_possible is overwritten below only by what the observer itself reports)
    path = os.getenv("QYRIX_OBSERVER_READ_TOKEN_FILE", "").strip()
    if not enabled() or not path:
        return {**base, "configured": False, "available": False, "reconciliations": []}
    try:
        with open(path) as f:
            token = f.read().strip()
    except OSError:
        return {**base, "configured": True, "available": False, "error": "READ_TOKEN_UNREADABLE", "reconciliations": []}
    try:
        r = (http or _read_http()).get("/v1/reconciliations", params={"tenant": tenant, "limit": 100},
                                       headers={"Authorization": "Bearer " + token})
    except Exception as e:
        return {**base, "configured": True, "available": False, "error": "OBSERVER_UNREACHABLE:" + type(e).__name__,
                "reconciliations": []}
    try:
        j = r.json()
    except ValueError:
        j = {}
    if r.status_code != 200 or not isinstance(j, dict) or not isinstance(j.get("reconciliations"), list):
        return {**base, "configured": True, "available": False, "error": "OBSERVER_HTTP_%d" % r.status_code,
                "reconciliations": []}
    rows = []
    for x in j["reconciliations"][:100]:
        if not isinstance(x, dict):
            continue
        y = {k: x.get(k) for k in _REC_FIELDS}
        if y["result"] not in RESULTS:                   # defensive: unknown values never reach the UI as a result
            y["reasons"], y["result"] = ["UNEXPECTED_RESULT_VALUE"], "INCONCLUSIVE"
        elif y["result"] == "ENFORCEMENT_VERIFIED" and (y.get("evidence_level") != "E3" or y.get("reasons")):
            y["reasons"], y["result"] = ["VERIFIED_WITHOUT_E3_EVIDENCE"], "INCONCLUSIVE"   # never relay a weak VERIFIED
        y["reasons"] = [str(z)[:64] for z in (y.get("reasons") or [])][:20]
        rows.append(y)
    return {**base, "configured": True, "available": True, "tenant": tenant, "scope": "canary", "reconciliations": rows,
            "verified_possible": j.get("verified_possible") is True, "note": str(j.get("note", ""))[:300]}
