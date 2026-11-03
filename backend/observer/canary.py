"""Observer canaries (Phase C3; design §6, §5.6, §12, §14, with the owner's amended decisions D1-D5).

What a canary run RECORDS (and nothing more):
  - the run itself, BEFORE anything is submitted (tokens minted here with `secrets`; only their SHA-256 is stored);
  - the test expectation: expected_condition = BLOCK, expected_basis = 'construction' - i.e. HOW the expectation was
    chosen (an observer-owned resource). It is NOT a validated policy outcome (no signed policy bundle until C6) and
    the Gate is never assumed or forced to block;
  - the submission outcome (P2: live submission DISABLED by default; never execute / redeem);
  - the REST response, labelled an unverified integration response;
  - the signed decision CLAIM from the C2 feed, if one arrives in T_decision (E0), or DECISION_MISSING;
  - every discrepancy between expectation, REST response and signed claim - as a record, not a conclusion;
  - observer-originated sensor observations (E3) of the canary token and of the positive-control token;
  - POSITIVE_CONTROL_PASSED / POSITIVE_CONTROL_FAILED; WINDOW_ENDED; CLEANED_UP; INTERRUPTED (after a restart).

What it NEVER does: produce a verdict or reconciliation result (C4), reach the backend over an unapproved network
path, expose a sensor beyond loopback (C5), or treat a producer claim as an observation.

Honest limit (§6): canaries test the integration and non-adversarial faults and exercise the decision feed. An
ADAPTIVE compromised backend can recognise canary credentials or destinations and behave honestly only for them.
"""
import hashlib
import http.server
import ipaddress
import json
import os
import secrets
import socketserver
import stat
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional

from observer import ledger
from observer.db import DbError, set_tenant
from observer.envelope import TENANT_RE

MAX_BODY = 4096
TOKEN_PATH = "/c/"


def mint() -> str:
    """128-bit CSPRNG token, hex. Never stored; only sha256(token) is."""
    return secrets.token_bytes(16).hex()


def h(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _dt(t: float) -> datetime:
    return datetime.fromtimestamp(t, timezone.utc)


def _is_token(s: str) -> bool:
    return len(s) == 32 and all(c in "0123456789abcdef" for c in s)


class CanaryError(Exception):
    observer_passthrough = True


# ---------------- sensors (observer-owned, loopback / observer directory only) ----------------
class HttpCanarySensor:
    """Loopback-only HTTP sensor. Refuses any non-loopback bind in C3 (network exposure is C5).
    A request to /c/<token> is looked up by hash; unknown or malformed requests are only COUNTED, never stored."""

    def __init__(self, record: Callable[..., bool], host: str = "127.0.0.1", port: int = 0, max_concurrency: int = 16):
        if not ipaddress.ip_address(host).is_loopback:
            raise CanaryError("C3 canary HTTP sensor binds to loopback only (network exposure is C5)")
        self.record, self.counters = record, {"matched": 0, "unmatched": 0, "busy": 0, "unrecorded": 0}
        slots = threading.BoundedSemaphore(max_concurrency)
        sensor = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):                  # no request logging (tokens would land in logs)
                pass

            def _handle(self):
                if not slots.acquire(blocking=False):
                    sensor.counters["busy"] += 1
                    self.send_response(503); self.end_headers(); return
                try:
                    n = min(int(self.headers.get("Content-Length") or 0), MAX_BODY)
                    body = self.rfile.read(n) if n > 0 else b""
                    path = self.path.split("?", 1)[0]
                    tok = path[len(TOKEN_PATH):] if path.startswith(TOKEN_PATH) else ""
                    ok = _is_token(tok) and sensor.record("canary_http", tok, method=self.command[:10],
                                                          path=self.path[:2048], body=body, peer=self.client_address[0])
                    sensor.counters["matched" if ok else "unmatched"] += 1
                    self.send_response(204 if ok else 404)
                    self.send_header("Content-Length", "0"); self.end_headers()
                except Exception:
                    sensor.counters["unrecorded"] += 1
                    try:
                        self.send_response(503); self.end_headers()
                    except Exception:
                        pass
                finally:
                    slots.release()

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _handle

        class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server((host, port), Handler)
        self.host, self.port = self.server.server_address[:2]
        threading.Thread(target=self.server.serve_forever, name="observer-canary-http", daemon=True).start()

    def url(self, token: str) -> str:
        return "http://%s:%d%s%s" % (self.host, self.port, TOKEN_PATH, token)

    def close(self):
        self.server.shutdown(); self.server.server_close()


class FileCanarySensor:
    """Polls an OBSERVER-OWNED directory (mode 0700) for <run_id>/<token>.canary. Regular files only, no symlinks.
    Observing backend writes through a shared volume is C5 (not claimed here)."""

    def __init__(self, record: Callable[..., bool], root: str, interval: float = 0.1):
        os.makedirs(root, mode=0o700, exist_ok=True)
        st = os.lstat(root)
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
            raise CanaryError("canary directory must be a real directory with mode 0700")
        self.record, self.root, self.interval = record, os.path.realpath(root), interval
        self._seen: Dict[str, tuple] = {}
        self._stop = threading.Event()
        self.counters = {"matched": 0, "ignored": 0, "unrecorded": 0}
        threading.Thread(target=self._loop, name="observer-canary-file", daemon=True).start()

    def path(self, run_id: str, token: str) -> str:
        return os.path.join(self.root, run_id, token + ".canary")

    def prepare(self, run_id: str) -> None:
        os.makedirs(os.path.join(self.root, run_id), mode=0o700, exist_ok=True)

    def cleanup(self, run_id: str) -> None:
        d = os.path.join(self.root, run_id)
        if not os.path.isdir(d) or os.path.islink(d):
            return
        for f in os.listdir(d):
            p = os.path.join(d, f)
            if os.path.islink(p) or os.path.isfile(p):
                os.unlink(p)
        os.rmdir(d)

    def scan(self) -> None:
        for run in os.listdir(self.root):
            d = os.path.join(self.root, run)
            if os.path.islink(d) or not os.path.isdir(d):
                continue
            for f in os.listdir(d):
                p = os.path.join(d, f)
                try:
                    st = os.lstat(p)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(st.st_mode) or not f.endswith(".canary") or not _is_token(f[:-7]):
                    self.counters["ignored"] += 1
                    continue
                sig = (st.st_mtime_ns, st.st_size)
                if self._seen.get(p) == sig:
                    continue                             # same write already recorded
                self._seen[p] = sig
                with open(p, "rb") as fh:
                    body = fh.read(MAX_BODY)
                ok = self.record("canary_file", f[:-7], method="WRITE", path=p, body=body, peer=None)
                self.counters["matched" if ok else "ignored"] += 1

    def _loop(self):
        while not self._stop.is_set():
            try:
                self.scan()
            except Exception:
                self.counters["unrecorded"] += 1
            self._stop.wait(self.interval)

    def close(self):
        self._stop.set()


# ---------------- P2 client (evaluate ONLY) ----------------
class P2Client:
    """Observer as a client of Sentinel's REST API with an observer-held canary agent key (design §6 P2).
    The ONLY call is POST /api/v1/sentinel/gate/evaluate. There is no execute or redeem code path.
    `live=False` (default, D4): nothing is sent; the run records SUBMISSION_DISABLED."""

    EVALUATE = "/api/v1/sentinel/gate/evaluate"

    def __init__(self, credentials: Dict[str, Dict], http=None, live: bool = False):
        # credentials: {tenant: {"key_id": public id, "token_file": path}} - the secret is read at use, never stored
        self.credentials, self.http, self.live = credentials, http, live

    def key_id(self, tenant: str) -> Optional[str]:
        return (self.credentials.get(tenant) or {}).get("key_id")

    def _token(self, tenant: str) -> str:
        path = (self.credentials.get(tenant) or {}).get("token_file")
        if not path:
            raise CanaryError("no canary credential for tenant")
        with open(path) as f:
            return f.read().strip()

    def evaluate(self, tenant: str, action: Dict) -> Dict:
        """-> {"submitted": bool, "status"?, "verdict"?, "error"?}. Connection failure before sending => not submitted."""
        if not self.live:
            return {"submitted": False, "disabled": True}
        try:
            token = self._token(tenant)
        except Exception:
            return {"submitted": False, "error": "CREDENTIAL_UNAVAILABLE"}
        try:
            r = self.http.post(self.EVALUATE, json=action, headers={"Authorization": "Bearer " + token})
        except Exception as e:
            name = type(e).__name__
            pre_send = name in ("ConnectError", "ConnectTimeout", "UnsupportedProtocol")
            return {"submitted": not pre_send, "error": "BACKEND_UNAVAILABLE:" + name}
        try:
            j = r.json()
        except ValueError:
            j = {}
        return {"submitted": True, "status": r.status_code, "verdict": j.get("verdict") if isinstance(j, dict) else None,
                "rules": (j.get("rules") or [])[:30] if isinstance(j, dict) else []}


# ---------------- run lifecycle ----------------
class CanaryService:
    def __init__(self, observer, http_sensor: Optional[HttpCanarySensor] = None,
                 file_sensor: Optional[FileCanarySensor] = None, p2: Optional[P2Client] = None,
                 clock: Optional[Callable[[], float]] = None):
        self.obs, self.db = observer, observer.db
        self.http, self.file = http_sensor, file_sensor
        self.p2 = p2 or P2Client({})
        self.clock = clock or observer.clock
        self.unrecorded = 0

    # -- helpers
    def _event(self, cur, run_id, tenant, kind, detail=None, now=None):
        cur.execute("INSERT INTO canary_run_events (run_id, tenant_id, at, kind, detail) VALUES (%s,%s,%s,%s,%s)"
                    " ON CONFLICT DO NOTHING", (run_id, tenant, _dt(now or self.clock()), kind, json.dumps(detail or {})))

    def _alert(self, cur, code, run_id, tenant, detail, now):
        ledger.append(cur, self.obs.signer, now, "alert", code, None, tenant, run_id, detail)

    # -- sensor callback: an E3 observation (only for a known token hash; never inferred from claims)
    def record(self, sensor: str, token: str, method=None, path=None, body=b"", peer=None) -> bool:
        th = h(token)
        now = self.clock()

        def go(cur):
            cur.execute("SELECT out_run_id, out_tenant, out_purpose, out_created_at, out_window_ends_at"
                        " FROM observer_canary_lookup(%s)", (th,))
            r = cur.fetchone()
            if r is None:
                return False
            run_id, tenant, purpose, created, wend = str(r[0]), r[1], r[2], r[3].timestamp(), r[4].timestamp()
            expected = "canary_http" if self._channel(cur, run_id, tenant) == "http" else "canary_file"
            if sensor != expected:
                return False                             # a token is valid on its own channel only
            timing = "in_window" if created <= now <= wend else "late"
            set_tenant(cur, tenant)
            oid = str(uuid.uuid4())
            cur.execute("INSERT INTO observations (observation_id, run_id, tenant_id, sensor, purpose, timing, observed_at,"
                        " token_sha256, method, path_sha256, body_sha256, bytes_in, peer)"
                        " VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (oid, run_id, tenant, sensor, purpose, timing, _dt(now), th, method,
                         hashlib.sha256((path or "").encode()).hexdigest(), hashlib.sha256(body or b"").hexdigest(),
                         len(body or b""), peer))
            if purpose == "canary":
                self._event(cur, run_id, tenant, "TOKEN_OBSERVED", {"observation_id": oid, "timing": timing,
                                                                     "sensor": sensor, "evidence_level": "E3"}, now)
                self._alert(cur, "CANARY_TOKEN_OBSERVED", run_id, tenant,
                            {"observation_id": oid, "timing": timing, "sensor": sensor,
                             "note": "observation only; no verdict in C3"}, now)
            return True
        try:
            return self.db.run(go)
        except (DbError, ledger.LedgerError):
            self.unrecorded += 1                         # sensor saw something it could not record: never silent
            return False

    @staticmethod
    def _channel(cur, run_id, tenant) -> str:
        set_tenant(cur, tenant)
        cur.execute("SELECT channel FROM canary_runs WHERE run_id=%s", (run_id,))
        return cur.fetchone()[0]

    # -- start a run
    def start(self, tenant: str, channel: str = "http", adapter: str = "rest_api") -> Dict:
        if not TENANT_RE.match(tenant or ""):
            raise CanaryError("invalid tenant")
        sensor = self.http if channel == "http" else self.file if channel == "file" else None
        if sensor is None:
            raise CanaryError("channel sensor not configured")
        cfg = self.obs.cfg
        run_id, token, control, corr = str(uuid.uuid4()), mint(), mint(), "obs_" + secrets.token_hex(16)
        now = self.clock()
        if channel == "http":
            resource, control_res, template = sensor.url(token), sensor.url(control), sensor.url("<token>")
            action = {"tool": "http", "method": "GET", "dest": resource, "correlation_id": corr}
        else:
            sensor.prepare(run_id)
            resource, control_res = sensor.path(run_id, token), sensor.path(run_id, control)
            template = sensor.path(run_id, "<token>")
            action = {"tool": "file.write", "method": "WRITE", "dest": resource, "correlation_id": corr}

        def create(cur):                                 # durable BEFORE any submission (§6)
            set_tenant(cur, tenant)
            cur.execute("INSERT INTO canary_runs (run_id, tenant_id, channel, injection_path, adapter, credential_key_id,"
                        " correlation_id, token_sha256, control_sha256, resource_template, expected_condition,"
                        " expected_basis, window_seconds, decision_seconds, created_at, window_ends_at, due_at)"
                        " VALUES (%s,%s,%s,'P2',%s,%s,%s,%s,%s,%s,'BLOCK','construction',%s,%s,%s,%s,%s)",
                        (run_id, tenant, channel, adapter[:64], self.p2.key_id(tenant), corr, h(token), h(control),
                         template, cfg.W, cfg.T_decision, _dt(now), _dt(now + cfg.W), _dt(now + max(cfg.W, cfg.T_decision))))
            self._event(cur, run_id, tenant, "CREATED", {"channel": channel, "expected_condition": "BLOCK",
                                                         "expected_basis": "construction"}, now)
            ledger.append(cur, self.obs.signer, now, "canary", "CANARY_RUN_CREATED", None, tenant, run_id,
                          {"channel": channel, "token_sha256": h(token), "correlation_id": corr,
                           "expected_condition": "BLOCK", "expected_basis": "construction"})
        self.db.run(create)                              # DB down => DbError, nothing was submitted
        res = self.p2.evaluate(tenant, action)
        t = self.clock()

        def after(cur):
            set_tenant(cur, tenant)
            if res.get("disabled"):
                self._event(cur, run_id, tenant, "SUBMISSION_DISABLED", {"reason": "live P2 submission disabled (D4)"}, t)
            elif not res.get("submitted"):
                self._event(cur, run_id, tenant, "SUBMISSION_FAILED", {"error": res.get("error")}, t)
            else:
                self._event(cur, run_id, tenant, "SUBMITTED", {"path": "P2", "error": res.get("error")}, t)
                self._event(cur, run_id, tenant, "RESPONSE_RECORDED", {
                    "status": res.get("status"), "claimed_verdict": res.get("verdict"), "rules": res.get("rules"),
                    "label": "unverified integration response (not evidence)"}, t)
        self.db.run(after)
        self._positive_control(channel, control_res)
        return {"run_id": run_id, "correlation_id": corr, "submission": res}

    def _positive_control(self, channel: str, control_res: str) -> None:
        """The observer stimulates its OWN sensor with the control token: proves the sensor records in this window."""
        try:
            if channel == "http":
                import urllib.request
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                opener.open(urllib.request.Request(control_res, method="GET"), timeout=2).close()
            else:
                with open(control_res, "w") as f:
                    f.write("positive-control")
        except Exception:
            pass                                         # a failed control shows up as POSITIVE_CONTROL_FAILED

    # -- finish due runs (monitor tick)
    def tick(self) -> List[str]:
        now = self.clock()
        done: List[str] = []
        for run in self._open_runs(due_before=now):
            self._finish(run, now)
            done.append(run["run_id"])
        return done

    def _open_runs(self, due_before: Optional[float] = None) -> List[Dict]:
        """Runs without WINDOW_ENDED / INTERRUPTED. Iterates tenants explicitly (RLS): tenant list from the ledger."""
        cut = _dt(due_before) if due_before is not None else None

        def go(cur):
            cur.execute("SELECT DISTINCT tenant_id FROM ledger WHERE code='CANARY_RUN_CREATED'")
            out = []
            for (t,) in cur.fetchall():
                set_tenant(cur, t)
                cur.execute("SELECT r.run_id, r.tenant_id, r.channel, r.correlation_id, r.created_at, r.window_ends_at,"
                            " r.due_at, r.decision_seconds FROM canary_runs r WHERE NOT EXISTS (SELECT 1 FROM canary_run_events e"
                            " WHERE e.run_id = r.run_id AND e.kind IN ('WINDOW_ENDED', 'INTERRUPTED'))"
                            " AND (%s::timestamptz IS NULL OR r.due_at <= %s::timestamptz)",
                            (cut, cut))
                out += [{"run_id": str(r[0]), "tenant": r[1], "channel": r[2], "corr": r[3], "created": r[4].timestamp(),
                         "window_end": r[5].timestamp(), "due": r[6].timestamp(), "t_decision": r[7]} for r in cur.fetchall()]
            return out
        return self.db.run(go, lock=False)

    def _finish(self, run: Dict, now: float) -> None:
        rid, t = run["run_id"], run["tenant"]

        def go(cur):
            set_tenant(cur, t)
            cur.execute("SELECT kind, detail FROM canary_run_events WHERE run_id=%s", (rid,))
            ev = {k: d for k, d in cur.fetchall()}
            submitted = "SUBMITTED" in ev
            # 1. signed decision claim from the C2 feed (E0), matched by the observer-minted correlation id
            cur.execute("SELECT envelope->'body'->>'verdict', received_at, event_id FROM events WHERE tenant_id=%s"
                        " AND type='decision' AND envelope->'body'->>'correlation_id'=%s ORDER BY received_at LIMIT 1",
                        (t, run["corr"]))
            claim = cur.fetchone()
            in_time = claim is not None and claim[1].timestamp() <= run["created"] + run["t_decision"]
            summary = {"expected_condition": "BLOCK", "expected_basis": "construction",
                       "submission": "submitted" if submitted else ("disabled" if "SUBMISSION_DISABLED" in ev else "failed")}
            if claim is not None and in_time:
                self._event(cur, rid, t, "DECISION_CLAIM_SEEN", {"claimed_verdict": claim[0], "event_id": str(claim[2]),
                                                                 "evidence_level": "E0"}, now)
                summary["decision_claim"] = {"verdict": claim[0], "evidence_level": "E0"}
                if claim[0] != "BLOCK":
                    self._discrepancy(cur, rid, t, now, "EXPECTATION_VS_SIGNED_CLAIM", "BLOCK", claim[0])
                resp = (ev.get("RESPONSE_RECORDED") or {}).get("claimed_verdict")
                if resp is not None and resp != claim[0]:
                    self._discrepancy(cur, rid, t, now, "REST_RESPONSE_VS_SIGNED_CLAIM", resp, claim[0])
            elif submitted:
                self._event(cur, rid, t, "DECISION_MISSING", {"t_decision": run["t_decision"],
                                                              "late_claim": claim is not None}, now)
                self._alert(cur, "DECISION_MISSING", rid, t, {"correlation_id": run["corr"],
                                                              "late_claim": claim is not None}, now)
                summary["decision_claim"] = "missing" if claim is None else "late"
            else:
                summary["decision_claim"] = "not_applicable (not submitted)"
            # 2. positive control: the observer's own stimulus must be observed by its own sensor inside the window
            cur.execute("SELECT count(*) FILTER (WHERE purpose='positive_control' AND timing='in_window'),"
                        " count(*) FILTER (WHERE purpose='canary') FROM observations WHERE run_id=%s", (rid,))
            pc, hits = cur.fetchone()
            if pc:
                self._event(cur, rid, t, "POSITIVE_CONTROL_PASSED", {}, now)
            else:
                self._event(cur, rid, t, "POSITIVE_CONTROL_FAILED", {}, now)
                self._alert(cur, "POSITIVE_CONTROL_FAILED", rid, t, {"channel": run["channel"]}, now)
            summary.update(positive_control=bool(pc), token_observations=hits,
                           result=None, note="no verdict in C3; reconciliation is C4")
            self._event(cur, rid, t, "WINDOW_ENDED", summary, now)
        self.db.run(go)
        self._cleanup(run, now)

    def _discrepancy(self, cur, rid, t, now, kind, a, b):
        d = {"kind": kind, "left": a, "right": b, "note": "recorded, not concluded"}
        self._event(cur, rid, t, "DECISION_DISCREPANCY", d, now)
        self._alert(cur, "DECISION_DISCREPANCY", rid, t, d, now)

    def _cleanup(self, run: Dict, now: float) -> None:
        if run["channel"] == "file" and self.file is not None:
            self.file.scan()                             # record anything written just before the end
            self.file.cleanup(run["run_id"])
        self.db.run(lambda cur: (set_tenant(cur, run["tenant"]),
                                 self._event(cur, run["run_id"], run["tenant"], "CLEANED_UP", {}, now)))

    # -- restart recovery (§14): runs open at start-up lost sensor continuity
    def recover(self) -> List[str]:
        now = self.clock()
        out = []
        for run in self._open_runs():
            def go(cur, run=run):
                set_tenant(cur, run["tenant"])
                self._event(cur, run["run_id"], run["tenant"], "INTERRUPTED",
                            {"reason": "observer restarted during the run; sensor continuity unknown"}, now)
                self._alert(cur, "CANARY_RUN_INTERRUPTED", run["run_id"], run["tenant"], {}, now)
            self.db.run(go)
            if run["channel"] == "file" and self.file is not None:
                self.file.cleanup(run["run_id"])
            out.append(run["run_id"])
        return out

    def run_detail(self, tenant: str, run_id: str) -> Optional[Dict]:
        def go(cur):
            set_tenant(cur, tenant)
            cur.execute("SELECT channel, correlation_id, expected_condition, expected_basis, created_at FROM canary_runs"
                        " WHERE run_id=%s", (run_id,))
            r = cur.fetchone()
            if not r:
                return None
            cur.execute("SELECT kind, at, detail FROM canary_run_events WHERE run_id=%s ORDER BY id", (run_id,))
            evs = [{"kind": k, "at": a.isoformat(), "detail": d} for k, a, d in cur.fetchall()]
            cur.execute("SELECT sensor, purpose, timing, observed_at, evidence_level FROM observations WHERE run_id=%s"
                        " ORDER BY observed_at", (run_id,))
            obs = [{"sensor": s, "purpose": p, "timing": ti, "observed_at": at.isoformat(), "evidence_level": el}
                   for s, p, ti, at, el in cur.fetchall()]
            return {"run_id": run_id, "tenant": tenant, "channel": r[0], "correlation_id": r[1],
                    "expected_condition": r[2], "expected_basis": r[3], "created_at": r[4].isoformat(),
                    "events": evs, "observations": obs, "result": None}
        return self.db.run(go, lock=False)
