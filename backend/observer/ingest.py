"""Signed ingest (design §5, §10, §12, §14). Order of checks for every envelope:

  1. size and structure (envelope.parse)                  -> OVERSIZE / MALFORMED / TENANT_MISMATCH
  2. producer listed in the root-signed manifest            -> UNKNOWN_PRODUCER
  3. key belongs to that producer (or, for epoch_change only, to the operator recovery keys) and is valid NOW
     -> SIGNATURE_INVALID;   Ed25519 signature over canonical(envelope without sig)  -> SIGNATURE_INVALID
  4. the key's scope covers the type (a GATE key can never sign epoch_change, observations or adapter reports)
     -> SCOPE_DENIED
  5. the producer may speak for the tenant                  -> TENANT_MISMATCH
  6. clock: heartbeats |issued_at - now| <= S; other types issued_at <= now + S (events are dated when the decision was
     taken and may legitimately arrive late from the outbox backlog; replay is prevented by event_id/seq uniqueness)
     -> CLOCK_SKEW
  7. in ONE observer-db transaction under the global ingest lock: idempotency (event_id), epoch, quarantine, sequence
     placement, watermarks, ledger record -> 200 accepted | duplicate | out_of_order, or EVENT_CONFLICT,
     PRODUCER_REGRESSION (stream quarantined), UNKNOWN_EPOCH, EPOCH_CLOSED, EPOCH_INVALID, STREAM_QUARANTINED.

Everything accepted here is a CLAIM (E0: decision, grant, heartbeat) or a self-report (E1: adapter_report).
"""
import json
import threading
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from observer import crypto, ledger
from observer.db import Database, DbError, set_tenant
from observer.envelope import Refused, parse, signed_bytes, stored
from observer.feed import Config, advance, feed_conditions
from observer.manifest import Manifest

ALWAYS_RECORD = {"EVENT_CONFLICT", "PRODUCER_REGRESSION", "SCOPE_DENIED"}     # security alerts: never throttled
MAX_THROTTLE_KEYS = 1024                                                       # audit F1: bounded memory
HEX64 = set("0123456789abcdef")


def _dt(t: float) -> datetime:
    return datetime.fromtimestamp(t, timezone.utc)


def _ts(v) -> Optional[float]:
    return v.timestamp() if v is not None else None


class Observer:
    def __init__(self, db: Database, manifest: Manifest, signing_key, cfg: Config = Config(),
                 clock: Callable[[], float] = time.time):
        self.db, self.manifest, self.key, self.cfg, self.clock = db, manifest, signing_key, cfg, clock
        self.key_id = crypto.describe(signing_key)[0]
        self.degraded: Optional[str] = None
        self._throttle: Dict[Tuple[str, str], float] = {}
        self._tlock = threading.Lock()
        self.counters: Dict[str, int] = {}

    # ---------------- keys, manifest, ledger integrity ----------------
    def signer(self):
        k = self.manifest.observer_keys.get(self.key_id)
        if k is None or not k.valid_at(self.clock()):
            raise ledger.LedgerError("OBSERVER_KEY_INVALID")
        return self.key, self.key_id

    def install_manifest(self) -> Dict:
        """Record the manifest; refuse a rollback to a lower version or a different document under the same version."""
        m = self.manifest

        def go(cur):
            cur.execute("SELECT manifest_version, digest FROM key_manifests ORDER BY manifest_version DESC LIMIT 1")
            r = cur.fetchone()
            if r and r[0] > m.version:
                raise Refused("MANIFEST_ROLLBACK", 409)
            if r and r[0] == m.version:
                if r[1].strip() != m.digest:
                    raise Refused("MANIFEST_VERSION_REUSED", 409)
                return {"installed": False, "version": m.version}
            cur.execute("INSERT INTO key_manifests (manifest_version, digest, doc) VALUES (%s,%s,%s)",
                        (m.version, m.digest, json.dumps(m.doc)))
            ledger.append(cur, self.signer, self.clock(), "config", "MANIFEST_INSTALLED", ref=str(m.version),
                          detail={"digest": m.digest})
            return {"installed": True, "version": m.version}
        return self.db.run(go)

    def verify_ledger(self) -> Dict:
        def go(cur):
            cur.execute("SELECT n, prev, hash, recorded_at, kind, code, producer_id, tenant_id, ref, detail, observer_key_id, sig"
                        " FROM ledger ORDER BY n")
            return ledger.verify(cur.fetchall(), self.manifest.observer_keys)
        v = self.db.run(go, lock=False)
        self.degraded = None if v["valid"] else "LEDGER_INVALID"
        return v

    # ---------------- entry point ----------------
    def ingest(self, raw: bytes) -> Tuple[int, Dict]:
        now = self.clock()
        if self.degraded:
            return 503, {"error": self.degraded}
        env = None
        try:
            env = parse(raw)
            key = self._authenticate(env)
            self._check_clock(env, now)
            return self.db.run(lambda cur: self._apply(cur, env, key, now))
        except Refused as r:
            self._count(r.code)
            self._record_refusal(r, env, now)
            return r.status, {"error": r.code}
        except ledger.LedgerError as e:
            return 503, {"error": str(e)}
        except DbError:
            self._count("OBSERVER_DB_UNAVAILABLE")
            return 503, {"error": "OBSERVER_DB_UNAVAILABLE"}
        except (ValueError, TypeError, OverflowError, RecursionError, AttributeError, KeyError):
            # audit F7: any malformed value that slipped past the structural checks is a refusal, never a 500
            self._count("MALFORMED")
            self._record_refusal(Refused("MALFORMED", 400, "unparseable value"), None, now)
            return 400, {"error": "MALFORMED"}

    def _count(self, code: str) -> None:
        self.counters[code] = self.counters.get(code, 0) + 1

    def _authenticate(self, env: Dict):
        p = self.manifest.producer(env["producer_id"])
        if p is None:
            raise Refused("UNKNOWN_PRODUCER", 403)
        key = p.keys.get(env["key_id"])
        if key is None and env["type"] == "epoch_change" and p.kind == "gate":
            key = self.manifest.recovery_keys.get(env["key_id"])
        if key is None or not key.valid_at(self.clock()):
            raise Refused("SIGNATURE_INVALID", 401, "key not listed for producer or not valid now")
        if not crypto.verify(key.public, env["sig"], signed_bytes(env)):
            raise Refused("SIGNATURE_INVALID", 401)
        env["_authenticated"] = True                     # from here on, refusals concern a verified producer (F1)
        if env["type"] not in key.scopes:
            raise Refused("SCOPE_DENIED", 403, "%s not in key scope" % env["type"])
        if env["tenant"] is not None and not p.allows_tenant(env["tenant"]):
            raise Refused("TENANT_MISMATCH", 403)
        if p.kind == "adapter" and env["epoch"] != 1:
            raise Refused("MALFORMED", 400, "adapter producers have no epochs")
        return key

    def _check_clock(self, env: Dict, now: float) -> None:
        skew = env["_issued"] - now
        if env["type"] == "heartbeat":
            if abs(skew) > self.cfg.S:
                raise Refused("CLOCK_SKEW", 400)
        elif skew > self.cfg.S:
            raise Refused("CLOCK_SKEW", 400)

    def _record_refusal(self, r: Refused, env: Optional[Dict], now: float) -> None:
        """Refusals go to the ledger, throttled to one per 60 s per key (security alerts are never throttled).
        Audit F1: for UNAUTHENTICATED input (no verified signature yet) the key is the code alone and NOTHING the sender
        chose is stored (no claimed producer id, tenant or event id) - varying those cannot multiply ledger rows.
        Authenticated keys are (code, producer) and therefore bounded by the manifest. The map itself is bounded."""
        authenticated = bool((env or {}).get("_authenticated"))
        pid = env["producer_id"] if authenticated else None
        if r.code not in ALWAYS_RECORD:
            k = (r.code, pid or "")
            with self._tlock:
                if now - self._throttle.get(k, -1e18) < 60:
                    self._count("REFUSAL_THROTTLED")
                    return
                if len(self._throttle) >= MAX_THROTTLE_KEYS:
                    for kk in [kk for kk, t in self._throttle.items() if now - t >= 60]:
                        del self._throttle[kk]
                    if len(self._throttle) >= MAX_THROTTLE_KEYS:
                        self._count("REFUSAL_THROTTLED")
                        return
                self._throttle[k] = now
        e = env if authenticated else {}
        try:
            self.db.run(lambda cur: ledger.append(
                cur, self.signer, now, "alert" if r.code in ALWAYS_RECORD else "refusal", r.code, producer_id=pid,
                tenant_id=e.get("tenant"), ref=e.get("event_id"),
                detail={"type": e.get("type"), "detail": r.detail, "authenticated": authenticated}))
        except (DbError, ledger.LedgerError):
            pass

    # ---------------- transactional part ----------------
    def _apply(self, cur, env: Dict, key, now: float) -> Tuple[int, Dict]:
        t = env["type"]
        if t == "epoch_change":
            return self._epoch_change(cur, env, key, now)
        if t == "adapter_report":
            return self._adapter_report(cur, env, key, now)
        current, status = self._stream(cur, env["producer_id"], env["epoch"], now)
        if t == "heartbeat":
            return self._heartbeat(cur, env, key, now, current, status)
        return self._event(cur, env, key, now, current, status)

    def _alert(self, cur, now, code, env, detail=None, tenant=None):
        return ledger.append(cur, self.signer, now, "alert", code, producer_id=env["producer_id"],
                             tenant_id=tenant if tenant is not None else env.get("tenant"), ref=env["event_id"],
                             detail=detail or {})

    def _refuse_tx(self, cur, now, env, code, status, detail=None) -> Tuple[int, Dict]:
        """A refusal decided inside the transaction: recorded in the SAME transaction (commits with it)."""
        self._count(code)
        if code in ALWAYS_RECORD:
            self._alert(cur, now, code, env, detail)
        else:
            k = (code, env["producer_id"])
            with self._tlock:
                due = now - self._throttle.get(k, 0) >= 60
                if due:
                    self._throttle[k] = now
            if due:
                ledger.append(cur, self.signer, now, "refusal", code, producer_id=env["producer_id"],
                              tenant_id=env.get("tenant"), ref=env["event_id"], detail=detail or {})
        return status, {"error": code}

    def _stream(self, cur, pid: str, epoch: int, now: float) -> Tuple[int, Optional[str]]:
        cur.execute("INSERT INTO producers (producer_id) VALUES (%s) ON CONFLICT DO NOTHING", (pid,))
        cur.execute("SELECT current_epoch FROM producers WHERE producer_id=%s FOR UPDATE", (pid,))
        current = cur.fetchone()[0]
        cur.execute("INSERT INTO streams (producer_id, epoch) VALUES (%s,%s) ON CONFLICT DO NOTHING", (pid, current))
        cur.execute("SELECT status FROM streams WHERE producer_id=%s AND epoch=%s FOR UPDATE", (pid, epoch))
        r = cur.fetchone()
        return current, (r[0] if r else None)

    def _quarantine(self, cur, now, env, reason: str, detail: Dict) -> None:
        cur.execute("UPDATE streams SET status='quarantined', reason=%s WHERE producer_id=%s AND epoch=%s AND status='active'",
                    (reason, env["producer_id"], env["epoch"]))
        self._alert(cur, now, "PRODUCER_REGRESSION", env, {"reason": reason, **detail})

    def _watermark(self, cur, pid, epoch, tenant) -> Dict:
        cur.execute("INSERT INTO watermarks (producer_id, epoch, tenant_id) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                    (pid, epoch, tenant))
        cur.execute("SELECT contiguous_seq, max_seq, attested_seq, gap_since, behind_since, last_proof_n, last_proof_head"
                    " FROM watermarks WHERE producer_id=%s AND epoch=%s AND tenant_id=%s FOR UPDATE", (pid, epoch, tenant))
        r = cur.fetchone()
        return {"contiguous_seq": r[0], "max_seq": r[1], "attested_seq": r[2], "gap_since": r[3], "behind_since": r[4],
                "last_proof_n": r[5], "last_proof_head": r[6].strip() if r[6] else None}

    def _save_watermark(self, cur, pid, epoch, tenant, w: Dict, now: float) -> None:
        gap = w["max_seq"] > w["contiguous_seq"]
        behind = w["attested_seq"] > w["contiguous_seq"]
        gap_since = (w["gap_since"] or _dt(now)) if gap else None
        behind_since = (w["behind_since"] or _dt(now)) if behind else None
        cur.execute("UPDATE watermarks SET contiguous_seq=%s, max_seq=%s, attested_seq=%s, gap_since=%s, behind_since=%s,"
                    " gap_alerted = gap_alerted AND %s, behind_alerted = behind_alerted AND %s,"
                    " last_proof_n=%s, last_proof_head=%s WHERE producer_id=%s AND epoch=%s AND tenant_id=%s",
                    (w["contiguous_seq"], w["max_seq"], w["attested_seq"], gap_since, behind_since, gap, behind,
                     w["last_proof_n"], w["last_proof_head"], pid, epoch, tenant))

    def _epoch_status(self, cur, now, env, current, status) -> Optional[Tuple[int, Dict]]:
        if env["epoch"] > current:
            return self._refuse_tx(cur, now, env, "UNKNOWN_EPOCH", 409, {"current_epoch": current})
        if env["epoch"] < current or status == "closed":
            return self._refuse_tx(cur, now, env, "EPOCH_CLOSED", 409, {"current_epoch": current})
        if status == "quarantined":
            return self._refuse_tx(cur, now, env, "STREAM_QUARANTINED", 409)
        return None

    # ---- decision / grant (gap-free seq) ----
    def _event(self, cur, env, key, now, current, status) -> Tuple[int, Dict]:
        pid, ep, tenant, seq = env["producer_id"], env["epoch"], env["tenant"], env["seq"]
        clean, digest = stored(env)
        set_tenant(cur, tenant)
        cur.execute("SELECT digest FROM events WHERE event_id=%s", (env["event_id"],))
        r = cur.fetchone()
        if r:
            if r[0].strip() == digest:
                self._count("DUPLICATE")
                return 200, {"status": "duplicate"}
            return self._refuse_tx(cur, now, env, "EVENT_CONFLICT", 409, {"seq": seq})
        refused = self._epoch_status(cur, now, env, current, status)
        if refused:
            return refused
        cur.execute("SELECT event_id FROM events WHERE producer_id=%s AND epoch=%s AND tenant_id=%s AND seq=%s",
                    (pid, ep, tenant, seq))
        if cur.fetchone():                         # the same number with different content: restore / rewrite / fork
            self._quarantine(cur, now, env, "SEQ_REUSED_WITH_DIFFERENT_CONTENT", {"seq": seq})
            self._count("PRODUCER_REGRESSION")
            return 409, {"error": "PRODUCER_REGRESSION"}
        w = self._watermark(cur, pid, ep, tenant)
        if seq <= w["contiguous_seq"]:             # cannot happen without the original row being gone: treat as regression
            self._quarantine(cur, now, env, "SEQ_BELOW_WATERMARK", {"seq": seq})
            return 409, {"error": "PRODUCER_REGRESSION"}
        cur.execute("SAVEPOINT ev")
        try:
            cur.execute("INSERT INTO events (event_id, producer_id, epoch, tenant_id, seq, type, evidence_level, key_id,"
                        " issued_at, received_at, digest, envelope) VALUES (%s,%s,%s,%s,%s,%s,'E0',%s,%s,%s,%s,%s)",
                        (env["event_id"], pid, ep, tenant, seq, env["type"], env["key_id"], _dt(env["_issued"]), _dt(now),
                         digest, json.dumps(clean)))
        except Exception as e:                     # event_id already used under ANOTHER tenant (invisible through RLS)
            if type(e).__name__ != "UniqueViolation":
                raise
            cur.execute("ROLLBACK TO SAVEPOINT ev")
            return self._refuse_tx(cur, now, env, "EVENT_CONFLICT", 409, {"seq": seq, "scope": "event_id"})
        w["max_seq"] = max(w["max_seq"], seq)
        if seq == w["contiguous_seq"] + 1:
            cur.execute("SELECT seq FROM events WHERE producer_id=%s AND epoch=%s AND tenant_id=%s AND seq > %s ORDER BY seq",
                        (pid, ep, tenant, w["contiguous_seq"]))
            w["contiguous_seq"] = advance(w["contiguous_seq"], [x[0] for x in cur.fetchall()])
        self._save_watermark(cur, pid, ep, tenant, w, now)
        ledger.append(cur, self.signer, now, "event", "ACCEPTED", pid, tenant, env["event_id"],
                      {"type": env["type"], "epoch": ep, "seq": seq, "digest": digest, "evidence_level": "E0"})
        self._count("ACCEPTED")
        return 200, {"status": "accepted", "contiguous_seq": w["contiguous_seq"]}

    # ---- adapter_report (E1, no stream) ----
    def _adapter_report(self, cur, env, key, now) -> Tuple[int, Dict]:
        clean, digest = stored(env)
        b = env["body"]
        if not (isinstance(b.get("integration"), str) and isinstance(b.get("correlation_id"), str)
                and isinstance(b.get("claims"), dict)):
            return 400, {"error": "MALFORMED"}
        set_tenant(cur, env["tenant"])
        cur.execute("SELECT digest FROM events WHERE event_id=%s", (env["event_id"],))
        r = cur.fetchone()
        if r:
            if r[0].strip() == digest:
                return 200, {"status": "duplicate"}
            return self._refuse_tx(cur, now, env, "EVENT_CONFLICT", 409)
        cur.execute("INSERT INTO events (event_id, producer_id, epoch, tenant_id, seq, type, evidence_level, key_id, issued_at,"
                    " received_at, digest, envelope) VALUES (%s,%s,1,%s,NULL,'adapter_report','E1',%s,%s,%s,%s,%s)",
                    (env["event_id"], env["producer_id"], env["tenant"], env["key_id"], _dt(env["_issued"]), _dt(now),
                     digest, json.dumps(clean)))
        ledger.append(cur, self.signer, now, "event", "ACCEPTED", env["producer_id"], env["tenant"], env["event_id"],
                      {"type": "adapter_report", "digest": digest, "evidence_level": "E1"})
        return 200, {"status": "accepted", "evidence_level": "E1"}

    # ---- heartbeat (E0 claim, own counter, never consumes seq) ----
    @staticmethod
    def _hb_body_ok(b: Dict) -> bool:
        ts = b.get("tenants")
        if not isinstance(ts, dict) or not isinstance(b.get("outbox_depth"), int) or len(ts) > 10000:
            return False
        for t, v in ts.items():
            if not isinstance(v, dict) or set(v) - {"allocated_through_seq", "proof_n", "proof_head"}:
                return False
            a, n, h = v.get("allocated_through_seq"), v.get("proof_n"), v.get("proof_head")
            if not (isinstance(a, int) and not isinstance(a, bool) and a >= 0):
                return False
            if n is not None and not (isinstance(n, int) and n >= 0):
                return False
            if h is not None and not (isinstance(h, str) and len(h) == 64 and set(h) <= HEX64):
                return False
        return True

    def _heartbeat(self, cur, env, key, now, current, status) -> Tuple[int, Dict]:
        pid, ep, hb = env["producer_id"], env["epoch"], env["hb_seq"]
        clean, digest = stored(env)
        b = env["body"]
        if not self._hb_body_ok(b):
            return self._refuse_tx(cur, now, env, "MALFORMED", 400, {"part": "heartbeat body"})
        p = self.manifest.producer(pid)
        if any(not p.allows_tenant(t) for t in b["tenants"]):
            return self._refuse_tx(cur, now, env, "TENANT_MISMATCH", 403)
        cur.execute("SELECT event_id, digest FROM heartbeats WHERE event_id=%s OR (producer_id=%s AND epoch=%s AND hb_seq=%s)",
                    (env["event_id"], pid, ep, hb))
        rows = cur.fetchall()
        if rows:
            if all(r[1].strip() == digest for r in rows):
                return 200, {"status": "duplicate"}
            return self._refuse_tx(cur, now, env, "EVENT_CONFLICT", 409, {"hb_seq": hb})
        refused = self._epoch_status(cur, now, env, current, status)
        if refused:
            return refused
        cur.execute("SELECT last_hb_seq FROM streams WHERE producer_id=%s AND epoch=%s", (pid, ep))
        last = cur.fetchone()[0]
        row = (env["event_id"], pid, ep, hb, env["key_id"], _dt(env["_issued"]), _dt(now), digest, json.dumps(clean))
        ins = ("INSERT INTO heartbeats (event_id, producer_id, epoch, hb_seq, status, key_id, issued_at, received_at, digest,"
               " envelope) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)")
        if hb <= last:                             # old / reordered: stored for audit, NEVER lowers any watermark
            cur.execute(ins, row[:4] + ("out_of_order",) + row[4:])
            self._alert(cur, now, "HEARTBEAT_OUT_OF_ORDER", env, {"hb_seq": hb, "newest_accepted": last})
            self._count("HEARTBEAT_OUT_OF_ORDER")
            return 200, {"status": "out_of_order"}
        regressions = []
        updates = []
        for t, v in sorted(b["tenants"].items()):
            w = self._watermark(cur, pid, ep, t)
            a, n, h = v["allocated_through_seq"], v.get("proof_n"), v.get("proof_head")
            if a < w["attested_seq"]:
                regressions.append({"tenant": t, "reason": "ALLOCATION_COUNTER_REGRESSED"})
            if n is not None and w["last_proof_n"] is not None and (
                    n < w["last_proof_n"] or (n == w["last_proof_n"] and h != w["last_proof_head"])):
                regressions.append({"tenant": t, "reason": "PROOF_HEAD_REGRESSED"})
            updates.append((t, w, a, n, h))
        if regressions:
            cur.execute(ins, row[:4] + ("regression",) + row[4:])
            self._quarantine(cur, now, env, "HEARTBEAT_CLAIM_REGRESSED", {"hb_seq": hb, "tenants": regressions})
            self._count("PRODUCER_REGRESSION")
            return 409, {"error": "PRODUCER_REGRESSION"}
        cur.execute(ins, row[:4] + ("accepted",) + row[4:])
        for t, w, a, n, h in updates:
            w["attested_seq"] = max(w["attested_seq"], a)
            if n is not None:
                w["last_proof_n"], w["last_proof_head"] = n, h
            self._save_watermark(cur, pid, ep, t, w, now)
            set_tenant(cur, t)
            cur.execute("INSERT INTO producer_claims (tenant_id, producer_id, epoch, hb_seq, allocated_through_seq, proof_n,"
                        " proof_head, received_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (t, pid, ep, hb, a, n, h, _dt(now)))
        set_tenant(cur, None)
        cur.execute("UPDATE streams SET last_hb_seq=%s, last_hb_received_at=%s, last_hb_issued_at=%s, silent_alerted=false"
                    " WHERE producer_id=%s AND epoch=%s", (hb, _dt(now), _dt(env["_issued"]), pid, ep))
        ledger.append(cur, self.signer, now, "heartbeat", "ACCEPTED", pid, None, env["event_id"],
                      {"epoch": ep, "hb_seq": hb, "digest": digest, "evidence_level": "E0", "tenants": len(updates)})
        self._count("HEARTBEAT")
        return 200, {"status": "accepted"}

    # ---- epoch change (operator recovery key only) ----
    def _epoch_change(self, cur, env, key, now) -> Tuple[int, Dict]:
        pid, b = env["producer_id"], env["body"]
        clean, digest = stored(env)
        ok = (isinstance(b.get("new_epoch"), int) and b["new_epoch"] == env["epoch"]
              and isinstance(b.get("last_trusted_seq_per_tenant"), dict)
              and all(isinstance(v, int) and v >= 0 for v in b["last_trusted_seq_per_tenant"].values())
              and isinstance(b.get("reason"), str) and 10 <= len(b["reason"]) <= 500 and set(b) == {
                  "new_epoch", "last_trusted_seq_per_tenant", "reason"})
        if not ok:
            return self._refuse_tx(cur, now, env, "MALFORMED", 400, {"part": "epoch_change body"})
        cur.execute("SELECT digest FROM epoch_changes WHERE event_id=%s", (env["event_id"],))
        r = cur.fetchone()
        if r:
            return (200, {"status": "duplicate"}) if r[0].strip() == digest else self._refuse_tx(
                cur, now, env, "EVENT_CONFLICT", 409)
        cur.execute("INSERT INTO producers (producer_id) VALUES (%s) ON CONFLICT DO NOTHING", (pid,))
        cur.execute("SELECT current_epoch FROM producers WHERE producer_id=%s FOR UPDATE", (pid,))
        current = cur.fetchone()[0]
        if b["new_epoch"] != current + 1:
            return self._refuse_tx(cur, now, env, "EPOCH_INVALID", 409, {"current_epoch": current})
        # audit F9: compare the operator's "last trusted" numbers with what the observer actually holds
        ahead = []
        for t, last in sorted(b["last_trusted_seq_per_tenant"].items()):
            cur.execute("SELECT contiguous_seq FROM watermarks WHERE producer_id=%s AND epoch=%s AND tenant_id=%s",
                        (pid, current, t))
            r = cur.fetchone()
            held = r[0] if r else 0
            if last > held:
                ahead.append({"tenant": t, "last_trusted_seq": last, "observer_contiguous_seq": held})
        cur.execute("INSERT INTO streams (producer_id, epoch) VALUES (%s,%s) ON CONFLICT DO NOTHING", (pid, current))
        cur.execute("UPDATE streams SET status='closed', reason='EPOCH_CHANGED' WHERE producer_id=%s AND epoch=%s"
                    " AND status='active'", (pid, current))
        cur.execute("UPDATE producers SET current_epoch=%s WHERE producer_id=%s", (b["new_epoch"], pid))
        cur.execute("INSERT INTO streams (producer_id, epoch) VALUES (%s,%s)", (pid, b["new_epoch"]))
        cur.execute("INSERT INTO epoch_changes (event_id, producer_id, new_epoch, key_id, received_at, digest, envelope)"
                    " VALUES (%s,%s,%s,%s,%s,%s,%s)", (env["event_id"], pid, b["new_epoch"], env["key_id"], _dt(now),
                                                       digest, json.dumps(clean)))
        self._alert(cur, now, "EPOCH_CHANGED", env, {"from": current, "to": b["new_epoch"],
                                                     "last_trusted_seq_per_tenant": b["last_trusted_seq_per_tenant"],
                                                     "reason": b["reason"], "recovery_key_id": env["key_id"],
                                                     "last_trusted_ahead": ahead})
        if ahead:                                  # recorded, not trusted: windows of the old epoch stay INCONCLUSIVE
            self._alert(cur, now, "EPOCH_LAST_TRUSTED_AHEAD", env, {"from": current, "tenants": ahead})
        return 200, {"status": "accepted", "epoch": b["new_epoch"]}

    # ---------------- liveness monitor (§5.5) ----------------
    def tick(self) -> List[str]:
        """Evaluate gap / tail / silence and append each NEW condition to the ledger once (re-armed when it clears)."""
        now = self.clock()

        def go(cur):
            raised = []
            cur.execute("SELECT s.producer_id, s.epoch, s.last_hb_received_at, s.silent_alerted FROM streams s"
                        " JOIN producers p ON p.producer_id = s.producer_id AND p.current_epoch = s.epoch WHERE s.status='active'")
            for pid, ep, last, alerted in cur.fetchall():
                if not alerted and (last is None or now - last.timestamp() > self.cfg.silent_after):
                    cur.execute("UPDATE streams SET silent_alerted=true WHERE producer_id=%s AND epoch=%s", (pid, ep))
                    ledger.append(cur, self.signer, now, "alert", "PRODUCER_SILENT", pid, None, None, {"epoch": ep})
                    raised.append("PRODUCER_SILENT:%s" % pid)
                cur.execute("SELECT tenant_id, gap_since, behind_since, gap_alerted, behind_alerted, contiguous_seq, max_seq,"
                            " attested_seq FROM watermarks WHERE producer_id=%s AND epoch=%s", (pid, ep))
                for t, gs, bs, ga, ba, c, m, a in cur.fetchall():
                    if gs is not None and not ga and now - gs.timestamp() > self.cfg.G:
                        cur.execute("UPDATE watermarks SET gap_alerted=true WHERE producer_id=%s AND epoch=%s AND tenant_id=%s", (pid, ep, t))
                        ledger.append(cur, self.signer, now, "alert", "DECISION_FEED_GAP", pid, t, None,
                                      {"epoch": ep, "contiguous_seq": c, "max_seq": m})
                        raised.append("DECISION_FEED_GAP:%s" % t)
                    if bs is not None and not ba and now - bs.timestamp() > self.cfg.G:
                        cur.execute("UPDATE watermarks SET behind_alerted=true WHERE producer_id=%s AND epoch=%s AND tenant_id=%s", (pid, ep, t))
                        ledger.append(cur, self.signer, now, "alert", "DECISION_FEED_GAP", pid, t, None,
                                      {"epoch": ep, "tail": True, "contiguous_seq": c, "attested_seq": a})
                        raised.append("DECISION_FEED_GAP_TAIL:%s" % t)
            return raised
        return self.db.run(go)

    def status(self) -> Dict:
        now = self.clock()

        def go(cur):
            cur.execute("SELECT n, hash FROM ledger ORDER BY n DESC LIMIT 1")
            head = cur.fetchone()
            cur.execute("SELECT s.producer_id, s.epoch, s.status, s.reason, s.last_hb_seq, s.last_hb_received_at, p.current_epoch"
                        " FROM streams s JOIN producers p USING (producer_id) ORDER BY 1, 2")
            streams = cur.fetchall()
            cur.execute("SELECT producer_id, epoch, tenant_id, contiguous_seq, max_seq, attested_seq, gap_since, behind_since"
                        " FROM watermarks ORDER BY 1, 2, 3")
            wms = cur.fetchall()
            return head, streams, wms
        head, streams, wms = self.db.run(go, lock=False)
        out = []
        for pid, ep, st, reason, hb, last, cur_ep in streams:
            w = [{"tenant_id": r[2], "contiguous_seq": r[3], "max_seq": r[4], "attested_seq": r[5],
                  "gap_since": _ts(r[6]), "behind_since": _ts(r[7])} for r in wms if r[0] == pid and r[1] == ep]
            s = {"status": st, "last_hb_received_at": _ts(last)}
            out.append({"producer_id": pid, "epoch": ep, "current": ep == cur_ep, "status": st, "reason": reason,
                        "last_hb_seq": hb, "heartbeat_age_s": None if last is None else round(now - last.timestamp(), 1),
                        "conditions": feed_conditions(now, s, w, self.cfg) if ep == cur_ep else ["EPOCH_CLOSED"],
                        "watermarks": [{k: v for k, v in x.items() if k not in ("gap_since", "behind_since")} for x in w]})
        return {"observer_key_id": self.key_id, "manifest_version": self.manifest.version, "degraded": self.degraded,
                "ledger": {"n": head[0] if head else 0, "head": head[1].strip() if head else ledger.GENESIS},
                "streams": out, "counters": dict(self.counters),
                "sensors": {}, "coverage": {"mediated": False, "reason": "NO_SENSORS (C3/C5 not implemented)"},
                "evidence": "claims only (E0/E1); no observer-originated evidence exists in C1-C2, so no result can be "
                            "ENFORCEMENT_VERIFIED"}
