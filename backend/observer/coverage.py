"""Signed coverage attestation (C5, design §7.3, §11).

The host attestor (observer/attestor.py, root on the Docker host - boundary D) inspects the RUNNING backend container
and probes from INSIDE its network namespace. It signs what it did and saw with an attestor key listed in the root-
signed manifest. The observer then JUDGES the network evidence itself, from its own sensors (§7.3 step 3):
  - every direct-path probe token must be ABSENT at the observer sink;
  - the positive-control token must be PRESENT at the sink AND its request recorded by the egress proxy (mediated);
  - the SNI-mismatch tunnel must have been refused by the proxy;
  - the DNS probe name must have reached the observer resolver.
An attestation is valid only if the signature, key, freshness, validity (<= 1 h), every attestor check AND every
observer check pass. Coverage for a window exists only if a valid attestation covers the WHOLE window and the
container the backend's heartbeat claims to be is the attested one (a claim can only invalidate, never validate)."""
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from observer import crypto, ledger
from observer.canonical import canonical
from observer.manifest import parse_time

FORMAT = "qyrix-coverage-attestation/1"
REQUIRED_ATTESTOR_CHECKS = ("container_running", "network_mode_not_host", "not_privileged", "cap_drop_all", "no_cap_add",
                            "networks_exact", "dns_is_observer", "ipv6_disabled_sysctl", "no_default_route",
                            "no_global_ipv6", "docker_user_rules_v4", "docker_user_rules_v6")
DIRECT_PROBES = ("ipv4_tcp_80", "ipv4_tcp_443", "ipv4_tcp_853", "dns_udp_direct")
MAX_VALIDITY = 3600.0


def _dt(t: float) -> datetime:
    return datetime.fromtimestamp(t, timezone.utc)


class CoverageService:
    def __init__(self, observer, clock=None):
        self.obs, self.db = observer, observer.db
        self.clock = clock or observer.clock
        self._gap_alerted = False

    def _key(self, kid: str):
        return self.obs.manifest.attestor_keys.get(kid)

    def submit(self, doc: Dict) -> Dict:
        """Verify, judge and store one attestation. Always stored (valid or not) so a failed attestation is evidence."""
        now = self.clock()
        reasons: List[str] = []
        if not isinstance(doc, dict) or doc.get("format") != FORMAT:
            return {"stored": False, "error": "MALFORMED"}
        k = self._key(str(doc.get("attestor_key_id", "")))
        body = {x: y for x, y in doc.items() if x != "sig"}
        if k is None or not k.valid_at(now) or not crypto.verify(k.public, str(doc.get("sig", "")), canonical(body)):
            return {"stored": False, "error": "SIGNATURE_INVALID"}         # unauthenticated: never stored
        try:
            at, until = parse_time(doc["attested_at"]), parse_time(doc["valid_until"])
            aid = str(uuid.UUID(doc["attestation_id"]))
            cid = str(doc["container_id"])[:128]
            checks, probes = dict(doc["attestor_checks"]), dict(doc["probes"])
        except (KeyError, TypeError, ValueError):
            return {"stored": False, "error": "MALFORMED"}
        if doc.get("channel") != "http":
            return {"stored": False, "error": "MALFORMED"}
        if abs(now - at) > self.obs.cfg.S:
            reasons.append("STALE_OR_FUTURE_ATTESTATION")
        if not (at < until <= at + MAX_VALIDITY):
            return {"stored": False, "error": "VALIDITY_INVALID"}
        for c in REQUIRED_ATTESTOR_CHECKS:
            if checks.get(c) is not True:
                reasons.append("ATTESTOR_CHECK_FAILED:" + c)
        oc = self._judge(probes, at)
        reasons += ["OBSERVER_CHECK_FAILED:" + n for n, ok in oc.items() if not ok]
        valid = not reasons

        def go(cur):
            cur.execute("INSERT INTO coverage_attestations (attestation_id, channel, container_id, image, attestor_key_id,"
                        " attested_at, valid_until, received_at, attestor_checks, observer_checks, valid, reasons, doc)"
                        " VALUES (%s,'http',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                        (aid, cid, str(doc.get("image", ""))[:256], k.key_id, _dt(at), _dt(until), _dt(now),
                         json.dumps(checks), json.dumps(oc), valid, reasons, json.dumps(doc)))
            ledger.append(cur, self.obs.signer, now, "coverage" if valid else "alert",
                          "COVERAGE_ATTESTED" if valid else "COVERAGE_GAP", None, None, aid,
                          {"container_id": cid, "valid": valid, "reasons": reasons})
        self.db.run(go)
        if valid:
            self._gap_alerted = False
        return {"stored": True, "attestation_id": aid, "valid": valid, "reasons": reasons, "observer_checks": oc}

    def _judge(self, probes: Dict, at: float) -> Dict[str, bool]:
        """The observer's own verdict on the network evidence (never the attestor's word)."""
        since = _dt(at - 300)

        def go(cur):
            out = {}
            for name in DIRECT_PROBES:
                p = probes.get(name) or {}
                h = p.get("token_sha256")
                if not (isinstance(h, str) and len(h) == 64):
                    out["direct_probe_declared:" + name] = False
                    continue
                cur.execute("SELECT count(*) FROM egress_observations WHERE kind='sink_hit' AND token_sha256=%s AND observed_at >= %s",
                            (h, since))
                out["direct_path_blocked:" + name] = cur.fetchone()[0] == 0
            pc = probes.get("positive_control") or {}
            cur.execute("SELECT count(*) FROM egress_observations WHERE kind='sink_hit' AND token_sha256=%s AND observed_at >= %s",
                        (pc.get("token_sha256", ""), since))
            hit = cur.fetchone()[0] > 0
            cur.execute("SELECT count(*) FROM egress_observations WHERE kind='http_request' AND execution_id::text=%s AND observed_at >= %s",
                        (str(pc.get("execution_id", "")), since))
            out["positive_control_reached_sink"] = hit
            out["positive_control_mediated_by_proxy"] = cur.fetchone()[0] > 0
            sm = probes.get("sni_mismatch") or {}
            cur.execute("SELECT count(*) FROM egress_observations WHERE kind='refused' AND reason='SNI_MISMATCH'"
                        " AND execution_id::text=%s AND observed_at >= %s", (str(sm.get("execution_id", "")), since))
            out["sni_mismatch_refused"] = cur.fetchone()[0] > 0
            dn = probes.get("dns_mediated") or {}
            cur.execute("SELECT count(*) FROM egress_observations WHERE kind='dns_query' AND qname=%s AND observed_at >= %s",
                        (str(dn.get("qname", "")).lower(), since))
            out["dns_reaches_observer_resolver"] = cur.fetchone()[0] > 0
            return out
        return self.db.run(go, lock=False)

    def current(self, t_from: float, t_to: float, container_claim: Optional[str]) -> Optional[Dict]:
        """Coverage for [t_from, t_to]: the LATEST attestation made at or before t_to decides (a newer FAILED attestation
        revokes coverage at once - an older valid one cannot outlive it). It must be valid, made at or before t_from,
        valid until at least t_to, and attest the container the backend claims to run in."""
        def go(cur):
            cur.execute("SELECT attestation_id, container_id, attested_at, valid_until, valid FROM coverage_attestations"
                        " WHERE attested_at <= %s ORDER BY attested_at DESC, received_at DESC LIMIT 1", (_dt(t_to),))
            return cur.fetchone()
        r = self.db.run(go, lock=False)
        if r is None:
            return None
        aid, cid, at, until, valid = r
        if not valid or at.timestamp() > t_from or until.timestamp() < t_to:
            return None
        if container_claim and not (cid.startswith(container_claim) or container_claim.startswith(cid)):
            return None                                   # the backend moved/restarted since: attestation is stale
        return {"mediated": True, "attestation_id": str(aid), "container_id": cid, "attested_at": at.isoformat(),
                "valid_until": until.isoformat()}

    def tick(self) -> Optional[str]:
        """COVERAGE_GAP alert once when no valid attestation covers 'now' (re-armed by the next valid one)."""
        now = self.clock()
        if self.current(now, now, None) is not None:
            self._gap_alerted = False
            return None
        if self._gap_alerted:
            return None
        self._gap_alerted = True
        self.db.run(lambda cur: ledger.append(cur, self.obs.signer, now, "alert", "COVERAGE_GAP", None, None, None,
                                              {"reason": "NO_CURRENT_VALID_ATTESTATION"}))
        return "COVERAGE_GAP"

    def status(self) -> Dict:
        now = self.clock()
        c = self.current(now, now, None)
        return {"mediated": c is not None, "current": c}


def sign_attestation(doc: Dict, key) -> Dict:
    kid, _ = crypto.describe(key)
    body = {**{k: v for k, v in doc.items() if k != "sig"}, "format": FORMAT, "attestor_key_id": kid}
    return {**body, "sig": crypto.sign(key, canonical(body))}


def attestation_skeleton(container_id: str, image: str, checks: Dict, probes: Dict, now: Optional[float] = None,
                         validity: float = MAX_VALIDITY) -> Dict:
    now = now if now is not None else time.time()
    return {"format": FORMAT, "attestation_id": str(uuid.uuid4()), "channel": "http", "container_id": container_id,
            "image": image, "attested_at": _dt(now).isoformat(), "valid_until": _dt(now + validity).isoformat(),
            "attestor_checks": checks, "probes": probes}
