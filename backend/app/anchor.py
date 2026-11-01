"""External proof anchoring with RFC 3161 trusted timestamps (no blockchain).

The SHA-256 head hash of the canonical proof chain is sent as the message imprint to a Time-Stamp Authority (TSA).
The signed TimeStampToken proves that the chain, up to record n, existed unchanged at the TSA's time. Anyone holding
the TSA's CA certificate can verify it independently:   openssl ts -verify -digest <head> -in token.tsr -CAfile tsa-ca.pem

Configuration (all optional; without them anchoring is NOT_CONFIGURED and verification stays PARTIAL_UNANCHORED):
  QYRIX_TSA_URL               https://... or http://... RFC 3161 endpoint (needs network egress from the backend)
  QYRIX_TSA_CA_FILE           PEM trust anchor(s) for the TSA certificate chain
  QYRIX_TSA_UNTRUSTED_FILE    optional PEM intermediates
  QYRIX_TSA_TIMEOUT_SECONDS   default 10

Rules: an anchor is stored ONLY after its token verified against the configured CA and matched the request nonce and
imprint. Anchoring never influences Gate decisions; a TSA failure only means the evidence stays unanchored.
Verification uses the system `openssl` binary (present in the backend image).
"""
import base64
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple

import httpx

HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AnchorError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


def config() -> Dict[str, Optional[str]]:
    return {"url": os.getenv("QYRIX_TSA_URL", "").strip() or None, "ca": os.getenv("QYRIX_TSA_CA_FILE", "").strip() or None,
            "untrusted": os.getenv("QYRIX_TSA_UNTRUSTED_FILE", "").strip() or None,
            "timeout": float(os.getenv("QYRIX_TSA_TIMEOUT_SECONDS", "10"))}


def problem() -> Optional[str]:
    c = config()
    if not shutil.which("openssl"):
        return "openssl binary not available"
    if not c["url"] or not re.match(r"^https?://", c["url"]):
        return "QYRIX_TSA_URL not configured"
    if not c["ca"] or not os.path.isfile(c["ca"]):
        return "QYRIX_TSA_CA_FILE not configured"
    return None


def can_verify() -> bool:
    c = config()
    return bool(shutil.which("openssl") and c["ca"] and os.path.isfile(c["ca"]))


def _openssl(*args: str, timeout: float = 20) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], capture_output=True, text=True, timeout=timeout)


def verify_token(head_hash: str, token_b64: str, queryfile: Optional[str] = None) -> Tuple[bool, str]:
    """Independent cryptographic verification of a stored token against the configured TSA CA."""
    if not HEX64.match(head_hash or ""):
        return False, "malformed head hash"
    c = config()
    if not can_verify():
        return False, "no TSA CA configured"
    with tempfile.TemporaryDirectory(prefix="qyrix-tsa-") as d:
        tsr = os.path.join(d, "token.tsr")
        try:
            raw = base64.b64decode(token_b64, validate=True)
        except Exception:
            return False, "token not base64"
        open(tsr, "wb").write(raw)
        args = ["ts", "-verify", "-in", tsr, "-CAfile", c["ca"]]
        args += ["-queryfile", queryfile] if queryfile else ["-digest", head_hash]
        if c["untrusted"]:
            args += ["-untrusted", c["untrusted"]]
        try:
            r = _openssl(*args)
        except Exception as e:
            return False, "openssl failed: " + type(e).__name__
        ok = r.returncode == 0 and "Verification: OK" in (r.stdout + r.stderr)
        return ok, "Verification: OK" if ok else (r.stdout + r.stderr).strip().splitlines()[-1][:160] if (r.stdout + r.stderr).strip() else "verification failed"


def _token_info(tsr: str) -> Dict[str, Optional[str]]:
    r = _openssl("ts", "-reply", "-in", tsr, "-text")
    t = r.stdout
    gen = re.search(r"Time stamp:\s*(.+)", t)
    ser = re.search(r"Serial number:\s*(\S+)", t)
    status = re.search(r"Status:\s*(.+)", t)
    return {"gen_time": gen.group(1).strip() if gen else None, "serial": ser.group(1).strip() if ser else None,
            "status": status.group(1).strip() if status else None}


def create_anchor(head_hash: str, n: int) -> Dict:
    """Request, verify and return an anchor for chain record n. Raises AnchorError; never returns an unverified anchor."""
    p = problem()
    if p:
        raise AnchorError("ANCHOR_NOT_CONFIGURED", p)
    if not HEX64.match(head_hash or "") or n < 1:
        raise AnchorError("EMPTY_PROOF_BUNDLE", "nothing to anchor")
    c = config()
    with tempfile.TemporaryDirectory(prefix="qyrix-tsa-") as d:
        tsq, tsr = os.path.join(d, "req.tsq"), os.path.join(d, "resp.tsr")
        q = _openssl("ts", "-query", "-digest", head_hash, "-sha256", "-cert", "-out", tsq)
        if q.returncode != 0:
            raise AnchorError("ANCHOR_REQUEST_FAILED", "could not build TimeStampReq")
        try:
            resp = httpx.post(c["url"], content=open(tsq, "rb").read(), timeout=c["timeout"],
                              headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"})
        except Exception as e:
            raise AnchorError("ANCHOR_UNAVAILABLE", "TSA unreachable: " + type(e).__name__)
        if resp.status_code != 200 or not resp.content:
            raise AnchorError("ANCHOR_UNAVAILABLE", "TSA HTTP %s" % resp.status_code)
        open(tsr, "wb").write(resp.content)
        info = _token_info(tsr)
        if not info["status"] or not info["status"].lower().startswith("granted"):
            raise AnchorError("ANCHOR_REJECTED", "TSA status: %s" % info["status"])
        token_b64 = base64.b64encode(resp.content).decode()
        ok, detail = verify_token(head_hash, token_b64, queryfile=tsq)    # imprint + nonce + signature + chain
        if not ok:
            raise AnchorError("ANCHOR_INVALID", detail)
        return {"id": str(uuid.uuid4()), "n": n, "head_hash": head_hash, "method": "rfc3161", "tsa_url": c["url"],
                "token_b64": token_b64, "gen_time": info["gen_time"], "serial": info["serial"],
                "created_at": datetime.now(timezone.utc).isoformat()}
