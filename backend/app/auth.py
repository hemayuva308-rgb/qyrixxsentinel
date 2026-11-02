"""FastAPI authentication / authorization dependencies. All checks are server-side; see app/identity.py."""
import hashlib
import hmac
import os
import time
from typing import Callable, Optional

from fastapi import Depends, Header, HTTPException, Request

from app import identity, observability as obs
from app.identity import AuthError, Principal

MIN_TOKEN_LEN = identity.MIN_TOKEN_LEN
PLACEHOLDER_PREFIX = identity.PLACEHOLDER_PREFIX


CLIENT_HEADER = "x-qyrix-client"
CLIENT_MAX_AGE = 120


def _client_sig_key() -> bytes:
    p = os.getenv("QYRIX_CLIENT_SIG_KEY_FILE", "").strip()
    try:
        k = open(p, "rb").read().strip() if p else b""
    except OSError:
        return b""
    return k if len(k) >= 32 and b"CHANGE_ME" not in k else b""


def sign_client(ip: str, key: bytes, ts: Optional[int] = None) -> str:
    """Frontend-side format (frontend/src/lib/backend.ts implements the same): v1|<ip or 'unknown'>|<unix ts>|<hmac>."""
    ts = int(time.time()) if ts is None else ts
    msg = "v1|%s|%d" % (ip, ts)
    return msg + "|" + hmac.new(key, msg.encode(), hashlib.sha256).hexdigest()


def client_key(request: Request) -> str:
    """Client identity for per-IP limits. Client-supplied headers are NEVER trusted as such:
    * a value relayed by our frontend counts only if it carries a valid, fresh HMAC under the shared key
      (QYRIX_CLIENT_SIG_KEY_FILE, a secret mounted into frontend and backend only); the frontend itself derives the IP
      only from operator-declared trusted proxy hops, else it says 'unknown';
    * otherwise the TCP peer address is used (direct API callers).
    'unknown' disables per-IP limits for that request (per-account and global limits still apply)."""
    raw = (request.headers.get(CLIENT_HEADER) or "").strip()[:200]
    key = _client_sig_key()
    if raw and key:
        parts = raw.split("|")
        if len(parts) == 4 and parts[0] == "v1":
            try:
                fresh = abs(time.time() - int(parts[2])) <= CLIENT_MAX_AGE
            except ValueError:
                fresh = False
            good = hmac.compare_digest(hmac.new(key, "|".join(parts[:3]).encode(), hashlib.sha256).hexdigest(), parts[3])
            ip = parts[1]
            if good and fresh and (ip == "unknown" or _valid_ip(ip)):
                return "unknown" if ip == "unknown" else "ip:" + ip
        obs.inc("qyrix_client_identity_rejected_total")
    return "tcp:" + (request.client.host if request.client else "unknown")


def _valid_ip(ip: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def principal(request: Request, authorization: str = Header(default="")) -> Principal:
    client = client_key(request)
    try:
        identity.check_auth_failures_allowed(client)
        if not authorization.startswith("Bearer "):
            identity.record_auth_failure(client, "missing")
            raise AuthError(401, "authentication required")
        try:
            p = identity.authenticate(authorization[7:])
        except AuthError as e:
            if e.status == 401:
                identity.record_auth_failure(client, "invalid")
            raise
        identity.check_rate(p)
        return p
    except AuthError as e:
        raise HTTPException(e.status, e.detail)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "authentication unavailable")      # identity store down => fail closed


def require(perm: str) -> Callable[..., Principal]:
    def dep(p: Principal = Depends(principal)) -> Principal:
        if not p.can(perm):
            raise HTTPException(403, "%s role required" % ("tenant" if p.platform else "permission '%s'" % perm))
        return p
    return dep


def require_platform(p: Principal = Depends(principal)) -> Principal:
    if not p.platform:
        raise HTTPException(403, "platform operator only")
    return p


# v1.1 compatibility: "admin role required" endpoints map to explicit permissions.
def require_admin(p: Principal = Depends(principal)) -> Principal:
    if not p.can("approval.decide") or p.role == "approver":
        raise HTTPException(403, "admin role required")
    return p


def _match(presented: str, env_name: str) -> bool:
    """v1.1 helper kept for compatibility: does `presented` equal a usable (>=24 chars, non-placeholder) env token?"""
    expected = os.getenv(env_name, "")
    return (len(expected) >= MIN_TOKEN_LEN and not expected.startswith(PLACEHOLDER_PREFIX)
            and hmac.compare_digest(presented.encode(), expected.encode()))
