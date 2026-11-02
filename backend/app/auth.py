"""FastAPI authentication / authorization dependencies. All checks are server-side; see app/identity.py."""
import os
from typing import Callable

from fastapi import Depends, Header, HTTPException, Request

from app import identity
from app.identity import AuthError, Principal

MIN_TOKEN_LEN = identity.MIN_TOKEN_LEN
PLACEHOLDER_PREFIX = identity.PLACEHOLDER_PREFIX


def client_key(request: Request) -> str:
    """Client identity for auth-failure throttling. The forwarded header is trusted only when the deployment says the
    backend sits behind our own frontend (QYRIX_TRUST_CLIENT_HEADER=1, set in docker-compose)."""
    if os.getenv("QYRIX_TRUST_CLIENT_HEADER") == "1":
        h = (request.headers.get("x-qyrix-client") or "").strip()[:64]
        if h:
            return h
    return request.client.host if request.client else "unknown"


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
    import hmac as _h
    expected = os.getenv(env_name, "")
    return (len(expected) >= MIN_TOKEN_LEN and not expected.startswith(PLACEHOLDER_PREFIX)
            and _h.compare_digest(presented.encode(), expected.encode()))
