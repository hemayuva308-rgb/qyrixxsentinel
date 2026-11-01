"""Bearer-token auth with two roles. Unset/short tokens disable that role (fail closed: nobody can log in)."""
import hmac, os
from fastapi import Depends, Header, HTTPException

MIN_TOKEN_LEN = 24
PLACEHOLDER_PREFIX = "CHANGE_ME"  # values copied from .env.example must never authenticate


def _match(presented: str, env_name: str) -> bool:
    expected = os.getenv(env_name, "")
    return len(expected) >= MIN_TOKEN_LEN and not expected.startswith(PLACEHOLDER_PREFIX) and hmac.compare_digest(presented.encode(), expected.encode())


def principal(authorization: str = Header(default="")) -> str:
    if not authorization.startswith("Bearer "):
        raise HTTPException(401, "authentication required")
    tok = authorization[7:]
    if _match(tok, "QYRIX_ADMIN_TOKEN"):
        return "admin"
    if _match(tok, "QYRIX_AGENT_TOKEN"):
        return "agent"
    raise HTTPException(401, "invalid credentials")


def require_admin(p: str = Depends(principal)) -> str:
    if p != "admin":
        raise HTTPException(403, "admin role required")
    return p
