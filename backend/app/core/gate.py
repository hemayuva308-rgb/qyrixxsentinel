import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from app.core.constants import ALLOWED_API_ROOTS, ALLOWED_EXACT_PATHS, SOLE_PATH_PREFIX


class QyrixGateMiddleware(BaseHTTPMiddleware):
    """Sole-path enforcement: only /api/v1/* (and /) are served."""
    async def dispatch(self, request: Request, call_next):
        start, path = time.time(), request.url.path
        if path not in ALLOWED_EXACT_PATHS and not any(path == p or path.startswith(p + "/") for p in ALLOWED_API_ROOTS):
            return JSONResponse(status_code=400, content={"error": "SOLE_PATH_VIOLATION", "allowed": ALLOWED_API_ROOTS})
        resp = await call_next(request)
        resp.headers["X-Qyrix-Gate"] = "enforced"
        resp.headers["X-Sole-Path"] = SOLE_PATH_PREFIX
        resp.headers["X-Time"] = "%sms" % round((time.time() - start) * 1000, 2)
        resp.headers["Cache-Control"] = "no-store"
        return resp
