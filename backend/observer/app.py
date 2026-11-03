"""Observer HTTP API (design §12), C1 subset: POST /v1/events, GET /v1/health, GET /v1/status.
/v1/canaries/run, /v1/reconciliations and /v1/evidence/export belong to C3/C4/C7 and are not exposed."""
import hashlib
import hmac
import threading
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from observer.envelope import MAX_BYTES
from observer.ingest import Observer


def create_app(obs: Observer, operator_token: Optional[str]) -> FastAPI:
    app = FastAPI(title="Qyrix Observer", version="c1", docs_url=None, redoc_url=None, openapi_url=None)
    want = hashlib.sha256(operator_token.encode()).digest() if operator_token else None
    lock = threading.Lock()

    @app.post("/v1/events")
    async def events(request: Request):
        raw = b""
        async for chunk in request.stream():           # bounded read: never buffer more than the envelope limit
            raw += chunk
            if len(raw) > MAX_BYTES:
                return JSONResponse({"error": "OVERSIZE"}, status_code=413)
        status, body = obs.ingest(raw)
        return JSONResponse(body, status_code=status)

    @app.get("/v1/health")
    def health():
        return {"health": "ok"}                         # liveness only, no data

    @app.get("/v1/status")
    def status(authorization: str = Header(default="")):
        if want is None:
            raise HTTPException(503, "OPERATOR_TOKEN_NOT_CONFIGURED")
        tok = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not tok or not hmac.compare_digest(hashlib.sha256(tok.encode()).digest(), want):
            raise HTTPException(401, "OPERATOR_AUTH_REQUIRED")
        with lock:
            return obs.status()

    return app
