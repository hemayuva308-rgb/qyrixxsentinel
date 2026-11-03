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


def create_app(obs: Observer, operator_token: Optional[str], canaries=None) -> FastAPI:
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

    def operator(authorization: str):
        if want is None:
            raise HTTPException(503, "OPERATOR_TOKEN_NOT_CONFIGURED")
        tok = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not tok or not hmac.compare_digest(hashlib.sha256(tok.encode()).digest(), want):
            raise HTTPException(401, "OPERATOR_AUTH_REQUIRED")

    @app.get("/v1/status")
    def status(authorization: str = Header(default="")):
        operator(authorization)
        with lock:
            out = obs.status()
        if canaries is not None:
            out["canaries"] = {"http_sensor": canaries.http.counters if canaries.http else None,
                               "file_sensor": canaries.file.counters if canaries.file else None,
                               "unrecorded_sensor_hits": canaries.unrecorded, "p2_live": canaries.p2.live}
        return out

    # C3 canaries (operator only; the canary sensors themselves are separate loopback listeners)
    @app.post("/v1/canaries/run")
    def canary_run(body: dict, authorization: str = Header(default="")):
        operator(authorization)
        if canaries is None:
            raise HTTPException(503, "CANARIES_NOT_CONFIGURED")
        from observer.canary import CanaryError
        from observer.db import DbError
        try:
            r = canaries.start(str(body.get("tenant", "")), str(body.get("channel", "http")))
        except CanaryError as e:
            raise HTTPException(400, str(e))
        except DbError:
            raise HTTPException(503, "OBSERVER_DB_UNAVAILABLE")
        return {"run_id": r["run_id"], "correlation_id": r["correlation_id"],
                "submission": {k: v for k, v in r["submission"].items() if k in ("submitted", "disabled", "status", "error")}}

    @app.get("/v1/canaries/{tenant}/{run_id}")
    def canary_get(tenant: str, run_id: str, authorization: str = Header(default="")):
        operator(authorization)
        if canaries is None:
            raise HTTPException(503, "CANARIES_NOT_CONFIGURED")
        import uuid as _u
        try:
            _u.UUID(run_id)
        except ValueError:
            raise HTTPException(404, "NOT_FOUND")
        d = canaries.run_detail(tenant, run_id)
        if d is None:
            raise HTTPException(404, "NOT_FOUND")
        return d

    return app
