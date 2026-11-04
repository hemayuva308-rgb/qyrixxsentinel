"""Observer HTTP API (design §12), C1 subset: POST /v1/events, GET /v1/health, GET /v1/status.
/v1/canaries/run, /v1/reconciliations and /v1/evidence/export belong to C3/C4/C7 and are not exposed."""
import asyncio
import hashlib
import hmac
import threading
import time
from collections import OrderedDict
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

MAX_INFLIGHT = 32            # audit F3: bounded concurrent ingest work (threadpool), excess => 503
RATE_BURST, RATE_PER_S, RATE_SOURCES = 200.0, 100.0, 4096   # audit F1: per-source token bucket, bounded LRU

from observer.envelope import MAX_BYTES
from observer.ingest import Observer


def create_app(obs: Observer, operator_token: Optional[str], canaries=None, read_tokens=None, c5=None) -> FastAPI:
    """read_tokens: [{"sha256": <hex of a read token>, "tenants": ["t1", ...] | ["*"]}] - READ-ONLY, tenant-scoped
    keys for GET /v1/reconciliations (e.g. the dashboard proxy); they cannot start canaries or read status."""
    app = FastAPI(title="Qyrix Observer", version="c1", docs_url=None, redoc_url=None, openapi_url=None)
    want = hashlib.sha256(operator_token.encode()).digest() if operator_token else None
    lock = threading.Lock()
    inflight = asyncio.Semaphore(MAX_INFLIGHT)
    buckets: "OrderedDict[str, list]" = OrderedDict()
    counters = {"rate_limited": 0, "busy": 0}

    def allow(source: str) -> bool:
        now = time.monotonic()
        b = buckets.pop(source, None) or [RATE_BURST, now]
        b[0] = min(RATE_BURST, b[0] + (now - b[1]) * RATE_PER_S)
        b[1] = now
        ok = b[0] >= 1.0
        if ok:
            b[0] -= 1.0
        buckets[source] = b
        while len(buckets) > RATE_SOURCES:
            buckets.popitem(last=False)
        return ok

    @app.post("/v1/events")
    async def events(request: Request):
        if not allow(request.client.host if request.client else "unknown"):
            counters["rate_limited"] += 1                # not ledgered: a flood cannot grow evidence (F1)
            return JSONResponse({"error": "RATE_LIMITED"}, status_code=429)
        raw = b""
        async for chunk in request.stream():           # bounded read: never buffer more than the envelope limit
            raw += chunk
            if len(raw) > MAX_BYTES:
                return JSONResponse({"error": "OVERSIZE"}, status_code=413)
        if inflight.locked():
            counters["busy"] += 1
            return JSONResponse({"error": "OBSERVER_BUSY"}, status_code=503)
        async with inflight:                             # F3: DB, locks and signing run in the threadpool, not the loop
            status, body = await run_in_threadpool(obs.ingest, raw)
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
        out["ingest"] = dict(counters)
        if c5 is not None:
            out["coverage"] = c5["coverage"].status()
            out["egress"] = {"counters": dict(c5["recorder"].counters), "open_tunnels": len(c5["proxy"].open_tunnels)}
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

    keys = []
    for k in read_tokens or []:
        hx = str(k.get("sha256", "")).lower()
        if len(hx) == 64 and all(c in "0123456789abcdef" for c in hx) and isinstance(k.get("tenants"), list):
            keys.append((bytes.fromhex(hx), frozenset(str(t) for t in k["tenants"])))

    def reader_tenants(authorization: str):
        tok = authorization[7:] if authorization.startswith("Bearer ") else ""
        if not tok:
            raise HTTPException(401, "READ_AUTH_REQUIRED")
        d = hashlib.sha256(tok.encode()).digest()
        if want is not None and hmac.compare_digest(d, want):
            return None                                  # operator: every tenant
        found = None
        for kd, tenants in keys:                         # compare against every key (no early exit on a match)
            if hmac.compare_digest(d, kd):
                found = tenants
        if found is None:
            raise HTTPException(401, "READ_AUTH_REQUIRED")
        return found

    @app.get("/v1/reconciliations")
    def reconciliations(tenant: str, since: Optional[str] = None, limit: int = 100, authorization: str = Header(default="")):
        allowed = reader_tenants(authorization)
        from observer.envelope import TENANT_RE
        if not TENANT_RE.match(tenant):
            raise HTTPException(400, "INVALID_TENANT")
        if allowed is not None and "*" not in allowed and tenant not in allowed:
            raise HTTPException(403, "TENANT_NOT_ALLOWED")
        if canaries is None:
            raise HTTPException(503, "CANARIES_NOT_CONFIGURED")
        t = None
        if since:
            from observer.manifest import parse_time
            try:
                t = parse_time(since)
            except ValueError:
                raise HTTPException(400, "INVALID_SINCE")
        from observer.db import DbError
        try:
            rows = canaries.list_reconciliations(tenant, t, max(1, min(int(limit), 500)))
        except DbError:
            raise HTTPException(503, "OBSERVER_DB_UNAVAILABLE")
        cov = c5["coverage"].status() if c5 is not None else {"mediated": False}
        return {"tenant": tenant, "scope": "canary", "reconciliations": rows,
                "verified_possible": bool(cov.get("mediated")),
                "note": "ENFORCEMENT_VERIFIED requires a current, valid, signed coverage attestation of the backend's "
                        "network namespace (C5) plus every other condition; otherwise an absent observation is INCONCLUSIVE."}

    # C5: signed coverage attestations from the host attestor (operator credential over mTLS; signature checked too)
    @app.post("/v1/coverage/attestations")
    def coverage_submit(body: dict, authorization: str = Header(default="")):
        operator(authorization)
        if c5 is None:
            raise HTTPException(503, "C5_TOPOLOGY_NOT_ENABLED")
        from observer.db import DbError
        try:
            r = c5["coverage"].submit(body)
        except DbError:
            raise HTTPException(503, "OBSERVER_DB_UNAVAILABLE")
        if not r.get("stored"):
            raise HTTPException(400, r.get("error", "REFUSED"))
        return r

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
