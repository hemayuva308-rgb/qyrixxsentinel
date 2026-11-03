import os
from datetime import datetime, timezone
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.gate import QyrixGateMiddleware
from app import api
from app.demo import router as demo_router

app = FastAPI(title="Qyrix Sentinel", version="1.5.0-dev", docs_url=None, redoc_url=None)
origins = [o.strip() for o in os.getenv("QYRIX_CORS_ORIGINS", "").split(",") if o.strip() and o.strip() != "*"]
if origins:  # default: no CORS at all; the frontend reaches this API server-side through its own proxy
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST"],
                       allow_headers=["Authorization", "Content-Type"])
app.add_middleware(QyrixGateMiddleware)
for r in (api.sentinel, api.tools, api.auth, api.platform, api.ops):
    app.include_router(r)
app.include_router(demo_router)


def _start_canaries() -> None:
    """Opt-in periodic enforcement canaries (QYRIX_CEV_CANARY_INTERVAL_SECONDS > 0). Fixtures are never scheduled."""
    from app import cev, gateway, integrations
    ids = [i.strip() for i in os.getenv("QYRIX_CEV_CANARY_ADAPTERS", "rest_api").split(",") if i.strip()]
    cev.start_scheduler(lambda: gateway.PROD,
                        lambda: [integrations.ADAPTERS[i] for i in ids if i in integrations.ADAPTERS and i not in integrations.FIXTURES])


_start_canaries()


@app.get("/")
def root():
    return {"service": "qyrix-sentinel", "status": "ok"}


@app.get("/api/v1/health")
def health():
    return {"health": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}
