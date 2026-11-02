"""Per-tenant Gate contexts. Isolation by construction: a request can only ever reach the context of its own
principal's tenant, and each context has its own provenance store, approvals, evaluations, grants, proof chain file,
anchors, workspace, destination allowlist, adapters and PostgreSQL view (tenant filter + row-level security).

The default tenant is the v1.x production context (gateway.PROD). Other tenants exist only when QYRIX_MULTI_TENANT=1
and PostgreSQL persistence is up (fail closed otherwise).
"""
import os
import threading
from typing import Dict, Optional

from fastapi import HTTPException

from app import adapter as adapters, gateway as g, identity, netguard, observability as obs, persistence, provenance as prov

_lock = threading.Lock()
_contexts: Dict[str, "g.GateContext"] = {}


def _tenant_dir() -> str:
    d = os.path.join(os.path.dirname(os.path.abspath(g.CHAIN_FILE)), "tenants")
    os.makedirs(d, exist_ok=True)
    return d


def _workspace_root() -> str:
    """Tenant workspaces need a WRITABLE root (the image filesystem is read-only in production)."""
    return os.getenv("QYRIX_TENANT_WORKSPACE_ROOT") or os.path.join(g.WORKSPACE, "tenants")


def _build(tid: str) -> "g.GateContext":
    t = identity.store().get_tenant(tid)
    if t is None:
        raise HTTPException(403, "tenant unavailable")
    approved = tuple(t["approved_domains"] or ())         # non-default tenants: deny all destinations unless configured
    approved_fn = lambda: approved
    ws = os.path.join(_workspace_root(), tid)
    os.makedirs(ws, exist_ok=True)
    ctx = g.GateContext(tid, prov.ProvenanceStore(), os.path.join(_tenant_dir(), tid + ".jsonl"), approved_fn,
                        {"http": adapters.HttpAdapter(approved_fn), "file.read": adapters.FileAdapter(ws, lambda s: g._redact(s))}, ws)
    g._load_chain(ctx)
    g._load_anchors(ctx)
    dsn = persistence.dsn_from_env()
    if not dsn:
        raise HTTPException(503, "PERSISTENCE_REQUIRED")
    try:
        g.attach_persistence(ctx, persistence.PgPersistence(dsn, tenant_id=tid))
    except Exception:
        ctx.state["persistence"] = "down"                  # context exists but blocks everything (R17)
        obs.inc("qyrix_persistence_down_total", tenant=tid)
    return ctx


def ctx_for(p: identity.Principal) -> "g.GateContext":
    if p.platform or not p.tenant:
        raise HTTPException(403, "tenant role required")
    if p.tenant == identity.DEFAULT_TENANT:
        return g.PROD
    if not identity.multi_tenant_enabled():
        raise HTTPException(403, "MULTI_TENANCY_DISABLED")
    with _lock:
        ctx = _contexts.get(p.tenant)
        if ctx is None:
            try:
                ctx = _build(p.tenant)
            except HTTPException:
                raise
            except Exception:
                obs.inc("qyrix_tenant_context_failures_total", tenant=p.tenant)
                obs.event("tenant_context_failed", tenant=p.tenant)
                raise HTTPException(503, "TENANT_CONTEXT_UNAVAILABLE")      # fail closed, never a half-built context
            _contexts[p.tenant] = ctx
        return ctx


def loaded() -> Dict[str, "g.GateContext"]:
    with _lock:
        return {"default": g.PROD, **_contexts}


def forget(tid: str) -> None:
    with _lock:
        _contexts.pop(tid, None)
