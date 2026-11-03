"""HTTP API. Every route authenticates (app/auth.py), checks an explicit permission from the server-side matrix
(app/identity.py) and resolves the caller's OWN tenant context (app/tenancy.py). Domain logic lives in app/gateway.py.
Public routes: /api/v1/health, /api/v1/ready, /api/v1/demo/*, /api/v1/auth/session (credential exchange, throttled).
"""
import hmac
import json
import os
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field

from app import accounts, anchor, gateway as g, identity, observability as obs, observer_feed, persistence, proof, tenancy
from app.auth import client_key, principal, require, require_platform
from app.identity import AuthError, Principal

sentinel = APIRouter(prefix="/api/v1/sentinel", tags=["sentinel"])
tools = APIRouter(prefix="/api/v1/tools", tags=["tools"])
auth = APIRouter(prefix="/api/v1/auth", tags=["auth"])
platform = APIRouter(prefix="/api/v1/platform", tags=["platform"])
ops = APIRouter(prefix="/api/v1", tags=["ops"])


def _err(e: Exception):
    if isinstance(e, AuthError):
        raise HTTPException(e.status, e.detail)
    if isinstance(e, g.ExecRefused):
        raise HTTPException(e.status, e.code)
    if isinstance(e, persistence.PersistenceError):
        raise HTTPException(503, "persistence unavailable")        # fail closed, no internals leaked
    raise e


def _call(fn, *a):
    try:
        return fn(*a)
    except HTTPException:
        raise
    except Exception as e:
        _err(e)


# ---------------- core ----------------
@sentinel.post("/inspect")
def inspect_ep(b: g.Text, p: Principal = Depends(require("inspect"))):
    ctx = tenancy.ctx_for(p)
    return {**g.inspect_text(b.text, ctx.approved()), "classification": g.classify(b.text)}


@sentinel.post("/provenance/step")
def step_ep(b: g.Step, p: Principal = Depends(require("provenance.write"))):
    ctx = tenancy.ctx_for(p)
    if g._persistence_down(ctx):
        raise HTTPException(503, "PERSISTENCE_UNAVAILABLE")
    try:
        return ctx.prov.add_step(b.source, b.label, g._redact(b.text), [str(x) for x in b.parents])   # redact before storage
    except Exception:
        if ctx.db is not None:
            ctx.state["persistence"] = "down"
            obs.inc("qyrix_persistence_down_total", tenant=p.tenant)
            raise HTTPException(503, "PERSISTENCE_UNAVAILABLE")
        raise


@sentinel.get("/provenance")
def prov_ep(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    return {"limit": ctx.prov.memory_limit, "steps": ctx.prov.all_steps()}


@sentinel.post("/gate/evaluate")
def gate_ep(a: g.Action, p: Principal = Depends(require("gate.evaluate"))):
    if a.execute:
        raise HTTPException(400, "EXECUTE_MOVED: evaluate first, then POST /api/v1/tools/execute with gate_evaluation_id and grant_id")
    ctx = tenancy.ctx_for(p)
    r = g.evaluate(a, ctx, p.cred_id)          # any grant is bound to THIS authenticated credential
    obs.inc("qyrix_gate_decisions_total", tenant=p.tenant, verdict=r["verdict"])
    for rule in r["rules"]:
        obs.inc("qyrix_gate_rule_hits_total", rule=rule)
    obs.event("gate_decision", tenant=p.tenant, cred=p.cred_id, verdict=r["verdict"], rules=r["rules"], tool=a.tool[:32],
              evaluation=r["gate_evaluation_id"], grant_issued=bool(r["grant_id"]))
    return r


@tools.post("/execute")
async def execute_ep(request: Request, p: Principal = Depends(require("tools.execute"))):
    try:
        body = json.loads(await request.body() or b"null")
    except ValueError:
        raise HTTPException(400, "INVALID_JSON")
    ctx = tenancy.ctx_for(p)
    try:
        x = g.execute_grant(body, ctx, p.cred_id)
    except g.ExecRefused as e:
        obs.inc("qyrix_executions_total", tenant=p.tenant, outcome=e.code)
        obs.event("execution_refused", tenant=p.tenant, cred=p.cred_id, refusal=e.code)
        raise HTTPException(e.status, e.code)
    obs.inc("qyrix_executions_total", tenant=p.tenant, outcome="EXECUTED" if x["executed"] else "FAILED")
    obs.event("execution", tenant=p.tenant, cred=p.cred_id, evaluation=x["gate_evaluation_id"], executed=x["executed"], adapter=x["adapter"])
    return x


@sentinel.post("/grants/{gid}/revoke")
def revoke_ep(gid: str, p: Principal = Depends(require("grant.revoke"))):
    try:
        r = g.revoke_grant(gid[:64], p.label(), tenancy.ctx_for(p))
    except Exception as e:
        _err(e)
    obs.event("grant_revoked", tenant=p.tenant, cred=p.cred_id, grant=gid[:64])
    return r


_INTEGRATION_RE = __import__("re").compile(r"^[a-z0-9_-]{1,64}$")


@tools.post("/redeem")
async def redeem_ep(request: Request, p: Principal = Depends(require("tools.execute")),
                    x_qyrix_integration: Optional[str] = Header(None)):
    """v1.5 delegated execution for platform adapters (e.g. the MCP proxy): consume the single-use grant for the exact
    params_digest the integration will execute. Sentinel performs no tool call here."""
    try:
        body = json.loads(await request.body() or b"null")
    except ValueError:
        raise HTTPException(400, "INVALID_JSON")
    integ = x_qyrix_integration if x_qyrix_integration and _INTEGRATION_RE.match(x_qyrix_integration) else "external"
    ctx = tenancy.ctx_for(p)
    try:
        r = g.redeem_grant(body, integ, ctx, p.cred_id)
    except g.ExecRefused as e:
        obs.inc("qyrix_executions_total", tenant=p.tenant, outcome=e.code)
        obs.event("redemption_refused", tenant=p.tenant, cred=p.cred_id, refusal=e.code, scope=integ)
        raise HTTPException(e.status, e.code)
    obs.inc("qyrix_executions_total", tenant=p.tenant, outcome="DELEGATED")
    obs.event("execution_delegated", tenant=p.tenant, cred=p.cred_id, evaluation=r["gate_evaluation_id"], scope=integ)
    return r


# ---------------- universal adapters + Continuous Enforcement Verification (v1.5) ----------------
class CanaryReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    adapter: str = Field(..., max_length=64)
    channel: str = Field("http", pattern="^(http|file)$")


class CevDemoReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    channel: str = Field("http", pattern="^(http|file)$")


def _fixtures_enabled() -> bool:
    return os.getenv("QYRIX_CEV_TEST_FIXTURES") == "1" or g._demo_enabled()


def _cev_adapter(adapter_id: str):
    from app import integrations
    ad = integrations.ADAPTERS.get(adapter_id)
    if ad is None:
        raise HTTPException(404, "UNKNOWN_ADAPTER")
    if adapter_id in integrations.FIXTURES and not _fixtures_enabled():
        raise HTTPException(403, "TEST_FIXTURES_DISABLED: set QYRIX_CEV_TEST_FIXTURES=1 (evaluation environments only)")
    return ad


@sentinel.get("/integrations")
def integrations_ep(p: Principal = Depends(require("read"))):
    from app import integrations
    return {"contract": "qyrix-adapter-contract/v1", "integrations": integrations.listing(),
            "test_fixtures_enabled": _fixtures_enabled()}


@sentinel.post("/cev/canary")
def cev_canary_ep(b: CanaryReq, p: Principal = Depends(require("cev.run"))):
    from app import cev
    ad = _cev_adapter(b.adapter)
    return cev.run_canary(tenancy.ctx_for(p), ad, b.channel)


@sentinel.post("/cev/demo")
def cev_demo_ep(b: CevDemoReq = CevDemoReq(), p: Principal = Depends(require("cev.run"))):
    """Signature demonstration: the SAME must-block canary through an honest and a deliberately broken TEST FIXTURE."""
    from app import cev
    ctx = tenancy.ctx_for(p)
    honest = cev.run_canary(ctx, _cev_adapter("honest_fixture"), b.channel)
    broken = cev.run_canary(ctx, _cev_adapter("broken_fixture"), b.channel)
    return {"channel": b.channel, "honest": honest, "broken": broken, "chain_verify": g.verify_chain(ctx),
            "note": "Both adapters are controlled test fixtures; the broken one touches only an isolated canary."}


@sentinel.get("/observer/reconciliations")
def observer_reconciliations_ep(p: Principal = Depends(require("read"))):
    """C4: the independent observer's canary reconciliations for the CALLER'S tenant (read-only relay)."""
    return observer_feed.fetch_reconciliations(p.tenant)


@sentinel.get("/cev/results")
def cev_results_ep(p: Principal = Depends(require("read"))):
    from app import cev
    ctx = tenancy.ctx_for(p)
    # design §10: today's in-process CEV is labelled `colocated` - it never counts as observer evidence (E3)
    return {"results": [{**r, "evidence_level": "colocated"} for r in cev.results(ctx, 100)], "evidence_level": "colocated",
            "conformance": cev.conformance(ctx), "window_ms": int(cev.window_seconds() * 1000)}


# ---------------- proof ----------------
@sentinel.get("/proofs")
def proofs_ep(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        chain = list(ctx.chain)
    return {"chain": chain, "verify": g.verify_chain(ctx)}


@sentinel.get("/proofs/verify")
def verify_ep(p: Principal = Depends(require("read"))):
    return g.verify_chain(tenancy.ctx_for(p))


@sentinel.get("/proofs/export")
def export_ep(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        chain, anchors = list(ctx.chain), list(ctx.anchors)
    v = g.verify_chain(ctx)
    return {"format": "qyrix-proof-bundle/v2", "tenant": p.tenant, "exported_at": g.datetime.now(g.timezone.utc).isoformat(),
            "anchor_status": v.get("anchor_status"), "chain": chain, "anchors": anchors, "verify": v}


@sentinel.post("/proofs/anchor")
def anchor_ep(p: Principal = Depends(require("proof.anchor"))):
    ctx = tenancy.ctx_for(p)
    try:
        a = g.create_anchor(ctx)
    except anchor.AnchorError as e:
        obs.inc("qyrix_anchor_attempts_total", outcome=e.code)
        code = {"ANCHOR_NOT_CONFIGURED": 409, "EMPTY_PROOF_BUNDLE": 422, "PROOF_DEGRADED": 409, "ANCHOR_STALE": 409}.get(e.code, 503)
        raise HTTPException(code, "%s: %s" % (e.code, e.detail) if e.detail else e.code)
    obs.inc("qyrix_anchor_attempts_total", outcome="ANCHORED")
    obs.event("anchored", tenant=p.tenant, n=a["n"], tsa=a["tsa_url"])
    return a


@sentinel.get("/proofs/anchors")
def anchors_ep(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        anchors = [{k: v for k, v in a.items() if k != "token_b64"} for a in ctx.anchors]
    pr = anchor.problem()
    return {"configured": pr is None, "problem": pr, "can_verify": anchor.can_verify(), "tsa_url": anchor.config()["url"], "anchors": anchors}


@sentinel.post("/proofs/verify-bundle")
async def verify_bundle_ep(request: Request, p: Principal = Depends(require("read"))):
    raw = await request.body()
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(413, "bundle too large")
    try:
        bundle = json.loads(raw or b"null")
    except ValueError:
        raise HTTPException(400, "INVALID_JSON")
    try:
        return proof.verify_bundle_with_anchors(bundle, g._cached_verify_token if anchor.can_verify() else None)
    except proof.EmptyBundle:
        raise HTTPException(422, "EMPTY_PROOF_BUNDLE")


@sentinel.post("/proofs/tamper")
def tamper_ep(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        c = g.copy.deepcopy(ctx.chain)
    if c:
        c[0]["verdict"] = "ALLOW" if c[0]["verdict"] == "BLOCK" else "BLOCK"
    return {**proof.verify_records(c), "simulated": True}


# ---------------- approvals ----------------
@sentinel.post("/approvals")
def appr_create(b: g.ApprovalReq, p: Principal = Depends(require("approval.request"))):
    b = b.model_copy(update={"requested_by": p.label()})      # accountability comes from the principal, not the body
    try:
        return g.create_approval(b, tenancy.ctx_for(p))
    except g.ExecRefused as e:
        raise HTTPException(e.status, e.code)


@sentinel.get("/approvals")
def appr_list(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        return {"approvals": [g._public_appr(x) for x in list(ctx.appr.values())[::-1]]}


@sentinel.post("/approvals/{aid}/{decision}")
def appr_decide(aid: str, decision: str, p: Principal = Depends(require("approval.decide"))):
    try:
        r = g.decide_approval(aid[:64], decision, p.label(), tenancy.ctx_for(p))
    except g.ExecRefused as e:
        raise HTTPException(e.status, e.code)
    obs.event("approval_decided", tenant=p.tenant, cred=p.cred_id, approval=aid[:64], decision=decision)
    return r


# ---------------- operations within a tenant ----------------
@sentinel.post("/reset")
def reset_ep(p: Principal = Depends(require("demo.reset"))):
    if not g._demo_enabled():
        raise HTTPException(403, "reset disabled (evidence is append-only); set QYRIX_ENABLE_DEMO_RESET=1 for demo/eval only")
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        g._reset_state(ctx)
    obs.event("tenant_reset", tenant=p.tenant, cred=p.cred_id)
    return {"reset": True}


@sentinel.get("/status")
def status_ep(p: Principal = Depends(require("read"))):
    ctx = tenancy.ctx_for(p)
    return {**g.status_snapshot(ctx, p.role), "tenant": p.tenant, "credential": p.cred_id, "multi_tenant": identity.multi_tenant_enabled(),
            "integrity": {k: v for k, v in tenancy.ctx_for(p).state.get("integrity", {"status": "NOT_APPLICABLE"}).items() if k != "pending"},
            "observer_feed": {k: v for k, v in observer_feed.status().items()
                              if k in ("state", "reason", "outbox_depth", "stale_epoch_unsent", "heartbeats", "last_error")}}


@sentinel.post("/benchmark")
def benchmark_ep(p: Principal = Depends(require("demo.reset"))):
    """Evaluation harness (10 cases from the plan). It resets this tenant's state, so it is demo/eval-mode only."""
    if not g._demo_enabled():
        raise HTTPException(403, "benchmark resets state; set QYRIX_ENABLE_DEMO_RESET=1 for demo/eval only")
    ctx = tenancy.ctx_for(p)
    with ctx.lock:
        g._reset_state(ctx)
    return g.run_benchmark(ctx)


# ---------------- API keys (tenant admins) ----------------
class KeyReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(max_length=32)
    name: str = Field("", max_length=80)
    ttl_days: Optional[int] = None


@sentinel.post("/keys")
def key_create(b: KeyReq, p: Principal = Depends(require("keys.manage"))):
    try:
        return identity.create_key(p, p.tenant, b.role, b.name or b.role, b.ttl_days)
    except Exception as e:
        _err(e)


@sentinel.get("/keys")
def key_list(p: Principal = Depends(require("keys.manage"))):
    try:
        return {"keys": identity.list_keys(p, p.tenant)}
    except Exception as e:
        _err(e)


@sentinel.post("/keys/{kid}/revoke")
def key_revoke(kid: str, p: Principal = Depends(require("keys.manage"))):
    try:
        return identity.revoke_key(p, p.tenant, kid[:40])
    except Exception as e:
        _err(e)


# ---------------- sessions ----------------
class SessionReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    credential: str = Field(min_length=1, max_length=512)


@auth.post("/session")
def session_create(b: SessionReq, request: Request):
    client = client_key(request)
    try:
        identity.check_auth_failures_allowed(client)
        try:
            return identity.create_session(b.credential)
        except AuthError as e:
            if e.status == 401:
                identity.record_auth_failure(client, "session_login")
            raise
    except AuthError as e:
        raise HTTPException(e.status, e.detail)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(503, "authentication unavailable")


@auth.delete("/session")
def session_delete(authorization: str = Header(default="")):
    tok = authorization[7:] if authorization.startswith("Bearer ") else ""
    try:
        identity.end_session(tok)
    except Exception:
        raise HTTPException(503, "authentication unavailable")
    return {"ok": True}


# ---------------- human accounts (v1.4): login + TOTP MFA, enrolment, recovery, invitations, members ----------------
class LoginReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tenant: str = Field(min_length=3, max_length=40)          # which organisation to sign in to (verified by membership)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=256)


class MfaReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge: str = Field(min_length=10, max_length=128)
    code: Optional[str] = Field(None, max_length=10)
    recovery_code: Optional[str] = Field(None, max_length=40)


class ChallengeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge: str = Field(min_length=10, max_length=128)


class EnrollConfirmReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge: str = Field(min_length=10, max_length=128)
    code: str = Field(min_length=6, max_length=10)


class CodeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=6, max_length=10)


class PasswordChangeReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)
    code: Optional[str] = Field(None, max_length=10)


class ForgotReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)


class ResetReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=10, max_length=128)
    new_password: str = Field(min_length=1, max_length=256)


class AcceptReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=10, max_length=128)
    name: str = Field("", max_length=120)
    password: str = Field(min_length=1, max_length=256)


class InviteReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    role: str = Field(max_length=32)


class RoleReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field(max_length=32)


@auth.post("/login")
def user_login(b: LoginReq, request: Request):
    return _call(accounts.login, b.tenant, b.email, b.password, client_key(request))


@auth.post("/login/mfa")
def user_login_mfa(b: MfaReq, request: Request):
    if bool(b.code) == bool(b.recovery_code):
        raise HTTPException(422, "provide exactly one of code or recovery_code")
    return _call(accounts.login_mfa, b.challenge, b.code, b.recovery_code, client_key(request))


@auth.post("/mfa/enroll/start")
def mfa_enroll_start(b: ChallengeReq):
    return _call(accounts.enroll_start, b.challenge)


@auth.post("/mfa/enroll/confirm")
def mfa_enroll_confirm(b: EnrollConfirmReq):
    return _call(accounts.enroll_confirm, b.challenge, b.code)


@auth.post("/mfa/recovery-codes")
def mfa_recovery_codes(b: CodeReq, p: Principal = Depends(principal)):
    return _call(accounts.regenerate_recovery_codes, p, b.code)


@auth.get("/me")
def auth_me(p: Principal = Depends(principal)):
    return _call(accounts.me, p)


@auth.post("/password/change")
def password_change(b: PasswordChangeReq, p: Principal = Depends(principal)):
    return _call(accounts.change_password, p, b.current_password, b.new_password, b.code)


@auth.post("/password/forgot", status_code=202)
def password_forgot(b: ForgotReq, request: Request):
    return _call(accounts.forgot_password, b.email, client_key(request))


@auth.post("/password/reset")
def password_reset(b: ResetReq):
    return _call(accounts.reset_password, b.token, b.new_password)


@auth.post("/invitations/accept")
def invitation_accept(b: AcceptReq, request: Request):
    return _call(accounts.accept_invitation, b.token, b.name, b.password, client_key(request))


@sentinel.post("/invitations")
def invitation_create(b: InviteReq, p: Principal = Depends(require("users.manage"))):
    return _call(accounts.invite, p, p.tenant, b.email, b.role)


@sentinel.get("/invitations")
def invitation_list(p: Principal = Depends(require("users.manage"))):
    return {"invitations": _call(accounts.list_invitations, p)}


@sentinel.post("/invitations/{iid}/revoke")
def invitation_revoke(iid: str, p: Principal = Depends(require("users.manage"))):
    return _call(accounts.revoke_invitation, p, iid[:40])


@sentinel.get("/members")
def member_list(p: Principal = Depends(require("users.manage"))):
    return {"members": _call(accounts.list_members, p)}


@sentinel.post("/members/{uid}/role")
def member_role(uid: str, b: RoleReq, p: Principal = Depends(require("users.manage"))):
    return _call(accounts.set_role, p, uid[:40], b.role)


@sentinel.delete("/members/{uid}")
def member_remove(uid: str, p: Principal = Depends(require("users.manage"))):
    return _call(accounts.remove_member, p, uid[:40])


@sentinel.post("/members/{uid}/password-reset")
def member_password_reset(uid: str, p: Principal = Depends(require("users.manage"))):
    return _call(accounts.admin_reset_password, p, uid[:40])


@sentinel.post("/members/{uid}/mfa-reset")
def member_mfa_reset(uid: str, p: Principal = Depends(require("users.manage"))):
    return _call(accounts.admin_reset_mfa, p, uid[:40])


@platform.post("/tenants/{tid}/invitations")
def tenant_bootstrap_invite(tid: str, b: InviteReq, p: Principal = Depends(require_platform)):
    """Bootstrap / break-glass: invite an owner into an organisation. The platform never sees tenant data."""
    if not identity.multi_tenant_enabled() and tid != identity.DEFAULT_TENANT:
        raise HTTPException(409, "MULTI_TENANCY_DISABLED")
    return _call(accounts.invite, p, tid[:40], b.email, b.role)


# ---------------- platform (tenant lifecycle) ----------------
class TenantReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(max_length=40)
    name: str = Field(max_length=120)
    approved_domains: Optional[List[str]] = Field(None, max_length=200)


class TenantKeyReq(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str = Field("owner", max_length=32)
    name: str = Field("bootstrap owner", max_length=80)
    ttl_days: Optional[int] = 30


@platform.post("/tenants")
def tenant_create(b: TenantReq, p: Principal = Depends(require_platform)):
    try:
        return identity.create_tenant(p, b.id, b.name, b.approved_domains)
    except Exception as e:
        _err(e)


@platform.get("/tenants")
def tenant_list(p: Principal = Depends(require_platform)):
    return {"tenants": identity.store().list_tenants(), "multi_tenant": identity.multi_tenant_enabled()}


@platform.post("/tenants/{tid}/keys")
def tenant_key(tid: str, b: TenantKeyReq, p: Principal = Depends(require_platform)):
    if not identity.multi_tenant_enabled() and tid != identity.DEFAULT_TENANT:
        raise HTTPException(409, "MULTI_TENANCY_DISABLED")
    try:
        return identity.create_key(p, tid, b.role, b.name, b.ttl_days)
    except Exception as e:
        _err(e)


@platform.post("/tenants/{tid}/disable")
def tenant_disable(tid: str, p: Principal = Depends(require_platform)):
    try:
        identity.store().disable_tenant(tid)
    except Exception as e:
        _err(e)
    tenancy.forget(tid)
    obs.event("tenant_disabled", tenant=tid, by=p.label())
    return {"id": tid, "disabled": True}


# ---------------- operations ----------------
@ops.get("/ready")
def ready():
    """Readiness: the default tenant can make durable, verifiable decisions. 503 otherwise (orchestrators stop traffic)."""
    ctx = g.PROD
    v = g.verify_chain(ctx)
    checks = {"proof_chain": "ok" if v["valid"] else "fail", "gate": "degraded" if ctx.state["degraded"] else "ok",
              "persistence": ctx.state["persistence"],
              "integrity": ctx.state.get("integrity", {}).get("status", "NOT_APPLICABLE")}
    if ctx.state.get("integrity", {}).get("reason"):
        checks["integrity_reason"] = ctx.state["integrity"]["reason"]
    if identity.store().durable:
        try:
            ctx.db.ping() if ctx.db is not None else None
            checks["database"] = "ok" if ctx.db is not None else "fail"
        except Exception:
            checks["database"] = "fail"
    ok = (checks["proof_chain"] == "ok" and checks["gate"] == "ok" and checks["persistence"] != "down"
          and checks.get("database", "ok") == "ok" and checks["integrity"] in ("OK", "FRESH_INSTALL", "ADOPTED_EXISTING", "NOT_APPLICABLE"))
    if not ok:
        raise HTTPException(503, {"ready": False, "checks": checks})
    return {"ready": True, "checks": checks}


@ops.get("/metrics")
def metrics(authorization: str = Header(default="")):
    exp = os.getenv("QYRIX_METRICS_TOKEN", "")
    if len(exp) < identity.MIN_TOKEN_LEN or exp.startswith(identity.PLACEHOLDER_PREFIX):
        raise HTTPException(404, "metrics disabled (set QYRIX_METRICS_TOKEN)")
    tok = authorization[7:] if authorization.startswith("Bearer ") else ""
    if not hmac.compare_digest(tok.encode(), exp.encode()):
        raise HTTPException(401, "invalid metrics token")
    gauges = {}
    for tid, ctx in tenancy.loaded().items():
        with ctx.lock:
            n = len(ctx.chain)
        gauges['qyrix_proof_chain_length{tenant="%s"}' % tid] = n
        gauges['qyrix_gate_degraded{tenant="%s"}' % tid] = 1 if ctx.state["degraded"] else 0
        gauges['qyrix_persistence_up{tenant="%s"}' % tid] = {"postgres": 1, "memory": 0, "down": -1}[ctx.state["persistence"]]
        gauges['qyrix_external_calls{tenant="%s"}' % tid] = ctx.ext["calls"]
        ist = ctx.state.get("integrity", {}).get("status", "NOT_APPLICABLE")
        gauges['qyrix_integrity_ok{tenant="%s"}' % tid] = 0 if ist == "RECOVERY_REQUIRED" else (-1 if ist == "DISABLED" else 1)
    return PlainTextResponse(obs.render(gauges), media_type="text/plain; version=0.0.4")
