"""Identity and authorization: principals, roles, permission matrix, API keys, server-side sessions, rate limits.

Every authorization decision is made here, server-side, from the authenticated principal - never from request data.

Credentials
- Operator env tokens (bootstrap, default tenant): QYRIX_ADMIN_TOKEN -> admin, QYRIX_AGENT_TOKEN -> agent.
- Platform operator token: QYRIX_PLATFORM_TOKEN -> platform (may manage tenants; has NO data access in any tenant).
- Per-tenant API keys "qsk_<random 256-bit>": only their SHA-256 is stored; shown once at creation; expiring, revocable.
- Sessions "qss_<random 256-bit>": created from a credential by POST /api/v1/auth/session; SHA-256 stored server-side;
  absolute + idle expiry; revoked on logout, on revocation of the underlying key, or when an env token is rotated.
Env tokens shorter than 24 characters or starting with CHANGE_ME never authenticate (fail closed).

Stores: PostgreSQL when persistence is configured (required for multi-tenancy), otherwise in-memory (single tenant;
keys and sessions are lost on restart).
"""
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional

from app import observability as obs

MIN_TOKEN_LEN = 24
PLACEHOLDER_PREFIX = "CHANGE_ME"
DEFAULT_TENANT = "default"
TENANT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,39}$")
ROLES = ("owner", "admin", "security_reviewer", "approver", "auditor", "integrator", "agent")
ALL = frozenset(ROLES)

# Server-side permission matrix (master plan §8). Agents can never approve; approval is never execution.
PERMISSIONS: Dict[str, frozenset] = {
    "read":             ALL,                                                          # status, provenance, proofs, approvals list
    "inspect":          frozenset({"owner", "admin", "security_reviewer"}),           # enableIntegratorInspectionUpload=false
    "provenance.write": frozenset({"owner", "admin", "security_reviewer", "integrator", "agent"}),
    "gate.evaluate":    frozenset({"owner", "admin", "integrator", "agent"}),
    "tools.execute":    frozenset({"owner", "admin", "integrator", "agent"}),
    "approval.request": frozenset({"owner", "admin", "integrator", "agent"}),
    "approval.decide":  frozenset({"owner", "admin", "approver"}),
    "grant.revoke":     frozenset({"owner", "admin", "approver"}),
    "proof.anchor":     frozenset({"owner", "admin"}),
    "keys.manage":      frozenset({"owner", "admin"}),
    "demo.reset":       frozenset({"owner", "admin"}),
    "users.manage":     frozenset({"owner", "admin"}),
}
# Roles a key creator may grant: nobody can mint a key more powerful than themselves; owner keys only by owner/platform.
GRANTABLE = {"owner": set(ROLES), "admin": set(ROLES) - {"owner"}}


@dataclass(frozen=True)
class Principal:
    tenant: Optional[str]          # None only for the platform operator
    role: str                      # one of ROLES, or "platform"
    cred_id: str                   # "env:admin", "key:<id>", ...
    via: str = "bearer"            # "bearer" | "session"

    @property
    def platform(self) -> bool:
        return self.role == "platform"

    def can(self, perm: str) -> bool:
        return (not self.platform) and self.role in PERMISSIONS.get(perm, frozenset())

    def label(self) -> str:
        return "%s:%s" % (self.role, self.cred_id)


class AuthError(Exception):
    qyrix_passthrough = True              # a policy refusal: the DB pool re-raises it unchanged (after rollback)

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


# Opaque credentials minted by this server: "qsk_" (API key) / "qss_" (session) + secrets.token_urlsafe(32) = 256 bits.
_TOKEN_RE = re.compile(r"^q(sk|ss)_[A-Za-z0-9_-]{43}$")


def token_digest(token: str) -> Optional[str]:
    """Lookup digest for a SERVER-GENERATED 256-bit random token (API key or session id), or None if `token` is not one.

    SHA-256 is deliberate and sufficient here: the input has 256 bits of entropy, so a fast hash cannot be brute-forced,
    and a slow KDF would add CPU cost (DoS surface) to every authenticated request. It is NOT a password hash: anything
    that does not have the exact minted format is refused instead of hashed, so a human password or an operator token
    can never be stored or compared through this function. Output is byte-identical to v1.3/v1.4 (no migration)."""
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        return None
    return hashlib.sha256(token.encode()).hexdigest()


_FP_CACHE: Dict[str, str] = {}


def _secret_fingerprint(name: str, value: str) -> str:
    """Rotation fingerprint of an OPERATOR-CHOSEN secret (env token), stored in sessions.cred_fp. Such secrets may be
    low-entropy, so a fast hash stored in the database would allow offline guessing: use scrypt (memory-hard) and keep
    only 64 bits. Computed once per process per value (the env value does not change while the process runs)."""
    key = name + "\0" + value
    if key not in _FP_CACHE:
        dk = hashlib.scrypt(value.encode(), salt=("qyrix-env-fp:" + name).encode(), n=2 ** 15, r=8, p=1,
                            maxmem=64 * 1024 * 1024, dklen=16)
        _FP_CACHE.clear()                            # at most one live value per name: never accumulate old secrets
        _FP_CACHE[key] = dk.hex()[:16]
    return _FP_CACHE[key]


def _env(name: str) -> str:
    v = os.getenv(name, "")
    return v if len(v) >= MIN_TOKEN_LEN and not v.startswith(PLACEHOLDER_PREFIX) else ""


def _env_match(tok: str) -> Optional[Principal]:
    for name, role in (("QYRIX_ADMIN_TOKEN", "admin"), ("QYRIX_AGENT_TOKEN", "agent")):
        exp = _env(name)
        if exp and hmac.compare_digest(tok.encode(), exp.encode()):
            return Principal(DEFAULT_TENANT, role, "env:" + role)
    exp = _env("QYRIX_PLATFORM_TOKEN")
    if exp and hmac.compare_digest(tok.encode(), exp.encode()):
        return Principal(None, "platform", "env:platform")
    return None


def _env_fingerprint(cred_id: str) -> Optional[str]:
    name = {"env:admin": "QYRIX_ADMIN_TOKEN", "env:agent": "QYRIX_AGENT_TOKEN"}.get(cred_id)
    v = _env(name) if name else ""
    return _secret_fingerprint(name, v) if v else None


def session_ttl() -> int:
    return int(os.getenv("QYRIX_SESSION_TTL_SECONDS", "28800"))


def session_idle() -> int:
    return int(os.getenv("QYRIX_SESSION_IDLE_SECONDS", "1800"))


# ---------------- stores ----------------
class MemoryStore:
    durable = False

    def __init__(self):
        self.lock = threading.RLock()
        self.tenants: Dict[str, Dict] = {DEFAULT_TENANT: {"id": DEFAULT_TENANT, "name": "Default tenant", "approved_domains": None, "disabled": False}}
        self.keys: Dict[str, Dict] = {}          # key_hash -> record
        self.sessions: Dict[str, Dict] = {}      # id_hash -> record

    def get_tenant(self, tid):
        with self.lock:
            t = self.tenants.get(tid)
            return dict(t) if t and not t["disabled"] else None

    def list_tenants(self):
        with self.lock:
            return [dict(t) for t in self.tenants.values()]

    def create_tenant(self, tid, name, approved):
        with self.lock:
            if tid in self.tenants:
                raise AuthError(409, "TENANT_EXISTS")
            self.tenants[tid] = {"id": tid, "name": name, "approved_domains": approved, "disabled": False}

    def disable_tenant(self, tid):
        with self.lock:
            if tid not in self.tenants or tid == DEFAULT_TENANT:
                raise AuthError(404, "unknown tenant")
            self.tenants[tid]["disabled"] = True

    def insert_key(self, rec):
        with self.lock:
            self.keys[rec["key_hash"]] = rec

    def key_by_hash(self, h):
        with self.lock:
            r = self.keys.get(h)
            return dict(r) if r else None

    def list_keys(self, tid):
        with self.lock:
            return [dict(r) for r in self.keys.values() if r["tenant_id"] == tid]

    def revoke_key(self, tid, kid):
        with self.lock:
            for r in self.keys.values():
                if r["id"] == kid and r["tenant_id"] == tid and not r["revoked_at"]:
                    r["revoked_at"] = time.time()
                    for s in self.sessions.values():
                        if s["cred_id"] == "key:" + kid:
                            s["revoked_at"] = time.time()
                    return True
            return False

    def touch_key(self, h):
        pass

    def insert_session(self, rec):
        with self.lock:
            self.sessions[rec["id_hash"]] = rec

    def session_by_hash(self, h):
        with self.lock:
            r = self.sessions.get(h)
            return dict(r) if r else None

    def touch_session(self, h):
        with self.lock:
            if h in self.sessions:
                self.sessions[h]["last_seen"] = time.time()

    def revoke_session(self, h):
        with self.lock:
            if h in self.sessions:
                self.sessions[h]["revoked_at"] = time.time()


class PgStore:
    """PostgreSQL identity store, used through the least-privilege runtime account.
    Tenant-scoped rows (api_keys, sessions) are read/written inside that tenant's RLS context. Authentication lookups,
    which happen before the tenant is known, go through SECURITY DEFINER functions (owner: NOLOGIN qyrix_auth) that
    accept only a 64-hex SHA-256 hash - the runtime can verify a presented credential but cannot list credentials."""
    durable = True

    def __init__(self, conn):
        self.db = conn

    def _q(self, fn, tenant=None):
        return self.db.run(fn, tenant=tenant)

    def get_tenant(self, tid):
        def go(cur):
            cur.execute("SELECT id, name, approved_domains FROM tenants WHERE id=%s AND disabled_at IS NULL", (tid,))
            r = cur.fetchone()
            return {"id": r[0], "name": r[1], "approved_domains": list(r[2]) if r[2] is not None else None, "disabled": False} if r else None
        return self._q(go)

    def list_tenants(self):
        def go(cur):
            cur.execute("SELECT id, name, approved_domains, disabled_at FROM tenants ORDER BY created_at")
            return [{"id": r[0], "name": r[1], "approved_domains": list(r[2]) if r[2] is not None else None, "disabled": r[3] is not None} for r in cur.fetchall()]
        return self._q(go)

    def create_tenant(self, tid, name, approved):
        def go(cur):
            cur.execute("INSERT INTO tenants (id, name, approved_domains) VALUES (%s,%s,%s) ON CONFLICT (id) DO NOTHING RETURNING id", (tid, name, approved))
            return cur.fetchone() is not None
        if not self._q(go):                    # raised OUTSIDE the transaction runner (it maps errors to PersistenceError)
            raise AuthError(409, "TENANT_EXISTS")

    def disable_tenant(self, tid):
        def go(cur):
            cur.execute("UPDATE tenants SET disabled_at=now() WHERE id=%s AND id<>'default' AND disabled_at IS NULL RETURNING id", (tid,))
            if cur.fetchone() is None:
                return False
            cur.execute("UPDATE sessions SET revoked_at=now() WHERE tenant_id=%s AND revoked_at IS NULL", (tid,))
            return True
        if not self._q(go, tenant=tid):
            raise AuthError(404, "unknown tenant")

    def insert_key(self, r):
        self._q(lambda cur: cur.execute(
            "INSERT INTO api_keys (id, tenant_id, role, name, key_hash, created_by, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (r["id"], r["tenant_id"], r["role"], r["name"], r["key_hash"], r["created_by"],
             datetime.fromtimestamp(r["expires_at"], timezone.utc) if r["expires_at"] else None)), tenant=r["tenant_id"])

    def key_by_hash(self, h):
        def go(cur):
            cur.execute("SELECT id, tenant_id, role, expires_at, revoked_at, tenant_disabled FROM qyrix_lookup_key(%s)", (h,))
            r = cur.fetchone()
            if not r:
                return None
            return {"id": r[0], "tenant_id": r[1], "role": r[2], "expires_at": r[3].timestamp() if r[3] else None,
                    "revoked_at": r[4].timestamp() if r[4] else None, "tenant_disabled": bool(r[5])}
        return self._q(go)

    def list_keys(self, tid):
        def go(cur):
            cur.execute("SELECT id, role, name, created_by, created_at, expires_at, revoked_at, last_used_at FROM api_keys WHERE tenant_id=%s ORDER BY created_at", (tid,))
            return [{"id": r[0], "tenant_id": tid, "role": r[1], "name": r[2], "created_by": r[3], "created_at": r[4].isoformat(),
                     "expires_at": r[5].timestamp() if r[5] else None, "revoked_at": r[6].timestamp() if r[6] else None,
                     "last_used_at": r[7].isoformat() if r[7] else None} for r in cur.fetchall()]
        return self._q(go, tenant=tid)

    def revoke_key(self, tid, kid):
        def go(cur):
            cur.execute("UPDATE api_keys SET revoked_at=now() WHERE tenant_id=%s AND id=%s AND revoked_at IS NULL RETURNING id", (tid, kid))
            ok = cur.fetchone() is not None
            if ok:
                cur.execute("UPDATE sessions SET revoked_at=now() WHERE tenant_id=%s AND cred_id=%s AND revoked_at IS NULL", (tid, "key:" + kid))
            return ok
        return self._q(go, tenant=tid)

    def touch_key(self, h):
        self._q(lambda cur: cur.execute("SELECT qyrix_touch_key(%s)", (h,)))

    def insert_session(self, r):
        self._q(lambda cur: cur.execute(
            "INSERT INTO sessions (id_hash, tenant_id, role, cred_id, cred_fp, expires_at, user_id) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (r["id_hash"], r["tenant"], r["role"], r["cred_id"], r["cred_fp"], datetime.fromtimestamp(r["expires_at"], timezone.utc),
             r.get("user_id"))), tenant=r["tenant"])

    def session_by_hash(self, h):
        def go(cur):
            cur.execute("SELECT tenant_id, role, cred_id, cred_fp, expires_at, last_seen_at, revoked, tenant_disabled"
                        " FROM qyrix_lookup_session(%s)", (h,))
            r = cur.fetchone()
            if not r:
                return None
            return {"tenant": r[0], "role": r[1], "cred_id": r[2], "cred_fp": r[3], "expires_at": r[4].timestamp(), "last_seen": r[5].timestamp(),
                    "revoked_at": 1.0 if r[6] else None, "tenant_disabled": bool(r[7])}
        return self._q(go)

    def touch_session(self, h):
        self._q(lambda cur: cur.execute("SELECT qyrix_touch_session(%s)", (h,)))

    def revoke_session(self, h):
        self._q(lambda cur: cur.execute("SELECT qyrix_end_session(%s)", (h,)))


_store = MemoryStore()


def store():
    return _store


def use_store(s) -> None:
    """Also selects the limiter backend: a durable (PostgreSQL) identity store => shared counters across instances."""
    global _store
    _store = s
    limiter.impl = SharedLimiter(s.db) if getattr(s, "durable", False) and hasattr(s, "db") else Limiter()


def multi_tenant_enabled() -> bool:
    return os.getenv("QYRIX_MULTI_TENANT", "0") == "1"


# ---------------- rate limiting (sliding window, in-process) ----------------
class Limiter:
    """In-process sliding window. Used directly in memory mode (single instance) and as the documented degraded
    fallback for NON-security scopes when the shared store is unavailable."""
    def __init__(self):
        self.lock = threading.Lock()
        self.win: Dict[str, Deque[float]] = defaultdict(deque)

    def hit(self, key: str, limit: int, window: float = 60.0, count: bool = True) -> bool:
        """True if allowed. `count=False` only checks."""
        now = time.monotonic()
        with self.lock:
            q = self.win[key]
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= limit:
                return False
            if count:
                q.append(now)
            if len(self.win) > 50000:
                for k in [k for k, v in self.win.items() if not v][:25000]:
                    self.win.pop(k, None)
            return True

    def clear(self):
        with self.lock:
            self.win.clear()


# Scopes whose limits protect authentication: if the shared store is unavailable they FAIL CLOSED (503) rather than
# silently degrading to per-instance counters an attacker could spread across replicas.
SECURITY_SCOPES = ("authfail", "login", "mfa", "reset", "invite")


class SharedLimiter:
    """Rate limits shared by every application instance, stored in PostgreSQL (migration 006).

    Approximate sliding window from two aligned fixed windows: estimate = previous * (1 - elapsed/window) + current.
    Each decision is ONE transaction that row-locks the current bucket (upsert), so concurrent requests on any number of
    instances are serialised per bucket: no lost updates, no over-admission. Counters survive application restarts."""

    def __init__(self, pool):
        self.pool = pool
        self.local = Limiter()
        self._n = 0

    @staticmethod
    def _bucket(key: str) -> str:
        return hashlib.sha256(("qyrix-rl:" + key).encode()).hexdigest()

    def hit(self, key: str, limit: int, window: float = 60.0, count: bool = True) -> bool:
        w = max(1, int(window))
        now = time.time()
        cur_start = int(now // w) * w
        frac = (now - cur_start) / w
        b = self._bucket(key)

        def go(c):
            c.execute("INSERT INTO rate_limits (bucket, window_start, count, expires_at) VALUES (%s,%s,0, now() + make_interval(secs => %s))"
                      " ON CONFLICT (bucket, window_start) DO UPDATE SET count = rate_limits.count RETURNING count",
                      (b, cur_start, 2 * w + 5))
            cur = c.fetchone()[0]                                     # row is now locked until COMMIT
            c.execute("SELECT count FROM rate_limits WHERE bucket=%s AND window_start=%s", (b, cur_start - w))
            r = c.fetchone()
            prev = r[0] if r else 0
            est = prev * (1 - frac) + cur
            allowed = est + (1 if count else 0) <= limit if count else est < limit
            if allowed and count:
                c.execute("UPDATE rate_limits SET count = count + 1 WHERE bucket=%s AND window_start=%s", (b, cur_start))
            return allowed
        try:
            allowed = self.pool.run(go)
            self._n += 1
            if self._n % 500 == 0:
                self.pool.run(lambda c: c.execute("DELETE FROM rate_limits WHERE expires_at < now()"))
        except Exception:
            scope = key.split(":", 1)[0]
            obs.inc("qyrix_rate_limit_backend_errors_total", scope=scope)
            obs.event("rate_limit_backend_unavailable", severity="critical", scope=scope)
            if scope in SECURITY_SCOPES:
                raise AuthError(503, "rate limiter unavailable")      # fail closed for authentication paths
            allowed = self.local.hit(key, limit, window, count)       # degraded, per-instance (documented)
        if not allowed:
            obs.inc("qyrix_rate_limit_denials_total", scope=key.split(":", 1)[0])
        return allowed

    def clear(self):
        self.local.clear()
        try:
            self.pool.run(lambda c: c.execute("DELETE FROM rate_limits"))
        except Exception:
            pass


class _LimiterProxy:
    """Module-level `limiter`: shared (PostgreSQL) when an identity database is configured, in-process otherwise."""
    def __init__(self):
        self.impl = Limiter()

    def hit(self, key: str, limit: int, window: float = 60.0, count: bool = True) -> bool:
        return self.impl.hit(key, limit, window, count)

    def clear(self):
        self.impl.clear()

    @property
    def shared(self) -> bool:
        return isinstance(self.impl, SharedLimiter)


limiter = _LimiterProxy()


def client_known(client: str) -> bool:
    """Per-IP limits need a TRUSTED client address (see auth.client_key). An unknown client is not collapsed into one
    shared bucket (that would let one attacker lock out everybody); per-account and global limits still apply."""
    return bool(client) and client != "unknown"


def hit_ip(scope: str, client: str, limit: int, window: float = 60.0, count: bool = True) -> bool:
    return True if not client_known(client) else limiter.hit(scope + ":ip:" + client, limit, window, count)


def _lim(name: str, default: str) -> int:
    return int(os.getenv(name, default))


def check_auth_failures_allowed(client: str) -> None:
    if not hit_ip("authfail", client, _lim("QYRIX_AUTH_FAIL_PER_MIN", "20"), count=False) or \
       not limiter.hit("authfail:*", _lim("QYRIX_AUTH_FAIL_GLOBAL_PER_MIN", "300"), count=False):
        obs.inc("qyrix_rate_limited_total", scope="auth")
        obs.event("auth_throttled", severity="warning", client=client[:64])
        raise AuthError(429, "too many failed authentication attempts")


def record_auth_failure(client: str, reason: str) -> None:
    hit_ip("authfail", client, 10 ** 9)
    limiter.hit("authfail:*", 10 ** 9)
    obs.inc("qyrix_auth_failures_total", reason=reason)
    obs.event("auth_failure", reason=reason, client=client[:64])


def check_rate(p: Principal) -> None:
    if not limiter.hit("req:" + p.cred_id, _lim("QYRIX_RATE_LIMIT_PER_MIN", "1200")):
        obs.inc("qyrix_rate_limited_total", scope="principal")
        obs.event("rate_limited", cred=p.cred_id, tenant=p.tenant)
        raise AuthError(429, "rate limit exceeded")


# ---------------- authentication ----------------
def authenticate(token: str, allow_session: bool = True) -> Principal:
    """Resolve a bearer token to a principal or raise AuthError(401). Constant-time for env tokens; hashed lookups otherwise."""
    if not token or len(token) > 512:
        raise AuthError(401, "invalid credentials")
    p = _env_match(token)
    if p:
        return p
    if token.startswith("qsk_"):
        h = token_digest(token)
        if h is None:
            raise AuthError(401, "invalid credentials")
        r = _store.key_by_hash(h)
        if not r or r.get("revoked_at") or r.get("tenant_disabled") or (r.get("expires_at") and time.time() > r["expires_at"]):
            raise AuthError(401, "invalid credentials")
        try:
            _store.touch_key(h)
        except Exception:
            pass
        return Principal(r["tenant_id"], r["role"], "key:" + r["id"])
    if token.startswith("qss_") and allow_session:
        h = token_digest(token)
        if h is None:
            raise AuthError(401, "session expired")
        r = _store.session_by_hash(h)
        now = time.time()
        if (not r or r.get("revoked_at") or r.get("tenant_disabled") or now > r["expires_at"]
                or now - r["last_seen"] > session_idle()):
            raise AuthError(401, "session expired")
        if r["cred_id"].startswith("env:") and r.get("cred_fp") != _env_fingerprint(r["cred_id"]):
            raise AuthError(401, "session expired")          # operator token rotated => old sessions die
        if now - r["last_seen"] > 30:
            _store.touch_session(h)
        return Principal(r["tenant"], r["role"], r["cred_id"], via="session")
    raise AuthError(401, "invalid credentials")


def create_session(credential: str) -> Dict:
    p = authenticate(credential, allow_session=False)
    if p.platform:
        raise AuthError(403, "platform credentials cannot open a product session")
    token = "qss_" + secrets.token_urlsafe(32)
    exp = time.time() + session_ttl()
    _store.insert_session({"id_hash": token_digest(token), "tenant": p.tenant, "role": p.role, "cred_id": p.cred_id,
                           "cred_fp": _env_fingerprint(p.cred_id), "expires_at": exp, "last_seen": time.time(), "revoked_at": None})
    obs.inc("qyrix_sessions_total", action="created")
    obs.event("session_created", tenant=p.tenant, role=p.role, cred=p.cred_id)
    return {"session_token": token, "expires_at": datetime.fromtimestamp(exp, timezone.utc).isoformat(), "tenant": p.tenant, "role": p.role}


def create_user_session(user_id: str, tenant: str, role: str) -> Dict:
    """Human session (after password + MFA). Same opaque qss_ format and lifetime rules as key sessions, bound to a user."""
    token = "qss_" + secrets.token_urlsafe(32)
    exp = time.time() + session_ttl()
    _store.insert_session({"id_hash": token_digest(token), "tenant": tenant, "role": role, "cred_id": "user:" + user_id, "cred_fp": None,
                           "expires_at": exp, "last_seen": time.time(), "revoked_at": None, "user_id": user_id})
    obs.inc("qyrix_sessions_total", action="created")
    obs.event("session_created", tenant=tenant, role=role, cred="user:" + user_id)
    return {"session_token": token, "expires_at": datetime.fromtimestamp(exp, timezone.utc).isoformat(), "tenant": tenant, "role": role}


def end_session(token: str) -> None:
    h = token_digest(token)
    if h is not None and token.startswith("qss_"):
        _store.revoke_session(h)
        obs.inc("qyrix_sessions_total", action="revoked")


# ---------------- key & tenant management ----------------
def create_key(actor: Principal, tenant: str, role: str, name: str, ttl_days: Optional[int]) -> Dict:
    if role not in ROLES:
        raise AuthError(422, "unknown role")
    if not actor.platform:
        if actor.tenant != tenant or not actor.can("keys.manage"):
            raise AuthError(403, "not allowed")
        if role not in GRANTABLE.get(actor.role, set()):
            raise AuthError(403, "cannot grant a role above your own")
    if tenant != DEFAULT_TENANT and not _store.get_tenant(tenant):
        raise AuthError(404, "unknown tenant")
    if ttl_days is not None and not 1 <= ttl_days <= 3650:
        raise AuthError(422, "ttl_days out of range")
    token = "qsk_" + secrets.token_urlsafe(32)
    kid = "key_" + secrets.token_hex(6)
    rec = {"id": kid, "tenant_id": tenant, "role": role, "name": name[:80], "key_hash": token_digest(token), "created_by": actor.label(),
           "created_at": datetime.now(timezone.utc).isoformat(), "expires_at": time.time() + ttl_days * 86400 if ttl_days else None,
           "revoked_at": None, "last_used_at": None}
    _store.insert_key(rec)
    obs.event("api_key_created", tenant=tenant, role=role, key_id=kid, by=actor.label())
    return {"id": kid, "tenant": tenant, "role": role, "name": rec["name"], "api_key": token, "durable": _store.durable,
            "expires_at": datetime.fromtimestamp(rec["expires_at"], timezone.utc).isoformat() if rec["expires_at"] else None,
            "notice": "Store this key now; only its hash is kept and it cannot be shown again."}


def list_keys(actor: Principal, tenant: str) -> List[Dict]:
    if not actor.platform and (actor.tenant != tenant or not actor.can("keys.manage")):
        raise AuthError(403, "not allowed")
    return [{k: v for k, v in r.items() if k != "key_hash"} for r in _store.list_keys(tenant)]


def revoke_key(actor: Principal, tenant: str, kid: str) -> Dict:
    if not actor.platform and (actor.tenant != tenant or not actor.can("keys.manage")):
        raise AuthError(403, "not allowed")
    if not _store.revoke_key(tenant, kid):
        raise AuthError(404, "unknown or already revoked key")
    obs.event("api_key_revoked", tenant=tenant, key_id=kid, by=actor.label())
    return {"id": kid, "revoked": True}


def create_tenant(actor: Principal, tid: str, name: str, approved: Optional[List[str]]) -> Dict:
    if not actor.platform:
        raise AuthError(403, "platform operator only")
    if not multi_tenant_enabled():
        raise AuthError(409, "MULTI_TENANCY_DISABLED")
    if not _store.durable:
        raise AuthError(409, "PERSISTENCE_REQUIRED")
    if not TENANT_RE.match(tid or ""):
        raise AuthError(422, "tenant id must match ^[a-z0-9][a-z0-9-]{2,39}$")
    doms = None
    if approved is not None:
        doms = sorted({d.strip().lower() for d in approved if re.match(r"^[a-z0-9.-]{3,253}$", d.strip().lower())})
    _store.create_tenant(tid, name[:120], doms)
    obs.event("tenant_created", tenant=tid, by=actor.label())
    return {"id": tid, "name": name[:120], "approved_domains": doms}
