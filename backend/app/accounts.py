"""Human accounts (v1.4): organisation membership, invitations, scrypt passwords, TOTP MFA (RFC 6238) with replay
protection, one-time recovery codes, password reset / account recovery, login throttling and audit events.

Separation from machine credentials: API keys (qsk_) authenticate agents/integrations; humans authenticate ONLY through
/auth/login (+ MFA) and receive a server-side session (qss_, bound to user_id). A password is never accepted as a
bearer token and an API key never satisfies MFA. Human accounts require PostgreSQL (refused in memory mode).

Never logged: passwords, TOTP secrets/codes, recovery codes, invitation/reset/challenge tokens, session tokens.
E-mail addresses are logged only as a short keyed hash.
"""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

from app import identity, mailer, observability as obs
from app.identity import AuthError, Principal

# ---------------- configuration ----------------
def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def require_mfa() -> bool:
    return os.getenv("QYRIX_REQUIRE_MFA", "1") != "0"


CHALLENGE_TTL = 300
MAX_CHALLENGE_ATTEMPTS = 5
RECOVERY_CODES = 10

# ---------------- passwords (scrypt, stdlib) ----------------
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
_COMMON = {"password1234", "qwertyuiop12", "123456789012", "letmein12345", "administrator", "welcome12345", "changeme1234",
           "qyrixsentinel", "passwordpassword", "iloveyou1234"}


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=64 * 1024 * 1024, dklen=32)
    b = lambda x: base64.b64encode(x).decode()
    return "scrypt$%d$%d$%d$%s$%s" % (SCRYPT_N, SCRYPT_R, SCRYPT_P, b(salt), b(dk))


def verify_password(pw: str, stored: str) -> bool:
    try:
        alg, n, r, p, salt, dk = stored.split("$")
        if alg != "scrypt":
            return False
        got = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p), maxmem=64 * 1024 * 1024,
                             dklen=len(base64.b64decode(dk)))
        return hmac.compare_digest(got, base64.b64decode(dk))
    except Exception:
        return False


_DUMMY_HASH = None


def _dummy_verify(pw: str) -> None:
    """Same cost as a real verification, so unknown accounts are not distinguishable by timing."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_hex(16))
    verify_password(pw, _DUMMY_HASH)


def password_problem(pw: str, email: str) -> Optional[str]:
    if not isinstance(pw, str) or len(pw) < 12:
        return "password must be at least 12 characters"
    if len(pw) > 256:
        return "password too long"
    low = pw.lower()
    local = email.split("@")[0].lower()
    if low in _COMMON or len(set(pw)) < 5 or (len(local) >= 4 and local in low):
        return "password too weak (common, repetitive or contains the e-mail name)"
    return None


# ---------------- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) ----------------
STEP = 30


def _clock() -> float:            # indirection so tests can step TOTP time without touching the global clock
    return time.time()


def totp_at(secret: bytes, step: int, digits: int = 6) -> str:
    mac = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_match(secret: bytes, code: str, now: Optional[float] = None, window: int = 1) -> Optional[int]:
    """Matching time step (±window) or None. Constant-time compare per candidate."""
    if not isinstance(code, str) or not re.fullmatch(r"\d{6}", code or ""):
        return None
    step = int((now if now is not None else _clock()) // STEP)
    hit = None
    for s in range(step - window, step + window + 1):
        if hmac.compare_digest(totp_at(secret, s), code):
            hit = s
    return hit


def otpauth_uri(secret: bytes, email: str, tenant: str) -> str:
    from urllib.parse import quote
    b32 = base64.b32encode(secret).decode().rstrip("=")
    return "otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30" % (
        quote("Qyrix Sentinel (%s):%s" % (tenant, email)), b32, quote("Qyrix Sentinel"))


# ---------------- data key (AES-256-GCM for TOTP secrets at rest) ----------------
def _data_key() -> bytes:
    path = os.getenv("QYRIX_DATA_KEY_FILE", "").strip()
    if not path:
        raise AuthError(503, "MFA_KEY_NOT_CONFIGURED")
    try:
        raw = open(path, "rb").read().strip()
    except OSError:
        raise AuthError(503, "MFA_KEY_NOT_CONFIGURED") from None
    try:
        k = bytes.fromhex(raw.decode())
    except ValueError:
        k = base64.b64decode(raw)
    if len(k) != 32:
        raise AuthError(503, "MFA_KEY_NOT_CONFIGURED")
    return k


def seal_secret(secret: bytes, user_id: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(_data_key()).encrypt(nonce, secret, ("totp:" + user_id).encode())


def open_secret(blob: bytes, user_id: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        return AESGCM(_data_key()).decrypt(bytes(blob[:12]), bytes(blob[12:]), ("totp:" + user_id).encode())
    except AuthError:
        raise
    except Exception:
        raise AuthError(503, "MFA_SECRET_UNREADABLE") from None   # wrong key / tampered => fail closed


# ---------------- helpers ----------------
def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _tok(prefix: str) -> Tuple[str, str]:
    t = prefix + secrets.token_urlsafe(32)
    return t, _sha(t)


def email_tag(email: str) -> str:
    """Pseudonymous e-mail identifier for logs (not reversible without the address)."""
    return hashlib.sha256(("qyrix-email:" + (email or "").lower()).encode()).hexdigest()[:12]


def norm_email(e: str) -> str:
    e = (e or "").strip().lower()
    if len(e) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e):
        raise AuthError(422, "invalid e-mail address")
    return e


def _db():
    s = identity.store()
    if not getattr(s, "durable", False) or not hasattr(s, "db"):
        raise AuthError(409, "PERSISTENCE_REQUIRED")          # human accounts need PostgreSQL (fail closed)
    return s.db


def _now():
    return datetime.now(timezone.utc)


def _user_of(p: Principal) -> str:
    if not p.cred_id.startswith("user:"):
        raise AuthError(403, "human user session required")
    return p.cred_id[5:]


# ---------------- throttling (shared limiter; DB-backed when PostgreSQL is configured) ----------------
def _throttle_login(client: str, tenant: str, email: str) -> str:
    acct = "login:acct:" + _sha(tenant + "|" + email)
    if not identity.limiter.hit("login:ip:" + client, _int("QYRIX_LOGIN_PER_IP_PER_MIN", 30)) or \
       not identity.limiter.hit(acct, _int("QYRIX_LOGIN_MAX_FAILURES", 5), window=_int("QYRIX_LOGIN_LOCK_SECONDS", 900), count=False):
        obs.inc("qyrix_rate_limited_total", scope="login")
        obs.event("login_throttled", severity="warning", tenant=tenant, email=email_tag(email), client=client[:64])
        raise AuthError(429, "too many login attempts; try again later")
    return acct


def _fail_login(acct: str, tenant: str, email: str, reason: str, client: str) -> None:
    identity.limiter.hit(acct, 10 ** 9, window=_int("QYRIX_LOGIN_LOCK_SECONDS", 900))
    obs.inc("qyrix_login_failures_total", reason=reason)
    obs.event("login_failed", severity="warning", tenant=tenant, email=email_tag(email), reason=reason, client=client[:64])


# ---------------- login ----------------
def _challenge(cur, uid: str, tenant: str, purpose: str) -> str:
    tok, h = _tok("qch_")
    cur.execute("INSERT INTO login_challenges (token_hash, user_id, tenant_id, purpose, expires_at) VALUES (%s,%s,%s,%s,%s)",
                (h, uid, tenant, purpose, _now() + timedelta(seconds=CHALLENGE_TTL)))
    return tok


def login(tenant: str, email: str, password: str, client: str) -> Dict:
    db = _db()
    email = norm_email(email)
    if not identity.TENANT_RE.match(tenant or ""):
        raise AuthError(401, "invalid credentials")
    acct = _throttle_login(client, tenant, email)

    def find(cur):
        cur.execute("SELECT id, password_hash, mfa_enabled_at IS NOT NULL, disabled_at IS NOT NULL FROM users WHERE email=%s", (email,))
        return cur.fetchone()
    u = db.run(find)
    if not u:
        _dummy_verify(password)
        _fail_login(acct, tenant, email, "unknown_user", client)
        raise AuthError(401, "invalid credentials")
    uid, ph, mfa_on, disabled = u
    if not verify_password(password, ph) or disabled:
        _fail_login(acct, tenant, email, "disabled" if disabled else "bad_password", client)
        raise AuthError(401, "invalid credentials")

    def go(cur):
        cur.execute("SELECT m.role FROM memberships m JOIN tenants t ON t.id = m.tenant_id"
                    " WHERE m.tenant_id=%s AND m.user_id=%s AND t.disabled_at IS NULL", (tenant, uid))
        m = cur.fetchone()
        if not m:
            return None, None
        if mfa_on:
            return m[0], _challenge(cur, uid, tenant, "mfa")
        if require_mfa():
            return m[0], _challenge(cur, uid, tenant, "enroll")
        return m[0], None
    role, ch = db.run(go, tenant=tenant)
    if role is None:
        _fail_login(acct, tenant, email, "not_a_member", client)
        raise AuthError(401, "invalid credentials")
    if ch:
        obs.event("login_password_ok", tenant=tenant, user=uid, next="mfa" if mfa_on else "mfa_enrollment")
        return {"status": "mfa_required" if mfa_on else "mfa_enrollment_required", "challenge": ch, "expires_in": CHALLENGE_TTL}
    obs.event("login_succeeded", severity="warning", tenant=tenant, user=uid, mfa=False)   # only when MFA is optional
    return {"status": "ok", **identity.create_user_session(uid, tenant, role)}


def _take_challenge(cur, token: str, purpose: str) -> Tuple[str, str]:
    """Locks the challenge row; returns (user_id, tenant). Burns it after too many attempts."""
    if not isinstance(token, str) or not token.startswith("qch_"):
        raise AuthError(401, "invalid or expired challenge")
    cur.execute("SELECT user_id, tenant_id, attempts FROM login_challenges WHERE token_hash=%s AND purpose=%s AND used_at IS NULL"
                " AND expires_at > now() FOR UPDATE", (_sha(token), purpose))
    r = cur.fetchone()
    if not r or r[2] >= MAX_CHALLENGE_ATTEMPTS:
        raise AuthError(401, "invalid or expired challenge")
    return r[0], r[1]


def _bump(db, token: str):
    db.run(lambda cur: cur.execute("UPDATE login_challenges SET attempts = attempts + 1 WHERE token_hash=%s", (_sha(token),)))


def _role(cur, tenant: str, uid: str) -> Optional[str]:
    cur.execute("SELECT role FROM memberships WHERE tenant_id=%s AND user_id=%s", (tenant, uid))
    r = cur.fetchone()
    return r[0] if r else None


def login_mfa(challenge: str, code: Optional[str], recovery_code: Optional[str], client: str) -> Dict:
    db = _db()
    if not identity.limiter.hit("mfa:ip:" + client, _int("QYRIX_MFA_PER_IP_PER_MIN", 30)):
        raise AuthError(429, "too many attempts; try again later")

    def go(cur):
        uid, tenant = _take_challenge(cur, challenge, "mfa")
        cur.execute("SELECT set_config('qyrix.tenant_id', %s, true)", (tenant,))
        cur.execute("SELECT totp_secret_enc, last_totp_step FROM users WHERE id=%s AND disabled_at IS NULL FOR UPDATE", (uid,))
        u = cur.fetchone()
        if not u or u[0] is None:
            return None, uid, tenant, "no_mfa"
        method = None
        if code:
            step = totp_match(open_secret(u[0], uid), code)
            if step is not None and step > u[1]:                     # each time step can be used once (replay)
                cur.execute("UPDATE users SET last_totp_step=%s WHERE id=%s", (step, uid))
                method = "totp"
            elif step is not None:
                return None, uid, tenant, "totp_replay"
        elif recovery_code:
            cur.execute("UPDATE recovery_codes SET used_at=now() WHERE user_id=%s AND code_hash=%s AND used_at IS NULL RETURNING 1",
                        (uid, _sha(_norm_rc(recovery_code))))
            method = "recovery_code" if cur.fetchone() else None
        if not method:
            return None, uid, tenant, "bad_code"
        role = _role(cur, tenant, uid)
        if not role:
            return None, uid, tenant, "not_a_member"
        cur.execute("UPDATE login_challenges SET used_at=now() WHERE token_hash=%s", (_sha(challenge),))
        return (role, method), uid, tenant, None
    try:
        ok, uid, tenant, why = db.run(go, tenant="")
    except AuthError:
        raise
    if not ok:
        _bump(db, challenge)
        obs.inc("qyrix_mfa_failures_total", reason=why)
        obs.event("mfa_failed", severity="warning", tenant=tenant, user=uid, reason=why, client=client[:64])
        raise AuthError(401, "invalid code")
    role, method = ok
    if method == "recovery_code":
        left = db.run(lambda cur: (cur.execute("SELECT count(*) FROM recovery_codes WHERE user_id=%s AND used_at IS NULL", (uid,)),
                                   cur.fetchone()[0])[1])
        obs.event("recovery_code_used", severity="warning", tenant=tenant, user=uid, remaining=left)
    obs.event("login_succeeded", tenant=tenant, user=uid, mfa=method)
    return {"status": "ok", **identity.create_user_session(uid, tenant, role)}


# ---------------- MFA enrolment ----------------
def enroll_start(challenge: str) -> Dict:
    db = _db()
    secret = secrets.token_bytes(20)

    def go(cur):
        uid, tenant = _take_challenge(cur, challenge, "enroll")
        cur.execute("SELECT email FROM users WHERE id=%s", (uid,))
        email = cur.fetchone()[0]
        cur.execute("UPDATE users SET totp_pending_enc=%s WHERE id=%s", (seal_secret(secret, uid), uid))
        return email, tenant
    email, tenant = db.run(go)
    return {"secret": base64.b32encode(secret).decode().rstrip("="), "otpauth_uri": otpauth_uri(secret, email, tenant),
            "notice": "Add this to your authenticator app, then confirm with a current code. It is shown only now."}


def _new_recovery_codes(cur, uid: str):
    cur.execute("DELETE FROM recovery_codes WHERE user_id=%s", (uid,))
    codes = []
    for _ in range(RECOVERY_CODES):
        c = base64.b32encode(secrets.token_bytes(10)).decode().lower()          # 80 bits
        c = "-".join(c[i:i + 4] for i in range(0, 16, 4))
        cur.execute("INSERT INTO recovery_codes (user_id, code_hash) VALUES (%s,%s)", (uid, _sha(_norm_rc(c))))
        codes.append(c)
    return codes


def _norm_rc(c: str) -> str:
    return re.sub(r"[^a-z2-7]", "", (c or "").lower())


def enroll_confirm(challenge: str, code: str) -> Dict:
    db = _db()

    def go(cur):
        uid, tenant = _take_challenge(cur, challenge, "enroll")
        cur.execute("SELECT totp_pending_enc FROM users WHERE id=%s FOR UPDATE", (uid,))
        pend = cur.fetchone()[0]
        if pend is None:
            return None, uid, tenant
        step = totp_match(open_secret(pend, uid), code)
        if step is None:
            return None, uid, tenant
        cur.execute("UPDATE users SET totp_secret_enc=totp_pending_enc, totp_pending_enc=NULL, mfa_enabled_at=now(), last_totp_step=%s"
                    " WHERE id=%s", (step, uid))
        codes = _new_recovery_codes(cur, uid)
        cur.execute("UPDATE login_challenges SET used_at=now() WHERE token_hash=%s", (_sha(challenge),))
        cur.execute("SELECT set_config('qyrix.tenant_id', %s, true)", (tenant,))
        return (_role(cur, tenant, uid), codes), uid, tenant
    ok, uid, tenant = db.run(go)
    if not ok or not ok[0]:
        _bump(db, challenge)
        obs.event("mfa_enrollment_failed", severity="warning", tenant=tenant, user=uid)
        raise AuthError(401, "invalid code")
    role, codes = ok
    obs.event("mfa_enrolled", severity="warning", tenant=tenant, user=uid)
    return {"status": "ok", **identity.create_user_session(uid, tenant, role), "recovery_codes": codes,
            "notice": "Store these recovery codes offline. Each works once. They are shown only now."}


def regenerate_recovery_codes(p: Principal, code: str) -> Dict:
    db, uid = _db(), _user_of(p)

    def go(cur):
        cur.execute("SELECT totp_secret_enc, last_totp_step FROM users WHERE id=%s FOR UPDATE", (uid,))
        sec, last = cur.fetchone()
        step = totp_match(open_secret(sec, uid), code) if sec else None
        if step is None or step <= last:
            return None
        cur.execute("UPDATE users SET last_totp_step=%s WHERE id=%s", (step, uid))
        return _new_recovery_codes(cur, uid)
    codes = db.run(go)
    if not codes:
        obs.event("mfa_failed", severity="warning", tenant=p.tenant, user=uid, reason="recovery_regen_bad_code")
        raise AuthError(401, "invalid code")
    obs.event("recovery_codes_regenerated", severity="warning", tenant=p.tenant, user=uid)
    return {"recovery_codes": codes}


# ---------------- passwords ----------------
def _revoke_user_sessions(db, uid: str) -> int:
    return db.run(lambda cur: (cur.execute("SELECT qyrix_revoke_user_sessions(%s)", (uid,)), cur.fetchone()[0])[1])


def change_password(p: Principal, current: str, new: str, code: Optional[str]) -> Dict:
    db, uid = _db(), _user_of(p)
    u = db.run(lambda cur: (cur.execute("SELECT email, password_hash, totp_secret_enc, last_totp_step FROM users WHERE id=%s", (uid,)),
                            cur.fetchone())[1])
    if not verify_password(current, u[1]):
        obs.event("password_change_failed", severity="warning", tenant=p.tenant, user=uid, reason="bad_password")
        raise AuthError(401, "invalid credentials")
    if u[2] is not None:
        step = totp_match(open_secret(u[2], uid), code or "")
        if step is None or step <= u[3]:
            obs.event("password_change_failed", severity="warning", tenant=p.tenant, user=uid, reason="bad_code")
            raise AuthError(401, "invalid code")
    prob = password_problem(new, u[0])
    if prob:
        raise AuthError(422, prob)
    db.run(lambda cur: cur.execute("UPDATE users SET password_hash=%s, password_changed_at=now() WHERE id=%s", (hash_password(new), uid)))
    n = _revoke_user_sessions(db, uid)
    obs.event("password_changed", severity="warning", tenant=p.tenant, user=uid, sessions_revoked=n)
    return {"changed": True, "sessions_revoked": n, "notice": "All sessions were signed out. Sign in again."}


def _issue_reset(db, uid: str, by: str) -> str:
    tok, h = _tok("qpr_")
    db.run(lambda cur: cur.execute("INSERT INTO password_resets (token_hash, user_id, created_by, expires_at) VALUES (%s,%s,%s,%s)",
                                   (h, uid, by, _now() + timedelta(seconds=_int("QYRIX_RESET_TTL_SECONDS", 1800)))))
    return tok


def forgot_password(email: str, client: str) -> Dict:
    """Always the same answer (no account enumeration). A reset link is sent only through a configured mailer."""
    generic = {"status": "accepted", "notice": "If the account exists and e-mail delivery is configured, a reset link was sent."}
    try:
        email = norm_email(email)
    except AuthError:
        return generic
    if not identity.limiter.hit("reset:ip:" + client, _int("QYRIX_RESET_PER_IP_PER_HOUR", 10), window=3600) or \
       not identity.limiter.hit("reset:acct:" + _sha(email), 3, window=3600):
        return generic
    db = _db()
    u = db.run(lambda cur: (cur.execute("SELECT id FROM users WHERE email=%s AND disabled_at IS NULL", (email,)), cur.fetchone())[1])
    obs.event("password_reset_requested", email=email_tag(email), known=bool(u), mailer=mailer.configured())
    if u and mailer.configured():
        tok = _issue_reset(db, u[0], "self-service")
        mailer.send("password_reset", email, {"token": tok})
    return generic


def reset_password(token: str, new: str) -> Dict:
    db = _db()
    if not isinstance(token, str) or not token.startswith("qpr_"):
        raise AuthError(401, "invalid or expired reset token")

    def go(cur):
        cur.execute("SELECT r.user_id, u.email FROM password_resets r JOIN users u ON u.id = r.user_id WHERE r.token_hash=%s"
                    " AND r.used_at IS NULL AND r.expires_at > now() FOR UPDATE OF r", (_sha(token),))
        r = cur.fetchone()
        if not r:
            return None
        prob = password_problem(new, r[1])
        if prob:
            return ("weak", prob)
        cur.execute("UPDATE password_resets SET used_at=now() WHERE token_hash=%s", (_sha(token),))
        cur.execute("UPDATE users SET password_hash=%s, password_changed_at=now() WHERE id=%s", (hash_password(new), r[0]))
        return ("ok", r[0])
    r = db.run(go)
    if not r:
        obs.event("password_reset_failed", severity="warning", reason="invalid_token")
        raise AuthError(401, "invalid or expired reset token")
    if r[0] == "weak":
        raise AuthError(422, r[1])
    n = _revoke_user_sessions(db, r[1])
    obs.event("password_reset_completed", severity="warning", user=r[1], sessions_revoked=n)
    return {"reset": True, "notice": "Password changed. MFA is still required at sign-in."}


# ---------------- organisation membership & invitations ----------------
def _manage(p: Principal):
    if p.platform or not p.can("users.manage"):
        raise AuthError(403, "permission 'users.manage' required")


def invite(p: Optional[Principal], tenant: str, email: str, role: str) -> Dict:
    """Tenant owner/admin invites into their own organisation; the platform operator may bootstrap a tenant's owner."""
    db = _db()
    email = norm_email(email)
    if role not in identity.ROLES:
        raise AuthError(422, "unknown role")
    if p is not None and not p.platform:
        _manage(p)
        if p.tenant != tenant:
            raise AuthError(403, "not allowed")
        if role not in identity.GRANTABLE.get(p.role, set()):
            raise AuthError(403, "cannot grant a role above your own")
    if not identity.store().get_tenant(tenant):
        raise AuthError(404, "unknown tenant")
    tok, h = _tok("qsi_")
    iid = "inv_" + secrets.token_hex(6)
    by = p.label() if p else "system"
    exp = _now() + timedelta(hours=_int("QYRIX_INVITE_TTL_HOURS", 72))
    db.run(lambda cur: cur.execute("INSERT INTO invitations (id, tenant_id, email, role, token_hash, created_by, expires_at)"
                                   " VALUES (%s,%s,%s,%s,%s,%s,%s)", (iid, tenant, email, role, h, by, exp)), tenant=tenant)
    delivered = False
    if mailer.configured():
        delivered = mailer.send("invitation", email, {"token": tok, "tenant": tenant, "role": role})
    obs.event("invitation_created", severity="warning", tenant=tenant, invitation=iid, role=role, email=email_tag(email), by=by,
              delivered=delivered)
    return {"id": iid, "tenant": tenant, "email": email, "role": role, "expires_at": exp.isoformat(), "delivered_by_email": delivered,
            "invitation_token": tok,
            "notice": "Give this token to the invitee over a trusted channel if it was not e-mailed. It is shown only now."}


def accept_invitation(token: str, name: str, password: str, client: str) -> Dict:
    db = _db()
    if not identity.limiter.hit("invite:ip:" + client, _int("QYRIX_INVITE_PER_IP_PER_MIN", 10)):
        raise AuthError(429, "too many attempts; try again later")
    if not isinstance(token, str) or not token.startswith("qsi_"):
        raise AuthError(401, "invalid or expired invitation")
    inv = db.run(lambda cur: (cur.execute("SELECT id, tenant_id, email, role, expires_at, accepted, revoked, tenant_disabled"
                                          " FROM qyrix_lookup_invitation(%s)", (_sha(token),)), cur.fetchone())[1])
    if not inv or inv[5] or inv[6] or inv[7] or inv[4] < _now():
        obs.event("invitation_accept_failed", severity="warning", reason="invalid", client=client[:64])
        raise AuthError(401, "invalid or expired invitation")
    iid, tenant, email, role = inv[:4]
    existing = db.run(lambda cur: (cur.execute("SELECT id, password_hash FROM users WHERE email=%s", (email,)), cur.fetchone())[1])
    if existing:
        if not verify_password(password, existing[1]):             # linking an existing account needs ITS password
            obs.event("invitation_accept_failed", severity="warning", reason="bad_password", tenant=tenant)
            raise AuthError(401, "invalid credentials")
        uid = existing[0]
    else:
        prob = password_problem(password, email)
        if prob:
            raise AuthError(422, prob)
        uid = "usr_" + secrets.token_hex(8)
        db.run(lambda cur: cur.execute("INSERT INTO users (id, email, name, password_hash) VALUES (%s,%s,%s,%s)",
                                       (uid, email, (name or "")[:120], hash_password(password))))

    def go(cur):
        cur.execute("UPDATE invitations SET accepted_at=now() WHERE id=%s AND accepted_at IS NULL AND revoked_at IS NULL"
                    " AND expires_at > now() RETURNING id", (iid,))
        if cur.fetchone() is None:
            return False
        cur.execute("INSERT INTO memberships (tenant_id, user_id, role, created_by) VALUES (%s,%s,%s,%s)"
                    " ON CONFLICT (tenant_id, user_id) DO NOTHING", (tenant, uid, role, "invitation:" + iid))
        return True
    if not db.run(go, tenant=tenant):
        raise AuthError(401, "invalid or expired invitation")
    obs.event("invitation_accepted", severity="warning", tenant=tenant, invitation=iid, user=uid, role=role)
    return {"accepted": True, "tenant": tenant, "role": role, "next": "sign in; MFA enrolment is required on first sign-in"}


def list_invitations(p: Principal):
    _manage(p)
    return _db().run(lambda cur: (cur.execute("SELECT id, email, role, created_by, created_at, expires_at, accepted_at, revoked_at"
                                              " FROM invitations WHERE tenant_id=%s ORDER BY created_at DESC", (p.tenant,)),
                                  [dict(zip(("id", "email", "role", "created_by", "created_at", "expires_at", "accepted_at", "revoked_at"),
                                            [x.isoformat() if hasattr(x, "isoformat") else x for x in r])) for r in cur.fetchall()])[1],
                     tenant=p.tenant)


def revoke_invitation(p: Principal, iid: str):
    _manage(p)
    ok = _db().run(lambda cur: (cur.execute("UPDATE invitations SET revoked_at=now() WHERE tenant_id=%s AND id=%s AND accepted_at IS NULL"
                                            " AND revoked_at IS NULL RETURNING id", (p.tenant, iid)), cur.fetchone())[1], tenant=p.tenant)
    if not ok:
        raise AuthError(404, "unknown or closed invitation")
    obs.event("invitation_revoked", severity="warning", tenant=p.tenant, invitation=iid, by=p.label())
    return {"id": iid, "revoked": True}


def list_members(p: Principal):
    _manage(p)

    def go(cur):
        cur.execute("SELECT m.user_id, u.email, u.name, m.role, m.created_at, u.mfa_enabled_at IS NOT NULL, u.disabled_at IS NOT NULL"
                    " FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.tenant_id=%s ORDER BY m.created_at", (p.tenant,))
        return [{"user_id": r[0], "email": r[1], "name": r[2], "role": r[3], "since": r[4].isoformat(), "mfa": r[5], "disabled": r[6]}
                for r in cur.fetchall()]
    return _db().run(go, tenant=p.tenant)


def _target(cur, p: Principal, uid: str) -> str:
    """The target's role in the caller's org; enforces 'admins cannot act on owners' and 'not on yourself'."""
    if p.cred_id == "user:" + uid:
        raise AuthError(403, "use the self-service endpoints for your own account")
    r = _role(cur, p.tenant, uid)
    if r is None:
        raise AuthError(404, "unknown member")
    if r == "owner" and p.role != "owner":
        raise AuthError(403, "only an owner can manage an owner")
    return r


def _revoke_member_sessions(cur, tenant: str, uid: str):
    cur.execute("UPDATE sessions SET revoked_at=now() WHERE tenant_id=%s AND user_id=%s AND revoked_at IS NULL", (tenant, uid))


def set_role(p: Principal, uid: str, role: str):
    _manage(p)
    if role not in identity.ROLES:
        raise AuthError(422, "unknown role")
    if role not in identity.GRANTABLE.get(p.role, set()):
        raise AuthError(403, "cannot grant a role above your own")

    def go(cur):
        old = _target(cur, p, uid)
        if old == "owner" and role != "owner":
            cur.execute("SELECT count(*) FROM memberships WHERE tenant_id=%s AND role='owner'", (p.tenant,))
            if cur.fetchone()[0] <= 1:
                raise AuthError(409, "cannot demote the last owner")
        cur.execute("UPDATE memberships SET role=%s WHERE tenant_id=%s AND user_id=%s", (role, p.tenant, uid))
        _revoke_member_sessions(cur, p.tenant, uid)                     # sessions carry the old role
        return old
    old = _run_auth(go, p.tenant)
    obs.event("member_role_changed", severity="warning", tenant=p.tenant, user=uid, old=old, new=role, by=p.label())
    return {"user_id": uid, "role": role, "previous_role": old}


def remove_member(p: Principal, uid: str):
    _manage(p)

    def go(cur):
        old = _target(cur, p, uid)
        if old == "owner":
            cur.execute("SELECT count(*) FROM memberships WHERE tenant_id=%s AND role='owner'", (p.tenant,))
            if cur.fetchone()[0] <= 1:
                raise AuthError(409, "cannot remove the last owner")
        cur.execute("DELETE FROM memberships WHERE tenant_id=%s AND user_id=%s", (p.tenant, uid))
        _revoke_member_sessions(cur, p.tenant, uid)
        return old
    old = _run_auth(go, p.tenant)
    obs.event("member_removed", severity="warning", tenant=p.tenant, user=uid, role=old, by=p.label())
    return {"user_id": uid, "removed": True}


def admin_reset_password(p: Principal, uid: str):
    """Admin-assisted account recovery: a single-use reset token, handed to the user out of band (or e-mailed)."""
    _manage(p)
    db = _db()
    _run_auth(lambda cur: _target(cur, p, uid), p.tenant)
    tok = _issue_reset(db, uid, p.label())
    email = db.run(lambda cur: (cur.execute("SELECT email FROM users WHERE id=%s", (uid,)), cur.fetchone()[0])[1])
    delivered = mailer.send("password_reset", email, {"token": tok}) if mailer.configured() else False
    obs.event("password_reset_issued", severity="warning", tenant=p.tenant, user=uid, by=p.label(), delivered=delivered)
    return {"user_id": uid, "reset_token": tok, "delivered_by_email": delivered,
            "notice": "Single use, expires soon. Give it to the user over a trusted channel. MFA stays required."}


def admin_reset_mfa(p: Principal, uid: str):
    """Lost authenticator AND recovery codes: remove MFA; the user must re-enrol (after their password) at next sign-in."""
    _manage(p)
    db = _db()

    def go(cur):
        _target(cur, p, uid)
        cur.execute("UPDATE users SET totp_secret_enc=NULL, totp_pending_enc=NULL, mfa_enabled_at=NULL WHERE id=%s", (uid,))
        cur.execute("DELETE FROM recovery_codes WHERE user_id=%s", (uid,))
    _run_auth(go, p.tenant)
    n = _revoke_user_sessions(db, uid)
    obs.event("mfa_reset", severity="critical", tenant=p.tenant, user=uid, by=p.label(), sessions_revoked=n)
    return {"user_id": uid, "mfa_reset": True, "sessions_revoked": n}


def _run_auth(fn, tenant):
    """Run fn in the tenant context, letting AuthError (a policy refusal, not an outage) propagate unchanged."""
    box = {}

    def wrap(cur):
        try:
            return fn(cur)
        except AuthError as e:
            box["e"] = e
            raise
    try:
        return _db().run(wrap, tenant=tenant)
    except Exception:
        if "e" in box:
            raise box["e"]
        raise


def me(p: Principal) -> Dict:
    uid = _user_of(p)
    r = _db().run(lambda cur: (cur.execute("SELECT id, email, name, mfa_enabled_at, password_changed_at FROM users WHERE id=%s", (uid,)),
                               cur.fetchone())[1])
    left = _db().run(lambda cur: (cur.execute("SELECT count(*) FROM recovery_codes WHERE user_id=%s AND used_at IS NULL", (uid,)),
                                  cur.fetchone()[0])[1])
    return {"user_id": r[0], "email": r[1], "name": r[2], "tenant": p.tenant, "role": p.role, "mfa_enabled": r[3] is not None,
            "recovery_codes_remaining": left, "password_changed_at": r[4].isoformat()}
