"""Human identity acceptance tests (Phase D) on real PostgreSQL: invitations, scrypt passwords, TOTP MFA (RFC 6238 vectors,
replay), recovery codes, enrolment, login throttling, password change/reset, admin recovery, membership management,
session revocation, secret-free logging, separation from API keys."""
import base64, io, json, logging, os
import pytest
from fastapi.testclient import TestClient

from app import accounts, identity, mailer, migrate, persistence, tenancy
from app.identity import Principal
from app.main import app
from tests.test_persistence import Cluster, HAVE_PG

P, AU = "/api/v1/sentinel", "/api/v1/auth"
PLATFORM = "platform-token-for-tests-0123456789"
PW = "correct horse battery staple 42"


# ---------------- pure functions (no database) ----------------
@pytest.mark.parametrize("t,code", [(59, "94287082"), (1111111109, "07081804"), (1111111111, "14050471"),
                                    (1234567890, "89005924"), (2000000000, "69279037"), (20000000000, "65353130")])
def test_totp_rfc6238_sha1_vectors(t, code):
    assert accounts.totp_at(b"12345678901234567890", t // 30, digits=8) == code


def test_totp_window_and_format():
    s = os.urandom(20)
    now = 1_800_000_000
    assert accounts.totp_match(s, accounts.totp_at(s, now // 30), now) == now // 30
    assert accounts.totp_match(s, accounts.totp_at(s, now // 30 + 1), now) == now // 30 + 1      # +1 step clock skew
    assert accounts.totp_match(s, accounts.totp_at(s, now // 30 + 3), now) is None
    for bad in ("", "12345", "1234567", "abcdef", None, "12 456"):
        assert accounts.totp_match(s, bad, now) is None


def test_password_hashing_and_policy():
    h = accounts.hash_password(PW)
    assert h.startswith("scrypt$32768$8$1$") and PW not in h and accounts.verify_password(PW, h)
    assert not accounts.verify_password(PW + "x", h) and not accounts.verify_password(PW, "garbage")
    assert accounts.hash_password(PW) != h                                       # salted
    for weak in ("short", "aaaaaaaaaaaaaaaa", "password1234", "alice-is-great-2026"):
        assert accounts.password_problem(weak, "alice@example.com"), weak
    assert accounts.password_problem(PW, "alice@example.com") is None


def test_human_accounts_refused_without_postgres(monkeypatch):
    identity.use_store(identity.MemoryStore())
    r = TestClient(app).post(AU + "/login", json={"tenant": "default", "email": "a@example.com", "password": PW})
    assert r.status_code == 409 and r.json()["detail"] == "PERSISTENCE_REQUIRED"


# ---------------- PostgreSQL flows ----------------
pg = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(scope="module")
def cluster():
    c = Cluster()
    yield c
    c.destroy()


class Clock:
    def __init__(self):
        self.t = 1_900_000_000.0

    def __call__(self):
        return self.t

    def tick(self, steps=1):
        self.t += 30 * steps


@pytest.fixture
def h(cluster, monkeypatch, tmp_path):
    import psycopg
    db = "a" + os.urandom(4).hex()
    with psycopg.connect(cluster.admin_url, autocommit=True) as c:
        c.execute("CREATE DATABASE %s" % db)
    admin = cluster.admin_url.rsplit("/", 1)[0] + "/" + db
    migrate.migrate(admin)
    url = cluster.runtime_url(db)
    key = tmp_path / "data.key"; key.write_text(os.urandom(32).hex())
    for k, v in {"QYRIX_DATABASE_URL": url, "QYRIX_MULTI_TENANT": "1", "QYRIX_PLATFORM_TOKEN": PLATFORM,
                 "QYRIX_DATA_KEY_FILE": str(key)}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv("QYRIX_MAIL_WEBHOOK_URL", raising=False)
    identity.use_store(identity.PgStore(persistence.shared_connection(url)))
    identity.limiter.clear()
    clock = Clock(); monkeypatch.setattr(accounts, "_clock", clock)
    pl = TestClient(app, headers={"Authorization": "Bearer " + PLATFORM})
    for t in ("acme", "globex"):
        assert pl.post("/api/v1/platform/tenants", json={"id": t, "name": t}).status_code == 200
    yield {"pl": pl, "admin": admin, "url": url, "clock": clock, "key": key}
    with tenancy._lock:
        tenancy._contexts.clear()
    identity.use_store(identity.MemoryStore())
    identity.limiter.clear()


def bearer(tok):
    return TestClient(app, headers={"Authorization": "Bearer " + tok})


anon = TestClient(app)


def invite(h, tenant="acme", email="alice@example.com", role="owner", by=None):
    c = by or h["pl"]
    path = ("/api/v1/platform/tenants/%s/invitations" % tenant) if by is None else P + "/invitations"
    r = c.post(path, json={"email": email, "role": role})
    assert r.status_code == 200, r.text
    return r.json()["invitation_token"]


def onboard(h, tenant="acme", email="alice@example.com", role="owner", by=None):
    """Invitation -> account -> first login -> TOTP enrolment -> session. Returns (session, secret, recovery codes)."""
    tok = invite(h, tenant, email, role, by)
    assert anon.post(AU + "/invitations/accept", json={"token": tok, "name": "A", "password": PW}).status_code == 200
    r = anon.post(AU + "/login", json={"tenant": tenant, "email": email, "password": PW}).json()
    assert r["status"] == "mfa_enrollment_required" and "session_token" not in r
    st = anon.post(AU + "/mfa/enroll/start", json={"challenge": r["challenge"]}).json()
    secret = base64.b32decode(st["secret"] + "=" * (-len(st["secret"]) % 8))
    code = accounts.totp_at(secret, int(h["clock"]() // 30))
    done = anon.post(AU + "/mfa/enroll/confirm", json={"challenge": r["challenge"], "code": code}).json()
    assert done["status"] == "ok" and len(done["recovery_codes"]) == 10
    h["clock"].tick()
    return done["session_token"], secret, done["recovery_codes"]


def mfa_login(h, secret, tenant="acme", email="alice@example.com", code=None):
    r = anon.post(AU + "/login", json={"tenant": tenant, "email": email, "password": PW}).json()
    assert r["status"] == "mfa_required", r
    c = code or accounts.totp_at(secret, int(h["clock"]() // 30))
    return r["challenge"], anon.post(AU + "/login/mfa", json={"challenge": r["challenge"], "code": c})


@pg
def test_invitation_enrolment_and_mfa_login(h):
    sess, secret, _ = onboard(h)
    me = bearer(sess).get(AU + "/me").json()
    assert me["tenant"] == "acme" and me["role"] == "owner" and me["mfa_enabled"] and me["recovery_codes_remaining"] == 10
    assert bearer(sess).get(P + "/status").json()["credential"].startswith("user:usr_")
    ch, r = mfa_login(h, secret)
    assert r.status_code == 200 and r.json()["session_token"].startswith("qss_")


@pg
def test_no_session_before_mfa_and_challenge_is_not_a_credential(h):
    tok = invite(h)
    anon.post(AU + "/invitations/accept", json={"token": tok, "password": PW})
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW}).json()
    assert "session_token" not in r
    assert bearer(r["challenge"]).get(P + "/status").status_code == 401           # a challenge is not a session
    assert bearer(PW).get(P + "/status").status_code == 401                          # a password is never a bearer token
    assert anon.post(AU + "/session", json={"credential": PW}).status_code == 401     # nor exchangeable for a session


@pg
def test_totp_replay_wrong_code_and_challenge_burn(h):
    sess, secret, _ = onboard(h)
    code = accounts.totp_at(secret, int(h["clock"]() // 30))
    _, r = mfa_login(h, secret, code=code)
    assert r.status_code == 200
    _, r = mfa_login(h, secret, code=code)
    assert r.status_code == 401                                                       # same code, same step: replay refused
    h["clock"].tick()
    r0 = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW}).json()
    for _ in range(5):
        assert anon.post(AU + "/login/mfa", json={"challenge": r0["challenge"], "code": "000000"}).status_code == 401
    good = accounts.totp_at(secret, int(h["clock"]() // 30))
    assert anon.post(AU + "/login/mfa", json={"challenge": r0["challenge"], "code": good}).status_code == 401   # burnt


@pg
def test_recovery_codes_are_one_time_and_regenerable(h):
    sess, secret, codes = onboard(h)
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW}).json()
    ok = anon.post(AU + "/login/mfa", json={"challenge": r["challenge"], "recovery_code": codes[0].upper()})
    assert ok.status_code == 200
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW}).json()
    assert anon.post(AU + "/login/mfa", json={"challenge": r["challenge"], "recovery_code": codes[0]}).status_code == 401
    assert bearer(sess).get(AU + "/me").json()["recovery_codes_remaining"] == 9
    new = bearer(sess).post(AU + "/mfa/recovery-codes", json={"code": accounts.totp_at(secret, int(h["clock"]() // 30))}).json()
    assert len(new["recovery_codes"]) == 10 and codes[1] not in new["recovery_codes"]
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW}).json()
    assert anon.post(AU + "/login/mfa", json={"challenge": r["challenge"], "recovery_code": codes[1]}).status_code == 401   # old set gone


@pg
def test_login_errors_are_uniform_and_throttled(h, monkeypatch):
    onboard(h)
    bad = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": "wrong password!!"})
    unknown = anon.post(AU + "/login", json={"tenant": "acme", "email": "nobody@example.com", "password": "wrong password!!"})
    other_org = anon.post(AU + "/login", json={"tenant": "globex", "email": "alice@example.com", "password": PW})
    assert bad.status_code == unknown.status_code == other_org.status_code == 401
    assert bad.json() == unknown.json() == other_org.json() == {"detail": "invalid credentials"}
    identity.limiter.clear()
    for who in ("alice@example.com", "ghost@example.com"):                      # same lock behaviour, known or not
        codes = [anon.post(AU + "/login", json={"tenant": "acme", "email": who, "password": "wrong password!!"}).status_code
                 for _ in range(7)]
        assert codes[:5] == [401] * 5 and codes[5:] == [429, 429], (who, codes)
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW})
    assert r.status_code == 429                                                       # locked even with the right password


@pg
def test_password_change_revokes_sessions(h):
    sess, secret, _ = onboard(h)
    c = bearer(sess)
    assert c.post(AU + "/password/change", json={"current_password": "nope nope nope", "new_password": "x" * 20}).status_code == 401
    r = c.post(AU + "/password/change", json={"current_password": PW, "new_password": "a brand new long passphrase 7",
                                             "code": accounts.totp_at(secret, int(h["clock"]() // 30))})
    assert r.status_code == 200 and r.json()["sessions_revoked"] >= 1
    assert c.get(AU + "/me").status_code == 401


@pg
def test_admin_assisted_reset_and_mfa_reset(h):
    owner, osec, _ = onboard(h)
    tok = invite(h, email="bob@example.com", role="approver", by=bearer(owner))
    anon.post(AU + "/invitations/accept", json={"token": tok, "password": PW})
    bob = anon.post(AU + "/login", json={"tenant": "acme", "email": "bob@example.com", "password": PW}).json()
    st = anon.post(AU + "/mfa/enroll/start", json={"challenge": bob["challenge"]}).json()
    bsec = base64.b32decode(st["secret"] + "=" * (-len(st["secret"]) % 8))
    bs = anon.post(AU + "/mfa/enroll/confirm", json={"challenge": bob["challenge"], "code": accounts.totp_at(bsec, int(h["clock"]() // 30))}).json()
    members = bearer(owner).get(P + "/members").json()["members"]
    bob_id = next(m["user_id"] for m in members if m["email"] == "bob@example.com")
    rt = bearer(owner).post(P + "/members/%s/password-reset" % bob_id).json()["reset_token"]
    assert anon.post(AU + "/password/reset", json={"token": rt, "new_password": "short"}).status_code == 422
    assert anon.post(AU + "/password/reset", json={"token": rt, "new_password": "bobs new long passphrase 9"}).status_code == 200
    assert anon.post(AU + "/password/reset", json={"token": rt, "new_password": "bobs other passphrase 10"}).status_code == 401  # single use
    assert bearer(bs["session_token"]).get(AU + "/me").status_code == 401                   # sessions revoked
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "bob@example.com", "password": "bobs new long passphrase 9"}).json()
    assert r["status"] == "mfa_required"                                                     # reset never removes MFA
    assert bearer(owner).post(P + "/members/%s/mfa-reset" % bob_id).json()["mfa_reset"]
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "bob@example.com", "password": "bobs new long passphrase 9"}).json()
    assert r["status"] == "mfa_enrollment_required"


@pg
def test_membership_management_rules(h):
    owner, _, _ = onboard(h)
    o = bearer(owner)
    adm_tok = invite(h, email="carol@example.com", role="admin", by=o)
    anon.post(AU + "/invitations/accept", json={"token": adm_tok, "password": PW})
    carol = anon.post(AU + "/login", json={"tenant": "acme", "email": "carol@example.com", "password": PW}).json()
    st = anon.post(AU + "/mfa/enroll/start", json={"challenge": carol["challenge"]}).json()
    csec = base64.b32decode(st["secret"] + "=" * (-len(st["secret"]) % 8))
    cs = anon.post(AU + "/mfa/enroll/confirm", json={"challenge": carol["challenge"], "code": accounts.totp_at(csec, int(h["clock"]() // 30))}).json()
    c = bearer(cs["session_token"])
    ids = {m["email"]: m["user_id"] for m in o.get(P + "/members").json()["members"]}
    assert c.post(P + "/invitations", json={"email": "x@example.com", "role": "owner"}).status_code == 403   # admin can't mint owner
    assert c.post(P + "/members/%s/role" % ids["alice@example.com"], json={"role": "auditor"}).status_code == 403   # nor touch owners
    assert o.post(P + "/members/%s/role" % ids["alice@example.com"], json={"role": "admin"}).status_code == 403     # not yourself
    assert o.post(P + "/members/%s/role" % ids["carol@example.com"], json={"role": "auditor"}).status_code == 200
    assert c.get(AU + "/me").status_code == 401                                         # role change ends old-role sessions
    assert o.delete(P + "/members/%s" % ids["carol@example.com"]).status_code == 200
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "carol@example.com", "password": PW})
    assert r.status_code == 401                                                          # no longer a member


@pg
def test_invitations_single_use_expiry_revocation_and_tenant_scope(h):
    owner, _, _ = onboard(h)
    o = bearer(owner)
    tok = invite(h, email="dan@example.com", role="auditor", by=o)
    assert anon.post(AU + "/invitations/accept", json={"token": tok, "password": PW}).status_code == 200
    assert anon.post(AU + "/invitations/accept", json={"token": tok, "password": PW}).status_code == 401   # single use
    tok2 = invite(h, email="erin@example.com", role="auditor", by=o)
    iid = next(i["id"] for i in o.get(P + "/invitations").json()["invitations"] if i["email"] == "erin@example.com")
    assert o.post(P + "/invitations/%s/revoke" % iid).status_code == 200
    assert anon.post(AU + "/invitations/accept", json={"token": tok2, "password": PW}).status_code == 401  # revoked
    tok3 = invite(h, email="fay@example.com", role="auditor", by=o)
    import psycopg
    with psycopg.connect(h["admin"], autocommit=True) as a:
        a.execute("UPDATE invitations SET expires_at = now() - interval '1 minute' WHERE email = 'fay@example.com'")
    assert anon.post(AU + "/invitations/accept", json={"token": tok3, "password": PW}).status_code == 401  # expired
    g_owner, _, _ = onboard(h, tenant="globex", email="gil@example.com")
    assert all(i["email"] != "dan@example.com" for i in bearer(g_owner).get(P + "/invitations").json()["invitations"])
    assert bearer(g_owner).post(P + "/invitations/%s/revoke" % iid).status_code == 404
    assert all(m["email"] != "alice@example.com" for m in bearer(g_owner).get(P + "/members").json()["members"])


@pg
def test_existing_account_links_only_with_its_password(h):
    onboard(h)                                                                           # alice exists (acme)
    tok = invite(h, tenant="globex", email="alice@example.com", role="auditor")
    assert anon.post(AU + "/invitations/accept", json={"token": tok, "password": "an attacker chosen pass 1"}).status_code == 401
    assert anon.post(AU + "/invitations/accept", json={"token": tok, "password": PW}).status_code == 200


@pg
def test_forgot_password_is_generic_and_uses_only_the_mail_boundary(h, monkeypatch, tmp_path):
    onboard(h)
    a = anon.post(AU + "/password/forgot", json={"email": "alice@example.com"})
    b = anon.post(AU + "/password/forgot", json={"email": "nobody@example.com"})
    assert a.status_code == b.status_code == 202 and a.json() == b.json()
    import psycopg
    with psycopg.connect(h["admin"]) as c:
        assert c.execute("SELECT count(*) FROM password_resets").fetchone()[0] == 0     # mailer not configured: nothing issued
    sent = []
    sec = tmp_path / "mail.secret"; sec.write_text("m" * 40)
    monkeypatch.setenv("QYRIX_MAIL_WEBHOOK_URL", "https://mail-relay.internal/send")
    monkeypatch.setenv("QYRIX_MAIL_WEBHOOK_SECRET_FILE", str(sec))
    monkeypatch.setenv("QYRIX_PUBLIC_URL", "https://sentinel.example")
    monkeypatch.setattr(mailer, "_transport", lambda url, body, headers: (sent.append((url, json.loads(body), headers)), 202)[1])
    identity.limiter.clear()
    assert anon.post(AU + "/password/forgot", json={"email": "alice@example.com"}).json() == a.json()
    url, msg, hdr = sent[0]
    assert msg["kind"] == "password_reset" and msg["link"].startswith("https://sentinel.example/reset#token=qpr_") and hdr["x-qyrix-signature"]
    tok = msg["link"].split("#token=")[1]
    assert anon.post(AU + "/password/reset", json={"token": tok, "new_password": "reset via email works 123"}).status_code == 200


@pg
def test_totp_secret_encrypted_at_rest_and_wrong_key_fails_closed(h):
    sess, secret, codes = onboard(h)
    import psycopg
    with psycopg.connect(h["admin"]) as c:
        enc = bytes(c.execute("SELECT totp_secret_enc FROM users").fetchone()[0])
        rc = [r[0] for r in c.execute("SELECT code_hash FROM recovery_codes").fetchall()]
        ph = c.execute("SELECT password_hash FROM users").fetchone()[0]
    assert secret not in enc and base64.b32encode(secret) not in enc and len(enc) == 12 + 20 + 16
    assert not any(code.replace("-", "") in "".join(rc) for code in codes) and PW not in ph
    h["key"].write_text(os.urandom(32).hex())                                          # wrong data key
    r = anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": PW}).json()
    x = anon.post(AU + "/login/mfa", json={"challenge": r["challenge"], "code": accounts.totp_at(secret, int(h["clock"]() // 30))})
    assert x.status_code == 503 and "session_token" not in x.text


@pg
def test_no_secrets_in_security_logs(h):
    buf = io.StringIO(); hd = logging.StreamHandler(buf); logging.getLogger("qyrix.security").addHandler(hd)
    try:
        sess, secret, codes = onboard(h)
        ch, r = mfa_login(h, secret)
        anon.post(AU + "/login", json={"tenant": "acme", "email": "alice@example.com", "password": "wrong password!!"})
        tok = invite(h, email="hal@example.com", role="auditor", by=bearer(sess))
    finally:
        logging.getLogger("qyrix.security").removeHandler(hd)
    out = buf.getvalue()
    for ev in ("invitation_created", "invitation_accepted", "mfa_enrolled", "login_succeeded", "login_failed", "session_created"):
        assert '"event":"%s"' % ev in out, ev
    for s in [PW, "wrong password!!", sess, r.json()["session_token"], ch, tok, base64.b32encode(secret).decode().rstrip("="),
              "alice@example.com", "hal@example.com"] + codes:
        assert s not in out, s
