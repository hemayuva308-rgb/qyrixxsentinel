"""Regression tests for the PR #1 CodeQL remediation (weak hashing, exception exposure, clear-text logging)."""
import hashlib, io, json, logging, os, secrets
import pytest
from fastapi.testclient import TestClient

import app.gateway as g
from app import accounts, adapter, anchor, identity, integrity, netguard, observability as obs
from app.identity import Principal


# ---------------- token digests: compatibility + purpose restriction ----------------
def test_token_digest_is_byte_compatible_with_v14_storage():
    """Stored api_keys.key_hash / sessions.id_hash were SHA-256 hex of the full token: unchanged, no migration."""
    for prefix in ("qsk_", "qss_"):
        t = prefix + secrets.token_urlsafe(32)
        assert identity.token_digest(t) == hashlib.sha256(t.encode()).hexdigest()
    for prefix in ("qsi_", "qpr_", "qch_"):
        t = prefix + secrets.token_urlsafe(32)
        assert accounts._token_digest(t) == hashlib.sha256(t.encode()).hexdigest()
    c = "abcd-efgh-ijkl-mn23"
    assert accounts._rc_digest(c.upper()) == hashlib.sha256(b"abcdefghijklmn23").hexdigest()   # recovery codes unchanged


@pytest.mark.parametrize("value", ["correct horse battery staple", "admin-token-for-tests-0123456789", "qsk_short",
                                   "qsk_" + "A" * 44, "qsx_" + "A" * 43, "", None, "qss_" + "A" * 42 + "!"])
def test_digest_functions_refuse_anything_that_is_not_a_minted_token(value):
    assert identity.token_digest(value) is None
    assert accounts._token_digest(value) is None


def test_existing_keys_and_sessions_still_authenticate():
    identity.use_store(identity.MemoryStore())
    k = identity.create_key(Principal("default", "owner", "t"), "default", "auditor", "compat", None)
    assert identity.authenticate(k["api_key"]).role == "auditor"
    s = identity.create_session(k["api_key"])
    assert identity.authenticate(s["session_token"]).role == "auditor"
    with pytest.raises(identity.AuthError):
        identity.authenticate("qsk_" + "A" * 10)                       # malformed token: refused, not hashed


def test_operator_token_fingerprint_uses_scrypt_not_a_fast_hash(monkeypatch):
    monkeypatch.setenv("QYRIX_ADMIN_TOKEN", "operator-chosen-token-0123456789")
    fp = identity._env_fingerprint("env:admin")
    v = "operator-chosen-token-0123456789"
    assert fp == hashlib.scrypt(v.encode(), salt=b"qyrix-env-fp:QYRIX_ADMIN_TOKEN", n=2 ** 15, r=8, p=1,
                                maxmem=64 * 1024 * 1024, dklen=16).hex()[:16]
    assert fp != hashlib.sha256(("fp:" + v).encode()).hexdigest()[:16]   # the v1.4 fast fingerprint is gone
    assert identity._env_fingerprint("env:admin") == fp                    # stable (cached) within a process
    monkeypatch.setenv("QYRIX_ADMIN_TOKEN", "rotated-operator-token-0123456789")
    assert identity._env_fingerprint("env:admin") != fp                    # rotation still detected


# ---------------- no exception text / class names in responses ----------------
class _Boom(Exception):
    pass


def test_execution_errors_use_a_fixed_vocabulary():
    assert g._public_exec_error(netguard.NetguardError("prohibited address in dns answer")) == "prohibited address in dns answer"
    assert g._public_exec_error(adapter.AdapterError("path not allowed")) == "path not allowed"
    assert g._public_exec_error(adapter.AdapterError("/etc/secret-path: errno 13")) == "execution failed"
    assert g._public_exec_error(_Boom("internal detail /srv/x")) == "execution failed"


def test_llm_provider_errors_use_a_fixed_vocabulary():
    import httpx
    assert g._public_llm_error(httpx.ReadTimeout("t")) == "Timeout"
    assert g._public_llm_error(httpx.ConnectError("dns of internal-host failed")) == "provider unreachable"
    assert g._public_llm_error(ValueError("schema: extra key 'x'")) == "invalid model output (schema)"
    assert g._public_llm_error(_Boom("x")) == "provider error"


def test_integrity_reasons_never_carry_exception_text_or_class():
    assert integrity.reason_of(integrity.WitnessError("PROOF_CHAIN_REGRESSED")) == "PROOF_CHAIN_REGRESSED"
    assert integrity.reason_of(integrity.WitnessError("free text from somewhere")) == "CHECK_FAILED"
    assert integrity.reason_of(_Boom("OperationalError: connection to 10.0.0.5 failed")) == "CHECK_FAILED"


def test_anchor_verification_detail_is_generic(tmp_path, monkeypatch):
    ca = tmp_path / "ca.pem"; ca.write_text("not a certificate")
    monkeypatch.setenv("QYRIX_TSA_CA_FILE", str(ca))
    import base64
    ok, detail = anchor.verify_token("a" * 64, base64.b64encode(b"garbage").decode())
    assert ok is False and detail == "verification failed" and str(tmp_path) not in detail


def test_ready_and_status_expose_only_reason_codes(monkeypatch):
    from app.main import app
    from tests.conftest import ADMIN
    g.PROD.state["integrity"] = {"status": integrity.RECOVERY, "reason": integrity.reason_of(_Boom("secret-ish internals"))}
    try:
        r = TestClient(app).get("/api/v1/ready")
        assert r.status_code == 503 and r.json()["detail"]["checks"]["integrity_reason"] == "CHECK_FAILED"
        assert "_Boom" not in r.text and "internals" not in r.text
        s = TestClient(app, headers=ADMIN).get("/api/v1/sentinel/status").text
        assert "_Boom" not in s and "internals" not in s
    finally:
        g.PROD.state.pop("integrity", None)
