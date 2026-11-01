"""RFC 3161 anchoring: PASS only with a verified token covering the head; prefix => PARTIAL; mismatch/forgery => FAIL;
TSA unavailable or misbehaving => safe refusal; anchoring never changes Gate decisions. Uses a REAL local TSA."""
import base64, json, shutil
import pytest
from fastapi.testclient import TestClient

import app.gateway as g
from app import anchor, proof
from app.main import app
from tests.conftest import ADMIN, AGENT
from tests.tsa_local import LocalTSA

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl CLI required")
c = TestClient(app, headers=ADMIN)
agent = TestClient(app, headers=AGENT)
P = "/api/v1/sentinel"


@pytest.fixture(scope="module")
def tsa():
    t = LocalTSA()
    yield t
    t.close()


@pytest.fixture(autouse=True)
def clean(monkeypatch, tsa):
    c.post(P + "/reset")
    g._token_cache.clear()
    monkeypatch.setenv("QYRIX_TSA_URL", tsa.url)
    monkeypatch.setenv("QYRIX_TSA_CA_FILE", tsa.ca_file)
    tsa.fail_mode = None
    yield
    c.post(P + "/reset")


def decide(n=2):
    sid = c.post(P + "/provenance/step", json={"label": "TRUSTED", "text": "x"}).json()["id"]
    for _ in range(n):
        c.post(P + "/gate/evaluate", json={"tool": "http", "dest": "https://evil.example.net/x", "lineage": [sid]})
    return sid


def test_not_configured_stays_partial_unanchored(monkeypatch):
    monkeypatch.delenv("QYRIX_TSA_URL"); monkeypatch.delenv("QYRIX_TSA_CA_FILE")
    decide()
    r = c.post(P + "/proofs/anchor")
    assert r.status_code == 409 and r.json()["detail"].startswith("ANCHOR_NOT_CONFIGURED")
    assert c.get(P + "/proofs/verify").json()["status"] == "PARTIAL_UNANCHORED"


def test_anchor_covering_head_is_pass_then_new_records_make_it_partial():
    decide()
    r = c.post(P + "/proofs/anchor")
    assert r.status_code == 200, r.text
    a = r.json()
    assert a["method"] == "rfc3161" and a["n"] == 2 and a["serial"] and a["gen_time"] and "token_b64" not in a
    v = c.get(P + "/proofs/verify").json()
    assert v["status"] == "PASS" and v["anchor_status"] == "ANCHORED" and v["anchored_through"] == 2
    decide(1)                                                          # chain grows past the anchor
    v = c.get(P + "/proofs/verify").json()
    assert v["status"] == "PARTIAL_UNANCHORED" and v["anchor_status"] == "ANCHORED_PREFIX" and v["anchored_through"] == 2
    assert c.get(P + "/status").json()["chain_status"] == "PARTIAL_UNANCHORED"


def test_token_independently_verifiable_with_openssl(tmp_path, tsa):
    decide()
    c.post(P + "/proofs/anchor")
    a = g.PROD.anchors[-1]
    (tmp_path / "t.tsr").write_bytes(base64.b64decode(a["token_b64"]))
    import subprocess
    ok = subprocess.run(["openssl", "ts", "-verify", "-digest", a["head_hash"], "-in", str(tmp_path / "t.tsr"), "-CAfile", tsa.ca_file],
                        capture_output=True, text=True)
    assert "Verification: OK" in ok.stdout + ok.stderr
    bad = subprocess.run(["openssl", "ts", "-verify", "-digest", "0" * 64, "-in", str(tmp_path / "t.tsr"), "-CAfile", tsa.ca_file],
                         capture_output=True, text=True)
    assert "Verification: OK" not in bad.stdout + bad.stderr


def test_tampered_chain_after_anchoring_fails():
    decide()
    c.post(P + "/proofs/anchor")
    g.PROD.chain[0]["verdict"] = "ALLOW"                               # tamper with anchored evidence
    v = c.get(P + "/proofs/verify").json()
    assert v["status"] == "FAIL"


def test_mismatched_anchor_fails_and_degrades_gate():
    decide()
    c.post(P + "/proofs/anchor")
    g.PROD.anchors[-1] = {**g.PROD.anchors[-1], "head_hash": "f" * 64}  # anchor store manipulated
    v = c.get(P + "/proofs/verify").json()
    assert v["status"] == "FAIL" and v["anchor_status"] == "ANCHOR_MISMATCH"
    sid = c.post(P + "/provenance/step", json={"label": "TRUSTED", "text": "x"}).json()["id"]
    r = c.post(P + "/gate/evaluate", json={"tool": "http", "dest": "https://github.com/x", "lineage": [sid]}).json()
    assert r["verdict"] == "BLOCK" and "R11_PROOF_DEGRADED" in r["rules"]


def test_token_from_untrusted_tsa_is_rejected(monkeypatch, tsa):
    other = LocalTSA("ROGUE TSA")
    try:
        decide()
        monkeypatch.setenv("QYRIX_TSA_URL", other.url)                    # rogue TSA answers, but our CA does not trust it
        r = c.post(P + "/proofs/anchor")
        assert r.status_code == 503 and r.json()["detail"].startswith("ANCHOR_INVALID")
        assert not g.PROD.anchors
    finally:
        other.close()


def test_forged_token_in_store_fails_verification(monkeypatch, tsa):
    decide()
    c.post(P + "/proofs/anchor")
    other = LocalTSA("ROGUE TSA")
    try:
        monkeypatch.setenv("QYRIX_TSA_CA_FILE", other.ca_file)           # verifier's trust anchor no longer matches token
        g._token_cache.clear()
        v = c.get(P + "/proofs/verify").json()
        assert v["status"] == "FAIL" and v["anchor_status"] == "ANCHOR_INVALID"
    finally:
        other.close()


@pytest.mark.parametrize("mode,code", [("http500", "ANCHOR_UNAVAILABLE"), ("garbage", "ANCHOR_REJECTED")])
def test_tsa_failures_are_safe(tsa, mode, code):
    sid = decide()
    tsa.fail_mode = mode
    r = c.post(P + "/proofs/anchor")
    assert r.status_code == 503 and r.json()["detail"].startswith(code)
    assert not g.PROD.anchors and c.get(P + "/proofs/verify").json()["status"] == "PARTIAL_UNANCHORED"
    ok = c.post(P + "/gate/evaluate", json={"tool": "http", "dest": "https://github.com/x", "lineage": [sid]}).json()
    assert ok["verdict"] == "ALLOW"                                     # anchoring failure never changes decisions


def test_unreachable_tsa(monkeypatch):
    decide()
    monkeypatch.setenv("QYRIX_TSA_URL", "http://127.0.0.1:9/tsr")
    monkeypatch.setenv("QYRIX_TSA_TIMEOUT_SECONDS", "2")
    r = c.post(P + "/proofs/anchor")
    assert r.status_code == 503 and r.json()["detail"].startswith("ANCHOR_UNAVAILABLE")


def test_empty_chain_and_agent_cannot_anchor():
    assert c.post(P + "/proofs/anchor").status_code == 422
    decide()
    assert agent.post(P + "/proofs/anchor").status_code == 403


def test_exported_bundle_carries_anchor_and_verifies_offline(tsa, tmp_path):
    decide()
    c.post(P + "/proofs/anchor")
    b = c.get(P + "/proofs/export").json()
    assert b["anchors"] and b["verify"]["status"] == "PASS"
    assert c.post(P + "/proofs/verify-bundle", json=b).json()["status"] == "PASS"
    tam = json.loads(json.dumps(b)); tam["anchors"][0]["head_hash"] = "e" * 64
    assert c.post(P + "/proofs/verify-bundle", json=tam).json()["status"] == "FAIL"
    path = tmp_path / "bundle.json"; path.write_text(json.dumps(b))
    import subprocess, sys, os
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = subprocess.run([sys.executable, "scripts/verify_proof.py", str(path), "--tsa-ca", tsa.ca_file], cwd=here, capture_output=True, text=True)
    assert r.returncode == 0 and '"PASS"' in r.stdout
    r = subprocess.run([sys.executable, "scripts/verify_proof.py", str(path)], cwd=here, capture_output=True, text=True)
    assert r.returncode == 0 and '"PARTIAL_UNANCHORED"' in r.stdout     # without a trust anchor: never PASS


def test_anchors_survive_restart_via_file(tsa):
    decide()
    c.post(P + "/proofs/anchor")
    ctx = g.GateContext("restart", g.prov.ProvenanceStore(), g.CHAIN_FILE, lambda: (), {}, None)
    g._load_chain(ctx); g._load_anchors(ctx)
    assert len(ctx.anchors) == 1 and g.verify_chain(ctx)["status"] == "PASS"
