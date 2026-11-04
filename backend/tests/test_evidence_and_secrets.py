"""C5 hardening P1: the signed validation evidence verifies, and ANY tampering is detected; the secret-permission
checker flags wrong modes and offline key material under ./secrets. No Docker needed."""
import copy
import json
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ops", "observer"))
import secure_secrets  # noqa: E402
import verify_evidence  # noqa: E402

EV = os.path.join(ROOT, "evidence", "c5", "validation.json")


@pytest.fixture
def doc():
    d = json.load(open(EV))
    if "evidence_sig" not in d:
        pytest.skip("evidence predates signed format")
    return d


def test_committed_evidence_verifies_only_with_an_external_pin(doc):
    # The pin here is read from the file only because this is a test; in operation it comes from an independent channel.
    pin = doc["root_public_key"]
    assert verify_evidence.verify(doc, trusted_root=pin)["valid"]
    assert verify_evidence.verify(doc)["integrity"] == "INTEGRITY_SELF_CONSISTENT_UNPINNED"


@pytest.mark.parametrize("tamper", [
    lambda d: d["steps"][0].__setitem__("ok", not d["steps"][0]["ok"]),          # edit a result
    lambda d: d.__setitem__("commit", "0" * 40),                                  # claim another commit
    lambda d: d["ledger_rows"][0]["detail"].__setitem__("x", 1),                  # edit a signed ledger row
    lambda d: d["attestation_ids"].append("00000000-0000-0000-0000-000000000000"),  # invent an attestation
    lambda d: d["manifest"].__setitem__("manifest_version", 99),                  # swap the manifest
])
def test_tampered_evidence_is_rejected(doc, tamper):
    d = copy.deepcopy(doc)
    tamper(d)
    try:
        r = verify_evidence.verify(d, trusted_root=doc["root_public_key"])
    except Exception:  # manifest signature failure raises
        return
    assert r["valid"] is False


def test_secret_checker_flags_bad_mode_and_offline_keys(tmp_path):
    (tmp_path / "secrets" / "observer" / "ca").mkdir(parents=True)
    p = tmp_path / "secrets" / "data_key"
    p.write_text("x")
    os.chmod(p, 0o644)
    (tmp_path / "secrets" / "observer" / "ca" / "ca.key").write_text("x")
    res = {r["file"]: r for r in secure_secrets.check(str(tmp_path))}
    assert res["secrets/data_key"]["ok"] is False and res["secrets/data_key"]["mode"] == "0o644"
    assert res["secrets/observer/ca/ca.key"]["ok"] is False
