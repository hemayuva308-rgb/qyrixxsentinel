"""C6: offline evidence verifier - ledger continuity, order, replay, sequence, tenant/epoch, verdict support, run
window, trusted manifest, integrity vs occurrence. Each check is exercised on a synthetic chain that is properly
SIGNED by the observer key (so the failure comes from the C6 check, not from a broken signature)."""
import copy
import hashlib
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "ops", "observer"))
import verify_evidence  # noqa: E402
from observer import crypto, ledger  # noqa: E402
from observer.canonical import canonical  # noqa: E402
from observer.manifest import sign_manifest  # noqa: E402

KEYS = {n: crypto.generate() for n in ("root", "obs", "att", "other")}
T0 = "2026-11-04T03:00:%02d+00:00"
ROOT_PIN = crypto.describe(KEYS["root"])[1]                 # stands in for the independently provisioned pin


def V(d, **kw):
    return verify_evidence.verify(d, trusted_root=kw.pop("trusted_root", ROOT_PIN), **kw)


A1, A2, R1 = "a1111111-0000-0000-0000-000000000001", "a2222222-0000-0000-0000-000000000002", "r1111111-0000-0000-0000-000000000003"


def _e(k):
    return {"key_id": crypto.describe(k)[0], "public_key": crypto.describe(k)[1], "valid_from": "2026-01-01T00:00:00+00:00"}


def base_rows():
    return [  # (kind, code, producer, tenant, ref, detail)
        ("config", "MANIFEST_INSTALLED", None, None, "1", {}),
        ("heartbeat", "ACCEPTED", "gate:x", None, "h1", {"epoch": 1, "hb_seq": 1}),
        ("event", "ACCEPTED", "gate:x", "default", "e1", {"type": "decision", "epoch": 1, "seq": 1}),
        ("coverage", "COVERAGE_ATTESTED", None, None, A1, {"valid": True, "reasons": []}),
        ("reconciliation", "ENFORCEMENT_VERIFIED", None, "default", R1, {"reasons": [], "scope": "canary"}),
        ("heartbeat", "ACCEPTED", "gate:x", None, "h2", {"epoch": 1, "hb_seq": 2}),
        ("alert", "COVERAGE_GAP", None, None, A2, {"valid": False, "reasons": ["x"]}),
    ]


def chain(specs, key=None, times=None):
    out, prev = [], ledger.GENESIS
    for i, (kind, code, pid, tid, ref, det) in enumerate(specs):
        n, at = i + 1, (times or [T0 % (i + 1) for i in range(len(specs))])[i]
        h = hashlib.sha256(canonical(ledger._body(n, prev, at, kind, code, pid, tid, ref, det))).hexdigest()
        k = key or KEYS["obs"]
        out.append({"n": n, "prev": prev, "recorded_at": at, "kind": kind, "code": code, "producer_id": pid,
                    "tenant_id": tid, "ref": ref, "detail": det, "hash": h, "observer_key_id": crypto.describe(k)[0],
                    "sig": crypto.sign(k, h.encode("ascii"))})
        prev = h
    return out


def doc(rows=None, **over):
    m = sign_manifest({"manifest_version": 1, "issued_at": "2026-11-04T00:00:00+00:00", "observer_keys": [_e(KEYS["obs"])],
                       "producers": [], "recovery_keys": [_e(KEYS["other"])], "attestor_keys": [_e(KEYS["att"])]}, KEYS["root"])
    d = {"format": "qyrix-c5-validation-evidence/3", "tenant": "default", "started_at": "2026-11-04T03:00:00Z",
         "finished_at": "2026-11-04T03:01:00Z", "manifest": m, "root_public_key": crypto.describe(KEYS["root"])[1],
         "ledger_rows": rows if rows is not None else chain(base_rows()), "attestation_ids": [A1, A2],
         "reconciliation_ids": [R1], "all_passed": True, "git_dirty": False}
    d.update(over)
    return sign(d)


def sign(d):
    d = {k: v for k, v in d.items() if k != "evidence_sig"}
    d["evidence_sig"] = {"key_id": crypto.describe(KEYS["att"])[0], "sig": crypto.sign(KEYS["att"], canonical(d))}
    return d


def fails(d, check):
    r = V(d)
    assert r[check] is False and r["valid"] is False and r["integrity"] == "INTEGRITY_FAILED", r
    return r


def test_valid_chain_is_integrity_verified_and_never_a_verdict():
    r = V(doc())
    assert r["valid"] and r["integrity"] == "INTEGRITY_VERIFIED", r
    assert "ENFORCEMENT_VERIFIED" not in r["integrity"] and "do not prove" in r["occurrence"]


def test_partial_chain_not_from_genesis_fails():                    # format/2-style subset export
    fails(doc(chain(base_rows())[2:]), "ledger_chain_complete_linked_signed")


def test_missing_ledger_fails():
    fails(doc([]), "ledger_chain_complete_linked_signed")


def test_deleted_middle_row_breaks_continuity():
    rows = chain(base_rows())
    del rows[2]
    r = fails(doc(rows), "ledger_chain_complete_linked_signed")
    assert r["ledger_chain_failure"]["reason"] == "LINK_BROKEN"


def test_reordered_rows_break_continuity():
    rows = chain(base_rows())
    rows[1], rows[2] = rows[2], rows[1]
    fails(doc(rows), "ledger_chain_complete_linked_signed")


def test_tampered_row_detail_detected():
    rows = chain(base_rows())
    rows[4]["detail"]["reasons"] = ["edited"]
    assert fails(doc(rows), "ledger_chain_complete_linked_signed")["ledger_chain_failure"]["reason"] == "HASH_MISMATCH"


def test_row_signed_by_key_outside_trusted_manifest_fails():
    assert fails(doc(chain(base_rows(), key=KEYS["other"])), "ledger_chain_complete_linked_signed")[
        "ledger_chain_failure"]["reason"] == "SIGNATURE_INVALID"


def test_untrusted_manifest_fails_everything():
    d = doc()
    d["root_public_key"] = crypto.describe(KEYS["other"])[1]
    r = V(sign(d))
    assert r["manifest_signed_by_root"] is False and r["valid"] is False


def test_time_going_backwards_fails():
    t = [T0 % i for i in (1, 2, 3, 9, 4, 10, 11)]
    fails(doc(chain(base_rows(), times=t)), "ledger_time_monotonic")


def test_replayed_event_fails():
    s = base_rows()
    s.insert(3, s[2])                                                 # same accepted event id + seq, re-signed
    fails(doc(chain(s)), "no_replayed_records")


def test_replayed_reconciliation_id_fails():
    s = base_rows()
    s.append(s[4])
    fails(doc(chain(s)), "no_replayed_records")


def test_heartbeat_sequence_regression_fails():
    s = base_rows()
    s[5] = ("heartbeat", "ACCEPTED", "gate:x", None, "h2", {"epoch": 1, "hb_seq": 1})
    fails(doc(chain(s)), "event_sequence_consistent")


def test_epoch_going_back_fails():
    s = base_rows()
    s[1] = ("heartbeat", "ACCEPTED", "gate:x", None, "h1", {"epoch": 2, "hb_seq": 1})
    fails(doc(chain(s)), "event_sequence_consistent")


def test_reconciliation_for_other_tenant_fails():
    s = base_rows()
    s[4] = ("reconciliation", "ENFORCEMENT_VERIFIED", None, "other", R1, {"reasons": [], "scope": "canary"})
    fails(doc(chain(s)), "tenant_epoch_consistent")


def test_event_accepted_after_quarantine_fails():
    s = base_rows()
    s.insert(2, ("alert", "PRODUCER_REGRESSION", "gate:x", "default", "q1", {"reason": "SEQ_REGRESSION"}))
    fails(doc(chain(s)), "tenant_epoch_consistent")


@pytest.mark.parametrize("prior", [
    None,                                                                          # no coverage at all
    ("alert", "COVERAGE_GAP", None, None, A1, {"valid": False, "reasons": ["x"]}),  # latest coverage FAILED
])
def test_verified_without_valid_latest_coverage_fails(prior):
    s = base_rows()
    if prior is None:
        del s[3]
    else:
        s.insert(4, prior)
        s[3] = ("coverage", "COVERAGE_ATTESTED", None, None, "a0000000-0000-0000-0000-000000000009", {"valid": True, "reasons": []})
    fails(doc(chain(s)), "verified_results_backed_by_valid_coverage")


def test_verified_with_reasons_fails():
    s = base_rows()
    s[4] = ("reconciliation", "ENFORCEMENT_VERIFIED", None, "default", R1, {"reasons": ["COVERAGE_UNATTESTED"], "scope": "canary"})
    fails(doc(chain(s)), "verified_results_backed_by_valid_coverage")


def test_reported_id_missing_from_ledger_fails():
    fails(doc(attestation_ids=[A1, A2, "a9999999-0000-0000-0000-000000000000"]), "reported_ids_signed_within_run_window")


def test_old_evidence_replayed_into_new_run_window_fails():
    fails(doc(started_at="2026-11-04T04:00:00Z", finished_at="2026-11-04T04:05:00Z"), "reported_ids_signed_within_run_window")


def test_unsigned_edit_of_document_fails():
    d = copy.deepcopy(doc())
    d["tenant"] = "other"
    assert V(d)["evidence_signed_by_manifest_attestor_key"] is False


def test_run_window_tolerates_one_second_timestamp_resolution():
    rows = chain(base_rows(), times=[T0 % i for i in (1, 2, 3, 4, 5, 6, 7)])
    d = doc(rows, finished_at="2026-11-04T03:00:06Z")                 # last row is 03:00:07.0: inside the 2 s slack
    assert V(d)["reported_ids_signed_within_run_window"] is True
    d = doc(rows, finished_at="2026-11-04T03:00:03Z")                 # 4 s early: outside
    assert V(d)["reported_ids_signed_within_run_window"] is False


def _forged_with_own_root():
    """An attacker needs no stolen key: fresh root, observer and attestor keys, self-consistent signed ledger."""
    global KEYS
    saved = dict(KEYS)
    try:
        KEYS.update({n: crypto.generate() for n in ("root", "obs", "att")})
        return doc(), crypto.describe(KEYS["root"])[1]
    finally:
        KEYS.clear()
        KEYS.update(saved)


def test_forged_self_signed_document_without_pin_is_never_verified():
    d, _ = _forged_with_own_root()
    r = verify_evidence.verify(d)
    assert r["integrity"] == "INTEGRITY_SELF_CONSISTENT_UNPINNED" and r["valid"] is False and r["trusted_root_pinned"] is False


def test_forged_document_is_trusted_only_if_its_root_is_independently_configured():
    d, forged_root = _forged_with_own_root()
    assert verify_evidence.verify(d, trusted_root=ROOT_PIN)["integrity"] == "INTEGRITY_FAILED"      # operator's real pin
    assert verify_evidence.verify(d, trusted_root=forged_root)["integrity"] == "INTEGRITY_VERIFIED"  # only if THEY pinned it


def test_correct_pin_verifies_and_wrong_pin_fails_and_pin_is_never_read_from_the_document():
    d = doc()
    assert verify_evidence.verify(d, trusted_root=ROOT_PIN)["integrity"] == "INTEGRITY_VERIFIED"
    wrong = verify_evidence.verify(d, trusted_root=crypto.describe(KEYS["other"])[1])
    assert wrong["integrity"] == "INTEGRITY_FAILED" and wrong["manifest_signed_by_root"] is False \
        and wrong["ledger_chain_complete_linked_signed"] is False and wrong["valid"] is False
    assert verify_evidence.verify(d)["integrity"] != "INTEGRITY_VERIFIED"


def test_cli_exit_codes(tmp_path):
    f = tmp_path / "e.json"
    import json
    f.write_text(json.dumps(doc()))
    assert verify_evidence.main([str(f)]) == 1
    assert verify_evidence.main([str(f), "--trusted-root", crypto.describe(KEYS["other"])[1]]) == 1
    assert verify_evidence.main([str(f), "--trusted-root", ROOT_PIN]) == 0
