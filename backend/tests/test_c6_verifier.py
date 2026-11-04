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


def _make_repo():
    import subprocess
    import tempfile
    d = tempfile.mkdtemp()
    open(os.path.join(d, "docker-compose.yml"), "w").write("services: {}\n")
    git = ["git", "-C", d, "-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(git + ["init", "-q"], check=True)
    subprocess.run(git + ["add", "."], check=True)
    subprocess.run(git + ["commit", "-q", "-m", "x"], check=True)
    commit = subprocess.run(git + ["rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    return d, commit, hashlib.sha256(b"services: {}\n").hexdigest()


REPO, COMMIT, COMPOSE_SHA = _make_repo()


def V(d, **kw):
    kw.setdefault("repo", REPO)
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
         "reconciliation_ids": [R1], "all_passed": True, "git_dirty": False, "commit": COMMIT,
         "compose_files": {"docker-compose.yml": COMPOSE_SHA}}
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
    fails(doc(chain(s)), "epoch_progression_consistent")


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
    r = verify_evidence.verify(d, repo=REPO)
    assert r["integrity"] == "INTEGRITY_SELF_CONSISTENT_UNPINNED" and r["valid"] is False and r["trusted_root_pinned"] is False


def test_forged_document_is_trusted_only_if_its_root_is_independently_configured():
    d, forged_root = _forged_with_own_root()
    assert V(d)["integrity"] == "INTEGRITY_FAILED"      # operator's real pin
    assert verify_evidence.verify(d, repo=REPO, trusted_root=forged_root)["integrity"] == "INTEGRITY_VERIFIED"  # only if THEY pinned it


def test_correct_pin_verifies_and_wrong_pin_fails_and_pin_is_never_read_from_the_document():
    d = doc()
    assert V(d)["integrity"] == "INTEGRITY_VERIFIED"
    wrong = verify_evidence.verify(d, repo=REPO, trusted_root=crypto.describe(KEYS["other"])[1])
    assert wrong["integrity"] == "INTEGRITY_FAILED" and wrong["manifest_signed_by_root"] is False \
        and wrong["ledger_chain_complete_linked_signed"] is False and wrong["valid"] is False
    assert V(d, trusted_root='')["integrity"] != "INTEGRITY_VERIFIED"


def test_cli_exit_codes(tmp_path):
    f = tmp_path / "e.json"
    import json
    f.write_text(json.dumps(doc()))
    assert verify_evidence.main([str(f)]) == 1
    assert verify_evidence.main([str(f), "--trusted-root", crypto.describe(KEYS["other"])[1]]) == 1
    assert verify_evidence.main([str(f), "--trusted-root", ROOT_PIN]) == 1                       # no --repo: incomplete
    assert verify_evidence.main([str(f), "--trusted-root", ROOT_PIN, "--repo", REPO]) == 0


# ---- review findings: repo binding, quarantine/epoch, tenant, format, malformed ----
def test_pinned_but_no_repo_is_never_verified():
    r = verify_evidence.verify(doc(), trusted_root=ROOT_PIN)               # no repo
    assert r["integrity"] == "INTEGRITY_INCOMPLETE_NO_REPO_CHECK" and r["valid"] is False and r["repo_binding_checked"] is False


def test_wrong_commit_or_compose_hash_with_repo_fails():
    fails(doc(commit="0" * 40), "commit_exists_in_repo")
    fails(doc(compose_files={"docker-compose.yml": "0" * 64}), "compose_files_match_commit")


QUAR = ("alert", "PRODUCER_REGRESSION", "gate:x", "default", "q1", {"reason": "SEQ_BELOW_WATERMARK", "seq": 1})   # real shape: no epoch


def test_quarantine_without_epoch_and_without_prior_accepted_row_still_blocks_later_events():
    s = [("config", "MANIFEST_INSTALLED", None, None, "1", {}), QUAR] + base_rows()[2:]    # no accepted row BEFORE the alert
    fails(doc(chain(s)), "tenant_epoch_consistent")


def test_heartbeat_accepted_after_quarantine_fails():
    s = base_rows()
    s.insert(2, QUAR)
    s.insert(3, ("heartbeat", "ACCEPTED", "gate:x", None, "h1b", {"epoch": 1, "hb_seq": 2}))
    s[4:] = [x for x in s[4:] if x[2] != "gate:x" or x[0] != "event"]                       # leave only the heartbeat violation
    fails(doc(chain(s)), "tenant_epoch_consistent")


def _epoch_change(frm, to, ref="ec1"):
    return ("alert", "EPOCH_CHANGED", "gate:x", None, ref, {"from": frm, "to": to})


def test_valid_epoch_change_then_new_epoch_traffic_and_quarantine_scoped_to_old_epoch():
    s = base_rows()[:3] + [_epoch_change(1, 2)] + [
        ("heartbeat", "ACCEPTED", "gate:x", None, "h3", {"epoch": 2, "hb_seq": 1}),
        ("event", "ACCEPTED", "gate:x", "default", "e2", {"type": "decision", "epoch": 2, "seq": 1})] + base_rows()[3:5]
    assert V(doc(chain(s)))["epoch_progression_consistent"] is True


@pytest.mark.parametrize("bad", [
    _epoch_change(1, 3),                                         # skips an epoch
    _epoch_change(2, 3),                                         # not from the tracked epoch
    _epoch_change(1, 1),                                         # no progress
])
def test_invalid_epoch_change_fails(bad):
    s = base_rows()[:3] + [bad] + base_rows()[3:]
    fails(doc(chain(s)), "epoch_progression_consistent")


def test_traffic_on_old_or_future_epoch_fails():
    old = base_rows()[:3] + [_epoch_change(1, 2), ("heartbeat", "ACCEPTED", "gate:x", None, "h3", {"epoch": 1, "hb_seq": 9})]
    fails(doc(chain(old + base_rows()[3:])), "epoch_progression_consistent")
    future = base_rows()[:1] + [("heartbeat", "ACCEPTED", "gate:x", None, "h3", {"epoch": 2, "hb_seq": 1})] + base_rows()[3:]
    fails(doc(chain(future)), "epoch_progression_consistent")


@pytest.mark.parametrize("idx,row", [
    (2, ("event", "ACCEPTED", "gate:x", "other", "e1", {"type": "decision", "epoch": 1, "seq": 1})),     # foreign event
    (3, ("alert", "COVERAGE_GAP", None, "other", A1, {"valid": False, "reasons": []})),                   # foreign alert
])
def test_any_row_naming_a_foreign_tenant_fails(idx, row):
    s = base_rows()
    s[idx] = row
    fails(doc(chain(s)), "tenant_epoch_consistent")


@pytest.mark.parametrize("fmt", [None, "", "qyrix-c5-validation-evidence/2", "qyrix-c5-validation-evidence/4", 3])
def test_unsupported_format_is_rejected_with_clear_error(fmt):
    d = doc()
    d["format"] = fmt
    r = V(sign(d))
    assert r["integrity"] == "INTEGRITY_FAILED" and r["valid"] is False and r["error"].startswith("UNSUPPORTED_FORMAT")


@pytest.mark.parametrize("mutate", [
    lambda d: d.__setitem__("ledger_rows", [{"n": 1}]),                       # missing fields
    lambda d: d.__setitem__("ledger_rows", "garbage"),
    lambda d: d.__setitem__("manifest", "x"),
    lambda d: d["ledger_rows"][2].__setitem__("recorded_at", "not-a-date"),
    lambda d: d["ledger_rows"][1].__setitem__("detail", None),
    lambda d: d.__setitem__("evidence_sig", "x"),
    lambda d: d.__setitem__("started_at", 5),
])
def test_malformed_evidence_never_raises(mutate):
    d = doc()
    mutate(d)
    r = V(d)
    assert r["valid"] is False and r["integrity"] == "INTEGRITY_FAILED"


def test_non_object_and_unreadable_files(tmp_path):
    assert V([1, 2])["integrity"] == "INTEGRITY_FAILED" and V(None)["integrity"] == "INTEGRITY_FAILED"
    f = tmp_path / "bad.json"
    f.write_text("{not json")
    assert verify_evidence.main([str(f), "--trusted-root", ROOT_PIN]) == 1
    assert verify_evidence.main([str(tmp_path / "missing.json")]) == 1
