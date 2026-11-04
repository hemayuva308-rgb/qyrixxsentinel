"""Offline verifier for signed C5 validation evidence, extended with the C6 ledger checks:

    python3 ops/observer/verify_evidence.py evidence/c5/validation.json --trusted-root <base64 root key> [--repo .]

TRUST ANCHOR: the evidence carries its own root_public_key, so on its own it proves nothing: anyone can generate a root,
a manifest and a self-consistent signed ledger. --trusted-root must come from a channel INDEPENDENT of the evidence file
(e.g. recorded by the operator who ran validate_c5.py, which prints it and writes it to the offline directory). A wrong
pin => INTEGRITY_FAILED; no pin => at best INTEGRITY_SELF_CONSISTENT_UNPINNED (non-zero exit). Never INTEGRITY_VERIFIED.

Checks, with nothing but the file (and optionally the git repository):
  1. the supplied trusted root equals the evidence's root key, and the observer key manifest is signed by it;
  2. the evidence document is signed by the attestor key listed in that manifest;
  3. C6 chain: the exported observer ledger is COMPLETE from genesis, contiguous, every row re-hashes, links to its
     predecessor and is signed by a manifest observer key valid at its recorded time (observer.ledger.verify);
  4. C6 order: recorded_at never goes backwards along the chain;
  5. C6 replay: no duplicated row hash / signature, accepted event id, (producer, epoch, tenant, seq), reconciliation
     or attestation id;
  6. C6 sequence: heartbeat hb_seq strictly increases per (producer, epoch); a producer's epoch never goes back;
  7. C6 tenant / epoch: every reconciliation belongs to the evidence tenant; no event is accepted on a stream after
     its quarantine (PRODUCER_REGRESSION) in that epoch;
  8. C6 verdict support: every ENFORCEMENT_VERIFIED row has no reasons, canary scope, and the LATEST coverage record
     before it is a valid COVERAGE_ATTESTED (a later COVERAGE_GAP revokes it);
  9. every reported attestation / reconciliation id is a signed ledger row recorded inside the evidence's run window;
 10. (--repo) the recorded commit exists, and the compose files at that commit hash to the recorded values;
 11. the tracked tree was clean when the validation ran (so the commit IS the code that ran).
The verifier never emits an enforcement verdict. `integrity` says whether the records are authentic, complete and
mutually consistent; `occurrence` states what that does NOT prove. Missing or partial data => INTEGRITY_FAILED. Without --repo the commit/compose binding is not
checked, so the best result is INTEGRITY_INCOMPLETE_NO_REPO_CHECK (exit 1). Unsupported format or malformed fields =>
INTEGRITY_FAILED (never an exception).
Limitation: the root key is generated per validation run, so a valid signature proves the evidence is internally
consistent and untampered since signing - not WHO ran the validation."""
import argparse
import hashlib
import json
import os
import subprocess  # nosec B404 - fixed git argv
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "backend"))
from observer import crypto, ledger  # noqa: E402
from observer.canonical import canonical  # noqa: E402
from observer.manifest import Manifest  # noqa: E402

OCCURRENCE = ("Integrity only: signatures and hash links prove these records were written by holders of the listed "
              "observer/attestor keys and not altered or reordered since. They do not prove that the underlying events "
              "happened; E0/E1 rows are backend claims, and only the observer's own E3 sensor records, judged by the "
              "observer at the time, back ENFORCEMENT_VERIFIED.")


def _ts(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def chain_checks(rows, m, doc) -> dict:
    res = {}
    tup = [(r["n"], r["prev"], r["hash"], _ts(r["recorded_at"]), r["kind"], r["code"], r["producer_id"], r["tenant_id"],
            r["ref"], r["detail"], r["observer_key_id"], r["sig"]) for r in rows]
    v = ledger.verify(tup, m.observer_keys) if rows else {"valid": False, "reason": "NO_LEDGER"}
    res["ledger_chain_complete_linked_signed"] = v["valid"]
    if not v["valid"]:
        res["ledger_chain_failure"] = {k: v.get(k) for k in ("n", "reason")}
    times = [t[3] for t in tup]
    res["ledger_time_monotonic"] = all(a <= b for a, b in zip(times, times[1:]))
    seen, dup = set(), False
    for r in rows:
        keys = [("hash", r["hash"]), ("sig", r["sig"])]
        d = r["detail"] or {}
        if r["kind"] == "event" and r["code"] == "ACCEPTED":
            keys.append(("event", r["ref"]))
            if "seq" in d:
                keys.append(("seq", r["producer_id"], d.get("epoch"), r["tenant_id"], d["seq"]))
        if r["kind"] == "reconciliation" or r["code"] == "COVERAGE_ATTESTED" or (r["kind"], r["code"]) == ("alert", "COVERAGE_GAP") and r["ref"]:
            keys.append(("id", r["ref"]))
        for k in keys:
            dup |= k in seen
            seen.add(k)
    res["no_replayed_records"] = not dup
    # producer epoch progression. A producer starts at epoch 1 (O001 default); only a recorded EPOCH_CHANGED moves it, by
    # exactly +1 from the epoch we are tracking. PRODUCER_REGRESSION carries NO epoch, but the ingest only quarantines the
    # stream of the producer's CURRENT epoch, so that is what we quarantine. Accepted events AND heartbeats on a
    # quarantined or non-current stream are impossible in the real ingest and therefore invalid here.
    hb, cur_ep, seq_ok, epoch_ok = {}, {}, True, True
    quarantined, quarantine_ok = set(), True
    for r in rows:
        d, pid = r["detail"] or {}, r["producer_id"]
        e = cur_ep.get(pid, 1)
        if r["code"] == "EPOCH_CHANGED":
            if d.get("from") != e or d.get("to") != e + 1 or not isinstance(d.get("to"), int):
                epoch_ok = False
            cur_ep[pid] = e + 1
        elif r["code"] == "PRODUCER_REGRESSION":
            quarantined.add((pid, e))
        elif r["code"] == "ACCEPTED" and r["kind"] in ("event", "heartbeat") and "epoch" in d:
            if d["epoch"] != e and not (r["kind"] == "event" and d.get("type") == "adapter_report"):
                epoch_ok = False                                  # old (closed), future (unknown) or regressed epoch
            if (pid, d["epoch"]) in quarantined:
                quarantine_ok = False
            if r["kind"] == "heartbeat":
                k = (pid, d["epoch"])
                if not isinstance(d.get("hb_seq"), int) or d["hb_seq"] <= hb.get(k, -1):
                    seq_ok = False
                hb[k] = d.get("hb_seq", 0)
    res["event_sequence_consistent"] = seq_ok
    res["epoch_progression_consistent"] = epoch_ok
    tenant = doc.get("tenant")
    # single-tenant evidence: EVERY row that names a tenant must name this one (events, canaries, reconciliations, alerts)
    res["tenant_epoch_consistent"] = quarantine_ok and bool(tenant) and all(
        r["tenant_id"] in (None, tenant) for r in rows)
    cov, supported = None, True
    for r in rows:
        if r["code"] == "COVERAGE_ATTESTED" or (r["kind"], r["code"]) == ("alert", "COVERAGE_GAP"):
            cov = r
        if r["kind"] == "reconciliation" and r["code"] == "ENFORCEMENT_VERIFIED":
            d = r["detail"] or {}
            supported &= (d.get("reasons") == [] and d.get("scope") == "canary" and cov is not None
                          and cov["kind"] == "coverage" and (cov["detail"] or {}).get("valid") is True)
    res["verified_results_backed_by_valid_coverage"] = supported
    refs = {r["ref"]: _ts(r["recorded_at"]) for r in rows}
    ids = list(doc.get("attestation_ids", [])) + list(doc.get("reconciliation_ids", []))
    try:
        slack = timedelta(seconds=2)                                           # run timestamps have 1 s resolution
        lo, hi = _ts(doc["started_at"]) - slack, _ts(doc["finished_at"]) + slack
        res["reported_ids_signed_within_run_window"] = bool(ids) and len(ids) == len(set(ids)) and all(
            i in refs and lo <= refs[i] <= hi for i in ids)
    except (KeyError, ValueError):
        res["reported_ids_signed_within_run_window"] = False
    return res


def _verify(doc: dict, repo=None, trusted_root=None) -> dict:
    """trusted_root: base64 root public key obtained OUT OF BAND (never from `doc`). Without it the document's own
    root_public_key is self-asserted, so the result can never be INTEGRITY_VERIFIED."""
    res = {}
    pin = (trusted_root or "").strip()
    pinned = bool(pin) and pin == str(doc.get("root_public_key", "")).strip()
    res["trusted_root_pinned"] = pinned                       # False when absent OR different from the document's root
    m = None
    if not pin or pinned:                                     # a wrong pin: the document's manifest is not trusted at all
        try:
            m = Manifest(doc["manifest"], doc["root_public_key"])              # raises unless root-signed
        except Exception:  # nosec B110 - any manifest problem is a failure, reported below
            m = None
    res["manifest_signed_by_root"] = m is not None
    body = {k: v for k, v in doc.items() if k != "evidence_sig"}
    sig = doc.get("evidence_sig") or {}
    k = m.attestor_keys.get(sig.get("key_id")) if m else None
    res["evidence_signed_by_manifest_attestor_key"] = bool(k) and crypto.verify(k.public, sig.get("sig", ""), canonical(body))
    if m:
        res.update(chain_checks(doc.get("ledger_rows", []), m, doc))
    else:
        res["ledger_chain_complete_linked_signed"] = False
    if repo:
        c = subprocess.run(["git", "-C", repo, "cat-file", "-e", str(doc.get("commit")) + "^{commit}"], capture_output=True)  # nosec
        res["commit_exists_in_repo"] = c.returncode == 0
        hashes = {}
        for f in doc.get("compose_files", {}):
            o = subprocess.run(["git", "-C", repo, "show", "%s:%s" % (doc["commit"], f)], capture_output=True)  # nosec
            hashes[f] = hashlib.sha256(o.stdout).hexdigest() if o.returncode == 0 else None
        res["compose_files_match_commit"] = bool(hashes) and hashes == doc.get("compose_files", {})
    res["repo_binding_checked"] = bool(repo)                  # no --repo => commit/compose binding NOT checked => not verified
    res["all_passed_recorded"] = doc.get("all_passed") is True
    res["tracked_tree_clean_at_validation"] = doc.get("git_dirty") is False
    failure = res.pop("ledger_chain_failure", None)
    res["valid"] = all(v is True for v in res.values())
    rest_ok = all(v is True for k, v in res.items() if k not in ("trusted_root_pinned", "repo_binding_checked", "valid"))
    if res["valid"]:
        res["integrity"] = "INTEGRITY_VERIFIED"
    elif rest_ok and not pin:                                 # internally consistent, but the trust anchor is the file's own
        res["integrity"] = "INTEGRITY_SELF_CONSISTENT_UNPINNED"
    elif rest_ok and pin and res["trusted_root_pinned"] and not repo:   # pinned and consistent, repo binding not performed
        res["integrity"] = "INTEGRITY_INCOMPLETE_NO_REPO_CHECK"
    else:
        res["integrity"] = "INTEGRITY_FAILED"
    if failure:
        res["ledger_chain_failure"] = failure
    res["occurrence"] = OCCURRENCE
    res["limitation"] = ("the root key is generated per run; INTEGRITY_VERIFIED means only that the evidence chains to the "
                         "root key you supplied via --trusted-root, which must come from a channel independent of this "
                         "file. It does not identify who ran the validation.")
    return res


SUPPORTED_FORMATS = ("qyrix-c5-validation-evidence/3",)       # earlier formats lack the complete ledger / tenant field


def _failed(error: str) -> dict:
    return {"valid": False, "integrity": "INTEGRITY_FAILED", "error": error, "occurrence": OCCURRENCE}


def verify(doc, repo=None, trusted_root=None) -> dict:
    """Never raises: malformed or unsupported evidence is INTEGRITY_FAILED."""
    if not isinstance(doc, dict):
        return _failed("MALFORMED_EVIDENCE: not a JSON object")
    if doc.get("format") not in SUPPORTED_FORMATS:
        return _failed("UNSUPPORTED_FORMAT: %r (supported: %s)" % (str(doc.get("format"))[:80], ", ".join(SUPPORTED_FORMATS)))
    try:
        return _verify(doc, repo, trusted_root)
    except Exception as e:  # nosec B110 - fail closed on any malformed field
        return _failed("MALFORMED_EVIDENCE: %s" % type(e).__name__)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--repo")
    ap.add_argument("--trusted-root", help="base64 root public key from an independent channel (NOT from the evidence file)")
    a = ap.parse_args(argv)
    try:
        doc = json.load(open(a.file))
    except (OSError, ValueError) as e:
        doc = None
        print(json.dumps(_failed("UNREADABLE_EVIDENCE: %s" % type(e).__name__), indent=1))
        return 1
    r = verify(doc, a.repo, a.trusted_root)
    print(json.dumps(r, indent=1))
    return 0 if r["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
