"""Offline verifier for signed C5 validation evidence (evidence/c5/validation.json):

    python3 ops/observer/verify_evidence.py evidence/c5/validation.json [--repo .]

Checks, with nothing but the file (and optionally the git repository):
  1. the observer key manifest is signed by the root public key recorded in the evidence;
  2. the evidence document is signed by the attestor key listed in that manifest;
  3. every exported observer-ledger row (coverage attestations, reconciliations) re-hashes correctly and carries a
     valid signature by an observer key of the manifest;
  4. every attestation / reconciliation id the evidence reports appears in those signed ledger rows;
  5. (--repo) the recorded commit exists, and the compose files at that commit hash to the recorded values;
  6. the tracked tree was clean when the validation ran (so the commit IS the code that ran).
Limitation (stated in the output): the root key is generated per validation run, so a valid signature proves the
evidence is internally consistent and untampered since signing - not WHO ran the validation."""
import argparse
import hashlib
import json
import os
import subprocess  # nosec B404 - fixed git argv
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "backend"))
from observer import crypto, ledger  # noqa: E402
from observer.canonical import canonical  # noqa: E402
from observer.manifest import Manifest  # noqa: E402


def verify(doc: dict, repo=None) -> dict:
    res = {}
    m = Manifest(doc["manifest"], doc["root_public_key"])                      # raises unless root-signed
    res["manifest_signed_by_root"] = True
    body = {k: v for k, v in doc.items() if k != "evidence_sig"}
    sig = doc["evidence_sig"]
    k = m.attestor_keys.get(sig["key_id"])
    res["evidence_signed_by_manifest_attestor_key"] = bool(k) and crypto.verify(k.public, sig["sig"], canonical(body))
    rows = doc.get("ledger_rows", [])
    ok_rows = True
    for r in rows:
        from datetime import datetime
        at = datetime.fromisoformat(r["recorded_at"])
        b = ledger._body(r["n"], r["prev"], at.isoformat(), r["kind"], r["code"], r["producer_id"], r["tenant_id"],
                         r["ref"], r["detail"])
        h = hashlib.sha256(canonical(b)).hexdigest()
        ok = m.observer_keys.get(r["observer_key_id"])
        ok_rows &= h == r["hash"] and bool(ok) and crypto.verify(ok.public, r["sig"], h.encode("ascii"))
    res["ledger_rows_hash_and_observer_signature"] = ok_rows and bool(rows)
    refs = {r["ref"] for r in rows}
    res["attestation_ids_in_signed_ledger"] = all(a in refs for a in doc.get("attestation_ids", []))
    res["reconciliation_ids_in_signed_ledger"] = all(x in refs for x in doc.get("reconciliation_ids", []))
    if repo:
        c = subprocess.run(["git", "-C", repo, "cat-file", "-e", doc["commit"] + "^{commit}"], capture_output=True)  # nosec
        res["commit_exists_in_repo"] = c.returncode == 0
        hashes = {}
        for f in doc.get("compose_files", {}):
            o = subprocess.run(["git", "-C", repo, "show", "%s:%s" % (doc["commit"], f)], capture_output=True)  # nosec
            hashes[f] = hashlib.sha256(o.stdout).hexdigest() if o.returncode == 0 else None
        res["compose_files_match_commit"] = hashes == doc.get("compose_files", {})
    res["all_passed_recorded"] = doc.get("all_passed") is True
    res["tracked_tree_clean_at_validation"] = doc.get("git_dirty") is False
    res["valid"] = all(res.values())
    res["limitation"] = "root key generated per run: proves integrity and consistency, not the identity of the runner"
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--repo")
    a = ap.parse_args(argv)
    r = verify(json.load(open(a.file)), a.repo)
    print(json.dumps(r, indent=1))
    return 0 if r["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
