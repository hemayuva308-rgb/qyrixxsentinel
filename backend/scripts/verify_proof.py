"""Offline proof-bundle verifier (no server, no network).
  cd backend && python scripts/verify_proof.py bundle.json
Accepts an export from GET /api/v1/sentinel/proofs/export (or a bare list of records).
Exit codes: 0 = PARTIAL_UNANCHORED/PASS (internally consistent), 1 = FAIL, 2 = EMPTY_PROOF_BUNDLE / unreadable.
Note: this build has no external anchor, so PASS is never produced; PARTIAL_UNANCHORED is the best outcome."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import proof

if len(sys.argv) != 2:
    sys.exit(__doc__)
try:
    bundle = json.load(open(sys.argv[1]))
    res = proof.verify_bundle(bundle)
except proof.EmptyBundle:
    print(json.dumps({"status": "EMPTY_PROOF_BUNDLE"})); sys.exit(2)
except (OSError, ValueError) as e:
    print(json.dumps({"status": "UNREADABLE", "error": type(e).__name__})); sys.exit(2)
print(json.dumps(res, indent=1))
sys.exit(0 if res["status"] in (proof.PASS, proof.PARTIAL_UNANCHORED) else 1)
