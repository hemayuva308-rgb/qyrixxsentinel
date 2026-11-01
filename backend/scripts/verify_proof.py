"""Offline proof-bundle verifier (no server needed).
  cd backend && python scripts/verify_proof.py bundle.json [--tsa-ca tsa-ca.pem]
Accepts an export from GET /api/v1/sentinel/proofs/export (or a bare list of records).
With --tsa-ca, RFC 3161 anchor tokens carried in the bundle are verified with `openssl ts -verify` against YOUR trust
anchor: PASS only if the latest verified anchor covers the chain head. Without it, anchors cannot be trusted and the
best possible result is PARTIAL_UNANCHORED.
Exit codes: 0 = PASS or PARTIAL_UNANCHORED (internally consistent), 1 = FAIL, 2 = EMPTY_PROOF_BUNDLE / unreadable."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import proof

args = [a for a in sys.argv[1:]]
ca = None
if "--tsa-ca" in args:
    i = args.index("--tsa-ca"); ca = args[i + 1]; del args[i:i + 2]
if len(args) != 1:
    sys.exit(__doc__)
verify_token = None
if ca:
    os.environ["QYRIX_TSA_CA_FILE"] = ca
    from app import anchor
    if not anchor.can_verify():
        sys.exit("cannot verify anchors: openssl missing or CA file not readable")
    verify_token = anchor.verify_token
try:
    bundle = json.load(open(args[0]))
    res = proof.verify_bundle_with_anchors(bundle, verify_token)
except proof.EmptyBundle:
    print(json.dumps({"status": "EMPTY_PROOF_BUNDLE"})); sys.exit(2)
except (OSError, ValueError) as e:
    print(json.dumps({"status": "UNREADABLE", "error": type(e).__name__})); sys.exit(2)
print(json.dumps(res, indent=1))
sys.exit(0 if res["status"] in (proof.PASS, proof.PARTIAL_UNANCHORED) else 1)
