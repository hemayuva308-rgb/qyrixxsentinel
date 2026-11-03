"""Operator key tooling (run OFFLINE for the root and recovery keys).

    python -m observer.keytool gen --out root.pem            # prints key_id + public key; file mode 0600
    python -m observer.keytool pub --key root.pem
    python -m observer.keytool sign-manifest --root-key root.pem --in manifest.json --out manifest.signed.json

Private key material is never printed."""
import argparse
import json
import sys

from observer import crypto
from observer.manifest import sign_manifest


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen"); g.add_argument("--out", required=True)
    p = sub.add_parser("pub"); p.add_argument("--key", required=True)
    s = sub.add_parser("sign-manifest")
    s.add_argument("--root-key", required=True); s.add_argument("--in", dest="src", required=True); s.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "gen":
        k = crypto.generate()
        crypto.write_private(a.out, k)
        kid, pub = crypto.describe(k)
        print(json.dumps({"key_id": kid, "public_key": pub}))
    elif a.cmd == "pub":
        kid, pub = crypto.describe(crypto.load_private(a.key))
        print(json.dumps({"key_id": kid, "public_key": pub}))
    else:
        doc = json.load(open(a.src))
        signed = sign_manifest(doc, crypto.load_private(a.root_key))
        with open(a.out, "w") as f:
            json.dump(signed, f, indent=1, sort_keys=True)
        print(json.dumps({"signed": True, "manifest_version": signed.get("manifest_version"), "root_key_id": signed["root_key_id"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
