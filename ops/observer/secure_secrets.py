"""Ownership and permissions for the compose secrets (C5 hardening P1). Run as root on the Docker host:

    sudo python3 ops/observer/secure_secrets.py apply|check [--root .]

Compose file secrets are bind mounts, so the HOST owner/mode is what a container sees. Every private key / token read
by the application (uid 10001, backend/Dockerfile) is 10001:10001 0400; the one file read by BOTH PostgreSQL (uid 70)
and the migrator (uid 10001) is 70:10001 0440; certificates and the signed manifest are public (0444). The CA private
key, root key, recovery key and attestor key are NEVER under ./secrets: they live in the offline directory (0700 root)."""
import argparse
import os
import stat
import sys

APP, PG = 10001, 70
SPEC = [  # path relative to the repo root, uid, gid, mode
    ("secrets/db_admin_password", PG, APP, 0o440),
    ("secrets/db_runtime_password", APP, APP, 0o400),
    ("secrets/state_witness_key", APP, APP, 0o400),
    ("secrets/data_key", APP, APP, 0o400),
    ("secrets/client_sig_key", APP, APP, 0o400),
    ("secrets/observer/gate_signing_key.pem", APP, APP, 0o400),
    ("secrets/observer/observer_signing_key.pem", APP, APP, 0o400),
    ("secrets/observer/backend/backend.key", APP, APP, 0o400),
    ("secrets/observer/server/observer.key", APP, APP, 0o400),
    ("secrets/observer/operator_token", APP, APP, 0o400),
    ("secrets/observer/observer_db_runtime_password", APP, APP, 0o400),
    ("secrets/observer/observer_db_admin_password", PG, APP, 0o440),
    ("secrets/observer/canary/agent_token", APP, APP, 0o400),
    ("secrets/observer/canary/creds.json", APP, APP, 0o400),
    ("secrets/observer/backend/backend.crt", 0, 0, 0o444),
    ("secrets/observer/server/observer.crt", 0, 0, 0o444),
    ("secrets/observer/ca/ca.crt", 0, 0, 0o444),
    ("secrets/observer/manifest.signed.json", 0, 0, 0o444),
]
FORBIDDEN = ("ca.key", "root.pem", "recovery.pem", "attestor_signing.pem", "attestor.key")


def apply(root: str) -> None:
    for rel, uid, gid, mode in SPEC:
        p = os.path.join(root, rel)
        if os.path.exists(p):
            os.chown(p, uid, gid)
            os.chmod(p, mode)
    for d in ("secrets/observer/canary",):
        p = os.path.join(root, d)
        if os.path.isdir(p):
            os.chown(p, APP, APP)
            os.chmod(p, 0o500)


def check(root: str) -> list:
    out = []
    for rel, uid, gid, mode in SPEC:
        p = os.path.join(root, rel)
        if not os.path.exists(p):
            continue
        st = os.stat(p)
        ok = (st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (uid, gid, mode)
        out.append({"file": rel, "owner": "%d:%d" % (st.st_uid, st.st_gid), "mode": oct(stat.S_IMODE(st.st_mode)), "ok": ok})
    for dirpath, _, files in os.walk(os.path.join(root, "secrets")):
        for f in files:
            if f in FORBIDDEN:
                out.append({"file": os.path.relpath(os.path.join(dirpath, f), root), "ok": False,
                            "problem": "offline key material inside ./secrets"})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", choices=["apply", "check"])
    ap.add_argument("--root", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
    a = ap.parse_args(argv)
    if a.cmd == "apply":
        apply(a.root)
    res = check(a.root)
    for r in res:
        print(("ok   " if r["ok"] else "BAD  ") + r["file"], r.get("owner", ""), r.get("mode", ""), r.get("problem", ""))
    return 0 if all(r["ok"] for r in res) else 1


if __name__ == "__main__":
    sys.exit(main())
