"""Observer service entrypoint:  python -m observer.main

Configuration (all required unless noted; nothing is read from the backend):
  OBSERVER_DATABASE_URL | OBSERVER_DB_HOST(+PORT/NAME/USER) + OBSERVER_DB_PASSWORD_FILE   observer-db, runtime account
  OBSERVER_ROOT_PUBLIC_KEY       pinned root public key (base64 raw Ed25519) - deployment config, not a data store
  OBSERVER_MANIFEST_FILE         key manifest signed by the root key
  OBSERVER_SIGNING_KEY_FILE      observer signing key (PEM); must be listed and valid in the manifest
  OBSERVER_OPERATOR_TOKEN_FILE   (optional) bearer token for GET /v1/status; without it /v1/status is disabled
  OBSERVER_HEARTBEAT_SECONDS, OBSERVER_GRACE_SECONDS, OBSERVER_MAX_SKEW_SECONDS   (optional; defaults 10 / 30 / 120)
  OBSERVER_BIND (default 0.0.0.0), OBSERVER_PORT (default 9000)

Start-up is fail closed: manifest signature, manifest rollback, runtime account privileges, schema version and the full
ledger chain are verified before the port opens."""
import json
import os
import sys
import threading
import time

from observer import crypto
from observer.app import create_app
from observer.db import Database, dsn_from_env, runtime_problems
from observer.feed import Config
from observer.ingest import Observer
from observer.manifest import Manifest
from observer.migrate import expected


def build(env=os.environ) -> Observer:
    dsn = dsn_from_env()
    if not dsn:
        raise SystemExit("observer database not configured")
    db = Database(dsn)

    def check(cur):
        p = runtime_problems(cur)
        cur.execute("SELECT name FROM schema_migrations")
        return p, [m for m in expected() if m not in {r[0] for r in cur.fetchall()}]
    problems, missing = db.run(check, lock=False)
    if problems:
        raise SystemExit("observer runtime account is over-privileged: " + ", ".join(problems))
    if missing:
        raise SystemExit("observer database not migrated: missing " + ", ".join(missing))
    manifest = Manifest(json.load(open(env["OBSERVER_MANIFEST_FILE"])), env["OBSERVER_ROOT_PUBLIC_KEY"].strip())
    cfg = Config(H=float(env.get("OBSERVER_HEARTBEAT_SECONDS", 10)), G=float(env.get("OBSERVER_GRACE_SECONDS", 30)),
                 S=float(env.get("OBSERVER_MAX_SKEW_SECONDS", 120)))
    obs = Observer(db, manifest, crypto.load_private(env["OBSERVER_SIGNING_KEY_FILE"]), cfg)
    v = obs.verify_ledger()
    if not v["valid"]:
        raise SystemExit("observer ledger does not verify (%s at n=%s): follow the recovery procedure" % (v["reason"], v["n"]))
    obs.install_manifest()
    return obs


def monitor(obs: Observer, interval: float) -> None:
    while True:
        try:
            obs.tick()
        except Exception:
            pass                                      # monitor failures are visible as missing alerts / stale status
        time.sleep(interval)


def main() -> int:
    obs = build()
    tok = None
    if os.getenv("OBSERVER_OPERATOR_TOKEN_FILE"):
        tok = open(os.environ["OBSERVER_OPERATOR_TOKEN_FILE"]).read().strip() or None
    threading.Thread(target=monitor, args=(obs, obs.cfg.H), name="observer-monitor", daemon=True).start()
    import uvicorn
    uvicorn.run(create_app(obs, tok), host=os.getenv("OBSERVER_BIND", "0.0.0.0"), port=int(os.getenv("OBSERVER_PORT", "9000")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
