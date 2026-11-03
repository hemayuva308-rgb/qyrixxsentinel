"""Observer service entrypoint:  python -m observer.main

Configuration (all required unless noted; nothing is read from the backend):
  OBSERVER_DATABASE_URL | OBSERVER_DB_HOST(+PORT/NAME/USER) + OBSERVER_DB_PASSWORD_FILE   observer-db, runtime account
  OBSERVER_ROOT_PUBLIC_KEY       pinned root public key (base64 raw Ed25519) - deployment config, not a data store
  OBSERVER_MANIFEST_FILE         key manifest signed by the root key
  OBSERVER_SIGNING_KEY_FILE      observer signing key (PEM); must be listed and valid in the manifest
  OBSERVER_OPERATOR_TOKEN_FILE   (optional) bearer token for GET /v1/status; without it /v1/status is disabled
  OBSERVER_HEARTBEAT_SECONDS, OBSERVER_GRACE_SECONDS, OBSERVER_MAX_SKEW_SECONDS   (optional; defaults 10 / 30 / 120)
  OBSERVER_CANARIES=1 (+ OBSERVER_CANARY_HTTP_PORT [loopback only], OBSERVER_CANARY_DIR, OBSERVER_CANARY_CREDENTIALS_FILE,
    OBSERVER_CANARY_P2_LIVE=1 + OBSERVER_CANARY_BACKEND_URL - live P2 is OFF by default)   (optional, C3)
  OBSERVER_READ_TOKENS_FILE  (optional, C4) tenant-scoped READ-ONLY keys for GET /v1/reconciliations, stored as SHA-256
  OBSERVER_TLS_CERT_FILE, OBSERVER_TLS_KEY_FILE, OBSERVER_TLS_CLIENT_CA_FILE   mTLS (REQUIRED for any non-loopback bind)
  OBSERVER_C5_TOPOLOGY=1 + OBSERVER_EGRESS_BIND, OBSERVER_DNS_BIND, OBSERVER_DNS_UPSTREAM, OBSERVER_SINK_HOST,
    OBSERVER_EGRESS_ALLOW_CIDRS, OBSERVER_EGRESS_STATIC_HOSTS     (C5 egress chokepoint; docker-compose.observer.yml)
  OBSERVER_BIND (default 127.0.0.1; the C5 deployment sets the container address), OBSERVER_PORT (default 9000)

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
        done = {r[0] for r in cur.fetchall()}            # fetch ONCE (C1 bug: re-fetched per migration, found by C3)
        return p, [m for m in expected() if m not in done]
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


def build_canaries(obs: Observer, env=os.environ):
    """C3 canaries (optional). Sensors are loopback-only; live P2 submission stays OFF unless
    OBSERVER_CANARY_P2_LIVE=1 is set explicitly (D4: connectivity and security are validated in the deployment phase)."""
    from observer.canary import CanaryService, FileCanarySensor, HttpCanarySensor, P2Client
    if env.get("OBSERVER_CANARIES", "") != "1":
        return None
    svc = CanaryService(obs)
    if env.get("OBSERVER_CANARY_HTTP_PORT"):
        svc.http = HttpCanarySensor(svc.record, env.get("OBSERVER_CANARY_HTTP_HOST", "127.0.0.1"),
                                    int(env["OBSERVER_CANARY_HTTP_PORT"]), external=env.get("OBSERVER_C5_TOPOLOGY") == "1")
    if env.get("OBSERVER_CANARY_DIR"):
        svc.file = FileCanarySensor(svc.record, env["OBSERVER_CANARY_DIR"])
    creds = json.load(open(env["OBSERVER_CANARY_CREDENTIALS_FILE"])) if env.get("OBSERVER_CANARY_CREDENTIALS_FILE") else {}
    live = env.get("OBSERVER_CANARY_P2_LIVE") == "1" and bool(env.get("OBSERVER_CANARY_BACKEND_URL"))
    http = None
    if live:
        import httpx
        http = httpx.Client(base_url=env["OBSERVER_CANARY_BACKEND_URL"], timeout=5.0, trust_env=False)
    svc.p2 = P2Client(creds.get("tenants", {}), http, live)
    svc.recover()                                     # runs left open by a previous process => INTERRUPTED
    return svc


def build_c5(obs: Observer, env=os.environ):
    """C5 sensors (OBSERVER_C5_TOPOLOGY=1, docker-compose.observer.yml): egress proxy, DNS forwarder, coverage sink and
    the coverage service. Without them coverage is absent and nothing can be ENFORCEMENT_VERIFIED."""
    if env.get("OBSERVER_C5_TOPOLOGY") != "1":
        return None
    from observer.coverage import CoverageService
    from observer.egress import DnsForwarder, EgressProxy, Recorder, Sink, default_resolve
    rec = Recorder(obs)
    static = json.loads(env.get("OBSERVER_EGRESS_STATIC_HOSTS", "{}") or "{}")   # test topology names only

    def resolve(h):
        return sorted(set(static.get(h, [])) | set(default_resolve(h) if h not in static else []))
    ph, pp = env["OBSERVER_EGRESS_BIND"].rsplit(":", 1)
    proxy = EgressProxy(rec, ph, int(pp), resolve, [c for c in env.get("OBSERVER_EGRESS_ALLOW_CIDRS", "").split(",") if c])
    dh, dp = env["OBSERVER_DNS_BIND"].rsplit(":", 1)
    uh, up = env.get("OBSERVER_DNS_UPSTREAM", "127.0.0.11:53").rsplit(":", 1)
    dns = DnsForwarder(rec, dh, int(dp), (uh, int(up)))
    sink = Sink(rec, env["OBSERVER_SINK_HOST"]) if env.get("OBSERVER_SINK_HOST") else None
    return {"recorder": rec, "proxy": proxy, "dns": dns, "sink": sink, "coverage": CoverageService(obs)}


def monitor(obs: Observer, interval: float, canaries=None, c5=None) -> None:
    while True:
        try:
            obs.tick()
            if c5 is not None:
                c5["coverage"].tick()
            if canaries is not None:
                canaries.tick()
        except Exception:
            pass                                      # monitor failures are visible as missing alerts / stale status
        time.sleep(min(interval, 1.0) if canaries is not None else interval)


def main() -> int:
    obs = build()
    tok = None
    if os.getenv("OBSERVER_OPERATOR_TOKEN_FILE"):
        tok = open(os.environ["OBSERVER_OPERATOR_TOKEN_FILE"]).read().strip() or None
    canaries = build_canaries(obs)
    c5 = build_c5(obs)
    if c5 is not None and canaries is not None:
        canaries.coverage = c5["coverage"]
    read_tokens = []
    if os.getenv("OBSERVER_READ_TOKENS_FILE"):         # [{"sha256": hex(sha256(token)), "tenants": [...]}]; hashes only
        read_tokens = json.load(open(os.environ["OBSERVER_READ_TOKENS_FILE"])).get("tokens", [])
    threading.Thread(target=monitor, args=(obs, obs.cfg.H, canaries, c5), name="observer-monitor", daemon=True).start()
    import uvicorn
    from observer.tls import server_settings
    host = os.getenv("OBSERVER_BIND", "127.0.0.1")
    tls = server_settings(os.environ, host)           # F2: non-loopback => mTLS or refuse to start
    uvicorn.run(create_app(obs, tok, canaries, read_tokens, c5), host=host, port=int(os.getenv("OBSERVER_PORT", "9000")), **tls)
    return 0


if __name__ == "__main__":
    sys.exit(main())
