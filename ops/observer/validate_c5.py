"""C5 validation on a REAL Docker host (run as root from the repository root):

    sudo python3 ops/observer/validate_c5.py [--keep]

Brings up docker-compose.yml + docker-compose.observer.yml (+ ops/observer/c5-harness.override.yml), applies the
DOCKER-USER rules, and records - in evidence/c5/validation.json - what actually happened:
  1. direct egress attempts from INSIDE the running backend container fail;
  2. the host attestor's signed attestation is judged VALID by the observer;
  3. a live P2 canary through the real backend (Gate BLOCK, signed claim via mTLS outbox) is ENFORCEMENT_VERIFIED;
  4. negative controls: an extra `egress` attachment and missing DOCKER-USER rules each make the attestation INVALID
     (COVERAGE_GAP), and a canary run under a failed attestation is INCONCLUSIVE;
  5. teardown (unless --keep).
Secrets are generated locally under ./secrets/observer (git-ignored) and never printed."""
import json
import os
import secrets as pysecrets
import ssl
import subprocess  # nosec B404 - fixed docker/compose argv
import sys
import time
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "backend"))
from observer import crypto, tls  # noqa: E402
from observer.manifest import sign_manifest  # noqa: E402

S = os.path.join(ROOT, "secrets", "observer")
PROJECT = "qyrixxsentinel"
FILES = ["-f", "docker-compose.yml", "-f", "docker-compose.observer.yml", "-f", "ops/observer/c5-harness.override.yml"]
NETS = ",".join("%s_%s" % (PROJECT, n) for n in ("internal", "observer_ingest", "egress_in"))
OBS = "https://172.30.1.2:9443"
result = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "steps": []}


def sh(argv, check=True, env=None, capture=True):
    r = subprocess.run(argv, cwd=ROOT, env=env, capture_output=capture, text=True, timeout=600)  # nosec B603
    if check and r.returncode != 0:
        raise SystemExit("command failed: %s\n%s" % (" ".join(argv[:4]), (r.stderr or "")[-2000:]))
    return r


def step(name, ok, **detail):
    result["steps"].append({"step": name, "ok": bool(ok), **detail})
    print(("PASS " if ok else "FAIL ") + name, json.dumps(detail)[:300], flush=True)


def write(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)


def prepare():
    base = os.path.join(ROOT, "secrets")
    for f in ("db_admin_password", "db_runtime_password", "state_witness_key", "data_key", "client_sig_key"):
        p = os.path.join(base, f)
        if not os.path.exists(p):
            write(p, pysecrets.token_hex(32), 0o644)
    os.makedirs(S, exist_ok=True)
    tls.make_ca(os.path.join(S, "ca"))
    tls.issue(os.path.join(S, "ca"), "observer", ["observer", "172.30.1.2"], True, os.path.join(S, "server"))
    tls.issue(os.path.join(S, "ca"), "backend", [], False, os.path.join(S, "backend"))
    tls.issue(os.path.join(S, "ca"), "attestor", [], False, os.path.join(S, "attestor"))
    for p in ("server/observer.key", "backend/backend.key"):       # secrets are bind-mounted: readable by the service
        os.chmod(os.path.join(S, p), 0o644)
    keys = {n: crypto.generate() for n in ("root", "observer_signing_key", "gate_signing_key", "recovery", "attestor_signing")}
    for n in ("observer_signing_key", "gate_signing_key"):
        write(os.path.join(S, n + ".pem"), crypto.private_pem(keys[n]).decode(), 0o644)
    write(os.path.join(S, "attestor_signing.pem"), crypto.private_pem(keys["attestor_signing"]).decode())
    for n in ("operator_token", "observer_db_admin_password", "observer_db_runtime_password"):
        write(os.path.join(S, n), pysecrets.token_hex(32), 0o644)
    env = {"QYRIX_ADMIN_TOKEN": pysecrets.token_hex(24), "QYRIX_AGENT_TOKEN": pysecrets.token_hex(24),
           "OBSERVER_ROOT_PUBLIC_KEY": crypto.describe(keys["root"])[1],
           "QYRIX_HARNESS_SITE_PACKAGES": "/usr/local/lib/python3.13/site-packages",
           "QYRIX_STATE_WITNESS": "enabled", "OBSERVER_CANARIES": "1", "OBSERVER_CANARY_P2_LIVE": "1",
           "OBSERVER_CANARY_BACKEND_URL": "http://backend:8000", "OBSERVER_CANARY_CREDENTIALS_FILE": "/run/canary/creds.json"}
    write(os.path.join(S, "canary", "agent_token"), env["QYRIX_AGENT_TOKEN"], 0o644)
    write(os.path.join(S, "canary", "creds.json"), json.dumps(
        {"tenants": {"default": {"key_id": "env-agent", "token_file": "/run/canary/agent_token"}}}), 0o644)
    return keys, env


def compose(env, *args, check=True):
    e = {**os.environ, **env}
    return sh(["docker", "compose", "-p", PROJECT, *FILES, *args], check=check, env=e)


def client():
    import httpx
    ctx = ssl.create_default_context(cafile=os.path.join(S, "ca", "ca.crt"))
    ctx.load_cert_chain(os.path.join(S, "attestor", "attestor.crt"), os.path.join(S, "attestor", "attestor.key"))
    tok = open(os.path.join(S, "operator_token")).read().strip()
    return httpx.Client(base_url=OBS, verify=ctx, timeout=15, trust_env=False, headers={"Authorization": "Bearer " + tok})


def backend_id():
    return sh(["docker", "ps", "-q", "--no-trunc", "-f", "label=com.docker.compose.project=%s" % PROJECT,
               "-f", "label=com.docker.compose.service=backend"]).stdout.strip()


def attest():
    r = sh([sys.executable, "-m", "observer.attestor", "--container", backend_id(), "--observer", OBS,
            "--ca", os.path.join(S, "ca", "ca.crt"), "--cert", os.path.join(S, "attestor", "attestor.crt"),
            "--key", os.path.join(S, "attestor", "attestor.key"), "--operator-token-file", os.path.join(S, "operator_token"),
            "--attestor-key", os.path.join(S, "attestor_signing.pem"), "--networks", NETS, "--dns", "172.30.2.2",
            "--proxy", "172.30.2.2:3128", "--sink", "172.30.3.2"], check=False,
           env={**os.environ, "PYTHONPATH": os.path.join(ROOT, "backend")})
    try:
        return json.loads(r.stdout)
    except ValueError:
        return {"error": (r.stdout + r.stderr)[-800:]}


def canary(c, wait=40):
    r = c.post("/v1/canaries/run", json={"tenant": "default", "channel": "http"}).json()
    end = time.time() + wait
    while time.time() < end:
        rows = [x for x in c.get("/v1/reconciliations", params={"tenant": "default"}).json()["reconciliations"]
                if x["run_id"] == r["run_id"]]
        if rows and (rows[0]["result"] != "INCONCLUSIVE" or time.time() > end - 2):
            return r, rows[0]
        time.sleep(2)
    return r, None


def main():
    keep = "--keep" in sys.argv
    keys, env = prepare()
    try:
        compose(env, "up", "-d", "--no-build", "db", "migrate", "backend")
        for _ in range(90):
            st = sh(["docker", "inspect", "-f", "{{.State.Health.Status}}", backend_id()], check=False).stdout.strip()
            if st == "healthy":
                break
            time.sleep(2)
        step("backend healthy on internal networks only", st == "healthy")
        iid = compose(env, "exec", "-T", "db", "psql", "-U", "qyrix", "-d", "qyrix", "-tAc",
                      "SELECT install_id FROM installation").stdout.strip()
        e = lambda k: {"key_id": crypto.describe(k)[0], "public_key": crypto.describe(k)[1], "valid_from": "2026-01-01T00:00:00+00:00"}
        doc = {"manifest_version": 1, "issued_at": "2026-11-03T00:00:00+00:00", "observer_keys": [e(keys["observer_signing_key"])],
               "producers": [{"producer_id": "gate:" + iid, "tenants": ["*"],
                              "keys": [{**e(keys["gate_signing_key"]), "scopes": ["decision", "grant", "heartbeat"]}]}],
               "recovery_keys": [e(keys["recovery"])], "attestor_keys": [e(keys["attestor_signing"])]}
        write(os.path.join(S, "manifest.signed.json"), json.dumps(sign_manifest(doc, keys["root"])), 0o644)
        compose(env, "up", "-d", "--no-build", "observer-db", "observer-migrate", "observer")
        compose(env, "restart", "backend")                 # pick up the observer (publisher boot)
        sh(["sh", "ops/observer/docker-user.sh", "apply"])
        step("DOCKER-USER rules applied (IPv4 + IPv6)", sh(["sh", "ops/observer/docker-user.sh", "check"], check=False).returncode == 0)
        c = client()
        for _ in range(60):
            try:
                if c.get("/v1/health").json() == {"health": "ok"}:
                    break
            except Exception:
                pass
            time.sleep(2)
        step("observer reachable from the host over mTLS only", True)
        # 1. direct egress from inside the RUNNING backend container (its own code path, its own namespace)
        probe = ("import socket,sys\nr={}\nfor ip,p in (('1.1.1.1',443),('172.30.3.2',443),('8.8.8.8',53)):\n"
                 "    try:\n        socket.create_connection((ip,p),timeout=3).close(); r[ip]='CONNECTED'\n"
                 "    except OSError as e:\n        r[ip]=type(e).__name__+':'+str(e.errno)\nprint(r)")
        out = compose(env, "exec", "-T", "backend", "python", "-c", probe, check=False).stdout.strip()
        step("direct egress from the backend container fails", "CONNECTED" not in out, result=out)
        for _ in range(30):                                 # backend heartbeats delivered over mTLS
            s = c.get("/v1/status").json()
            if any(x.get("last_hb_seq", 0) > 0 for x in s.get("streams", [])):
                break
            time.sleep(2)
        step("backend heartbeats delivered to the observer (mTLS outbox)", any(x.get("last_hb_seq", 0) > 0 for x in s.get("streams", [])))
        # 2. attestation of the real namespace
        a = attest()
        step("host attestation judged VALID by the observer", a.get("observer", {}).get("valid") is True,
             attestor_checks=a.get("attestor_checks"), observer_checks=a.get("observer", {}).get("observer_checks"),
             reasons=a.get("observer", {}).get("reasons"))
        # 3. live canary through the real backend
        run, rec = canary(c)
        step("live P2 canary through the backend is ENFORCEMENT_VERIFIED", rec is not None and rec["result"] == "ENFORCEMENT_VERIFIED",
             reconciliation=rec, submission=run.get("submission"))
        # 4a. negative control: extra egress attachment
        sh(["docker", "network", "connect", "%s_egress" % PROJECT, backend_id()])
        a2 = attest()
        step("NEGATIVE: extra egress attachment => attestation INVALID", a2.get("observer", {}).get("valid") is False,
             reasons=a2.get("observer", {}).get("reasons"))
        run2, rec2 = canary(c)
        step("NEGATIVE: canary under failed coverage is not VERIFIED", rec2 is None or rec2["result"] != "ENFORCEMENT_VERIFIED",
             reconciliation=rec2)
        sh(["docker", "network", "disconnect", "%s_egress" % PROJECT, backend_id()])
        # 4b. negative control: host firewall removed
        sh(["sh", "ops/observer/docker-user.sh", "undo"])
        a3 = attest()
        step("NEGATIVE: DOCKER-USER rules missing => attestation INVALID", a3.get("observer", {}).get("valid") is False,
             reasons=a3.get("observer", {}).get("reasons"))
        sh(["sh", "ops/observer/docker-user.sh", "apply"])
        a4 = attest()
        step("restored topology => attestation VALID again", a4.get("observer", {}).get("valid") is True)
        st = c.get("/v1/status").json()
        result["observer_status"] = {k: st.get(k) for k in ("coverage", "egress", "ingest", "manifest_version")}
    finally:
        result["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        result["all_passed"] = all(s["ok"] for s in result["steps"]) and bool(result["steps"])
        os.makedirs(os.path.join(ROOT, "evidence", "c5"), exist_ok=True)
        with open(os.path.join(ROOT, "evidence", "c5", "validation.json"), "w") as f:
            json.dump(result, f, indent=1, default=str)
        if not keep:
            compose(env, "down", "-v", "--remove-orphans", check=False)
            sh(["sh", "ops/observer/docker-user.sh", "undo"], check=False)
    print("ALL PASSED" if result["all_passed"] else "SOME STEPS FAILED")
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
