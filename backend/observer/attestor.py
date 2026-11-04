"""Host attestor (C5, design §7.3). Runs as ROOT ON THE DOCKER HOST (boundary D), never inside the backend:

    python3 -m observer.attestor --container <backend container> --observer https://172.30.1.2:9443 \\
        --ca CA.crt --cert attestor.crt --key attestor.key --operator-token-file TOKEN --attestor-key attestor.pem \\
        --networks qyrixxsentinel_internal,qyrixxsentinel_observer_ingest,qyrixxsentinel_egress_in \\
        --dns 172.30.2.2 --proxy 172.30.2.2:3128 --sink 172.30.3.2

1. `docker inspect` the RUNNING backend container (networks, NetworkMode, privileges, capabilities, DNS, image, PID).
2. Inside the backend's OWN network namespace (`nsenter --net=/proc/<pid>/ns/net`, HOST binaries - no backend code):
   IPv4 routes, global IPv6, IPv6 sysctl; then token probes: direct TCP 80/443/853 and UDP 53 to the observer sink,
   a positive control THROUGH the proxy, a tunnel with a mismatched SNI, and a DNS query via Docker's embedded resolver.
3. The host firewall rules (DOCKER-USER, IPv4 + IPv6) for the backend-side bridges.
4. Sign everything with the attestor key (listed in the root-signed manifest) and submit it over mTLS.
The OBSERVER then judges the probes from its own sink / proxy / resolver records; the attestor's word on the network is
not trusted. Exit code 0 only if the observer accepted the attestation as VALID."""
import argparse
import hashlib
import json
import os
import ssl
import subprocess  # nosec B404 - fixed host binaries, no shell, no untrusted input
import sys
import time
import uuid

from observer import crypto
from observer.coverage import attestation_skeleton, sign_attestation

PROBE = r'''
import socket, ssl, sys, json
a = json.loads(sys.argv[1])
def tcp(ip, port, payload):
    try:
        s = socket.create_connection((ip, port), timeout=2); s.sendall(payload); s.close(); return "connected"
    except OSError as e:
        return "failed:" + type(e).__name__
out = {}
for name, port in (("ipv4_tcp_80", 80), ("ipv4_tcp_443", 443), ("ipv4_tcp_853", 853)):
    out[name] = tcp(a["sink"], port, b"qxtok-" + a["tok"][name].encode())
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.sendto(b"qxtok-" + a["tok"]["dns_udp_direct"].encode(), (a["sink"], 53)); out["dns_udp_direct"] = "sent"
except OSError as e:
    out["dns_udp_direct"] = "failed:" + type(e).__name__
ph, pp = a["proxy"].rsplit(":", 1)
try:
    s = socket.create_connection((ph, int(pp)), timeout=3)
    s.sendall(("GET http://%s:80/qxtok/%s HTTP/1.1\r\nHost: %s\r\nX-Qyrix-Host: %s\r\nX-Qyrix-Execution: %s\r\n\r\n"
               % (a["sink"], a["pc"], a["sink_host"], a["sink_host"], a["pce"])).encode())
    out["positive_control"] = s.recv(64).decode("latin-1").split("\r\n")[0]; s.close()
except OSError as e:
    out["positive_control"] = "failed:" + type(e).__name__
try:
    s = socket.create_connection((ph, int(pp)), timeout=3)
    s.sendall(("CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\nX-Qyrix-Host: %s\r\nX-Qyrix-Execution: %s\r\n\r\n"
               % (a["sink"], a["sink"], a["sink_host"], a["sme"])).encode())
    s.recv(128)
    c = ssl.create_default_context(); c.check_hostname = False; c.verify_mode = ssl.CERT_NONE
    try:
        c.wrap_socket(s, server_hostname="fronted.example").close()
    except (ssl.SSLError, OSError):
        pass
    out["sni_mismatch"] = "attempted"
except OSError as e:
    out["sni_mismatch"] = "failed:" + type(e).__name__
q = a["dns_name"]
pkt = b"\x51\x51\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(bytes([len(l)]) + l.encode() for l in q.split(".")) + b"\x00\x00\x01\x00\x01"
try:
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3); u.sendto(pkt, ("127.0.0.11", 53))
    try:
        u.recvfrom(512); out["dns_mediated"] = "answered"
    except OSError:
        out["dns_mediated"] = "sent"
except OSError as e:
    out["dns_mediated"] = "failed:" + type(e).__name__
print(json.dumps(out))
'''


def run(argv, check=False) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=60, check=check)  # nosec B603 - fixed argv


def inspect(container: str) -> dict:
    return json.loads(run(["docker", "inspect", container], check=True).stdout)[0]


def in_ns(pid: int, argv):
    return run(["nsenter", "--net=/proc/%d/ns/net" % pid, *argv])


def firewall_ok(ipt: str, bridges) -> bool:
    for br in bridges:
        r = run([ipt, "-C", "DOCKER-USER", "-i", br, "!", "-o", br, "-m", "comment", "--comment", "qyrix-c5", "-j", "DROP"])
        if r.returncode != 0:
            return False
    return True


def resolve_container(a) -> str:
    """The CURRENT backend container: by explicit name/id, or by compose labels (survives re-creation)."""
    if getattr(a, "container", None):
        return a.container
    r = run(["docker", "ps", "-a", "-q", "--no-trunc", "-f", "label=com.docker.compose.project=%s" % a.compose_project,
             "-f", "label=com.docker.compose.service=%s" % a.compose_service])
    ids = [x for x in r.stdout.split() if x]
    return ids[0] if len(ids) == 1 else ""


def absent(name: str) -> dict:
    """Backend container missing / ambiguous: a signed FAILED attestation, which revokes coverage at once."""
    return {"container_id": name or "absent", "image": "", "checks": {"container_running": False},
            "probes": {"ipv6_mode": "unknown", "reason": "CONTAINER_NOT_FOUND"}}


def collect(a) -> dict:
    name = resolve_container(a)
    if not name:
        return absent("absent:%s/%s" % (getattr(a, "compose_project", ""), getattr(a, "compose_service", "")))
    try:
        info = inspect(name)
    except (subprocess.CalledProcessError, ValueError, IndexError):
        return absent("absent:" + name)
    if not info.get("State", {}).get("Running"):
        return {**absent(info["Id"]), "image": info.get("Image", "")}
    hc, st, ns = info["HostConfig"], info["State"], info["NetworkSettings"]
    pid = int(st.get("Pid") or 0)
    checks = {
        "container_running": bool(st.get("Running")) and pid > 0,
        "network_mode_not_host": not (hc.get("NetworkMode", "") == "host" or hc.get("NetworkMode", "").startswith("container:")),
        "not_privileged": not hc.get("Privileged"),
        "cap_drop_all": "ALL" in (hc.get("CapDrop") or []),
        "no_cap_add": not (hc.get("CapAdd") or []),
        "networks_exact": set((ns.get("Networks") or {}).keys()) == set(a.networks.split(",")),
        "dns_is_observer": (hc.get("Dns") or []) == [a.dns],
    }
    routes = in_ns(pid, ["ip", "-4", "route", "show"]).stdout if pid else "default"
    v6 = in_ns(pid, ["ip", "-6", "addr", "show", "scope", "global"]).stdout if pid else "x"
    r6 = in_ns(pid, ["cat", "/proc/sys/net/ipv6/conf/all/disable_ipv6"]) if pid else None
    if r6 is not None and r6.returncode == 0:
        ipv6_mode, ipv6_ok = "disabled_by_sysctl" if r6.stdout.strip() == "1" else "enabled", r6.stdout.strip() == "1"
    elif pid and not os.path.exists("/proc/sys/net/ipv6") and in_ns(pid, ["ls", "/proc/sys/net/ipv6"]).returncode != 0:
        ipv6_mode, ipv6_ok = "absent_from_kernel", True    # no IPv6 stack at all: strictly stronger than the sysctl
    else:
        ipv6_mode, ipv6_ok = "unknown", False
    checks.update(no_default_route="default" not in routes, no_global_ipv6=v6.strip() == "", ipv6_disabled_sysctl=ipv6_ok)
    bridges = a.bridges.split(",")
    checks.update(docker_user_rules_v4=firewall_ok("iptables", bridges), docker_user_rules_v6=firewall_ok("ip6tables", bridges))
    tok = {n: os.urandom(16).hex() for n in ("ipv4_tcp_80", "ipv4_tcp_443", "ipv4_tcp_853", "dns_udp_direct")}
    pc, pce, sme = os.urandom(16).hex(), str(uuid.uuid4()), str(uuid.uuid4())
    dns_name = "%s.dnscheck.qyrix.invalid" % os.urandom(16).hex()
    probe_in = {"sink": a.sink, "proxy": a.proxy, "sink_host": a.sink_host, "tok": tok, "pc": pc, "pce": pce, "sme": sme,
                "dns_name": dns_name}
    seen = {}
    if pid:
        r = in_ns(pid, [sys.executable, "-I", "-c", PROBE, json.dumps(probe_in)])
        seen = json.loads(r.stdout or "{}")
    time.sleep(1.5)                                        # let the observer record sink / proxy / resolver hits
    h = lambda t: hashlib.sha256(t.encode()).hexdigest()
    probes = {**{n: {"token_sha256": h(t), "attempt": seen.get(n)} for n, t in tok.items()},
              "positive_control": {"token_sha256": h(pc), "execution_id": pce, "attempt": seen.get("positive_control")},
              "sni_mismatch": {"execution_id": sme, "attempt": seen.get("sni_mismatch")},
              "dns_mediated": {"qname": dns_name, "attempt": seen.get("dns_mediated")}}
    probes["ipv6_mode"] = ipv6_mode
    return {"container_id": info["Id"], "image": info.get("Image", ""), "checks": checks, "probes": probes}


def submit(a, doc: dict) -> dict:
    import httpx
    ctx = ssl.create_default_context(cafile=a.ca)
    ctx.load_cert_chain(a.cert, a.key)
    tok = open(a.operator_token_file).read().strip()
    with httpx.Client(base_url=a.observer, verify=ctx, timeout=15, trust_env=False) as c:
        r = c.post("/v1/coverage/attestations", json=doc, headers={"Authorization": "Bearer " + tok})
    try:
        return {"status": r.status_code, **r.json()}
    except ValueError:
        return {"status": r.status_code}


REQUIRED = ("observer", "ca", "cert", "key", "operator-token-file", "attestor-key", "networks", "dns", "proxy", "sink")


def parse(argv=None):
    """CLI flags, optionally defaulted from --config FILE (JSON: {"observer": ..., "compose-project": ...}); the systemd
    units use the config file so no secret path or value appears in a unit or a process list."""
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config")
    known, _ = pre.parse_known_args(argv)
    cfg = json.load(open(known.config)) if known.config else {}
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config")
    ap.add_argument("--container", default=cfg.get("container"))
    ap.add_argument("--compose-project", default=cfg.get("compose-project"))
    ap.add_argument("--compose-service", default=cfg.get("compose-service", "backend"))
    for k in REQUIRED:
        ap.add_argument("--" + k, default=cfg.get(k), required=k not in cfg)
    ap.add_argument("--sink-host", default=cfg.get("sink-host", "sink.c5.qyrix.internal"))
    ap.add_argument("--bridges", default=cfg.get("bridges", "qyrix-int,qyrix-ingest,qyrix-egin"))
    ap.add_argument("--validity", type=float, default=float(cfg.get("validity", 1800.0)))
    ap.add_argument("--dry-run", action="store_true", help="print the signed attestation instead of submitting it")
    a = ap.parse_args(argv)
    if not a.container and not a.compose_project:
        ap.error("--container or --compose-project is required")
    return a


def main(argv=None) -> int:
    a = parse(argv)
    if os.geteuid() != 0:
        print("the attestor must run as root on the Docker host (nsenter, iptables)", file=sys.stderr)
        return 2
    c = collect(a)
    doc = sign_attestation(attestation_skeleton(c["container_id"], c["image"], c["checks"], c["probes"],
                                                validity=a.validity), crypto.load_private(a.attestor_key))
    if a.dry_run:
        print(json.dumps(doc, indent=1))
        return 0
    res = submit(a, doc)
    print(json.dumps({"attestor_checks": c["checks"], "observer": res}, indent=1))
    return 0 if res.get("valid") is True else 1


if __name__ == "__main__":
    sys.exit(main())
