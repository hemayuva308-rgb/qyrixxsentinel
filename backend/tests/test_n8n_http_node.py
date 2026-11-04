"""Phase 1A PROTOTYPE (+ security remediation): n8n Qyrix Sentinel HTTP node (integrations/n8n) end to end against
  * the REAL Gate API over verified HTTPS (uvicorn, in process: /api/v1/sentinel/gate/evaluate + /api/v1/tools/redeem),
  * the REAL C5 EgressProxy with the REAL N2 grant_authorizer (observer on real PostgreSQL; tagged CONNECT 443 only),
  * a recording TLS origin (certificate from a dedicated test CA) - no external destination is ever contacted.
Claim publication: this module's Gate is in memory (no outbox), so CLAIM_RELAY mirrors what the PostgreSQL outbox
publisher sends for each REAL grant: the signed decision + `issued` claim when the grant exists and the `redeemed` claim
once the Gate marks it used. The real PostgreSQL -> Publisher -> Observer path is covered by test_n8n_pg_publication.py."""
import json
import os
import pathlib
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import psycopg
import pytest
import uvicorn
from fastapi.testclient import TestClient

from app import gateway as g, identity
from app.identity import Principal
from app.main import app
from observer import tls as otls
from observer.egress import EgressProxy, Recorder, grant_authorizer
from observer.feed import Config
from tests.conftest import AGENT
from tests.observer_support import HAVE_PG, Keys, ObserverCluster, envelope, make_observer, raw
from tests.test_mcp_proxy import fresh  # noqa: F401  (autouse: resets the Gate between tests)

NODE = shutil.which("node")
pytestmark = [pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available"),
              pytest.mark.skipif(not NODE, reason="node not installed")]
ROOT = pathlib.Path(__file__).resolve().parents[2]
HARNESS = str(ROOT / "integrations" / "n8n" / "test" / "harness.js")
PKG = ROOT / "integrations" / "n8n"
HOST = "github.com"                                    # in the Gate's default approved list; pinned to the local origin
TOKEN = AGENT["Authorization"].split(" ", 1)[1]
REQUIRED_EXCLUDE = [
    "n8n-nodes-base.code", "n8n-nodes-base.function", "n8n-nodes-base.functionItem", "n8n-nodes-base.executeCommand",
    "n8n-nodes-base.ssh", "n8n-nodes-base.ftp", "n8n-nodes-base.git", "n8n-nodes-base.httpRequest",
    "n8n-nodes-base.readWriteFile", "n8n-nodes-base.readBinaryFile", "n8n-nodes-base.readBinaryFiles",
    "n8n-nodes-base.writeBinaryFile", "n8n-nodes-base.localFileTrigger",
    "@n8n/n8n-nodes-langchain.code", "@n8n/n8n-nodes-langchain.toolCode", "@n8n/n8n-nodes-langchain.toolHttpRequest",
    "@n8n/n8n-nodes-langchain.mcpClient", "@n8n/n8n-nodes-langchain.mcpClientTool"]


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def deploy_env(files_dir):
    """The pinned n8n hardening the node requires (docs/N8N_INTEGRATION.md)."""
    return {"N8N_BLOCK_ENV_ACCESS_IN_NODE": "true", "N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES": "true",
            "N8N_RESTRICT_FILE_ACCESS_TO": str(files_dir), "NODES_EXCLUDE": json.dumps(REQUIRED_EXCLUDE)}


class Origin:
    """TLS origin on 127.0.0.1:443 that records the exact bytes of every request it receives. A request whose path
    starts with /hangup is read completely and then dropped without a response (outcome UNKNOWN for the node)."""
    def __init__(self, tmp):
        ca, srv = str(tmp / "ca"), str(tmp / "srv")
        otls.make_ca(ca, "n8n test CA"); otls.issue(ca, "origin", [HOST], True, srv)
        self.ca_dir, self.ca = ca, os.path.join(ca, "ca.crt")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(os.path.join(srv, "origin.crt"), os.path.join(srv, "origin.key"))
        self.requests, self.lock = [], threading.Lock()
        self.s = socket.socket(); self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", 443)); self.s.listen(16)

        def serve():
            while True:
                try:
                    cn, _ = self.s.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(cn, server_side=True) as t:
                        buf = b""
                        while b"\r\n\r\n" not in buf:
                            d = t.recv(65536)
                            if not d:
                                break
                            buf += d
                        head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1")
                        n = next((int(l.split(":", 1)[1]) for l in head.split("\r\n") if l.lower().startswith("content-length:")), 0)
                        while len(buf.split(b"\r\n\r\n", 1)[1]) < n:
                            buf += t.recv(65536)
                        with self.lock:
                            self.requests.append(buf)
                        if b" /hangup" in buf.split(b"\r\n", 1)[0]:
                            continue
                        body = b'{"ok":true}'
                        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
                except (ssl.SSLError, OSError, IndexError, ValueError):
                    pass
        self.thread = threading.Thread(target=serve, daemon=True); self.thread.start()

    def close(self):
        """Release :443 for later test modules: shutdown() unblocks the accept() thread, which a bare close() does not."""
        try:
            self.s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.s.close(); self.thread.join(5)

    def count(self):
        with self.lock:
            return len(self.requests)


def gate_tls(origin, tmp):
    """A server certificate for 127.0.0.1 from the test CA: the node talks to Sentinel over VERIFIED TLS only."""
    out = str(tmp / "gate")
    otls.issue(origin.ca_dir, "gate", ["127.0.0.1"], True, out)
    return os.path.join(out, "gate.crt"), os.path.join(out, "gate.key")


class FakeGate:
    """Misbehaving Gate (HTTPS, same test CA) for the fail-closed cases: timeout, malformed, missing grant, wrong digest,
    mismatched ids, bad redemption."""
    def __init__(self, cert, key):
        self.mode, self.calls = "ok", []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, body):
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_POST(self):
                req = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                outer.calls.append(self.path)
                m = outer.mode
                if m.startswith("badredeem") or m == "badcorr":   # a VALID decision for this exact action (unless badcorr)
                    if self.path.endswith("/evaluate"):
                        outer.digest = g._digest(req["tool"], req["method"], req["dest"], req["cmd"], req["data"])
                        b = {"verdict": "ALLOW", "grant_id": "grt_" + "b" * 32, "gate_evaluation_id": "e2", "params_digest": outer.digest,
                             "correlation_id": "someone-else" if m == "badcorr" else req["correlation_id"], "task_id": req["task_id"]}
                    else:
                        b = {"redeemed": m != "badredeem-false", "params_digest": outer.digest,
                             "gate_evaluation_id": "e-other" if m == "badredeem-eval" else req["gate_evaluation_id"],
                             "correlation_id": "c-other" if m == "badredeem-corr" else req["correlation_id"],
                             "execution_id": "not-a-uuid" if m == "badredeem-execid" else str(uuid.uuid4())}
                    return self.reply(json.dumps(b).encode())
                if m == "slow":
                    time.sleep(3)
                body = {"notjson": b"<html>oops</html>", "array": b"[1,2]", "noverdict": b'{"rules":[]}',
                        "nogrant": json.dumps({"verdict": "ALLOW", "grant_id": None, "gate_evaluation_id": "e1", "params_digest": "0" * 64}).encode(),
                        "wrongdigest": json.dumps({"verdict": "ALLOW", "grant_id": "grt_" + "a" * 32, "gate_evaluation_id": "e1",
                                                   "params_digest": "0" * 64}).encode()}.get(m, b"{}")
                self.reply(body)
        self.port = free_port()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sc.minimum_version = ssl.TLSVersion.TLSv1_2
        sc.load_cert_chain(cert, key)
        self.srv.socket = sc.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    @property
    def url(self):
        return "https://127.0.0.1:%d" % self.port


@pytest.fixture(scope="module")
def lab():
    tmp = pathlib.Path(tempfile.mkdtemp())
    origin = Origin(tmp)
    cert, key = gate_tls(origin, tmp)
    port = free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", ssl_certfile=cert, ssl_keyfile=key))
    threading.Thread(target=server.run, daemon=True).start()
    end = time.time() + 15
    while not server.started and time.time() < end:
        time.sleep(0.05)
    cluster = ObserverCluster(); url, admin = cluster.new_db(); keys = Keys()
    obs = make_observer(url, keys, time.time, cfg=Config()); rec = Recorder(obs)
    proxy = EgressProxy(rec, "127.0.0.1", 0, lambda h: {HOST: ["127.0.0.1"]}.get(h, []), [],
                        authorize=grant_authorizer(obs.db, clock=time.time, wait=3.0), untagged_allow=[])   # tagged: 443 only
    proxy._is_public = lambda ip: True                 # loopback stands in for a public destination (as in the N2 tests)
    relay = {"mode": "on", "issued": set(), "used": set(), "stop": False, "seq": 0}

    def emit(type_, body):
        relay["seq"] += 1
        st, r = obs.ingest(raw(envelope(keys.gate, keys.gate_pid, type_, body, seq=relay["seq"], issued=time.time())))
        assert st == 200, r

    def claim_relay():                                 # mirrors the REAL Gate's grants as the outbox publisher would
        while not relay["stop"]:
            with g.PROD.lock:
                grants = [(gid, dict(gr)) for gid, gr in g.PROD.grants.items()]
                evals = {k: dict(v) for k, v in g.PROD.evals.items()}
            for gid, gr in grants:
                ev = evals.get(gr["gate_evaluation_id"]) or {}
                base = {"gate_evaluation_id": gr["gate_evaluation_id"], "grant_id": gid, "execution_id": gr["execution_id"]}
                if gid not in relay["issued"]:
                    relay["issued"].add(gid)
                    if relay["mode"] != "off" and ev.get("host"):
                        emit("decision", {"gate_evaluation_id": gr["gate_evaluation_id"], "correlation_id": ev.get("correlation_id"),
                                          "verdict": "ALLOW", "rule_ids": [], "dest_host": ev["host"]})
                        emit("grant", dict(base, kind="issued"))
                if gr.get("used") and gid not in relay["used"]:
                    relay["used"].add(gid)
                    if relay["mode"] == "on" and ev.get("host"):
                        emit("grant", dict(base, kind="redeemed", integration="n8n_http"))
            time.sleep(0.02)
    threading.Thread(target=claim_relay, daemon=True).start()
    secrets_dir = tmp / "secrets"; secrets_dir.mkdir()
    files_dir = tmp / "n8n-files"; files_dir.mkdir()
    tok = secrets_dir / "token"; tok.write_text(TOKEN); os.chmod(tok, 0o600)
    yield {"gate": "https://127.0.0.1:%d" % port, "proxy": proxy, "origin": origin, "admin": admin, "relay": relay,
           "token_file": str(tok), "files_dir": files_dir, "fake": FakeGate(cert, key)}
    relay["stop"] = True; server.should_exit = True; proxy.close(); origin.close(); cluster.destroy()


def base_env(lab_or_parts):
    l = lab_or_parts
    return {"PATH": os.environ.get("PATH", ""), "QYRIX_SENTINEL_URL": l["gate"], "QYRIX_SENTINEL_TOKEN_FILE": l["token_file"],
            "QYRIX_SENTINEL_CA_FILE": l["origin"].ca, "QYRIX_EGRESS_PROXY_URL": "http://127.0.0.1:%d" % l["proxy"].port,
            "QYRIX_STATIC_HOSTS": json.dumps({HOST: "127.0.0.1"}), "QYRIX_UPSTREAM_CA_FILE": l["origin"].ca,
            "QYRIX_GATE_TIMEOUT_MS": "5000", "QYRIX_EGRESS_TIMEOUT_MS": "8000", **deploy_env(l["files_dir"])}


def run(lab, spec, **env_over):
    env = base_env(lab)
    env.update({k: v for k, v in env_over.items() if v is not None})
    for k, v in env_over.items():
        if v is None:
            env.pop(k, None)
    p = subprocess.run([NODE, HARNESS], input=json.dumps(spec), capture_output=True, text=True, env=env, timeout=60)
    lines = [l for l in p.stdout.splitlines() if l.strip()]
    return json.loads(lines[-1]), p.stdout, p.stderr


def node_spec(**params):
    return {"mode": "node", "params": {"method": "GET", "headers": "{}", "lineage": "", **params}}


def proxy_rows(lab):
    with psycopg.connect(lab["admin"], autocommit=True) as c:
        return c.execute("SELECT kind, host, execution_id::text, reason FROM egress_observations ORDER BY observed_at").fetchall()


def chain(kind=None):
    with g.PROD.lock:
        return [dict(r) for r in g.PROD.chain if kind is None or r.get("verdict") == kind or r.get("kind") == kind]


CTX = {"correlationId": "n8n:wfT:1:nodeT:0", "taskId": "n8n-wf-wfT"}

# Audit A-2 fixture: a SYNTHETIC token-shaped value whose "_" is percent-encoded (%5F) - a non-canonical spelling of the same URL.
# It is assembled from fragments at runtime so no secret-shaped literal sits in the source (secret scanners flag one even though
# it is fake: its GitHub checksum is invalid). The assembled value is byte-for-byte the one the test always used.
SYNTHETIC_ENCODED_TOKEN_URL = "https://github.com/x?k=" + "ghp" + "%5F" + "".join(("aB3dE5gH7jK9", "mN1pQ3sT5vW7", "yZ9bC1dE3fG5"))


# ---------------- exact binding ----------------
def test_js_digest_equals_gate_params_digest():
    vectors = [["http", "GET", "https://github.com/a", "", ""], ["http", "post", "  https://github.com/x?y=1  ", "", '{"a":1}'],
               ["http", "GET", "https://github.com/é中", "", "café \U0001F600"], ["http", "PUT", "https://github.com/", "", "x" * 70000],
               ["http", "GET", "https://github.com/", "cmd \"q\" \\ \n\t\r\x00\x1f\x7f", "ctrl\x08\x0c"]]
    p = subprocess.run([NODE, HARNESS], input=json.dumps({"mode": "digest", "vectors": vectors}), capture_output=True, text=True, timeout=30)
    assert json.loads(p.stdout)["output"] == [g._digest(*v) for v in vectors]


def test_allowed_get_end_to_end_with_exact_wire_execution_and_correlation_ids(lab):
    n0, rows0 = lab["origin"].count(), len(proxy_rows(lab))
    url = "https://github.com/repos/qyrix?x=1"
    r, out, err = run(lab, node_spec(url=url, headers='{"Accept":"application/json","X-Request-Id":"abc"}'), )
    assert r["ok"], r
    o = r["output"][0]; q = o["qyrix"]
    assert o["status"] == 200 and o["body"] == '{"ok":true}'
    assert q["verdict"] == "ALLOW" and q["evidence"] == "E1_ADAPTER_SELF_REPORT"
    assert q["correlation_id"] == "n8n:wfTest01:42:node-1:0" and q["task_id"] == "n8n-wf-wfTest01"
    # the origin received exactly the request that was described to (and digested by) the Gate
    b, _, _ = run(lab, {"mode": "build", "args": {"url": url, "method": "GET", "headers": {"Accept": "application/json", "X-Request-Id": "abc"}}})
    assert lab["origin"].count() == n0 + 1 and lab["origin"].requests[-1].decode() == b["output"]["wire"]
    assert b"x-qyrix" not in lab["origin"].requests[-1].lower()            # tags go to the proxy only
    # execution_id: Gate-issued, used as the proxy tag, observed by the proxy
    new = proxy_rows(lab)[rows0:]
    assert ("tunnel_open", HOST, q["execution_id"], None) in new and all(x[2] == q["execution_id"] for x in new if x[0].startswith("tunnel"))
    with g.PROD.lock:
        grant = next(gr for gr in g.PROD.grants.values() if gr["gate_evaluation_id"] == q["gate_evaluation_id"])
    assert grant["execution_id"] == q["execution_id"] and grant["used"] is True
    # correlation_id recorded by the Gate for the decision and the delegation
    dec = [x for x in chain() if x.get("kind") == "gate_decision" and x.get("gate_evaluation_id") == q["gate_evaluation_id"]]
    dele = [x for x in chain("EXECUTION_DELEGATED") if x.get("gate_evaluation_id") == q["gate_evaluation_id"]]
    assert dec[0]["correlation_id"] == q["correlation_id"] and dele[0]["correlation_id"] == q["correlation_id"]
    assert dele[0]["integration"] == "n8n_http" and dele[0]["params_digest"] == q["params_digest"]


def test_head_is_supported(lab):
    n0 = lab["origin"].count()
    r, _, _ = run(lab, node_spec(method="HEAD", url="https://github.com/head"))
    assert r["ok"], r
    assert lab["origin"].count() == n0 + 1 and lab["origin"].requests[-1].startswith(b"HEAD /head HTTP/1.1\r\n")


# ---------------- remediation: no state-changing methods, no expression lineage ----------------
@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
def test_state_changing_methods_are_refused_before_the_gate(lab, method):
    lab["fake"].mode, lab["fake"].calls[:] = "ok", []
    step = TestClient(app, headers=AGENT).post("/api/v1/sentinel/provenance/step", json={"label": "TRUSTED", "text": "x"}).json()
    r, _, _ = run(lab, node_spec(method=method, url="https://github.com/api/issues", lineage=step["id"]), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "METHOD_NOT_SUPPORTED" and r["outcome"] == "NOT_SENT" and lab["fake"].calls == []
    src = (PKG / "nodes" / "QyrixHttp" / "QyrixHttp.node.js").read_text()
    assert "'POST'" not in src and "'DELETE'" not in src and "name: 'body'" not in src     # not even offered in the UI


@pytest.mark.parametrize("raw_lineage", ["={{ $json.lineage }}", "  =x", ["a"], "{{ $json.lineage }}", "{{'abc'}}"])
def test_expression_lineage_is_refused_before_the_gate(lab, raw_lineage):
    lab["fake"].mode, lab["fake"].calls[:] = "ok", []
    spec = node_spec(url="https://github.com/x", lineage=str(uuid.uuid4()))
    spec["rawParams"] = dict(spec["params"], lineage=raw_lineage)
    r, _, _ = run(lab, spec, QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "LINEAGE_EXPRESSION_NOT_ALLOWED" and lab["fake"].calls == []
    assert "noDataExpression: true" in (PKG / "nodes" / "QyrixHttp" / "QyrixHttp.node.js").read_text()


# ---------------- audit A-3 (restricted mode): method, URL and headers are fixed values too ----------------
@pytest.mark.parametrize("name,raw", [("url", "={{ 'https://github.com/' + $json.p }}"), ("url", "https://github.com/{{ $json.p }}"),
                                      ("headers", "={{ $json.h }}"), ("headers", '{"X-A":"{{ $json.secret }}"}'),
                                      ("method", "={{ $json.m }}"), ("url", ["https://github.com/"])])
def test_expressions_in_url_headers_and_method_are_refused_before_the_gate(lab, name, raw):
    lab["fake"].mode, lab["fake"].calls[:] = "ok", []
    spec = node_spec(url="https://github.com/x")
    spec["rawParams"] = dict(spec["params"], **{name: raw})
    r, _, _ = run(lab, spec, QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "EXPRESSION_NOT_ALLOWED" and name in r["message"] and r["outcome"] == "NOT_SENT"
    assert lab["fake"].calls == []                                          # nothing reached the Gate
    src = (PKG / "nodes" / "QyrixHttp" / "QyrixHttp.node.js").read_text()
    for prop in ("'method'", "'url'", "'headers'", "'lineage'"):
        line = next(l for l in src.splitlines() if "name: " + prop in l and "displayName" in l or ("name: " + prop) in l)
        assert "noDataExpression: true" in line or "noDataExpression: true" in src.split("name: " + prop, 1)[1].split("}", 1)[0]


def test_fixed_values_still_work(lab):
    r, _, _ = run(lab, node_spec(url="https://github.com/fixed", headers='{"Accept":"application/json"}'))
    assert r["ok"], r


# ---------------- audit A-6: Retry On Fail ----------------
def test_retry_on_fail_is_refused_before_the_gate(lab):
    lab["fake"].mode, lab["fake"].calls[:] = "ok", []
    n0, d0 = lab["origin"].count(), len(chain("gate_decision"))
    spec = node_spec(url="https://github.com/retry"); spec["retryOnFail"] = True
    r, _, _ = run(lab, spec, QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "RETRY_ON_FAIL_NOT_ALLOWED" and r["outcome"] == "NOT_SENT" and lab["fake"].calls == []
    r, _, _ = run(lab, spec)                                                # the real Gate: no decision, no request, no grant
    assert not r["ok"] and r["code"] == "RETRY_ON_FAIL_NOT_ALLOWED"
    assert lab["origin"].count() == n0 and len(chain("gate_decision")) == d0
    spec["continueOnFail"] = True
    r, _, _ = run(lab, spec)                                                # Continue On Fail reports it, still nothing sent
    assert r["ok"] and r["output"][0]["qyrix"]["error"] == "RETRY_ON_FAIL_NOT_ALLOWED" and lab["origin"].count() == n0


def test_fixed_lineage_is_passed_to_the_gate(lab):
    step = TestClient(app, headers=AGENT).post("/api/v1/sentinel/provenance/step", json={"label": "UNTRUSTED", "text": "webhook"}).json()
    r, _, _ = run(lab, node_spec(url="https://github.com/lineage", lineage=step["id"]))
    assert r["ok"], r                                                      # GET with lineage: evaluated with that lineage
    dec = [x for x in chain() if x.get("kind") == "gate_decision" and x.get("gate_evaluation_id") == r["output"][0]["qyrix"]["gate_evaluation_id"]]
    assert dec and step["id"] in json.dumps(dec[0])


# ---------------- remediation: Sentinel only over verified HTTPS ----------------
@pytest.mark.parametrize("url", ["http://127.0.0.1:1", "http://localhost:8000", "ftp://127.0.0.1", "https://127.0.0.1:1/path"])
def test_sentinel_url_must_be_https(lab, url):
    r, out, err = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=url)
    assert not r["ok"] and r["code"] == "CONFIG_INVALID" and r["outcome"] == "NOT_SENT" and TOKEN not in out + err


def test_sentinel_certificate_is_verified(lab):
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_CA_FILE=None)   # system trust: test CA unknown
    assert not r["ok"] and r["code"] == "GATE_UNREACHABLE" and r["outcome"] == "NOT_SENT"


class EvilGate:
    """A Sentinel impostor with a certificate from a CA the node does not trust. It records whether anything arrived."""
    def __init__(self, tmp):
        ca = str(tmp / "evil-ca"); otls.make_ca(ca, "evil CA"); otls.issue(ca, "evil", ["127.0.0.1"], True, str(tmp / "evil-srv"))
        self.seen = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                outer.seen.append(self.headers.get("Authorization"))
                body = b'{"verdict":"BLOCK","rules":["X"]}'
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        self.port = free_port()
        self.srv = ThreadingHTTPServer(("127.0.0.1", self.port), H)
        sc = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sc.minimum_version = ssl.TLSVersion.TLSv1_2
        sc.load_cert_chain(str(tmp / "evil-srv" / "evil.crt"), str(tmp / "evil-srv" / "evil.key"))
        self.srv.socket = sc.wrap_socket(self.srv.socket, server_side=True)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()


@pytest.mark.parametrize("value", ["0", "false", "no"])
def test_environment_cannot_disable_gate_tls_verification(lab, tmp_path, value):
    """Audit A-1. Baseline behaviour: with NODE_TLS_REJECT_UNAUTHORIZED=0 the bearer token was sent to the impostor."""
    evil = EvilGate(tmp_path)
    url = "https://127.0.0.1:%d" % evil.port
    # (a) the TLS layer itself: gatePost requests verification explicitly, so the environment switch has no effect
    r, _, _ = run(lab, {"mode": "raw-evaluate", "action": {"tool": "http", "method": "GET", "dest": "https://github.com/x", "cmd": "", "data": "{}",
                                                          "correlation_id": "c-a1", "task_id": "t-a1"}},
                  QYRIX_SENTINEL_URL=url, QYRIX_SENTINEL_CA_FILE=None, NODE_TLS_REJECT_UNAUTHORIZED=value)
    assert not r["ok"] and r["code"] == "GATE_UNREACHABLE" and evil.seen == [], (r, evil.seen)
    # (b) the deployment check refuses to run at all while the switch is set
    r, out, err = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=url, QYRIX_SENTINEL_CA_FILE=None, NODE_TLS_REJECT_UNAUTHORIZED=value)
    assert not r["ok"] and r["code"] == "DEPLOYMENT_INSECURE" and evil.seen == [] and TOKEN not in out + err
    evil.srv.shutdown()


def test_tls_verification_switch_value_1_is_allowed(lab):
    r, _, _ = run(lab, node_spec(url="https://github.com/tls1"), NODE_TLS_REJECT_UNAUTHORIZED="1")
    assert r["ok"], r


# ---------------- remediation: pinned deployment hardening ----------------
@pytest.mark.parametrize("over", [
    {"N8N_BLOCK_ENV_ACCESS_IN_NODE": None}, {"N8N_BLOCK_ENV_ACCESS_IN_NODE": "false"},
    {"N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES": "false"}, {"N8N_RESTRICT_FILE_ACCESS_TO": None},
    {"N8N_RESTRICT_FILE_ACCESS_TO": "relative/dir"}, {"NODES_EXCLUDE": None}, {"NODES_EXCLUDE": "not json"},
    {"NODES_EXCLUDE": json.dumps(REQUIRED_EXCLUDE[1:])}, {"NODES_EXCLUDE": json.dumps(REQUIRED_EXCLUDE[:-1])},
    {"N8N_RESTRICT_FILE_ACCESS_TO": "SECRETS"}, {"N8N_RESTRICT_FILE_ACCESS_TO": "PARENT"}])
def test_insecure_n8n_deployment_is_refused_before_the_gate(lab, over):
    lab["fake"].mode, lab["fake"].calls[:] = "ok", []
    sec = os.path.dirname(lab["token_file"])
    over = {k: (sec if v == "SECRETS" else os.path.dirname(sec) if v == "PARENT" else v) for k, v in over.items()}
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url, **over)
    assert not r["ok"] and r["code"] == "DEPLOYMENT_INSECURE" and lab["fake"].calls == [], r


def test_required_exclusions_match_the_core_and_the_docs():
    out = subprocess.run([NODE, "-e", "process.stdout.write(JSON.stringify(require(%s).REQUIRED_NODES_EXCLUDE))"
                          % json.dumps(str(PKG / "lib" / "qyrix-core.js"))], capture_output=True, text=True, timeout=20)
    assert json.loads(out.stdout) == REQUIRED_EXCLUDE
    doc = (ROOT / "docs" / "N8N_INTEGRATION.md").read_text()
    assert all(n in doc for n in REQUIRED_EXCLUDE)
    for k in ("N8N_BLOCK_ENV_ACCESS_IN_NODE", "N8N_BLOCK_FILE_ACCESS_TO_N8N_FILES", "N8N_RESTRICT_FILE_ACCESS_TO", "Retry On Fail"):
        assert k in doc


# ---------------- Gate refusals and failures: nothing is sent ----------------
def test_gate_block_is_never_sent(lab):
    n0, rows0 = lab["origin"].count(), len(proxy_rows(lab))
    r, _, _ = run(lab, node_spec(url="https://evil.example.org/x"))
    assert not r["ok"] and r["code"] == "GATE_BLOCK" and "R1_DEST_NOT_APPROVED" in r["message"]
    assert r["outcome"] == "NOT_SENT" and r["ids"]["correlation_id"] == "n8n:wfTest01:42:node-1:0"
    assert lab["origin"].count() == n0 and len(proxy_rows(lab)) == rows0


def test_r8_unmapped_action_is_refused(lab):
    a = {"tool": "n8n:unmapped", "method": "CALL", "dest": "", "cmd": "", "data": "{}", "correlation_id": "c-r8", "task_id": "t-r8"}
    r, _, _ = run(lab, {"mode": "raw-evaluate", "action": a})
    assert not r["ok"] and r["code"] == "GATE_BLOCK" and "R8_UNSUPPORTED_TOOL" in r["message"]


def test_gate_unavailable_fails_closed(lab):
    n0 = lab["origin"].count()
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL="https://127.0.0.1:%d" % free_port())
    assert not r["ok"] and r["code"] == "GATE_UNREACHABLE" and lab["origin"].count() == n0


def test_gate_timeout_fails_closed(lab):
    lab["fake"].mode = "slow"
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url, QYRIX_GATE_TIMEOUT_MS="500")
    assert not r["ok"] and r["code"] == "GATE_TIMEOUT"


@pytest.mark.parametrize("mode", ["notjson", "array", "noverdict"])
def test_malformed_gate_response_fails_closed(lab, mode):
    lab["fake"].mode, lab["fake"].calls[:] = mode, []
    n0 = lab["origin"].count()
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "GATE_MALFORMED" and lab["origin"].count() == n0 and lab["fake"].calls == ["/api/v1/sentinel/gate/evaluate"]


def test_allow_without_grant_fails_closed(lab):
    lab["fake"].mode, lab["fake"].calls[:] = "nogrant", []
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "GRANT_MISSING" and "/api/v1/tools/redeem" not in lab["fake"].calls


def test_gate_digest_that_differs_from_the_request_is_never_redeemed(lab):
    lab["fake"].mode, lab["fake"].calls[:] = "wrongdigest", []
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "DIGEST_MISMATCH" and lab["fake"].calls == ["/api/v1/sentinel/gate/evaluate"]


def test_decision_for_another_correlation_id_is_never_redeemed(lab):
    lab["fake"].mode, lab["fake"].calls[:] = "badcorr", []
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "GATE_MALFORMED" and "correlation_id" in r["message"]
    assert lab["fake"].calls == ["/api/v1/sentinel/gate/evaluate"]


@pytest.mark.parametrize("mode,what", [("badredeem-execid", "execution_id"), ("badredeem-false", "redemption"),
                                       ("badredeem-eval", "gate_evaluation_id"), ("badredeem-corr", "correlation_id")])
def test_malformed_redemption_fails_closed_before_any_egress(lab, mode, what):
    lab["fake"].mode, lab["fake"].calls[:] = mode, []
    n0, rows0 = lab["origin"].count(), len(proxy_rows(lab))
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "GATE_MALFORMED" and what in r["message"], r
    assert lab["fake"].calls == ["/api/v1/sentinel/gate/evaluate", "/api/v1/tools/redeem"]
    assert lab["origin"].count() == n0 and len(proxy_rows(lab)) == rows0              # the proxy was never contacted
    assert r["ids"]["gate_evaluation_id"] == "e2" and "execution_id" not in r["ids"]


def test_grant_replay_is_refused_by_the_gate(lab):
    r, _, _ = run(lab, {"mode": "replay", "args": {"url": "https://github.com/replay", "method": "GET"}, "ctx": CTX})
    assert not r["ok"] and r["code"] == "GATE_REFUSED" and "GRANT_REPLAY" in r["message"] and r.get("first")


def test_destination_tampered_after_authorization_is_refused(lab):
    n0 = lab["origin"].count()
    spec = {"mode": "tamper", "args": {"url": "https://github.com/a", "method": "GET"},
            "tampered": {"url": "https://github.com/b", "method": "GET"}, "ctx": CTX}
    r, _, _ = run(lab, spec)
    assert not r["ok"] and r["code"] == "GATE_REFUSED" and "PARAMS_DIGEST_MISMATCH" in r["message"] and lab["origin"].count() == n0
    b, _, _ = run(lab, {"mode": "build", "args": {"url": "https://github.com/a", "method": "GET"}})
    assert b["output"]["frozen"] is True                                   # one immutable request object is digested AND sent


@pytest.mark.parametrize("args,code", [
    ({"url": "https://github.com/", "method": "GET", "proxy": "x"}, "ARGS_NOT_ALLOWED"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"Authorization": "Bearer x"}}, "HEADER_NOT_ALLOWED"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"Proxy-Foo": "x"}}, "HEADER_NOT_ALLOWED"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"X-Qyrix-Execution": "x"}}, "HEADER_NOT_ALLOWED"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"Host": "evil.example"}}, "HEADER_NOT_ALLOWED"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"Cookie": "a=b"}}, "HEADER_NOT_ALLOWED"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"X-A": "1", "x-a": "2"}}, "ARGS_AMBIGUOUS"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"X-A": {"nested": "x"}}}, "HEADER_INVALID"),
    ({"url": "https://github.com/", "method": "GET", "headers": {"X-A": "a\r\nInjected: 1"}}, "HEADER_INVALID"),
    ({"url": "https://github.com/", "method": "GET", "headers": ["a"]}, "ARGS_INVALID"),
    ({"url": "http://github.com/", "method": "GET"}, "URL_NOT_SUPPORTED"),
    ({"url": "https://github.com:8443/", "method": "GET"}, "URL_NOT_SUPPORTED"),
    ({"url": "https://GitHub.com/", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com:443/", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://u:p@github.com/", "method": "GET"}, "URL_INVALID"),
    ({"url": "https://github.com/#frag", "method": "GET"}, "URL_INVALID"),
    ({"url": "https://github.com/", "method": "get"}, "METHOD_NOT_SUPPORTED"),
    ({"url": "https://github.com/", "method": "TRACE"}, "METHOD_NOT_SUPPORTED"),
    ({"url": "https://github.com/", "method": "POST", "bodyType": "json", "body": "{}"}, "METHOD_NOT_SUPPORTED"),
    ({"url": "https://github.com/", "method": "DELETE"}, "METHOD_NOT_SUPPORTED"),
    ({"url": "https://github.com/", "method": "GET", "bodyType": "text", "body": "x"}, "ARGS_AMBIGUOUS"),
    ({"url": "https://github.com/", "method": "GET", "bodyType": "none", "body": "x"}, "ARGS_AMBIGUOUS"),
    ({"url": "https://github.com/", "method": "GET", "bodyType": "binary"}, "BODY_TYPE_NOT_SUPPORTED"),
    ({"url": "https://github.com/", "method": "GET", "body": [1, 2]}, "BODY_NOT_SUPPORTED"),
    ({"url": "https://github.com/", "method": "GET", "lineage": "abc"}, "ARGS_INVALID"),
    # audit A-2 (node side): non-canonical percent-encoding can hide a secret from a literal-text scanner
    ({"url": SYNTHETIC_ENCODED_TOKEN_URL, "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com/x?%74oken=abc", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com/%61pi_key/x", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com/x?a=%7E", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com/x?a=%2f", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com/x?a=%zz", "method": "GET"}, "URL_NOT_CANONICAL"),
    ({"url": "https://github.com/x?a=100%", "method": "GET"}, "URL_NOT_CANONICAL"),
])

def test_strict_argument_allow_list_rejects_before_the_gate(lab, args, code):
    r, _, _ = run(lab, {"mode": "build", "args": args})
    assert not r["ok"] and r["code"] == code, r


@pytest.mark.parametrize("url", ["https://github.com/x?a=%2F&b=%20c&d=%C3%A9&e=%3D", "https://github.com/p%20q/r?s=%26"])
def test_canonical_percent_encoding_is_accepted(lab, url):
    r, _, _ = run(lab, {"mode": "build", "args": {"url": url, "method": "GET"}})
    assert r["ok"], r


def test_oversized_payload_is_rejected_before_gate_evaluation(lab):
    lab["fake"].mode, lab["fake"].calls[:] = "ok", []
    big = json.dumps({"X-Big-%02d" % i: "a" * 4000 for i in range(17)})  # 17 x 4000 chars > 65,536 with GET (no body)
    r, _, _ = run(lab, node_spec(url="https://github.com/x", headers=big), QYRIX_SENTINEL_URL=lab["fake"].url)
    assert not r["ok"] and r["code"] == "PAYLOAD_TOO_LARGE" and lab["fake"].calls == []


# ---------------- egress ----------------
def test_proxy_refuses_without_claims_and_the_error_carries_safe_ids(lab):
    n0, rows0 = lab["origin"].count(), len(proxy_rows(lab))
    lab["relay"]["mode"] = "off"                                           # no claim at all => N2 must refuse
    try:
        r, _, _ = run(lab, node_spec(url="https://github.com/noclaim"))
    finally:
        lab["relay"]["mode"] = "on"
    assert not r["ok"] and r["code"] == "EGRESS_REFUSED" and lab["origin"].count() == n0
    assert [x[3] for x in proxy_rows(lab)[rows0:] if x[0] == "refused"] == ["EXECUTION_NOT_AUTHORISED"]
    assert r["outcome"] == "NOT_SENT_GRANT_CONSUMED" and r["ids"]["gate_evaluation_id"] and r["ids"]["execution_id"]
    assert "execution_id=%s" % r["ids"]["execution_id"] in r["message"] and "outcome=NOT_SENT_GRANT_CONSUMED" in r["message"]


def test_issued_but_unredeemed_grant_cannot_open_egress(lab):
    """HIGH-1 regression, end to end: the issued claim reaches the observer but no redemption claim does."""
    n0, rows0 = lab["origin"].count(), len(proxy_rows(lab))
    lab["relay"]["mode"] = "issued_only"
    try:
        r, _, _ = run(lab, node_spec(url="https://github.com/unredeemed"))
    finally:
        lab["relay"]["mode"] = "on"
    assert not r["ok"] and r["code"] == "EGRESS_REFUSED" and lab["origin"].count() == n0
    assert [x[3] for x in proxy_rows(lab)[rows0:] if x[0] == "refused"] == ["EXECUTION_NOT_REDEEMED"]


def test_no_direct_network_fallback(lab):
    n0 = lab["origin"].count(); d0 = len(chain("gate_decision"))
    socket.create_connection(("127.0.0.1", 443), timeout=2).close()        # the origin IS directly reachable from here...
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_EGRESS_PROXY_URL=None)
    assert not r["ok"] and r["code"] == "EGRESS_NOT_CONFIGURED"            # ...yet nothing goes direct
    assert len(chain("gate_decision")) == d0                               # and no grant was consumed (checked before the Gate)
    r, _, _ = run(lab, node_spec(url="https://github.com/x"), QYRIX_EGRESS_PROXY_URL="http://127.0.0.1:%d" % free_port())
    assert not r["ok"] and r["code"] == "EGRESS_UNREACHABLE" and lab["origin"].count() == n0
    assert r["outcome"] == "NOT_SENT_GRANT_CONSUMED"


def test_failure_after_the_request_was_written_is_reported_as_unknown(lab):
    n0 = lab["origin"].count()
    spec = node_spec(url="https://github.com/hangup"); spec["continueOnFail"] = True
    r, _, _ = run(lab, spec)
    assert r["ok"] and lab["origin"].count() == n0 + 1                     # the upstream DID receive the request
    q = r["output"][0]["qyrix"]
    assert q["outcome"] == "UNKNOWN" and q["sent"] == "unknown" and q["execution_id"] and q["gate_evaluation_id"]
    assert q["evidence"] == "E1_ADAPTER_SELF_REPORT"


# ---------------- secrets, tenancy, evidence ----------------
def test_tokens_and_secrets_never_appear_in_output_or_logs(lab):
    blobs = []
    for spec, env in ((node_spec(url="https://evil.example.org/x"), {}), (node_spec(url="https://github.com/x"), {"QYRIX_SENTINEL_URL": "https://127.0.0.1:1"}),
                      (node_spec(url="https://github.com/x?api_key=SYNTHETIC-NOT-A-KEY"), {}),
                      (node_spec(url="https://github.com/x"), {"QYRIX_SENTINEL_URL": "http://127.0.0.1:1"}),
                      ({"mode": "build", "args": {"url": "https://github.com/", "method": "GET", "headers": {"Authorization": "Bearer " + TOKEN}}}, {})):
        r, out, err = run(lab, spec, **env)
        assert not r["ok"]
        blobs.append(out + err)
    assert all(TOKEN not in b for b in blobs) and all("SYNTHETIC-NOT-A-KEY" not in b for b in blobs)
    assert "R12_SECRET_TO_EXTERNAL" in blobs[2] or "R2_SECRET_EXFIL" in blobs[2]   # the Gate's secret scanner sees the node's request


def test_grants_are_bound_to_the_node_credential(lab):
    other = identity.create_key(Principal(None, "platform", "env:platform"), "default", "agent", "other-n8n", None)["api_key"]
    r, _, _ = run(lab, {"mode": "cross-credential", "args": {"url": "https://github.com/x", "method": "GET"}, "ctx": CTX}, OTHER_TOKEN=other)
    assert not r["ok"] and r["code"] == "GATE_REFUSED" and "GRANT_AGENT_MISMATCH" in r["message"]
    src = (PKG / "nodes" / "QyrixHttp" / "QyrixHttp.node.js").read_text()
    props = {p for p in ("tenant", "token", "credential", "apiKey") if "name: '%s'" % p in src}
    assert props == set()                                                  # the workflow cannot choose a tenant or credential


def test_adapter_never_claims_independent_evidence(lab):
    r, _, _ = run(lab, node_spec(url="https://github.com/evidence"))
    assert r["ok"] and r["output"][0]["qyrix"]["evidence"] == "E1_ADAPTER_SELF_REPORT"
    assert "ENFORCEMENT_VERIFIED" not in json.dumps(r) and '"E3"' not in json.dumps(r)
    for f in (PKG / "lib" / "qyrix-core.js", PKG / "nodes" / "QyrixHttp" / "QyrixHttp.node.js"):
        s = f.read_text()
        assert "'ENFORCEMENT_VERIFIED'" not in s and '"ENFORCEMENT_VERIFIED"' not in s and "'E3'" not in s


def test_continue_on_fail_reports_the_refusal_and_sends_nothing(lab):
    n0 = lab["origin"].count()
    spec = node_spec(url="https://evil.example.org/x"); spec["continueOnFail"] = True
    r, _, _ = run(lab, spec)
    q = r["output"][0]["qyrix"]
    assert r["ok"] and q["error"] == "GATE_BLOCK" and q["sent"] is False and q["outcome"] == "NOT_SENT" and lab["origin"].count() == n0
    assert q["correlation_id"] == "n8n:wfTest01:42:node-1:0" and q["gate_evaluation_id"] is None and q["execution_id"] is None


def test_each_item_gets_its_own_decision_and_single_use_grant(lab):
    n0 = lab["origin"].count()
    spec = node_spec(url="https://github.com/items"); spec["items"] = 2
    r, _, _ = run(lab, spec)
    assert r["ok"] and len(r["output"]) == 2 and lab["origin"].count() == n0 + 2
    ids = [o["qyrix"] for o in r["output"]]
    assert len({q["gate_evaluation_id"] for q in ids}) == 2 and len({q["execution_id"] for q in ids}) == 2
    assert [q["correlation_id"] for q in ids] == ["n8n:wfTest01:42:node-1:0", "n8n:wfTest01:42:node-1:1"]
