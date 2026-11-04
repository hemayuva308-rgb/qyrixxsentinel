"""Phase C2: CONNECT execution header with the approved pinned-IP design (design §4, §7.5): the proxy is asked for the
PINNED IP (SSRF pinning unchanged), TLS SNI/certificate use the hostname, X-Qyrix-Execution + X-Qyrix-Host ride on the
CONNECT request. Plus: the execution id reaches the adapter only during a granted execution; MCP adapter reports are
signed E1 envelopes the observer accepts as adapter_report only."""
import datetime
import os
import socket
import ssl
import tempfile
import threading
import time
import uuid

import pytest

import app.gateway as g
from app import adapter as adapters, netguard, observer_feed, provenance as prov

HOST = "api.example.com"


def _cert(tmp):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
         .not_valid_after(now + datetime.timedelta(hours=1))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .sign(k, hashes.SHA256()))
    cp, kp = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    open(cp, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    return cp, kp


def _listen():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(4)
    return s, s.getsockname()[1]


def _head(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = conn.recv(4096)
        if not d:
            break
        buf += d
    lines = buf.split(b"\r\n\r\n")[0].decode().split("\r\n")
    return lines[0], {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}


@pytest.fixture
def tls_origin(tmp_path):
    cp, kp = _cert(str(tmp_path))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    seen = {}
    ctx.sni_callback = lambda sock, name, c: seen.__setitem__("sni", name)
    srv, port = _listen()

    def run():
        c, _ = srv.accept()
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                seen["request"] = _head(t)
                t.sendall(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except (ssl.SSLError, OSError):
            seen["tls_error"] = True                    # the client refused our certificate (expected in one test)
    threading.Thread(target=run, daemon=True).start()
    client = ssl.create_default_context(cafile=cp)
    yield port, seen, client
    srv.close()


@pytest.fixture
def proxy():
    """A minimal forward proxy that records what it is asked, and connects ONLY to the CONNECT target given."""
    srv, port = _listen()
    seen = []

    def pipe(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        finally:
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(c):
        line, hdrs = _head(c)
        seen.append((line, hdrs))
        if line.startswith("CONNECT "):
            hp = line.split()[1]
            ip, p = hp.rsplit(":", 1)
            up = socket.create_connection((ip, int(p)), timeout=5)
            c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            threading.Thread(target=pipe, args=(up, c), daemon=True).start()
            pipe(c, up)
        else:
            c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            c.close()

    def run():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=run, daemon=True).start()
    yield "http://127.0.0.1:%d" % port, seen
    srv.close()


def test_https_connect_targets_pinned_ip_and_tags_execution(proxy, tls_origin):
    purl, seen = proxy
    port, origin, client_ctx = tls_origin
    eid = str(uuid.uuid4())
    st, loc = netguard._proxied_request("GET", "https://%s:%d/v1/x?q=1" % (HOST, port), HOST, "127.0.0.1", purl, eid, 5,
                                        ssl_context=client_ctx)
    assert (st, loc) == (302, "/next")
    line, hdrs = seen[0]
    assert line == "CONNECT 127.0.0.1:%d HTTP/1.1" % port                  # the pinned IP, never the name
    assert hdrs["x-qyrix-execution"] == eid and hdrs["x-qyrix-host"] == HOST
    assert origin["sni"] == HOST                                            # TLS name = host (cert verified for it)
    assert origin["request"][0] == "GET /v1/x?q=1 HTTP/1.1" and origin["request"][1]["host"] == HOST
    assert "x-qyrix-execution" not in origin["request"][1]                  # tags stay on the CONNECT, not in TLS


def test_https_certificate_still_verified_through_tunnel(proxy, tls_origin):
    purl, _ = proxy
    port, _, _ = tls_origin
    with pytest.raises(ssl.SSLError):                                       # default trust store: self-signed refused
        netguard._proxied_request("GET", "https://%s:%d/" % (HOST, port), HOST, "127.0.0.1", purl, str(uuid.uuid4()), 5)


def test_plain_http_through_proxy_carries_tags_and_pinned_ip(proxy):
    purl, seen = proxy
    eid = str(uuid.uuid4())
    assert netguard._proxied_request("POST", "http://%s:8080/a" % HOST, HOST, "203.0.113.9", purl, eid, 5) == (204, None)
    line, hdrs = seen[0]
    assert line == "POST http://203.0.113.9:8080/a HTTP/1.1"
    assert hdrs["host"] == HOST and hdrs["x-qyrix-execution"] == eid and hdrs["x-qyrix-host"] == HOST


@pytest.mark.parametrize("host,eid,purl", [
    ("api.example.com\r\nX-Evil: 1", str(uuid.uuid4()), "http://127.0.0.1:1"),
    (HOST, "not-a-uuid\r\nX: y", "http://127.0.0.1:1"),
    (HOST, str(uuid.uuid4()), "https://127.0.0.1:1"),
    (HOST, str(uuid.uuid4()), "socks5://127.0.0.1:1"),
])
def test_tagging_input_validation(host, eid, purl):
    with pytest.raises(netguard.NetguardError):
        netguard._proxied_request("GET", "https://%s/" % HOST, host, "127.0.0.1", purl, eid, 1)


def test_without_proxy_the_direct_pinned_path_is_unchanged(monkeypatch):
    monkeypatch.setattr(netguard, "_proxied_request", lambda *a, **k: pytest.fail("proxy used without configuration"))
    calls = []

    class FakeClient:
        def __init__(self, **kw):
            calls.append(kw)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def request(self, method, target, headers, extensions):
            calls.append((method, target, headers, extensions))
            return type("R", (), {"status_code": 200, "headers": {}})()
    monkeypatch.setattr(netguard.httpx, "Client", FakeClient)
    assert netguard.pinned_request_full("GET", "https://%s/x" % HOST, HOST, "203.0.113.5") == (200, None)
    assert calls[1] == ("GET", "https://203.0.113.5/x", {"Host": HOST}, {"sni_hostname": HOST})
    assert calls[0]["trust_env"] is False


def test_http_adapter_passes_proxy_and_current_execution_id(monkeypatch):
    got = {}
    monkeypatch.setenv("QYRIX_EGRESS_PROXY_URL", "http://observer-proxy:3128")
    monkeypatch.setattr(netguard, "check_http_dest",
                        lambda d, a: type("C", (), {"ok": True, "host": HOST, "url": "https://%s/x" % HOST})())
    monkeypatch.setattr(netguard, "resolve_public", lambda h: ["203.0.113.5"])
    monkeypatch.setattr(netguard, "pinned_request_full", lambda *a, **k: got.update(args=a, **k) or (200, None))
    eid = str(uuid.uuid4())
    tok = adapters.EXECUTION_ID.set(eid)
    try:
        adapters.HttpAdapter(lambda: (HOST,))({"dest": "https://%s/x" % HOST, "method": "GET"})
    finally:
        adapters.EXECUTION_ID.reset(tok)
    assert got["proxy"] == "http://observer-proxy:3128" and got["execution_id"] == eid and got["args"][3] == "203.0.113.5"


def test_execute_grant_exposes_execution_id_only_during_execution(tmp_path):
    seen = []

    class Rec:
        name = "file.read"

        def __call__(self, params):
            seen.append(adapters.EXECUTION_ID.get())
            return {"bytes": 0}
    ws = tmp_path / "ws"; ws.mkdir(); (ws / "README.md").write_text("x")
    ctx = g.GateContext("t-exec", prov.ProvenanceStore(), None, lambda: (HOST,), {"file.read": Rec()}, str(ws))
    t = ctx.prov.add_step("ticket", "TRUSTED", "read")
    r = g.evaluate(g.Action(tool="file.read", dest="README.md", lineage=[t["id"]]), ctx)
    assert r["verdict"] == "ALLOW"
    g.execute_grant({"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}, ctx)
    assert seen == [ctx.grants[r["grant_id"]]["execution_id"]] and uuid.UUID(seen[0]).version == 4
    assert adapters.EXECUTION_ID.get() is None


def test_memory_mode_emits_nothing_even_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv("QYRIX_OBSERVER_URL", "http://observer.test")
    ctx = g.GateContext("t-mem", prov.ProvenanceStore(), None, lambda: (HOST,), {}, str(tmp_path))
    assert observer_feed.decision_events(ctx, {"id": "x", "verdict": "BLOCK"}) == []
    assert observer_feed.consume_event(ctx, "x", {"id": "g"}, "executed") is None


# ---------------- MCP proxy adapter reports (E1) ----------------
class _Capture:
    def __init__(self):
        self.posts = []

    def post(self, path, content, headers):
        self.posts.append((path, content))
        return type("R", (), {"status_code": 200})()


def _observer_for(keys):
    from observer.ingest import Observer
    return Observer(None, keys.manifest(), keys.observer)


def test_adapter_report_is_signed_e1_and_accepted_only_as_adapter_report():
    from observer.envelope import Refused, parse
    from tests.observer_support import Keys
    keys = Keys()
    cap = _Capture()
    rep = observer_feed.AdapterReporter("http://observer.test", keys.adapter, "mcp_proxy", "default", http=cap)
    env = rep.report("corr-1", True, str(uuid.uuid4()), wait=True)
    assert cap.posts[0][0] == "/v1/events" and env["type"] == "adapter_report" and env["seq"] is None
    obs = _observer_for(keys)
    p = parse(cap.posts[0][1])
    key = obs._authenticate(p)                                              # signature, scope, tenant all valid
    assert key.scopes == {"adapter_report"}
    forged = dict(p, type="decision", seq=1)                                # cannot be re-labelled as a decision
    with pytest.raises(Refused):
        obs._authenticate(forged)


def test_mcp_proxy_reports_forwarded_and_blocked_without_affecting_calls(tmp_path):
    from tests.observer_support import Keys
    from tests.test_mcp_proxy import Harness
    keys = Keys()
    exe = str(uuid.uuid4())

    class Stub:
        verdict = "ALLOW"

        def evaluate(self, action):
            return {"verdict": self.verdict, "grant_id": "grt_x" if self.verdict == "ALLOW" else None,
                    "gate_evaluation_id": str(uuid.uuid4()), "params_digest": "d" * 64, "rules": [] if self.verdict == "ALLOW" else ["R1_DEST_NOT_APPROVED"]}

        def redeem(self, d, corr, task=None):
            return {"redeemed": True, "execution_id": exe}
    stub = Stub()
    h = Harness(tmp_path, sentinel=stub)
    cap = _Capture()
    h.proxy.reporter = observer_feed.AdapterReporter("http://observer.test", keys.adapter, http=cap)
    try:
        r = h.call(1, "echo", {"url": "https://api.example.com/x"})
        assert r and "result" in r and not r["result"].get("isError")
        stub.verdict = "BLOCK"
        r = h.call(2, "echo", {"url": "https://evil.example.net/x"})
        assert r["result"]["isError"]
        end = time.time() + 5
        while len(cap.posts) < 2 and time.time() < end:
            time.sleep(0.05)
        import json
        bodies = sorted((json.loads(c)["body"] for _, c in cap.posts), key=lambda b: not b["claims"]["forwarded"])
        assert bodies[0]["claims"] == {"forwarded": True} and bodies[0]["execution_id"] == exe
        assert bodies[1]["claims"] == {"forwarded": False} and bodies[1]["execution_id"] is None
    finally:
        h.proxy.close()


def test_mcp_proxy_report_failure_never_blocks_a_call(tmp_path):
    from tests.observer_support import Keys
    from tests.test_mcp_proxy import Harness

    class Boom:
        def report(self, *a, **k):
            raise RuntimeError("observer down")

    class Stub:
        def evaluate(self, action):
            return {"verdict": "ALLOW", "grant_id": "g", "gate_evaluation_id": "e", "params_digest": "d", "rules": []}

        def redeem(self, d, corr, task=None):
            return {"redeemed": True}
    h = Harness(tmp_path, sentinel=Stub())
    h.proxy.reporter = Boom()
    try:
        r = h.call(1, "echo", {"url": "https://api.example.com/x"})
        assert r and not r["result"].get("isError")
    finally:
        h.proxy.close()
