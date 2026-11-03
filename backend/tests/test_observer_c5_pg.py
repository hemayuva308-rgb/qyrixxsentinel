"""C5 sensors and coverage on REAL PostgreSQL with REAL sockets (loopback): egress proxy (CONNECT lifecycle, pinned-IP
+ resolution check, SNI peek, execution-id reuse, T_tunnel, plain HTTP, fail-closed recording), DNS forwarder, sink,
signed coverage attestation judged by the observer, and ENFORCEMENT_VERIFIED only with every condition."""
import datetime
import json
import os
import socket
import ssl
import threading
import time
import uuid

import psycopg
import pytest

from observer import canary as oc
from observer.coverage import CoverageService, attestation_skeleton, sign_attestation, REQUIRED_ATTESTOR_CHECKS
from observer.db import Database
from observer.egress import DnsForwarder, EgressProxy, Recorder, Sink, new_token, parse_sni
from observer.feed import Config
from tests.observer_support import HAVE_PG, Keys, ObserverCluster, envelope, heartbeat, make_observer, raw

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")
HOST = "api.example.com"


@pytest.fixture(scope="module")
def cluster():
    c = ObserverCluster()
    yield c
    c.destroy()


@pytest.fixture
def ob(cluster):
    url, admin = cluster.new_db()
    keys = Keys()
    obs = make_observer(url, keys, time.time, cfg=Config(W=0.5, T_decision=1.0))
    rec = Recorder(obs)
    proxy = EgressProxy(rec, "127.0.0.1", 0, lambda h: {HOST: ["127.0.0.1"], "sink.test": ["127.0.0.1"]}.get(h, []),
                        ["127.0.0.0/8"])
    yield {"obs": obs, "admin": admin, "url": url, "keys": keys, "rec": rec, "proxy": proxy}
    proxy.close()


def q(admin, sql, p=()):
    with psycopg.connect(admin, autocommit=True) as c:
        cur = c.execute(sql, p)
        return cur.fetchall() if cur.description else None


def _tls_server(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    k = ec.generate_private_key(ec.SECP256R1())
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
         .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(hours=1))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False).sign(k, hashes.SHA256()))
    cp, kp = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    open(cp, "wb").write(c.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(cp, kp)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(8)

    def run():
        while True:
            try:
                cn, _ = s.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(cn, server_side=True) as t:
                    t.recv(100); t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (ssl.SSLError, OSError):
                pass
    threading.Thread(target=run, daemon=True).start()
    return s, s.getsockname()[1]


def connect(proxy, ip, port, xhost=HOST, xexec=None):
    s = socket.create_connection(("127.0.0.1", proxy.port), timeout=5)
    h = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n" % (ip, port, ip, port)
    if xhost:
        h += "X-Qyrix-Host: %s\r\n" % xhost
    if xexec:
        h += "X-Qyrix-Execution: %s\r\n" % xexec
    s.sendall((h + "\r\n").encode())
    resp = s.recv(200)
    return s, resp


def tls_through(s, sni):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    t = ctx.wrap_socket(s, server_hostname=sni)
    t.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    data = t.recv(100)
    t.close()
    return data


def rows(ob, kind=None):
    sql = "SELECT kind, host, sni, dest_ip, execution_id::text, reason, bytes_in, bytes_out FROM egress_observations"
    return q(ob["admin"], sql + (" WHERE kind=%s ORDER BY observed_at" if kind else " ORDER BY observed_at"), (kind,) if kind else ())


def wait_rows(ob, kind, n, t=5.0):
    end = time.time() + t
    while time.time() < end:
        r = rows(ob, kind)
        if len(r) >= n:
            return r
        time.sleep(0.05)
    return rows(ob, kind)


# ---------------- egress proxy ----------------
def test_connect_tunnel_lifecycle_with_sni(ob, tmp_path):
    srv, port = _tls_server(tmp_path)
    eid = str(uuid.uuid4())
    s, resp = connect(ob["proxy"], "127.0.0.1", port, xexec=eid)
    assert resp.startswith(b"HTTP/1.1 200")
    assert b"ok" in tls_through(s, HOST)
    o = wait_rows(ob, "tunnel_open", 1); c = wait_rows(ob, "tunnel_close", 1)
    assert o[0][:5] == ("tunnel_open", HOST, None, "127.0.0.1", eid)
    assert c[0][1:5] == (HOST, HOST, "127.0.0.1", eid) and c[0][6] > 0 and c[0][7] > 0
    srv.close()


def test_sni_mismatch_is_refused(ob, tmp_path):
    srv, port = _tls_server(tmp_path)
    eid = str(uuid.uuid4())
    s, resp = connect(ob["proxy"], "127.0.0.1", port, xexec=eid)
    with pytest.raises((ssl.SSLError, OSError)):
        tls_through(s, "other.example")                                   # domain fronting attempt
    r = wait_rows(ob, "refused", 1)
    assert r[0][5] == "SNI_MISMATCH" and r[0][2] == "other.example" and r[0][4] == eid
    srv.close()


def test_pinned_ip_must_be_in_observer_resolution(ob):
    s, resp = connect(ob["proxy"], "127.0.0.2", 443)
    assert resp.startswith(b"HTTP/1.1 403")
    assert rows(ob, "refused")[0][5] == "IP_NOT_IN_HOST_RESOLUTION"


def test_tagged_connect_must_use_pinned_ip_and_valid_tags(ob):
    for target, xhost, xexec, why in ((HOST, HOST, None, "TAGGED_CONNECT_MUST_USE_PINNED_IP"),
                                      ("127.0.0.1", "BAD HOST", None, "INVALID_X_QYRIX_HOST"),
                                      ("127.0.0.1", HOST, "not-uuid", "INVALID_X_QYRIX_EXECUTION"),
                                      ("127.0.0.1", None, str(uuid.uuid4()), "EXECUTION_WITHOUT_HOST")):
        s, resp = connect(ob["proxy"], target, 443, xhost, xexec)
        assert resp.startswith((b"HTTP/1.1 400", b"HTTP/1.1 403")), why
    assert {r[5] for r in rows(ob, "refused")} == {"TAGGED_CONNECT_MUST_USE_PINNED_IP", "INVALID_X_QYRIX_HOST",
                                                   "INVALID_X_QYRIX_EXECUTION", "EXECUTION_WITHOUT_HOST"}


def test_private_destination_refused_without_allow_list(ob):
    p = EgressProxy(ob["rec"], "127.0.0.1", 0, lambda h: ["127.0.0.1"])     # no allowed CIDRs
    try:
        s, resp = connect(p, "127.0.0.1", 443)
        assert resp.startswith(b"HTTP/1.1 403") and rows(ob, "refused")[0][5] == "DESTINATION_NOT_ALLOWED"
    finally:
        p.close()


def test_execution_id_reuse_is_refused_by_the_database(ob, tmp_path):
    srv, port = _tls_server(tmp_path)
    eid = str(uuid.uuid4())
    s1, r1 = connect(ob["proxy"], "127.0.0.1", port, xexec=eid)
    s2, r2 = connect(ob["proxy"], "127.0.0.1", port, xexec=eid)
    assert r1.startswith(b"HTTP/1.1 200") and r2.startswith(b"HTTP/1.1 403")
    assert "EXECUTION_ID_REUSE" in {r[5] for r in rows(ob, "refused")}
    assert q(ob["admin"], "SELECT count(*) FROM ledger WHERE code='EXECUTION_ID_REUSE'") == [(1,)]
    s1.close(); srv.close()


def test_tunnel_lifetime_is_bounded(ob, tmp_path):
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(2); port = srv.getsockname()[1]
    held = []
    threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()   # upstream that never closes
    p = EgressProxy(ob["rec"], "127.0.0.1", 0, lambda h: ["127.0.0.1"], ["127.0.0.0/8"], t_tunnel=1.0)
    try:
        s, _ = connect(p, "127.0.0.1", port, xhost=None)                    # untagged: no SNI requirement
        s.sendall(b"\x16\x03\x01\x00\x05hello")                             # idle afterwards
        r = wait_rows(ob, "tunnel_close", 1, 5)
        assert r[0][5] == "T_TUNNEL_EXPIRED"
    finally:
        p.close(); srv.close()


def test_plain_http_is_request_level_and_tags_are_stripped(ob):
    got = {}
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(2)

    def run():
        c, _ = srv.accept()
        got["req"] = c.recv(4096)
        c.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"); c.close()
    threading.Thread(target=run, daemon=True).start()
    eid = str(uuid.uuid4())
    s = socket.create_connection(("127.0.0.1", ob["proxy"].port))
    s.sendall(("GET http://127.0.0.1:%d/v1/x?q=1 HTTP/1.1\r\nHost: %s\r\nX-Qyrix-Host: %s\r\nX-Qyrix-Execution: %s\r\n"
               "Proxy-Authorization: x\r\n\r\n" % (srv.getsockname()[1], HOST, HOST, eid)).encode())
    assert s.recv(100).startswith(b"HTTP/1.1 204")
    assert got["req"].startswith(b"GET /v1/x?q=1 HTTP/1.1") and b"X-Qyrix" not in got["req"] and b"Proxy-" not in got["req"]
    assert rows(ob, "http_request")[0][:5] == ("http_request", HOST, None, "127.0.0.1", eid)
    srv.close()


def test_proxy_fails_closed_when_it_cannot_record(ob, cluster):
    from observer.ingest import Observer
    dead = Observer(Database("postgresql://observer_runtime@127.0.0.1:1/none", timeout=1), ob["keys"].manifest(),
                    ob["keys"].observer, Config(), time.time)
    p = EgressProxy(Recorder(dead), "127.0.0.1", 0, lambda h: ["127.0.0.1"], ["127.0.0.0/8"])
    try:
        s, resp = connect(p, "127.0.0.1", 9)
        assert resp.startswith(b"HTTP/1.1 503")                             # no evidence => no egress
    finally:
        p.close()


def test_parse_sni_handles_garbage():
    assert parse_sni(b"") is None and parse_sni(b"\x16\x03\x01\x00\x02\x01\x00") is None and parse_sni(b"GET /") is None


# ---------------- DNS forwarder + sink ----------------
def test_dns_forwarder_records_and_relays(ob):
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); up.bind(("127.0.0.1", 0))

    def answer():
        d, a = up.recvfrom(512); up.sendto(d[:2] + b"\x81\x80" + d[4:], a)
    threading.Thread(target=answer, daemon=True).start()
    f = DnsForwarder(ob["rec"], "127.0.0.1", 0, up.getsockname())
    try:
        qname = "%s.dnscheck.qyrix.invalid" % new_token()
        pkt = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
            bytes([len(l)]) + l.encode() for l in qname.split(".")) + b"\x00\x00\x01\x00\x01"
        c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.settimeout(3)
        c.sendto(pkt, (f.host, f.port))
        assert c.recvfrom(512)[0][:2] == b"\x12\x34"
        assert q(ob["admin"], "SELECT qname, qtype FROM egress_observations WHERE kind='dns_query'") == [(qname, 1)]
    finally:
        f.close(); up.close()


def test_sink_records_token_hashes_only(ob):
    import hashlib
    sk = Sink(ob["rec"], "127.0.0.1", tcp_ports=(0,), udp_port=0)
    try:
        tok = new_token()
        s = socket.create_connection(("127.0.0.1", sk.ports[0])); s.sendall(b"QXTOK qxtok-" + tok.encode()); s.recv(10); s.close()
        r = wait_rows(ob, "sink_hit", 1)
        got = q(ob["admin"], "SELECT token_sha256 FROM egress_observations WHERE kind='sink_hit'")
        assert got == [(hashlib.sha256(tok.encode()).hexdigest(),)] and tok not in json.dumps(r, default=str)
    finally:
        sk.close()


# ---------------- coverage attestation ----------------
def _evidence(ob, sink_port, dns_name=None, send_direct=False):
    """Produce the network evidence a real attestor run would produce, through the REAL proxy / sink."""
    import hashlib
    toks = {n: new_token() for n in ("ipv4_tcp_80", "ipv4_tcp_443", "ipv4_tcp_853", "dns_udp_direct")}
    pc, pce, sme = new_token(), str(uuid.uuid4()), str(uuid.uuid4())
    s = socket.create_connection(("127.0.0.1", ob["proxy"].port))
    s.sendall(("GET http://127.0.0.1:%d/qxtok/%s HTTP/1.1\r\nHost: sink.test\r\nX-Qyrix-Host: sink.test\r\n"
               "X-Qyrix-Execution: %s\r\n\r\n" % (sink_port, pc, pce)).encode())
    s.recv(100); s.close()
    s, _ = connect(ob["proxy"], "127.0.0.1", sink_port, xhost="sink.test", xexec=sme)
    try:
        tls_through(s, "fronted.example")
    except (ssl.SSLError, OSError):
        pass
    if send_direct:                                                        # a bypass route exists
        d = socket.create_connection(("127.0.0.1", sink_port)); d.sendall(b"qxtok-" + toks["ipv4_tcp_443"].encode()); d.close()
    if dns_name:
        f = DnsForwarder(ob["rec"], "127.0.0.1", 0, ("127.0.0.1", 9))
        pkt = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"".join(
            bytes([len(l)]) + l.encode() for l in dns_name.split(".")) + b"\x00\x00\x01\x00\x01"
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(pkt, (f.host, f.port))
        time.sleep(0.3); f.close()
    time.sleep(0.5)
    h = lambda t: hashlib.sha256(t.encode()).hexdigest()
    return {**{n: {"token_sha256": h(t)} for n, t in toks.items()},
            "positive_control": {"token_sha256": h(pc), "execution_id": pce},
            "sni_mismatch": {"execution_id": sme}, "dns_mediated": {"qname": dns_name or ""}}


def _checks(**over):
    return {**{c: True for c in REQUIRED_ATTESTOR_CHECKS}, **over}


@pytest.fixture
def sink(ob):
    sk = Sink(ob["rec"], "127.0.0.1", tcp_ports=(0,), udp_port=0)
    yield sk
    sk.close()


def test_valid_attestation_judged_by_observer(ob, sink):
    cov = CoverageService(ob["obs"])
    name = "%s.dnscheck.qyrix.invalid" % new_token()
    doc = sign_attestation(attestation_skeleton("abc123def456", "img", _checks(), _evidence(ob, sink.ports[0], name)),
                           ob["keys"].attestor)
    r = cov.submit(doc)
    assert r["valid"] and r["reasons"] == [] and all(r["observer_checks"].values())
    assert cov.current(time.time(), time.time() + 60, "abc123def456")["attestation_id"] == r["attestation_id"]
    assert cov.current(time.time(), time.time() + 60, "ffffffffffff") is None           # container moved => stale
    assert cov.current(time.time(), time.time() + 7200, None) is None                   # beyond validity


@pytest.mark.parametrize("variant", ["direct_path_open", "attestor_check_failed", "no_dns", "stale"])
def test_invalid_attestations_never_give_coverage(ob, sink, variant):
    cov = CoverageService(ob["obs"])
    name = None if variant == "no_dns" else "%s.dnscheck.qyrix.invalid" % new_token()
    probes = _evidence(ob, sink.ports[0], name, send_direct=variant == "direct_path_open")
    checks = _checks(no_default_route=False) if variant == "attestor_check_failed" else _checks()
    at = time.time() - 600 if variant == "stale" else None
    r = cov.submit(sign_attestation(attestation_skeleton("abc123def456", "img", checks, probes, now=at), ob["keys"].attestor))
    assert r["stored"] and r["valid"] is False and r["reasons"]
    assert cov.current(time.time(), time.time(), None) is None
    assert q(ob["admin"], "SELECT count(*) FROM ledger WHERE code='COVERAGE_GAP'") == [(1,)]


def test_attestation_signature_key_and_validity(ob, sink):
    cov = CoverageService(ob["obs"])
    probes = _evidence(ob, sink.ports[0])
    assert cov.submit(sign_attestation(attestation_skeleton("c", "i", _checks(), probes), ob["keys"].gate))["error"] == "SIGNATURE_INVALID"
    d = sign_attestation(attestation_skeleton("c", "i", _checks(), probes), ob["keys"].attestor)
    d["attestor_checks"]["no_default_route"] = False                     # tampered after signing
    assert cov.submit(d)["error"] == "SIGNATURE_INVALID"
    long = sign_attestation(attestation_skeleton("c", "i", _checks(), probes, validity=7200), ob["keys"].attestor)
    assert cov.submit(long)["error"] == "VALIDITY_INVALID"
    assert q(ob["admin"], "SELECT count(*) FROM coverage_attestations") == [(0,)]


def test_gap_alert_when_no_coverage(ob):
    cov = CoverageService(ob["obs"])
    assert cov.tick() == "COVERAGE_GAP" and cov.tick() is None            # once per gap


def test_o004_tables_are_append_only_and_verified_needs_coverage(ob):
    with psycopg.connect(ob["url"], autocommit=True) as c:
        for sql in ("UPDATE egress_observations SET reason='x'", "DELETE FROM coverage_attestations",
                    "TRUNCATE egress_observations"):
            with pytest.raises(psycopg.Error):
                c.execute(sql)


# ---------------- ENFORCEMENT_VERIFIED end to end ----------------
def _run_canary(ob, svc, cov_doc=None, tunnel=False, claim_cid=None):
    from tests.test_observer_canary_pg import FakeBackend
    from observer.canary import P2Client
    tf = os.path.join("/tmp", "qx-cred-%s" % uuid.uuid4().hex); open(tf, "w").write("t")
    svc.p2 = P2Client({"default": {"key_id": "k", "token_file": tf}}, FakeBackend("block"), live=True)
    r = svc.start("default")
    k = ob["keys"]
    body = {"gate_evaluation_id": str(uuid.uuid4()), "correlation_id": r["correlation_id"], "verdict": "BLOCK", "rule_ids": []}
    ob["obs"].ingest(raw(envelope(k.gate, k.gate_pid, "decision", body, seq=1, issued=time.time())))
    if tunnel:
        connect(ob["proxy"], "127.0.0.1", svc.http.port, xhost=None)
    time.sleep(1.3)
    svc.tick()
    hb = heartbeat(k, 1, {"default": {"allocated_through_seq": 1}}, issued=time.time())
    if claim_cid:
        hb["body"]["container_id"] = claim_cid
        from observer import crypto
        from observer.canonical import canonical
        hb["sig"] = crypto.sign(k.gate, canonical({x: y for x, y in hb.items() if x != "sig"}))
    ob["obs"].ingest(raw(hb))
    time.sleep(0.1)
    svc.tick()
    return q(ob["admin"], "SELECT version, result, reasons FROM reconciliations WHERE run_id=%s ORDER BY version", (r["run_id"],))


@pytest.mark.parametrize("case", ["verified", "no_attestation", "tunnel_to_canary_host", "container_moved"])
def test_enforcement_verified_only_with_every_condition(ob, sink, case):
    svc = oc.CanaryService(ob["obs"])
    svc.http = oc.HttpCanarySensor(svc.record)
    svc.coverage = CoverageService(ob["obs"])
    try:
        if case != "no_attestation":
            name = "%s.dnscheck.qyrix.invalid" % new_token()
            assert svc.coverage.submit(sign_attestation(attestation_skeleton(
                "abc123def456", "img", _checks(), _evidence(ob, sink.ports[0], name)), ob["keys"].attestor))["valid"]
        res = _run_canary(ob, svc, tunnel=case == "tunnel_to_canary_host",
                          claim_cid="ffffffffffff" if case == "container_moved" else "abc123def456")
        last = res[-1]
        if case == "verified":
            assert last[1:] == ("ENFORCEMENT_VERIFIED", [])
            f = q(ob["admin"], "SELECT facts->'coverage'->>'attestation_id', evidence_level FROM reconciliations"
                               " WHERE result='ENFORCEMENT_VERIFIED'")
            assert f[0][0] and f[0][1] == "E3"
        else:
            assert last[1] == "INCONCLUSIVE"
            assert {"no_attestation": "COVERAGE_UNATTESTED", "tunnel_to_canary_host": "TUNNEL_TO_CANARY_HOST",
                    "container_moved": "COVERAGE_UNATTESTED"}[case] in last[2]
    finally:
        svc.http.close()


def test_verified_row_without_attestation_is_refused_by_schema(ob):
    svc = oc.CanaryService(ob["obs"]); svc.http = oc.HttpCanarySensor(svc.record)
    try:
        r = svc.start("default")
        with psycopg.connect(ob["url"], autocommit=True) as c:
            c.execute("SELECT set_config('observer.tenant', 'default', false)")
            with pytest.raises(psycopg.Error):
                c.execute("INSERT INTO reconciliations (recon_id, run_id, tenant_id, version, result, reasons, evidence_level,"
                          " facts, decided_at, ledger_n, ledger_hash) VALUES (gen_random_uuid(), %s, 'default', 1,"
                          " 'ENFORCEMENT_VERIFIED', '{}', 'E3', '{}', now(), 1, repeat('0',64))", (r["run_id"],))
    finally:
        svc.http.close()
