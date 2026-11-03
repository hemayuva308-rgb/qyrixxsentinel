"""Audit F2: observer transport is mutual TLS. Real uvicorn TLS listener with REQUIRED client certificates."""
import socket
import ssl
import threading
import time

import httpx
import pytest

from app import observer_feed
from observer import tls
from observer.app import create_app


def _port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class _FakeObs:
    def ingest(self, raw):
        return 200, {"status": "accepted"}


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    ca, rogue = str(d / "ca"), str(d / "rogue")
    tls.make_ca(ca); tls.make_ca(rogue, "Rogue CA")
    tls.issue(ca, "observer", ["127.0.0.1", "localhost"], True, str(d / "srv"))
    tls.issue(ca, "backend", [], False, str(d / "cli"))
    tls.issue(rogue, "intruder", [], False, str(d / "bad"))
    return d


@pytest.fixture(scope="module")
def server(pki):
    import uvicorn
    port = _port()
    env = {"OBSERVER_TLS_CERT_FILE": str(pki / "srv" / "observer.crt"), "OBSERVER_TLS_KEY_FILE": str(pki / "srv" / "observer.key"),
           "OBSERVER_TLS_CLIENT_CA_FILE": str(pki / "ca" / "ca.crt")}
    srv = uvicorn.Server(uvicorn.Config(create_app(_FakeObs(), None), host="127.0.0.1", port=port, log_level="critical",
                                        **tls.server_settings(env, "0.0.0.0")))
    t = threading.Thread(target=srv.run, daemon=True); t.start()
    for _ in range(100):
        if srv.started:
            break
        time.sleep(0.05)
    yield "https://127.0.0.1:%d" % port
    srv.should_exit = True
    t.join(5)


def _client(monkeypatch, url, pki, cert="cli/backend", ca="ca"):
    monkeypatch.setenv("QYRIX_OBSERVER_CA_FILE", str(pki / ca / "ca.crt"))
    if cert:
        monkeypatch.setenv("QYRIX_OBSERVER_CLIENT_CERT_FILE", str(pki / (cert + ".crt")))
        monkeypatch.setenv("QYRIX_OBSERVER_CLIENT_KEY_FILE", str(pki / (cert + ".key")))
    return observer_feed.observer_client(url)


def test_mtls_with_valid_client_certificate(server, pki, monkeypatch):
    c = _client(monkeypatch, server, pki)
    assert c.get("/v1/health").json() == {"health": "ok"}
    assert c.post("/v1/events", content=b"{}").json() == {"status": "accepted"}


def test_client_without_certificate_is_rejected(server, pki):
    ctx = ssl.create_default_context(cafile=str(pki / "ca" / "ca.crt"))
    with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, ssl.SSLError)):
        httpx.Client(base_url=server, verify=ctx, trust_env=False).get("/v1/health")


def test_client_certificate_from_another_ca_is_rejected(server, pki, monkeypatch):
    c = _client(monkeypatch, server, pki, cert="bad/intruder")
    with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
        c.get("/v1/health")


def test_client_refuses_an_untrusted_observer(server, pki, monkeypatch):
    c = _client(monkeypatch, server, pki, ca="rogue")                # pinned CA does not match the server
    with pytest.raises(httpx.ConnectError):
        c.get("/v1/health")


def test_plain_http_to_non_loopback_and_incomplete_mtls_are_refused(monkeypatch):
    with pytest.raises(RuntimeError, match="plain HTTP"):
        observer_feed.observer_client("http://observer:9000")
    for v in ("QYRIX_OBSERVER_CA_FILE", "QYRIX_OBSERVER_CLIENT_CERT_FILE", "QYRIX_OBSERVER_CLIENT_KEY_FILE"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(RuntimeError, match="mTLS"):
        observer_feed.observer_client("https://observer:9000")
    with pytest.raises(RuntimeError):
        observer_feed.observer_client("ftp://observer")
    observer_feed.observer_client("http://127.0.0.1:9000")           # loopback development stays possible


def test_server_refuses_non_loopback_bind_without_mtls(pki):
    with pytest.raises(SystemExit, match="without mTLS"):
        tls.server_settings({}, "0.0.0.0")
    with pytest.raises(SystemExit, match="incomplete"):
        tls.server_settings({"OBSERVER_TLS_CERT_FILE": "x"}, "10.0.0.2")
    assert tls.server_settings({}, "127.0.0.1") == {}
    s = tls.server_settings({"OBSERVER_TLS_CERT_FILE": "c", "OBSERVER_TLS_KEY_FILE": "k", "OBSERVER_TLS_CLIENT_CA_FILE": "a"}, "10.0.0.2")
    assert s["ssl_cert_reqs"] == ssl.CERT_REQUIRED


def test_private_keys_are_owner_only(pki):
    import os, stat
    for p in ("ca/ca.key", "srv/observer.key", "cli/backend.key"):
        assert stat.S_IMODE(os.stat(pki / p).st_mode) == 0o600


def test_publisher_and_reporter_fail_closed_on_bad_transport(monkeypatch):
    from observer import crypto
    with pytest.raises(RuntimeError):
        observer_feed.AdapterReporter("http://observer:9000", crypto.generate())
