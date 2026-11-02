"""Monitoring & alerting (Phase H): detection rules, de-duplication, signed webhook boundary, secret-free payloads."""
import hashlib, hmac, io, json, logging, time
import pytest
from fastapi.testclient import TestClient

from app import alerts, identity, observability as obs
from app.main import app
from tests.conftest import ADMIN

P = "/api/v1/sentinel"
admin = TestClient(app, headers=ADMIN)


@pytest.fixture(autouse=True)
def fresh(monkeypatch):
    alerts.reset_for_tests(); obs.reset_for_tests(); identity.limiter.clear()
    monkeypatch.delenv("QYRIX_ALERT_WEBHOOK_URL", raising=False)
    admin.post(P + "/reset")
    yield
    alerts.reset_for_tests(); identity.limiter.clear()


def names():
    return [a["alert"] for a in alerts.recent]


def test_repeated_execution_blocks_alert_once_per_window(monkeypatch):
    monkeypatch.setenv("QYRIX_ALERT_BLOCKS_PER_5MIN", "5")
    for _ in range(12):
        r = admin.post(P + "/gate/evaluate", json={"tool": "http", "method": "POST", "dest": "https://evil.example.net/x"}).json()
        assert r["verdict"] == "BLOCK"
    assert names().count("repeated_execution_blocks") == 1                 # de-duplicated, not 8 alerts
    a = next(x for x in alerts.recent if x["alert"] == "repeated_execution_blocks")
    assert a["tenant"] == "default" and a["severity"] == "high" and a["count"] == 5


def test_repeated_refused_executions_alert(monkeypatch):
    monkeypatch.setenv("QYRIX_ALERT_REFUSALS_PER_5MIN", "3")
    for i in range(4):
        admin.post("/api/v1/tools/execute", json={"gate_evaluation_id": "00000000-0000-4000-8000-00000000000%d" % i, "grant_id": "grt_x"})
    assert "repeated_execution_refusals" in names()


def test_authentication_spike_alert(monkeypatch):
    monkeypatch.setenv("QYRIX_ALERT_AUTH_FAILURES_PER_5MIN", "4")
    for _ in range(5):
        TestClient(app, headers={"Authorization": "Bearer qsk_guess"}).get(P + "/status")
    assert "auth_failure_spike" in names()


@pytest.mark.parametrize("kind,sev", [("tenant_isolation_violation", "critical"), ("db_privilege_violation", "critical"),
                                      ("data_integrity_failure", "critical"), ("proof_integrity_failure", "critical"),
                                      ("rate_limit_backend_unavailable", "critical"), ("persistence_unavailable", "high")])
def test_never_expected_events_alert_immediately(kind, sev):
    obs.event(kind, severity=sev, tenant="acme", reason="TEST")
    a = alerts.recent[-1]
    assert a["alert"] == kind and a["severity"] == sev and a["tenant"] == "acme" and a["count"] == 1


def test_proof_chain_tampering_raises_a_critical_alert(tmp_path):
    import app.gateway as g
    from app import provenance as prov
    f = tmp_path / "c.jsonl"
    ctx = g.GateContext("t", prov.ProvenanceStore(), str(f), lambda: (), {}, None)
    g._record(ctx, {"kind": "gate_decision", "verdict": "BLOCK", "rule_ids": [], "tool": "http", "ext_calls": 0})
    rec = json.loads(f.read_text()); rec["verdict"] = "ALLOW"; f.write_text(json.dumps(rec) + "\n")
    ctx2 = g.GateContext("t", prov.ProvenanceStore(), str(f), lambda: (), {}, None)
    g._load_chain(ctx2)
    assert ctx2.state["degraded"] and names()[-1] == "proof_integrity_failure"


def test_webhook_is_signed_and_carries_no_secrets(monkeypatch, tmp_path):
    sent = []
    key = tmp_path / "alert.key"; key.write_text("a" * 40)
    monkeypatch.setenv("QYRIX_ALERT_WEBHOOK_URL", "https://alerts.internal/hook")
    monkeypatch.setenv("QYRIX_ALERT_WEBHOOK_SECRET_FILE", str(key))
    monkeypatch.setattr(alerts, "_transport", lambda url, body, headers: (sent.append((body, headers)), 204)[1])
    obs.event("tenant_isolation_violation", severity="critical", tenant="acme", reason="query qsk_abcdefghijklmnopqrstuvwxyz leaked",
              token="qss_" + "z" * 40, data="api_key=SYNTHETIC-NOT-A-KEY")
    for _ in range(50):
        if sent:
            break
        time.sleep(0.05)
    body, headers = sent[0]
    assert headers["x-qyrix-signature"] == hmac.new(b"a" * 40, body, hashlib.sha256).hexdigest()
    text = body.decode()
    assert "qsk_abcdefghijklmnopqrstuvwxyz" not in text and "qss_" not in text and "SYNTHETIC-NOT-A-KEY" not in text
    assert json.loads(text)["alert"] == "tenant_isolation_violation"


def test_slow_alert_receiver_never_blocks_requests(monkeypatch, tmp_path):
    key = tmp_path / "alert.key"; key.write_text("a" * 40)
    monkeypatch.setenv("QYRIX_ALERT_WEBHOOK_URL", "https://alerts.internal/hook")
    monkeypatch.setenv("QYRIX_ALERT_WEBHOOK_SECRET_FILE", str(key))
    monkeypatch.setattr(alerts, "_transport", lambda *a: time.sleep(5) or 200)
    t0 = time.time()
    obs.event("db_privilege_violation", severity="critical", problems="superuser")
    assert time.time() - t0 < 0.5


def test_event_values_are_scrubbed_even_in_allowed_fields():
    buf = io.StringIO(); h = logging.StreamHandler(buf); logging.getLogger("qyrix.security").addHandler(h)
    try:
        # fake values built at runtime so no credential-shaped literal sits in source (secret scanners)
        fake_bearer, fake_key = "abcdefgh" + "ijklmnop123", "sk-" + "live-" + "1234567890abcdef"
        fake_reset, fake_age = "qpr" + "_0123456789abcdef", "AGE-SECRET" + "-KEY-1" + "Q" * 12
        obs.event("custom", reason="Authorization: Bearer " + fake_bearer, note="api_key=" + fake_key,
                  detail=[fake_reset, {"inner": fake_age}], code="123456", email="a@b.example")
    finally:
        logging.getLogger("qyrix.security").removeHandler(h)
    out = buf.getvalue()
    for s in (fake_bearer, fake_key, fake_reset, fake_age, "123456", "a@b.example"):
        assert s not in out, s
    assert "[REDACTED]" in out


def test_alerts_are_exported_as_metrics(monkeypatch):
    monkeypatch.setenv("QYRIX_METRICS_TOKEN", "metrics-token-for-tests-0123456789")
    obs.event("data_integrity_failure", severity="critical", tenant="default", reason="TEST")
    m = TestClient(app, headers={"Authorization": "Bearer metrics-token-for-tests-0123456789"}).get("/api/v1/metrics").text
    assert "qyrix_alert_engine_errors_total" not in m
    assert 'qyrix_alerts_total{alert="data_integrity_failure",severity="critical"} 1.0' in m
