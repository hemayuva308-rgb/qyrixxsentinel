"""C5 hardening P2: bounded DNS anomaly MONITORING (alerts only; no prevention is claimed)."""
import secrets

from observer.egress import DnsMonitor


class Rec:
    def __init__(self):
        self.alerts, self.counters = [], {}

    def count(self, k):
        self.counters[k] = self.counters.get(k, 0) + 1

    def alert(self, code, detail, now):
        self.alerts.append(code)


def mon(**kw):
    t = {"now": 1000.0}
    r = Rec()
    return DnsMonitor(r, clock=lambda: t["now"], **kw), r, t


def test_normal_queries_raise_nothing():
    m, r, _ = mon()
    for q in ("api.example.com", "www.google.com", "pypi.org", "files.pythonhosted.org") * 20:
        assert m.observe("172.30.2.130", q) == []
    assert r.alerts == []


def test_query_rate_per_source():
    m, r, t = mon(rate_per_min=50)
    out = [m.observe("172.30.2.130", "api.example.com") for _ in range(60)]
    assert ["DNS_QUERY_RATE"] in out and "DNS_QUERY_RATE" in r.alerts
    t["now"] += 61
    assert m.observe("172.30.2.130", "api.example.com") == []           # window slides


def test_tunnelling_shaped_queries():
    m, r, _ = mon(subdomains_per_min=20)
    for i in range(30):                                                  # data encoded in subdomains of one zone
        m.observe("172.30.2.130", "%s.exfil.example" % secrets.token_hex(16))
    assert {"DNS_SUBDOMAIN_BURST", "DNS_HIGH_ENTROPY_LABEL"} <= set(r.alerts)
    assert "DNS_LONG_NAME" in m.observe("172.30.2.130", "a" * 60 + ".example.com")


def test_attestor_probe_zone_is_exempt():
    m, r, _ = mon()
    for _ in range(5):
        assert m.observe("172.30.2.130", "%s.dnscheck.qyrix.invalid" % secrets.token_hex(16)) == []


def test_memory_is_bounded():
    m, r, _ = mon(max_sources=10, max_zones=10, subdomains_per_min=5)
    for i in range(500):
        m.observe("10.0.%d.%d" % (i // 250, i % 250), "x%d.zone%d.example" % (i, i))
    assert len(m.sources) <= 10 and len(m.zones) <= 10 and all(len(z) <= 6 for z in m.zones.values())
