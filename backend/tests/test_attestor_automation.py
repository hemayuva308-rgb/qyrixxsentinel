"""C5 hardening: attestor automation. Event filter + debounce + restart behaviour (unit), and on REAL PostgreSQL:
a stopped / missing backend container yields a signed FAILED attestation that revokes coverage at once; an expired
attestation gives no coverage; an older success is never reused after a failure."""
import json
import time

import pytest

from observer import attestor, attestor_watch
from observer.coverage import CoverageService, attestation_skeleton, sign_attestation
from observer.egress import new_token
from tests.observer_support import HAVE_PG
from tests.test_observer_c5_pg import _checks, _evidence, cluster, ob, sink  # noqa: F401

P, S, NETS = "qyrixxsentinel", "backend", {"qyrixxsentinel_internal", "qyrixxsentinel_egress"}


def ev(t, action, **attrs):
    return {"Type": t, "Action": action, "Actor": {"Attributes": attrs}}


@pytest.mark.parametrize("e,want", [
    (ev("container", "start", **{"com.docker.compose.project": P, "com.docker.compose.service": S}), True),
    (ev("container", "die", **{"com.docker.compose.project": P, "com.docker.compose.service": S}), True),
    (ev("container", "exec_start: sh", **{"com.docker.compose.project": P, "com.docker.compose.service": S}), False),
    (ev("container", "start", **{"com.docker.compose.project": P, "com.docker.compose.service": "frontend"}), False),
    (ev("network", "connect", name="qyrixxsentinel_egress", container="abc"), True),
    (ev("network", "disconnect", name="qyrixxsentinel_internal", container="abc"), True),
    (ev("network", "connect", name="unrelated_net", container="abc"), False),
    (ev("image", "pull"), False),
])
def test_event_filter(e, want):
    assert attestor_watch.relevant(e, P, S, NETS) is want


def test_watcher_attests_on_start_and_debounces_bursts():
    calls = []
    w = attestor_watch.Watcher("cfg", P, S, NETS, debounce=0.3, attest=lambda: calls.append(time.time()) or 0)
    w.attest_now("watcher_start")                                     # a (re)started watcher attests FIRST
    for a in ("stop", "die", "start", "restart"):                    # one compose recreate = burst of events
        w.handle(json.dumps(ev("container", a, **{"com.docker.compose.project": P, "com.docker.compose.service": S})))
    w.handle("not json")
    time.sleep(0.6)
    assert len(calls) == 2 and [r["why"] for r in w.runs] == ["watcher_start", "container:restart"]


def test_absent_container_attestation_is_well_formed():
    a = attestor.absent("absent:p/backend")
    assert a["checks"] == {"container_running": False} and a["container_id"] == "absent:p/backend"


pg = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pg
def test_failed_attestation_from_missing_container_revokes_coverage(ob, sink):
    cov = CoverageService(ob["obs"])
    name = "%s.dnscheck.qyrix.invalid" % new_token()
    ok = cov.submit(sign_attestation(attestation_skeleton("abc123def456", "img", _checks(), _evidence(ob, sink.ports[0], name)),
                                     ob["keys"].attestor))
    assert ok["valid"] and cov.current(time.time(), time.time() + 5, "abc123def456")
    time.sleep(0.05)
    gone = attestor.absent("absent:qyrixxsentinel/backend")
    r = cov.submit(sign_attestation(attestation_skeleton(gone["container_id"], "", gone["checks"], gone["probes"]),
                                    ob["keys"].attestor))
    assert r["stored"] and r["valid"] is False and "ATTESTOR_CHECK_FAILED:container_running" in r["reasons"]
    assert cov.current(time.time(), time.time() + 5, "abc123def456") is None    # the old success is NOT reused


@pg
def test_expired_attestation_gives_no_coverage(ob, sink):
    cov = CoverageService(ob["obs"])
    name = "%s.dnscheck.qyrix.invalid" % new_token()
    r = cov.submit(sign_attestation(attestation_skeleton("abc123def456", "img", _checks(), _evidence(ob, sink.ports[0], name),
                                                         validity=1.0), ob["keys"].attestor))
    assert r["valid"] and cov.current(time.time(), time.time() + 0.2, "abc123def456")
    time.sleep(1.2)
    assert cov.current(time.time(), time.time(), "abc123def456") is None
    assert cov.tick() == "COVERAGE_GAP"
