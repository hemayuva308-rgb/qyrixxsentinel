"""C4 reconciler truth table, exhaustively (design §11): never ENFORCEMENT_VERIFIED in C4; a definite result only when
EVERY precondition holds; INCONCLUSIVE always carries reasons; no observation => COVERAGE_UNATTESTED."""
import itertools

from observer.reconcile import BYPASS, INCONCLUSIVE, UNAUTHORIZED, VERIFIED, Claim, Facts, reconcile

CLAIMS = [None] + [Claim(v, it, ss, ce, rv, gp) for v, it, ss, ce, rv, gp in itertools.product(
    ["BLOCK", "ALLOW"], [True, False], ["active", "quarantined", "closed"], [True, False], [False, True], [True, False])]


def grid():
    for st, sub, pc, tin, tl, eb, fc, pq, c, cov, ht in itertools.product(
            ["open", "ended", "interrupted"], ["submitted", "disabled", "failed", "unknown"], [True, False], [0, 2], [0, 1],
            [False, True], [True, False], [False, True], CLAIMS, COVS, [0, 1]):
        yield Facts(st, sub, pc, tin, tl, eb, fc, pq, c, cov, ht)


COVS = [None, {"mediated": True}, {"mediated": False, "attestation_id": "a"}, {"mediated": True, "attestation_id": "a"}]


def covered(f):
    return bool(f.coverage) and f.coverage.get("mediated") is True and bool(f.coverage.get("attestation_id"))


def clean_claim(c):
    return (c is not None and c.verdict == "BLOCK" and c.in_time and c.stream_status == "active" and c.current_epoch
            and not c.reversed and c.gate_producer)


def test_exhaustive_truth_table():
    n = 0
    for f in grid():
        n += 1
        out = reconcile(f)
        if f.status == "open":
            assert out is None
            continue
        result, reasons = out
        assert result in (VERIFIED, BYPASS, UNAUTHORIZED, INCONCLUSIVE)
        base = f.status == "ended" and f.submission == "submitted" and f.positive_control and not f.epoch_boundary
        all_verified = (base and f.token_in_window == 0 and f.token_late == 0 and f.canary_host_traffic == 0
                        and clean_claim(f.claim) and f.feed_complete and not f.producers_quarantined and covered(f))
        assert (result == VERIFIED) == all_verified, f                        # iff EVERY independent condition holds
        if result == BYPASS:
            assert base and f.token_in_window > 0 and clean_claim(f.claim) and reasons == []
        elif result == UNAUTHORIZED:
            assert (base and f.token_in_window > 0 and f.claim is None and f.feed_complete
                    and not f.producers_quarantined and reasons == [])
        elif result == VERIFIED:
            assert reasons == []
        else:
            assert reasons
            if f.token_in_window == 0 and not covered(f):
                assert "COVERAGE_UNATTESTED" in reasons         # silence without attested mediation is never enforcement
        # completeness: when every precondition holds, the definite result IS produced
        if base and f.token_in_window > 0 and clean_claim(f.claim):
            assert result == BYPASS
        if base and f.token_in_window > 0 and f.claim is None and f.feed_complete and not f.producers_quarantined:
            assert result == UNAUTHORIZED
    assert n > 200000


def test_coverage_needs_an_attestation_id():
    f = Facts("ended", "submitted", True, 0, 0, False, True, False, Claim("BLOCK", True, "active", True, False), {"mediated": True})
    assert reconcile(f) == (INCONCLUSIVE, ["COVERAGE_UNATTESTED"])
    f2 = Facts("ended", "submitted", True, 0, 0, False, True, False, Claim("BLOCK", True, "active", True, False),
               {"mediated": True, "attestation_id": "a1"})
    assert reconcile(f2) == (VERIFIED, [])
