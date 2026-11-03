"""C4 reconciler truth table, exhaustively (design §11): never ENFORCEMENT_VERIFIED in C4; a definite result only when
EVERY precondition holds; INCONCLUSIVE always carries reasons; no observation => COVERAGE_UNATTESTED."""
import itertools

from observer.reconcile import BYPASS, INCONCLUSIVE, UNAUTHORIZED, Claim, Facts, reconcile

CLAIMS = [None] + [Claim(v, it, ss, ce, rv, gp) for v, it, ss, ce, rv, gp in itertools.product(
    ["BLOCK", "ALLOW"], [True, False], ["active", "quarantined", "closed"], [True, False], [False, True], [True, False])]


def grid():
    for st, sub, pc, tin, tl, eb, fc, pq, c, cov in itertools.product(
            ["open", "ended", "interrupted"], ["submitted", "disabled", "failed", "unknown"], [True, False], [0, 2], [0, 1],
            [False, True], [True, False], [False, True], CLAIMS, [None, {"mediated": True}]):
        yield Facts(st, sub, pc, tin, tl, eb, fc, pq, c, cov)


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
        assert result in (BYPASS, UNAUTHORIZED, INCONCLUSIVE) and result != "ENFORCEMENT_VERIFIED"
        base = f.status == "ended" and f.submission == "submitted" and f.positive_control and not f.epoch_boundary
        if result == BYPASS:
            assert base and f.token_in_window > 0 and clean_claim(f.claim) and reasons == []
        elif result == UNAUTHORIZED:
            assert (base and f.token_in_window > 0 and f.claim is None and f.feed_complete
                    and not f.producers_quarantined and reasons == [])
        else:
            assert reasons
            if f.token_in_window == 0:
                assert "COVERAGE_UNATTESTED" in reasons         # silence is never enforcement (no C5 coverage)
        # completeness: when every precondition holds, the definite result IS produced
        if base and f.token_in_window > 0 and clean_claim(f.claim):
            assert result == BYPASS
        if base and f.token_in_window > 0 and f.claim is None and f.feed_complete and not f.producers_quarantined:
            assert result == UNAUTHORIZED
    assert n > 50000


def test_coverage_input_cannot_create_verified():
    f = Facts("ended", "submitted", True, 0, 0, False, True, False, Claim("BLOCK", True, "active", True, False), {"mediated": True})
    assert reconcile(f) == (INCONCLUSIVE, ["COVERAGE_UNATTESTED"])
