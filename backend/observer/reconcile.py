"""Reconciler v2, C4 minimal scope: CANARY RUNS ONLY (design §11, §6; owner-approved C4 plan).

Pure function over facts the observer itself holds. Results:

  BYPASS_DETECTED         an observer-originated (E3) canary-token observation INSIDE the window, while the signed
                          decision claim for the run's observer-minted correlation id says BLOCK, the claim came in time
                          from an ACTIVE, current-epoch gate stream and was not reversed, the canary was submitted, the
                          positive control passed and no epoch change touched the run.
  UNAUTHORIZED_EXECUTION  the same E3 in-window observation with NO decision claim at all, under the same conditions,
                          AND a closing heartbeat (issued and received after the run was due) whose claimed allocation
                          the contiguous watermark has reached - so the claim is not merely still in flight (§5.6).
  INCONCLUSIVE            everything else, with explicit reasons.

ENFORCEMENT_VERIFIED is NOT producible in C4: §11 requires a current coverage attestation of the channel (C5 host
attestor), which does not exist. Absence of an observation therefore always yields INCONCLUSIVE /
COVERAGE_UNATTESTED. The O003 schema refuses the value as well.

Producer claims (E0) are used only to classify an observed effect (which claim did it contradict?) - never as evidence
that something did or did not happen. Backend-reported heads (producer_claims) are not an input at all.
"""
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

BYPASS = "BYPASS_DETECTED"
UNAUTHORIZED = "UNAUTHORIZED_EXECUTION"
INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class Claim:
    verdict: str                      # as signed by the producer (E0)
    in_time: bool                     # received within T_decision of the run
    stream_status: str                # active | quarantined | closed
    current_epoch: bool
    reversed: bool                    # a later claim for the same evaluation reversed it (audit F4)
    gate_producer: bool = True


@dataclass(frozen=True)
class Facts:
    status: str                       # open | ended | interrupted
    submission: str                   # submitted | disabled | failed | unknown
    positive_control: bool
    token_in_window: int
    token_late: int
    epoch_boundary: bool              # an epoch change was received at/after the run started (audit F13/F9)
    feed_complete: bool               # closing heartbeat reached by the contiguous watermark (all current gate streams)
    producers_quarantined: bool       # any gate stream of the tenant's producers is quarantined
    claim: Optional[Claim] = None
    coverage: Optional[Dict] = field(default=None)     # C5 coverage attestation; always None in C4

    def as_dict(self) -> Dict:
        return asdict(self)


def reconcile(f: Facts) -> Optional[Tuple[str, List[str]]]:
    """-> None while the run is open, else (result, reasons). Reasons are empty only for a definite result."""
    if f.status == "open":
        return None
    base: List[str] = []
    if f.status == "interrupted":
        base.append("RUN_INTERRUPTED")
    if f.submission != "submitted":
        base.append("SUBMISSION_" + f.submission.upper())
    if not f.positive_control:
        base.append("POSITIVE_CONTROL_NOT_PASSED")
    if f.epoch_boundary:
        base.append("EPOCH_BOUNDARY")
    claim_issues: List[str] = []
    c = f.claim
    if c is not None:
        if not c.gate_producer:
            claim_issues.append("CLAIM_NOT_FROM_GATE")
        if c.reversed:
            claim_issues.append("DECISION_REVERSED")
        if c.stream_status != "active":
            claim_issues.append("CLAIM_STREAM_" + c.stream_status.upper())
        if not c.current_epoch:
            claim_issues.append("CLAIM_EPOCH_CLOSED")
        if not c.in_time:
            claim_issues.append("CLAIM_LATE")
        if c.verdict != "BLOCK":
            claim_issues.append("CLAIM_NOT_BLOCK")
    if f.token_in_window > 0:
        if not base and c is not None and not claim_issues:
            return BYPASS, []
        if not base and c is None:
            if f.producers_quarantined:
                return INCONCLUSIVE, ["PRODUCER_QUARANTINED"]
            if not f.feed_complete:
                return INCONCLUSIVE, ["DECISION_FEED_INCOMPLETE"]
            return UNAUTHORIZED, []
        return INCONCLUSIVE, base + claim_issues + ([] if c is not None else ["NO_DECISION_CLAIM"])
    reasons = base + claim_issues
    if f.token_late:
        reasons.append("LATE_OBSERVATION_ONLY")
    if c is None and f.submission == "submitted":
        reasons.append("NO_DECISION_CLAIM")
    reasons.append("COVERAGE_UNATTESTED")       # no observation != enforcement without mediation (C5)
    return INCONCLUSIVE, reasons
