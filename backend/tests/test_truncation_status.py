"""What can and cannot detect proof-chain TAIL TRUNCATION today (removal of the newest records). Documents the honest
status referenced by docs/BENCHMARK_V2.md and the benchmark report:
  * a bare hash chain: cannot;
  * RFC 3161 anchoring (optional, off by default): detects truncation below an anchored record, not after the latest
    anchor (structural coverage here; token verification is tested in tests/test_anchor.py against a local TSA);
  * state witness and PostgreSQL proof mirror (durable mode only): tested in test_integrity.py / test_persistence.py,
    asserted here to exist so the documentation cannot silently drift from the code."""
import inspect

from app import adapter, gateway as g, integrity, proof, provenance as prov
from tests import test_integrity, test_persistence


def _chain(n=5):
    sb = adapter.SandboxAdapter()
    ctx = g.GateContext("trunc", prov.ProvenanceStore(), None, lambda: ("api.partner.example.com",), {"http": sb}, None)
    for i in range(n):
        g.evaluate(g.Action(tool="http", method="GET", dest="https://api.partner.example.com/v1/%d" % i), ctx)
    return [dict(r) for r in ctx.chain]


def test_bare_hash_chain_cannot_detect_tail_truncation():
    c = _chain()
    assert proof.verify_records(c)["valid"] and proof.verify_records(c[:-2])["valid"]   # still "valid": undetectable


def test_anchor_detects_truncation_below_the_anchored_record_only():
    c = _chain()
    anchor = [{"id": "a1", "n": 4, "head_hash": c[3]["hash"]}]
    assert proof.evaluate_anchors(c, anchor).get("anchor_status") != "ANCHOR_MISMATCH"
    assert proof.evaluate_anchors(c[:3], anchor)["anchor_status"] == "ANCHOR_MISMATCH"   # anchored record removed
    assert proof.evaluate_anchors(c[:4], anchor).get("anchor_status") != "ANCHOR_MISMATCH"  # after the anchor: not covered


def test_durable_mode_mitigations_exist_and_are_tested():
    src = inspect.getsource(integrity.check_tenant)
    assert "PROOF_CHAIN_REGRESSED" in src and "DATABASE_EVIDENCE_REGRESSED" in src
    assert "PROOF_MIRROR_MISMATCH" in inspect.getsource(g._sync_proof_mirror)
    assert hasattr(test_integrity, "test_partial_loss_truncated_chain_and_deleted_db_rows")
    assert hasattr(test_persistence, "test_truncated_chain_file_vs_mirror_degrades_gate")
