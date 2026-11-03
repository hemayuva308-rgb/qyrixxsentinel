"""C4 prerequisite fixes on REAL PostgreSQL: audit F4 (revocations and reversed ALLOWs reach the claim stream in the
same transaction), F9 (epoch change 'last trusted' compared with observer watermarks), F13 (heartbeat right after
delivery)."""
import uuid

import pytest

import app.gateway as g
from tests.observer_support import HAVE_PG, envelope, raw
from tests.test_observer_feed_pg import (OBS_URL, adm, allow, block, bk, enabled, keys, observer, ocl, oq, outbox,  # noqa: F401
                                         publisher)
from tests.test_persistence import A, boot

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


def test_f4_operator_revocation_emits_revoked_claim_atomically(bk, enabled):
    ctx = boot(bk)
    a = allow(ctx)
    g.revoke_grant(a["grant_id"], "admin@example.test", ctx)
    rows = [r[3] for r in outbox(bk) if r[2] == "grant"]
    assert [(r["kind"], r["refusal_code"]) for r in rows] == [("issued", None), ("revoked", "REVOKED_BY_OPERATOR")]
    assert rows[1]["execution_id"] == ctx.grants[a["grant_id"]]["execution_id"]
    assert "admin@example.test" not in str(rows)                         # no operator identity in claims
    assert adm(bk, "SELECT revoked_at IS NOT NULL FROM grants WHERE id=%s", (a["grant_id"],)) == [(True,)]


def test_f4_revocation_still_happens_if_claim_cannot_be_written(bk, enabled):
    ctx = boot(bk)
    a = allow(ctx)
    adm(bk, "REVOKE EXECUTE ON FUNCTION qyrix_observer_emit(text, text, uuid, jsonb) FROM qyrix_app")
    assert g.revoke_grant(a["grant_id"], "admin", ctx)["revoked"] is True  # safety beats telemetry
    assert adm(bk, "SELECT revoked_at IS NOT NULL FROM grants WHERE id=%s", (a["grant_id"],)) == [(True,)]


def test_f4_reversed_allow_is_followed_by_reversal_and_revocation_claims(bk, enabled, monkeypatch):
    ctx = boot(bk)
    t = ctx.prov.add_step("ticket", "TRUSTED", "read")
    real = g._prove
    monkeypatch.setattr(g, "_prove", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    r = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), ctx)
    monkeypatch.setattr(g, "_prove", real)
    assert r["verdict"] == "BLOCK" and r["rules"] == ["R0_FAIL_CLOSED"]
    rows = [(x[2], x[3].get("verdict"), x[3].get("kind"), x[3].get("reversed_from"), x[3].get("gate_evaluation_id"))
            for x in outbox(bk)]
    assert [x[:4] for x in rows] == [("decision", "ALLOW", None, None), ("grant", None, "issued", None),
                                     ("decision", "BLOCK", None, "ALLOW"), ("grant", None, "revoked", None)]
    assert len({x[4] for x in rows}) == 1                                 # all about the same evaluation


def test_f9_epoch_change_last_trusted_ahead_is_alerted(observer, keys):
    obs = observer["obs"]
    body = {"gate_evaluation_id": str(uuid.uuid4()), "correlation_id": "c", "verdict": "BLOCK", "rule_ids": []}
    import time
    obs.ingest(raw(envelope(keys.gate, keys.gate_pid, "decision", body, seq=1, issued=time.time())))
    ec = {"new_epoch": 2, "last_trusted_seq_per_tenant": {"default": 999, "tenant-b": 0},
          "reason": "restored backup after disk failure INC-11"}
    r = obs.ingest(raw(envelope(keys.recovery, keys.gate_pid, "epoch_change", ec, tenant=None, epoch=2, issued=time.time())))
    assert r == (200, {"status": "accepted", "epoch": 2})
    al = oq(observer, "SELECT detail FROM ledger WHERE code='EPOCH_LAST_TRUSTED_AHEAD'")
    assert al[0][0]["tenants"] == [{"tenant": "default", "last_trusted_seq": 999, "observer_contiguous_seq": 1}]


def test_f13_heartbeat_follows_delivery(bk, enabled, keys, observer):
    ctx = boot(bk)
    block(ctx)
    pub = publisher(bk, keys, observer)
    st = pub.publish_once()
    assert st["sent"] == 1 and st["heartbeats"] == 1                     # no timer needed
    assert oq(observer, "SELECT attested_seq, contiguous_seq FROM watermarks") == [(1, 1)]
    assert pub.publish_once()["heartbeats"] == 1                          # nothing delivered => no extra heartbeat
