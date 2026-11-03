"""Phase C1 unit tests (no database): key manifest, envelope structure/signatures, watermark advance, feed conditions,
window closure. Design §5, §9, §12."""
import copy
import itertools
import json
import uuid

import pytest

from observer import crypto
from observer.canonical import canonical
from observer.envelope import MAX_BYTES, Refused, content_digest, parse, signed_bytes
from observer.feed import Config, Window, advance, feed_conditions, window_closure
from observer.manifest import Manifest, ManifestError, sign_manifest
from tests.observer_support import T0, Keys, decision, envelope, heartbeat, iso, raw


@pytest.fixture
def keys():
    return Keys()


# ---------------- manifest (§9) ----------------
def test_manifest_verifies_under_pinned_root(keys):
    m = keys.manifest()
    assert m.version == 1 and keys.gate_pid in m.producers
    assert m.producers[keys.gate_pid].keys[keys.kid(keys.gate)].scopes == {"decision", "grant", "heartbeat"}
    assert m.recovery_keys[keys.kid(keys.recovery)].scopes == {"epoch_change"}


def test_manifest_wrong_root_or_tampered_is_refused(keys):
    signed = sign_manifest(keys.manifest_doc(), keys.root)
    with pytest.raises(ManifestError, match="MANIFEST_SIGNATURE_INVALID"):
        Manifest(signed, crypto.describe(keys.other)[1])            # a different pinned root
    t = copy.deepcopy(signed)
    t["producers"][0]["keys"][0]["scopes"].append("heartbeat")      # any change after signing
    t["producers"][0]["tenants"] = ["default", "x-tenant"]
    with pytest.raises(ManifestError, match="MANIFEST_SIGNATURE_INVALID"):
        Manifest(t, keys.root_pub())


def test_manifest_scope_limits_by_producer_kind(keys):
    doc = keys.manifest_doc()
    doc["producers"][0]["keys"][0]["scopes"] = ["decision", "epoch_change"]   # a GATE key may never change epochs
    with pytest.raises(ManifestError, match="SCOPE_NOT_ALLOWED"):
        Manifest(sign_manifest(doc, keys.root), keys.root_pub())
    doc = keys.manifest_doc()
    doc["producers"][1]["keys"][0]["scopes"] = ["decision"]                  # an adapter may never claim decisions
    with pytest.raises(ManifestError, match="SCOPE_NOT_ALLOWED"):
        Manifest(sign_manifest(doc, keys.root), keys.root_pub())


def test_manifest_one_key_one_role(keys):
    doc = keys.manifest_doc()
    doc["recovery_keys"] = [keys.entry(keys.gate)]                           # GATE key reused as recovery key
    with pytest.raises(ManifestError, match="KEY_REUSED_ACROSS_ROLES"):
        Manifest(sign_manifest(doc, keys.root), keys.root_pub())
    doc = keys.manifest_doc()
    doc["observer_keys"] = [keys.entry(keys.root)]                           # root key used online
    with pytest.raises(ManifestError, match="KEY_REUSED_ACROSS_ROLES"):
        Manifest(sign_manifest(doc, keys.root), keys.root_pub())


def test_manifest_key_id_must_match_public_key(keys):
    doc = keys.manifest_doc()
    doc["producers"][0]["keys"][0]["key_id"] = keys.kid(keys.other)
    with pytest.raises(ManifestError, match="KEY_ID_MISMATCH"):
        Manifest(sign_manifest(doc, keys.root), keys.root_pub())


def test_key_validity_window_and_revocation(keys):
    m = keys.manifest(gate_extra={"valid_to": iso(T0 + 100), "revoked_at": iso(T0 + 50)})
    k = m.producers[keys.gate_pid].keys[keys.kid(keys.gate)]
    assert k.valid_at(T0) and not k.valid_at(T0 + 50) and not k.valid_at(T0 + 200) and not k.valid_at(999_999_999)


# ---------------- envelope (§12) ----------------
def test_envelope_roundtrip_and_signature(keys):
    env = decision(keys, 1)
    p = parse(raw(env))
    assert crypto.verify(keys.gate.public_key(), p["sig"], signed_bytes(p))
    p2 = dict(p, body={**p["body"], "verdict": "ALLOW"})
    assert not crypto.verify(keys.gate.public_key(), p["sig"], signed_bytes(p2))


@pytest.mark.parametrize("mutate,code", [
    (lambda e: e.update(extra=1), "MALFORMED"),
    (lambda e: e.pop("sig"), "MALFORMED"),
    (lambda e: e.update(schema="qyrix.event/v0"), "MALFORMED"),
    (lambda e: e.update(type="whatever"), "MALFORMED"),
    (lambda e: e.update(event_id="not-a-uuid"), "MALFORMED"),
    (lambda e: e.update(event_id=str(uuid.uuid1())), "MALFORMED"),
    (lambda e: e.update(issued_at="2026-01-01T00:00:00"), "MALFORMED"),        # no UTC offset
    (lambda e: e.update(seq=0), "MALFORMED"),
    (lambda e: e.update(seq=True), "MALFORMED"),
    (lambda e: e.update(hb_seq=1), "MALFORMED"),                               # decision may not carry hb_seq
    (lambda e: e.update(epoch=0), "MALFORMED"),
    (lambda e: e.update(tenant="UPPER"), "TENANT_MISMATCH"),
])
def test_envelope_structural_refusals(keys, mutate, code):
    env = decision(keys, 1)
    mutate(env)
    with pytest.raises(Refused) as e:
        parse(json.dumps(env).encode())
    assert e.value.code == code


def test_envelope_oversize_and_not_json():
    with pytest.raises(Refused) as e:
        parse(b"{" + b" " * MAX_BYTES + b"}")
    assert e.value.code == "OVERSIZE" and e.value.status == 413
    for bad in (b"\xff\xfe", b"[1,2]", b"null", b"{"):
        with pytest.raises(Refused) as e:
            parse(bad)
        assert e.value.code == "MALFORMED"


def test_heartbeat_never_carries_event_seq(keys):
    hb = heartbeat(keys, 1, {"default": {"allocated_through_seq": 0}})
    assert hb["seq"] is None and parse(raw(hb))["hb_seq"] == 1
    hb["seq"] = 5
    with pytest.raises(Refused):
        parse(raw(hb))


def test_content_digest_ignores_signature_and_key_id_only(keys):
    a = decision(keys, 1)
    b = dict(a, sig="x", key_id="ed25519:other")
    assert content_digest(a) == content_digest(b)
    for k, v in (("seq", 2), ("issued_at", iso(T0 + 1)), ("body", {"verdict": "ALLOW"}), ("tenant", "tenant-b")):
        assert content_digest(dict(a, **{k: v})) != content_digest(a)


def test_canonical_matches_backend_publisher():
    """The backend signs with app.observer_feed.canonical; both sides must produce identical bytes."""
    from app import observer_feed
    samples = [{"b": 1, "a": [1, "é", None, True]}, {"z": {"y": " ", "x": 1.5}}, {"k": "日本"}]
    for s in samples:
        assert observer_feed.canonical(s) == canonical(s)


# ---------------- watermarks / feed (§5.3, §5.5) ----------------
def test_advance_is_contiguous_only():
    assert advance(0, [1, 2, 3]) == 3
    assert advance(0, [2, 3]) == 0
    assert advance(3, [5, 4, 7]) == 5
    for perm in itertools.permutations([1, 2, 3, 4]):
        seen = []
        c = 0
        for s in perm:
            seen.append(s)
            c = advance(c, seen)
        assert c == 4


def test_feed_conditions():
    cfg = Config()
    ok = {"status": "active", "last_hb_received_at": T0}
    assert feed_conditions(T0 + 1, ok, [{"tenant_id": "default", "gap_since": None, "behind_since": None}], cfg) == []
    assert "PRODUCER_SILENT" in feed_conditions(T0 + 3 * cfg.H + 1, ok, [], cfg)
    assert "PRODUCER_SILENT" in feed_conditions(T0, {"status": "active", "last_hb_received_at": None}, [], cfg)
    w = [{"tenant_id": "default", "gap_since": T0, "behind_since": T0}]
    assert feed_conditions(T0 + cfg.G, ok, w, cfg) == []                          # grace not exceeded yet
    c = feed_conditions(T0 + cfg.G + 1, dict(ok, last_hb_received_at=T0 + cfg.G), w, cfg)
    assert "DECISION_FEED_GAP:default" in c and "DECISION_FEED_GAP_TAIL:default" in c
    assert "PRODUCER_REGRESSION" in feed_conditions(T0, dict(ok, status="quarantined"), [], cfg)


# ---------------- window closure (§5.6) ----------------
def _hb(t, alloc):
    return {"issued_at": t, "received_at": t, "tenants": {"default": alloc}}


def test_window_never_closes_without_sensors():
    """C1-C2 have no sensors, so condition 3 can never hold: every window ends NOT_CLOSABLE (=> INCONCLUSIVE)."""
    cfg = Config()
    win = Window(T0, "default")
    wm = {"contiguous_seq": 10}
    st = {"status": "active"}
    r = window_closure(win, T0 + 1, cfg, st, wm, [_hb(T0 + 5, 10)])
    assert r.state == "OPEN"
    r = window_closure(win, T0 + cfg.W + cfg.G + 1, cfg, st, wm, [_hb(T0 + 5, 10)])
    assert r.state == "NOT_CLOSABLE" and "WINDOW_NOT_CLOSABLE" in r.reasons and "SENSORS_NOT_AVAILABLE" in r.reasons


def test_window_closure_requires_every_condition():
    cfg = Config()
    win = Window(T0, "default")
    good = dict(win=win, now=T0 + 10, cfg=cfg, stream={"status": "active"}, wm={"contiguous_seq": 10},
                heartbeats=[_hb(T0 + 5, 10)], sensors={"http": {"healthy": True, "positive_control_at": T0 + 1}})
    assert window_closure(**good).state == "CLOSED"
    breaks = {
        "now": T0 + 1,                                                            # window still running
        "heartbeats": [_hb(T0 + 1, 10)],                                          # heartbeat not after t0+W
        "wm": {"contiguous_seq": 9},                                              # contiguous behind the claim
        "stream": {"status": "quarantined"},
        "sensors": {"http": {"healthy": False, "positive_control_at": T0 + 1}},
        **{"sensors_pc": None},
    }
    for k, v in breaks.items():
        if k == "sensors_pc":
            args = dict(good, sensors={"http": {"healthy": True, "positive_control_at": T0 - 5}})
        else:
            args = dict(good, **{k: v})
        assert window_closure(**args).state != "CLOSED", k
    assert window_closure(**dict(good, open_tunnels=1)).state != "CLOSED"
    late = dict(good, heartbeats=[{"issued_at": T0 + 5, "received_at": T0 + 1, "tenants": {"default": 10}}])
    assert window_closure(**late).state != "CLOSED"                               # a backdated/early heartbeat is not enough


def test_exhaustive_no_sensor_window_is_never_closed():
    """Property (design §11, §16): without observer sensors (C1-C2), NO combination of claims closes a window."""
    cfg = Config()
    win = Window(T0, "default")
    times = [T0 - 10, T0, T0 + cfg.W, T0 + cfg.W + 1, T0 + cfg.W + cfg.G + 5, T0 + 10 ** 6]
    for now, status, contiguous, alloc, hb_t, sensors, tunnels in itertools.product(
            times, ["active", "quarantined", "closed"], [0, 5, 10], [0, 5, 10, None], times,
            [None, {}, {"dns": {"healthy": True, "positive_control_at": T0 + 1}}], [0, 1]):
        hbs = [] if alloc is None else [{"issued_at": hb_t, "received_at": hb_t, "tenants": {"default": alloc}}]
        r = window_closure(win, now, cfg, {"status": status}, {"contiguous_seq": contiguous}, hbs, sensors, tunnels)
        assert r.state != "CLOSED"


def test_observer_package_has_no_verification_result_path():
    """C1-C2 contain no reconciler: no observer module holds a VERIFIED/BYPASS/UNAUTHORIZED result value."""
    import ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "observer"
    results = {"ENFORCEMENT_VERIFIED", "BYPASS_DETECTED", "UNAUTHORIZED_EXECUTION"}
    for f in root.glob("*.py"):
        consts = {n.value for n in ast.walk(ast.parse(f.read_text())) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert not (consts & results), (f.name, consts & results)


def test_observer_imports_nothing_from_backend():
    import pathlib, re
    root = pathlib.Path(__file__).resolve().parents[1] / "observer"
    for f in root.glob("*.py"):
        assert not re.search(r"^\s*(from|import)\s+app(\.|\s|$)", f.read_text(), re.M), f.name
