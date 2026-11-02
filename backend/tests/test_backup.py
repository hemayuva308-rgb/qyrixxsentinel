"""Encrypted backup / restore acceptance tests against real PostgreSQL clusters (scripts/backup.py, age + HMAC manifest).

Proves: full restore into a FRESH cluster (identity, RLS, ownership, replay protection intact); no plaintext in the
backup; wrong key, corrupted ciphertext, forged/altered manifest, missing and swapped files are all refused BEFORE
anything is touched; an interrupted database restore leaves the database unchanged; an interrupted chain swap puts the
previous chain back; wrong-order restores fail closed; older DB + newer chain stays replay-safe; no password in argv."""
import json, os, shutil, subprocess, sys
import pytest

import app.gateway as g
from app import adapter, identity, persistence, provenance as prov
from app.identity import Principal
from tests.test_persistence import Cluster, HAVE_PG, A

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import backup as bk  # noqa: E402

pytestmark = pytest.mark.skipif(not HAVE_PG, reason="PostgreSQL not available")


@pytest.fixture(autouse=True)
def keys(tmp_path, monkeypatch):
    """age identity (private, restore-time only), recipients (public, on the backup host) and the manifest signing key."""
    ident = tmp_path / "backup.identity"
    subprocess.run(["age-keygen", "-o", str(ident)], check=True, capture_output=True)
    pub = subprocess.run(["age-keygen", "-y", str(ident)], check=True, capture_output=True, text=True).stdout
    rec = tmp_path / "backup.recipients"; rec.write_text(pub)
    sig = tmp_path / "backup.sign"; sig.write_text(os.urandom(32).hex())
    monkeypatch.setenv("QYRIX_BACKUP_IDENTITY_FILE", str(ident))
    monkeypatch.setenv("QYRIX_BACKUP_RECIPIENTS_FILE", str(rec))
    monkeypatch.setenv("QYRIX_BACKUP_SIGNING_KEY_FILE", str(sig))
    return {"identity": ident, "recipients": rec, "sign": sig}


@pytest.fixture
def two(tmp_path):
    src, dst = Cluster(), Cluster()
    ws = tmp_path / "ws"; ws.mkdir(); (ws / "README.md").write_text("hello workspace")
    chain_dir = tmp_path / "chain"; chain_dir.mkdir()
    yield {"src": src, "dst": dst, "ws": str(ws), "chain_dir": str(chain_dir), "tmp": tmp_path}
    src.destroy(); dst.destroy()
    persistence._POOL.clear()


def boot(url, chain_dir, ws):
    ctx = g.GateContext("t", prov.ProvenanceStore(), os.path.join(chain_dir, "chain.jsonl"), lambda: ("api.example.com",),
                        {"file.read": adapter.FileAdapter(ws, g._redact)}, ws)
    g._load_chain(ctx)
    g._load_anchors(ctx)
    try:
        g.attach_persistence(ctx, persistence.PgPersistence(url))
    except Exception:
        ctx.state["persistence"] = "down"
    return ctx


def run(ctx, r):
    return g.execute_grant({"gate_evaluation_id": r["gate_evaluation_id"], "grant_id": r["grant_id"]}, ctx)


def refused(ctx, r):
    with pytest.raises(g.ExecRefused) as e:
        run(ctx, r)
    return e.value.code


def populate(env):
    c = boot(env["src"].url, env["chain_dir"], env["ws"])
    assert c.state["persistence"] == "postgres"
    t = c.prov.add_step("ticket", "TRUSTED", "read readme")
    u = c.prov.add_step("skill", "UNTRUSTED", "x")
    used = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c)
    assert run(c, used)["executed"]
    unused = g.evaluate(A(tool="file.read", dest="README.md", lineage=[t["id"]]), c)
    apr = g.create_approval(g.ApprovalReq(tool="http", method="DELETE", dest="https://api.example.com/v1/x"), c)
    g.decide_approval(apr["id"], "approve", "admin", c)
    identity.use_store(identity.PgStore(persistence.shared_connection(env["src"].url)))
    key = identity.create_key(Principal("default", "owner", "test"), "default", "auditor", "backup-test", None)
    identity.use_store(identity.MemoryStore())
    return c, {"t": t, "u": u, "used": used, "unused": unused, "apr": apr, "key": key}


def test_encrypted_backup_restores_into_a_fresh_cluster(two):
    c, s = populate(two)
    out = str(two["tmp"] / "bk")
    m = bk.backup(two["src"].admin_url, two["chain_dir"], out)
    assert m["order"] == ["db.dump.age", "chain.tar.age"] and oct(os.stat(out).st_mode & 0o777) == "0o700"
    assert sorted(os.listdir(out)) == ["chain.tar.age", "db.dump.age", "manifest.json"]          # no plaintext files
    for n in ("db.dump.age", "chain.tar.age"):
        blob = open(os.path.join(out, n), "rb").read()
        assert blob.startswith(b"age-encryption.org/v1") and b"read readme" not in blob and b"gate_decision" not in blob
        assert oct(os.stat(os.path.join(out, n)).st_mode & 0o777) == "0o600"

    shutil.rmtree(two["chain_dir"]); os.makedirs(two["chain_dir"])
    two["src"].destroy()                                            # the original database is gone
    bk.restore(two["dst"].admin_url, two["chain_dir"], out)

    r = boot(two["dst"].url, two["chain_dir"], two["ws"])
    assert r.state["persistence"] == "postgres" and not r.state["degraded"]
    assert g.verify_chain(r)["valid"] and len(r.chain) == len(c.chain)
    assert r.prov.trust_of(s["u"]["id"]) == "UNTRUSTED" and r.appr[s["apr"]["id"]]["status"] == "approved"
    assert refused(r, s["used"]) == "GRANT_REPLAY"                  # restored state cannot replay an execution
    assert run(r, s["unused"])["executed"]
    assert refused(r, s["unused"]) == "GRANT_REPLAY"
    identity.use_store(identity.PgStore(persistence.shared_connection(two["dst"].url)))
    try:
        assert identity.authenticate(s["key"]["api_key"]).role == "auditor"   # API keys (hashes) survive restore
    finally:
        identity.use_store(identity.MemoryStore())
    import psycopg                                                  # RLS + least-privilege role survive restore
    with psycopg.connect(two["dst"].url) as conn:
        with conn.transaction():
            assert conn.execute("SELECT count(*) FROM proof_records").fetchone()[0] == 0
            assert persistence.runtime_privilege_problems(conn.cursor()) == []
    with psycopg.connect(two["dst"].admin_url) as conn:            # definer functions still owned by the NOLOGIN roles
        owners = dict(conn.execute("SELECT proname, pg_get_userbyid(proowner) FROM pg_proc WHERE proname LIKE 'qyrix_%'").fetchall())
        assert owners["qyrix_lookup_key"] == "qyrix_auth" and owners["qyrix_reset_tenant_evidence"] == "qyrix_maint"


def _ground_truth(cluster):
    import psycopg
    with psycopg.connect(cluster.admin_url) as c:
        return c.execute("SELECT count(*) FROM proof_records").fetchone()[0]


def _refused_untouched(two, out, match, **kw):
    """Restore must fail with `match` and leave the target database and chain exactly as they were."""
    before_db, before_chain = _ground_truth(two["src"]), open(os.path.join(two["chain_dir"], "chain.jsonl")).read()
    with pytest.raises(SystemExit, match=match):
        bk.restore(two["src"].admin_url, two["chain_dir"], out, force=True, **kw)
    assert _ground_truth(two["src"]) == before_db
    assert open(os.path.join(two["chain_dir"], "chain.jsonl")).read() == before_chain


def test_wrong_decryption_key_is_refused_before_anything_changes(two, tmp_path, monkeypatch):
    c, _ = populate(two)
    out = str(two["tmp"] / "bk"); bk.backup(two["src"].admin_url, two["chain_dir"], out)
    g.evaluate(A(tool="file.read", dest="README.md"), c)            # live state moves on
    other = tmp_path / "other.identity"; subprocess.run(["age-keygen", "-o", str(other)], check=True, capture_output=True)
    monkeypatch.setenv("QYRIX_BACKUP_IDENTITY_FILE", str(other))
    _refused_untouched(two, out, "cannot decrypt")


def test_corrupted_ciphertext_is_refused(two):
    populate(two)
    out = str(two["tmp"] / "bk"); bk.backup(two["src"].admin_url, two["chain_dir"], out)
    p = os.path.join(out, "db.dump.age")
    b = bytearray(open(p, "rb").read()); b[len(b) // 2] ^= 0x01; open(p, "wb").write(bytes(b))
    _refused_untouched(two, out, "does not match its manifest hash")


def test_forged_or_altered_manifest_is_refused(two, keys):
    populate(two)
    out = str(two["tmp"] / "bk"); bk.backup(two["src"].admin_url, two["chain_dir"], out)
    p = os.path.join(out, "manifest.json")
    doc = json.load(open(p))
    # attacker with the PUBLIC key re-encrypts their own data and rewrites the hashes - but cannot sign the manifest
    fake = os.path.join(out, "db.dump.age")
    with open(fake, "wb") as f:
        subprocess.run(["age", "-e", "-R", str(keys["recipients"])], input=b"attacker data", stdout=f, check=True)
    doc["manifest"]["files"]["db.dump.age"]["sha256"] = bk._sha(fake)
    json.dump(doc, open(p, "w"))
    _refused_untouched(two, out, "manifest signature invalid")
    keys["sign"].write_text(os.urandom(32).hex())                  # wrong signing key also refuses
    with pytest.raises(SystemExit, match="manifest signature invalid"):
        bk.verify(out)


def test_missing_and_swapped_files_are_refused(two):
    c, _ = populate(two)
    a = str(two["tmp"] / "a"); bk.backup(two["src"].admin_url, two["chain_dir"], a)
    g.evaluate(A(tool="file.read", dest="README.md"), c)
    b = str(two["tmp"] / "b"); bk.backup(two["src"].admin_url, two["chain_dir"], b)
    shutil.copy(os.path.join(b, "chain.tar.age"), os.path.join(a, "chain.tar.age"))   # mix two genuine backups
    _refused_untouched(two, a, "does not match its manifest hash")
    os.remove(os.path.join(b, "db.dump.age"))
    _refused_untouched(two, b, "missing")


def test_interrupted_database_restore_leaves_database_unchanged(two, keys):
    """A pg_restore that fails half-way (here: a validly encrypted and signed but truncated dump) rolls back completely."""
    populate(two)
    out = str(two["tmp"] / "bk"); bk.backup(two["src"].admin_url, two["chain_dir"], out)
    ident = str(keys["identity"])
    plain = subprocess.run(["age", "-d", "-i", ident, os.path.join(out, "db.dump.age")], capture_output=True, check=True).stdout
    with open(os.path.join(out, "db.dump.age"), "wb") as f:
        subprocess.run(["age", "-e", "-R", str(keys["recipients"])], input=plain[: int(len(plain) * 0.8)], stdout=f, check=True)
    p = os.path.join(out, "manifest.json"); doc = json.load(open(p))     # re-sign as the legitimate operator would
    doc["manifest"]["files"]["db.dump.age"]["sha256"] = bk._sha(os.path.join(out, "db.dump.age"))
    import hmac as _h, hashlib as _hl
    doc["hmac_sha256"] = _h.new(keys["sign"].read_text().strip().encode(), bk._canon(doc["manifest"]), _hl.sha256).hexdigest()
    json.dump(doc, open(p, "w"))
    _refused_untouched(two, out, "rolled back")


def test_interrupted_chain_swap_puts_the_previous_chain_back(two, monkeypatch):
    populate(two)
    out = str(two["tmp"] / "bk"); bk.backup(two["src"].admin_url, two["chain_dir"], out)
    before = open(os.path.join(two["chain_dir"], "chain.jsonl")).read()
    real = os.replace
    calls = []

    def flaky(a, b):
        calls.append((a, b))
        if len(calls) == 2:                                             # the staging -> live rename "crashes"
            raise OSError("simulated crash during swap")
        return real(a, b)
    monkeypatch.setattr(bk.os, "replace", flaky)
    with pytest.raises(OSError):
        bk.restore(two["src"].admin_url, two["chain_dir"], out, force=True)
    monkeypatch.setattr(bk.os, "replace", real)
    assert open(os.path.join(two["chain_dir"], "chain.jsonl")).read() == before
    assert not [d for d in os.listdir(two["tmp"]) if d.startswith(".qyrix-restore-")]       # staging cleaned up


def test_backup_requires_keys_and_never_overwrites(two, monkeypatch):
    populate(two)
    out = str(two["tmp"] / "bk")
    monkeypatch.delenv("QYRIX_BACKUP_RECIPIENTS_FILE")
    with pytest.raises(SystemExit, match="recipients"):
        bk.backup(two["src"].admin_url, two["chain_dir"], out)
    assert not os.path.exists(out)


def test_chain_older_than_database_fails_closed(two):
    c, _ = populate(two)
    early = str(two["tmp"] / "early-chain")
    shutil.copytree(two["chain_dir"], early)                        # WRONG ORDER: chain captured first...
    g.evaluate(A(tool="file.read", dest="README.md"), c)            # ...more decisions happen...
    out = str(two["tmp"] / "bk")
    bk.backup(two["src"].admin_url, two["chain_dir"], out)                # ...then the DB is captured
    shutil.rmtree(two["chain_dir"]); shutil.copytree(early, two["chain_dir"])
    bk.restore(two["dst"].admin_url, str(two["tmp"] / "unused-dir"), out)
    r = boot(two["dst"].url, two["chain_dir"], two["ws"])
    assert r.state["degraded"] is True and r.state["persistence"] == "down"
    assert g.evaluate(A(tool="file.read", dest="README.md"), r)["verdict"] == "BLOCK"


def test_older_database_newer_chain_stays_replay_safe(two):
    """The safe direction of the ordering invariant: DB snapshot taken, THEN a grant executes, THEN the chain is copied.
    After restore the grant row says 'unused' but the chain holds EXECUTION_STARTED => it is loaded as used."""
    c, s = populate(two)
    old = str(two["tmp"] / "old"); new = str(two["tmp"] / "new"); mixed = str(two["tmp"] / "mixed")
    bk.backup(two["src"].admin_url, two["chain_dir"], old)                 # DB while 'unused' is unused
    assert run(c, s["unused"])["executed"]                            # executes after the DB snapshot
    bk.backup(two["src"].admin_url, two["chain_dir"], new)                 # chain containing EXECUTION_STARTED
    os.makedirs(mixed)
    shutil.copy(os.path.join(old, "db.dump.age"), mixed); shutil.copy(os.path.join(new, "chain.tar.age"), mixed)
    import hmac as _h, hashlib as _hl
    mm = {"format": bk.FORMAT, "order": list(bk.FILES), "files": {n: {"sha256": bk._sha(os.path.join(mixed, n))} for n in bk.FILES}}
    with open(os.path.join(mixed, "manifest.json"), "w") as f:      # signed by the operator (has the signing key)
        json.dump({"manifest": mm, "hmac_sha256": _h.new(open(os.environ["QYRIX_BACKUP_SIGNING_KEY_FILE"]).read().strip().encode(),
                                                         bk._canon(mm), _hl.sha256).hexdigest()}, f)
    restored_chain = str(two["tmp"] / "restored")
    bk.restore(two["dst"].admin_url, restored_chain, mixed)
    r = boot(two["dst"].url, restored_chain, two["ws"])
    assert r.state["persistence"] == "postgres" and not r.state["degraded"]   # DB mirror is a prefix: back-filled
    assert r.grants[s["unused"]["grant_id"]]["used"] is True
    assert refused(r, s["unused"]) == "GRANT_REPLAY"


def test_restore_refuses_to_overwrite_live_chain_and_backup_never_overwrites(two):
    populate(two)
    out = str(two["tmp"] / "bk")
    bk.backup(two["src"].admin_url, two["chain_dir"], out)
    with pytest.raises(FileExistsError):
        bk.backup(two["src"].admin_url, two["chain_dir"], out)
    with pytest.raises(SystemExit, match="not empty"):
        bk.restore(two["dst"].admin_url, two["chain_dir"], out)


def test_password_is_passed_by_environment_not_argv():
    marker = "synthetic-" + "not-a-password"                     # built at runtime: no credential-shaped literal in source
    conn, env = bk._pg_env("host=db port=5432 dbname=qyrix user=qyrix password=" + marker)
    assert marker not in conn and env["PGPASSWORD"] == marker


def test_no_http_route_can_serve_backups():
    """Backups are never downloadable through the product: no API route touches backup files, and the frontend proxy only
    relays the sentinel/, tools/execute and health API paths."""
    from app.main import app
    paths = [getattr(r, "path", "") for r in app.routes]
    assert not [p for p in paths if "backup" in p.lower() or "dump" in p.lower() or "download" in p.lower()]
    proxy = open(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "src", "app", "api", "proxy", "[...path]", "route.ts")).read()
    assert 'rel === "health" || rel.startsWith("sentinel/") || rel === "tools/execute"' in proxy
