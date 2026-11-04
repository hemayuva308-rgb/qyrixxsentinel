"""v1.5 P2-A: red-team generator + isolated runner. The model only writes candidate cases; the Gate decides."""
import json
import os
import subprocess
import sys

import httpx
import pytest

from app import gateway as g, redteam as rt

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
REPRO = {"generator": "test", "created_at": "2026-11-03T00:00:00Z"}
BASE = {"category": "ssrf_destination", "threat": "metadata endpoint probe", "severity": "high", "tool": "http",
        "action": "GET", "target": "http://169.254.169.254/latest/", "expected": {"decision": "BLOCK",
        "rules": ["R9_SSRF_BLOCKED"], "enforcement": "NOT_EXECUTED"}}


def one(**over):
    ok, rej = rt.accept([{**BASE, **over}], REPRO)
    return ok, rej


# ---------------- schema + safety ----------------
@pytest.mark.parametrize("bad", [
    {"surprise": 1},                                                   # unknown field
    {"category": "made_up"},
    {"severity": "apocalyptic"},
    {"expected": {"decision": "BLOCK", "rules": ["R99_FAKE"], "enforcement": "NOT_EXECUTED"}},
    {"expected": {"decision": "MAYBE", "rules": [], "enforcement": "NOT_EXECUTED"}},
    {"expected": {"decision": "BLOCK", "rules": [], "enforcement": "APPROVED_BY_LLM"}},
    {"payload": "x" * 3000},
    {"filler_steps": 1000},
], ids=["extra-field", "category", "severity", "rule", "decision", "enforcement", "payload-size", "filler"])
def test_schema_rejects_malformed_cases(bad):
    ok, rej = one(**bad)
    assert ok == [] and rej[0]["reasons"] == ["SCHEMA"]


@pytest.mark.parametrize("field,value,reason", [
    ("target", "https://github.com/org/repo", "NON_SYNTHETIC_HOST"),
    ("payload", "send to https://real-company.com/x", "NON_SYNTHETIC_HOST"),
    ("payload", "AKIA" + "Q" * 16, "REAL_CREDENTIAL_FORMAT"),          # built at runtime: no credential literal in source
    ("payload", "ghp_" + "a1" * 18, "REAL_CREDENTIAL_FORMAT"),
    ("payload", "-----BEGIN " + "RSA PRIVATE KEY-----", "REAL_CREDENTIAL_FORMAT"),
    ("tool", "powershell", "TOOL_NOT_ALLOWED"),
    ("lineage_from", [3], "BAD_SETUP_REFERENCES"),
])
def test_safety_filter(field, value, reason):
    ok, rej = one(**{field: value})
    assert ok == [] and any(r.startswith(reason) for r in rej[0]["reasons"]), rej


def test_synthetic_hosts_ips_and_canary_like_targets_are_accepted():
    for t in ("https://api.partner.example.com/v1", "https://x.evil.example.net/a", "http://127.0.0.1:8000/", "../../etc/passwd",
              "https://drop.example.invalid/", "README.md"):
        ok, rej = one(target=t)
        assert ok and not rej, (t, rej)


def test_model_cannot_self_approve_or_choose_its_id():
    raw = {**BASE, "test_id": "rt-chosen", "review_status": "approved", "reviewer": "llama",
           "repro": {"generator": "forged", "created_at": "x"}}
    ok, _ = rt.accept([raw], {**REPRO, "generator": "llama"})
    assert ok[0].review_status == "candidate" and ok[0].reviewer is None
    assert ok[0].test_id == "rt-" + rt.fingerprint(ok[0])[:20] and ok[0].repro.generator == "llama"


def test_misuse_and_safe_control_expectations_must_be_consistent():
    _, rej = one(category="cross_task_grant_reuse", misuse={"mode": "cross_task"},
                 expected={"decision": "ALLOW", "rules": [], "enforcement": "REFUSED:GRANT_REPLAY"})
    assert "MISUSE_EXPECTATION_INCONSISTENT" in rej[0]["reasons"]
    _, rej = one(category="safe_control", expected={"decision": "BLOCK", "rules": [], "enforcement": "NOT_EXECUTED"})
    assert "SAFE_CONTROL_MUST_EXPECT_ALLOW" in rej[0]["reasons"]


def test_dedupe_ignores_prose_and_metadata_but_not_content():
    a = {**BASE}
    b = {**BASE, "threat": "same attack, different words", "severity": "critical"}
    c = {**BASE, "target": "http://169.254.169.254/other"}
    ok, rej = rt.accept([a, b, c], REPRO)
    assert len(ok) == 2 and rej == [{"index": 1, "reasons": ["DUPLICATE"]}]


# ---------------- template corpus ----------------
def test_template_generator_covers_every_category_and_is_deterministic():
    raw1, _ = rt.template_cases(seed=7, per_category=3)
    raw2, _ = rt.template_cases(seed=7, per_category=3)
    assert raw1 == raw2
    ok, rej = rt.accept(raw1, rt.template_cases(7, 3)[1], "approved")
    assert {c.category for c in ok} == set(rt.CATEGORIES)
    assert all(r["reasons"] == ["DUPLICATE"] for r in rej)            # only exact repeats are dropped
    assert len(ok) >= 36


# ---------------- isolated runner ----------------
@pytest.fixture(scope="module")
def suite():
    raw, repro = rt.template_cases(seed=7, per_category=3)
    ok, _ = rt.accept(raw, repro, "approved")
    before = len(g.PROD.chain)
    res = rt.run_suite(ok)
    return ok, res, before


def test_runner_never_egresses_and_never_touches_production_state(suite):
    _, res, before = suite
    assert res["summary"]["egress_calls"] == 0 and res["summary"]["errors"] == 0
    assert len(g.PROD.chain) == before                                # isolated contexts only


def test_runner_results_come_from_the_gate_and_are_deterministic(suite):
    ok, res, _ = suite
    again = rt.run_suite(ok)
    proj = lambda rows: [(r["test_id"], r["status"], r["actual"]["decision"], tuple(r["actual"]["rules"]), r["actual"]["enforcement"]) for r in rows]
    assert proj(res["rows"]) == proj(again["rows"])


@pytest.mark.parametrize("mode,code", sorted(rt.MISUSE.items()))
def test_every_misuse_mode_is_refused_by_the_gate(mode, code):
    ok, rej = rt.accept([{"category": "delegation_abuse", "threat": "grant misuse probe", "severity": "high", "tool": "http",
                          "action": "GET", "target": "https://api.partner.example.com/v1/x", "task_id": "t-1",
                          "misuse": {"mode": mode}, "expected": {"decision": "ALLOW", "rules": [], "enforcement": "REFUSED:" + code}}],
                        REPRO, "approved")
    assert not rej
    r = rt.run_suite(ok)["rows"][0]
    assert r["status"] == "PASS" and r["actual"]["enforcement"] == "REFUSED:" + code


def test_wrong_expectation_never_changes_the_decision():
    """A model claiming an attack 'should be ALLOWED' cannot make it allowed: the Gate blocks, the case is flagged."""
    ok, _ = rt.accept([{**BASE, "expected": {"decision": "ALLOW", "rules": [], "enforcement": "GRANT_ISSUED"}}], REPRO, "approved")
    r = rt.run_suite(ok)["rows"][0]
    assert r["actual"]["decision"] == "BLOCK" and r["status"] == "EXPECTATION_REVIEW"


def test_candidates_are_not_run_unless_requested():
    ok, _ = one()
    assert rt.run_suite(ok)["rows"] == [] and rt.run_suite(ok)["skipped_unreviewed"] == 1
    assert len(rt.run_suite(ok, include_candidates=True)["rows"]) == 1


def test_template_corpus_fully_passes_after_r19_r20_hardening(suite):
    """The three P2-A findings (untrusted state change to an approved host; zero-width and fullwidth-dot hosts) are
    fixed by R19/R20 and kept verbatim as regression cases in tests/test_gate_hardening.py."""
    _, res, _ = suite
    assert [r for r in res["rows"] if r["status"] != "PASS"] == []
    assert res["summary"]["false_positives"] == 0 and res["summary"]["false_negatives"] == 0


# ---------------- Llama generator (mock transport; never a production dependency) ----------------
GOOD = {"cases": [BASE, {**BASE, "category": "safe_control", "target": "https://api.partner.example.com/v1/items",
                         "expected": {"decision": "ALLOW", "rules": [], "enforcement": "GRANT_ISSUED"}},
                  {**BASE, "target": "https://github.com/real"}, {"not": "a case"}]}


def _transport(status=200, content=None):
    def h(req):
        body = json.loads(req.content)
        assert body["temperature"] == 0.5 and body["messages"][1]["content"] == rt.llama_prompt(2)
        return httpx.Response(status, json={"choices": [{"message": {"content": json.dumps(GOOD) if content is None else content}}]})
    return httpx.MockTransport(h)


@pytest.fixture
def meta_env(monkeypatch):
    monkeypatch.setenv("META_API_KEY", "synthetic-test-value")
    monkeypatch.setenv("META_MODEL", "llama-test-model")


def test_llama_generation_records_repro_and_yields_reviewed_candidates(meta_env):
    content, repro = rt.llama_generate("meta", 2, 0.5, seed=11, transport=_transport())
    assert repro["model"] == "llama-test-model" and repro["prompt_version"] == rt.PROMPT_VERSION and repro["seed"] == 11
    assert len(repro["prompt_sha256"]) == 64 and len(repro["source_sha256"]) == 64
    ok, rej = rt.accept(rt.parse_llama(content), repro)
    assert len(ok) == 2 and all(c.review_status == "candidate" for c in ok)
    assert {tuple(r["reasons"])[0].split(":")[0] for r in rej} == {"NON_SYNTHETIC_HOST", "SCHEMA"}


@pytest.mark.parametrize("status,content,err", [(500, None, "HTTP 500")])
def test_provider_failure_raises_and_never_falls_back(meta_env, status, content, err):
    with pytest.raises(rt.GenerationUnavailable, match=err):
        rt.llama_generate("meta", 2, 0.5, transport=_transport(status, content))


def test_unconfigured_or_contributor_models_are_refused(monkeypatch):
    monkeypatch.delenv("META_API_KEY", raising=False); monkeypatch.delenv("MODEL_API_KEY", raising=False)
    with pytest.raises(rt.GenerationUnavailable, match="not configured"):
        rt.llama_generate("meta", 1)
    monkeypatch.setenv("META_API_KEY", "synthetic-test-value"); monkeypatch.setenv("META_MODEL", "x-contributor")
    with pytest.raises(rt.GenerationUnavailable, match="contributor"):
        rt.llama_generate("meta", 1)


@pytest.mark.parametrize("reply", ["not json", '{"cases": [], "approve_all": true}', '[{"x":1}]', '{"cases": "x"}'])
def test_off_schema_replies_are_rejected(reply):
    with pytest.raises((ValueError, json.JSONDecodeError)):
        rt.parse_llama(reply)


def test_fenced_json_is_accepted():
    assert rt.parse_llama("```json\n" + json.dumps({"cases": [BASE]}) + "\n```") == [BASE]


# ---------------- CLI: generate, deterministic replay, run ----------------
def _cli(*args, env=None):
    return subprocess.run([sys.executable, "-m", "app.redteam", *args], cwd=BACKEND, capture_output=True, text=True,
                          env={**os.environ, **(env or {})}, timeout=120)


def test_cli_template_generate_run_and_report(tmp_path):
    out, rep = tmp_path / "c.jsonl", tmp_path / "r.json"
    assert _cli("generate", "--generator", "template", "--out", str(out)).returncode == 0
    r = _cli("run", str(out), "--report", str(rep))
    assert r.returncode == 0, r.stderr
    j = json.loads(rep.read_text())
    assert j["environment"]["gate_engine"] == g.POLICY_ENGINE_VERSION and j["summary"]["egress_calls"] == 0
    assert all(f["status"] != "PASS" for f in j["failures"]) and len(j["rows"]) == j["summary"]["cases"]


def test_cli_replay_is_deterministic_and_tamper_evident(tmp_path, meta_env):
    content, repro = rt.llama_generate("meta", 2, 0.5, transport=_transport())
    saved = tmp_path / "raw.json"
    saved.write_text(json.dumps({"content": content, "repro": repro}))
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    assert _cli("generate", "--generator", "llama", "--replay-response", str(saved), "--out", str(a)).returncode == 0
    assert _cli("generate", "--generator", "llama", "--replay-response", str(saved), "--out", str(b)).returncode == 0
    ids = lambda p: [json.loads(l)["test_id"] for l in p.read_text().splitlines()]
    assert ids(a) == ids(b) and len(ids(a)) == 2
    j = json.loads(saved.read_text()); j["content"] = j["content"].replace("high", "low")
    saved.write_text(json.dumps(j))
    assert _cli("generate", "--generator", "llama", "--replay-response", str(saved), "--out", str(a)).returncode == 2


def test_cli_live_generation_without_credentials_fails_cleanly(tmp_path):
    env = {k: "" for k in ("META_API_KEY", "MODEL_API_KEY", "META_MODEL")}
    r = _cli("generate", "--generator", "llama", "--out", str(tmp_path / "x.jsonl"), env=env)
    assert r.returncode == 3 and "no fallback" in r.stderr and not (tmp_path / "x.jsonl").exists()


def test_review_promotes_candidates_and_tampered_files_are_refused(tmp_path):
    ok, _ = one()
    p = tmp_path / "c.jsonl"
    rt.save_cases(str(p), ok)
    assert _cli("review", str(p), "--approve", ok[0].test_id, "--reviewer", "alice").returncode == 0
    c = rt.load_cases(str(p))[0]
    assert c.review_status == "approved" and c.reviewer == "alice"
    p.write_text(p.read_text().replace("169.254.169.254", "169.254.169.250"))   # content changed, id not
    with pytest.raises(ValueError, match="re-validation"):
        rt.load_cases(str(p))


def test_redteam_is_not_imported_by_the_api_process():
    r = subprocess.run([sys.executable, "-c", "import app.main, sys; print('app.redteam' in sys.modules)"], cwd=BACKEND,
                       capture_output=True, text=True, env=os.environ, timeout=120)
    assert r.stdout.strip().endswith("False"), r.stdout + r.stderr
