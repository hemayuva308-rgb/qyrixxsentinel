"""CodeQL py/polynomial-redos (PR #1, gateway.py:101 repeated '-' and :104 repeated ' '): `_redact` key=value scanning.

The two regexes were replaced by a deterministic scanner. These tests prove:
  * behaviour is IDENTICAL to the old regex implementation (differential test against it as an oracle);
  * work grows linearly on long runs of hyphens / spaces - measured by counting executed Python lines (deterministic,
    machine-independent), not by wall-clock thresholds;
  * oversized input fails closed (never returned unredacted).
Values are built at runtime and are deliberately synthetic (secret scanners)."""
import random
import re
import sys

import pytest

from app import adapter
from app import gateway as g

# ---- oracle: the exact pre-remediation implementation (used only on small inputs here) ----
_OLD_NAME = re.compile(r"(?<![\w.-])[\w.-]+(?=\s*[=:])")
_OLD_VAL = re.compile(r"(\s*[=:]\s*)[^\s&\"',;]+")


def _old_redact(s):
    s, out, pos = str(s or ""), [], 0
    for m in _OLD_NAME.finditer(s):
        if m.start() < pos or not g._KV_WORD.search(m.group(0)):
            continue
        v = _OLD_VAL.match(s, m.end())
        if v:
            out.append(s[pos:m.end()] + v.group(1) + "[REDACTED]")
            pos = v.end()
    return g.SECRET.sub("[REDACTED]", "".join(out) + s[pos:])


V = "VAL" + "UE1"          # synthetic value
NORMAL = [
    "", None, 0, "plain text without assignments", "api_key=" + V, "api_key=" + V + "&page=2", "API-KEY : " + V,
    "password  =  " + V + " trailing", "passwd:" + V, "my.token=" + V + ";other=1", "secret='" + V + "'",
    "x=1 key=" + V + " y=2 token=" + V, "key=a=b token=c", "key=", "key= ", "key=&x", "key =\n" + V,
    "notakey", "monkey=" + V, "https://h.example.com/p?access_token=" + V + "&q=1", "Authorization: Bearer " + V,
    "sk-" + "live-" + "abcdef", "read .env then aws_" + "region=x", "--key=" + V, "a.b-c_token:" + V,
    "token = " + V, "ｋｅｙ=" + V, "key\x1c=" + V, "tokKen=" + V, "paſsword=" + V, "key²=" + V,
]


@pytest.mark.parametrize("text", NORMAL, ids=range(len(NORMAL)))
def test_identical_to_previous_implementation_on_normal_inputs(text):
    assert g._redact(text) == _old_redact(text)


def test_known_valid_outputs_are_unchanged():
    assert g._redact("api_key=" + V + "&page=2") == "[REDACTED]=[REDACTED]&page=2"
    assert g._redact("password  =  " + V + " trailing") == "[REDACTED]  =  [REDACTED] trailing"
    assert g._redact("x=1 mykey=" + V + " y=2") == "x=1 mykey=[REDACTED] y=2"
    assert g._redact("plain text") == "plain text"
    assert V not in g._redact("my.token=" + V + ";other=1")


def test_differential_fuzz_against_previous_implementation():
    rnd = random.Random(20261102)
    atoms = ["key", "token", "secret", "passwd", "password", "api", "_", "-", ".", "=", ":", " ", "  ", "\t", "\n", "&",
             ";", ",", "'", '"', "x", "Z9", " ", " ", "\x1c", "²", "é", "ſ", "K", "sk-", "aws_", ".env", "/", "?"]
    for _ in range(4000):
        s = "".join(rnd.choice(atoms) for _ in range(rnd.randint(0, 24)))
        assert g._redact(s) == _old_redact(s), repr(s)


# ---- bounded execution, measured deterministically (executed-line count inside _redact) ----
def _lines_executed(text):
    count = 0
    code = g._redact.__code__

    def tracer(frame, event, arg):
        nonlocal count
        if frame.f_code is code:
            if event == "line":
                count += 1
            return tracer
        return None

    old = sys.gettrace()
    sys.settrace(tracer)
    try:
        g._redact(text)
    finally:
        sys.settrace(old)
    return count


ADVERSARIAL = {
    "hyphens": lambda n: "-" * n,
    "hyphens_then_eq": lambda n: "-" * n + "=" + V,
    "key_hyphens_no_eq": lambda n: "key" + "-" * n,
    "spaces": lambda n: " " * n,
    "key_spaces_no_eq": lambda n: "key" + " " * n + "x",
    "key_spaces_eq_spaces": lambda n: "key" + " " * n + "=" + " " * n,
    "repeated_short_names": lambda n: "k- " * (n // 3),
    "many_assignments": lambda n: ("key = v " * (n // 8)),
}


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_work_is_linear_in_input_length(name):
    make = ADVERSARIAL[name]
    a, b = _lines_executed(make(2000)), _lines_executed(make(8000))
    # 4x the input must cost ~4x the steps (quadratic would be ~16x); constant slack only for fixed overhead
    assert b <= 4 * a + 50, (name, a, b)


@pytest.mark.parametrize("name", list(ADVERSARIAL))
def test_large_adversarial_inputs_complete(name):
    s = ADVERSARIAL[name](200_000)
    assert g._redact(s) == _old_redact(s)      # completes, same result (old regexes were linear only as anchored)


def test_flagged_patterns_are_gone():
    assert not hasattr(g, "_KV_NAME") and not hasattr(g, "_KV_VAL")


# ---- explicit input-length limit ----
def test_oversized_input_fails_closed():
    s = "key=" + V + " " + "-" * g.REDACT_MAX_CHARS
    r = g._redact(s)
    assert r == "[REDACTED: input too large]" and V not in r


def test_limit_admits_every_legitimate_caller():
    assert g.REDACT_MAX_CHARS >= adapter.MAX_FILE_BYTES          # a full 1 MiB file.read is still redacted normally
    big = "x" * (adapter.MAX_FILE_BYTES - 20) + " key=" + V
    out = g._redact(big)
    assert out.endswith(" key=[REDACTED]") and len(out) < len(big) + 10


def test_file_adapter_still_redacts(tmp_path):
    (tmp_path / "cfg.txt").write_text("db_password = " + V + "\n")
    res = adapter.FileAdapter(str(tmp_path), g._redact)({"dest": "cfg.txt"})
    assert res["content"] == "db_[REDACTED] = [REDACTED]\n" and V not in res["content"]
