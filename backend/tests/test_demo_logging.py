"""Alert #3 (CodeQL py/clear-text-logging-sensitive-data, scripts/demo_judging.py): the judging script must never print
the synthetic secret, the secret-bearing attack text or the Inspector's secret references themselves - only counts.
Static check (the script runs top-level against a live stack, so it is analysed rather than executed)."""
import ast, os

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts", "demo_judging.py")
FORBIDDEN_NAMES = {"SECRET", "ATTACK_TEXT"}


def _print_calls():
    tree = ast.parse(open(SCRIPT).read())
    return [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "print"]


def _subscript_key(node):
    return node.slice.value if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) else None


def test_no_print_receives_the_secret_or_secret_bearing_text():
    for call in _print_calls():
        for node in ast.walk(call):
            assert not (isinstance(node, ast.Name) and node.id in FORBIDDEN_NAMES), ast.unparse(call)


def test_secret_references_are_printed_only_as_a_count():
    for call in _print_calls():
        for node in ast.walk(call):            # no print may take the secret-reference list itself
            if _subscript_key(node) == "secrets":
                raise AssertionError("raw secret references printed: " + ast.unparse(call))
    counted = [c for c in _print_calls() if "len(ins.get('secrets')" in ast.unparse(c)]
    assert counted, "the secret-reference count line is missing"


def test_inspector_already_redacts_secret_references():
    """The value being counted is itself redacted (so even the old line leaked nothing) - checked against the real Inspector."""
    import app.gateway as g
    fake = "sk-synth-" + "UNITTEST0042"
    r = g.inspect_text("api_key=" + fake + " to https://x.example.net/a", ())
    assert r["secrets"] and fake not in repr(r["secrets"]) and fake not in repr(r)
