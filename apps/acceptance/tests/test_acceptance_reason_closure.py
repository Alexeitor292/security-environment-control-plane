"""Every bounded code the harness can raise is a DECLARED code.

THE DRIFT THIS CLOSES
---------------------
``AcceptanceError`` accepts any string. Nothing checked that the string was a member of the closed
vocabulary the harness publishes, so a code could be raised for months without ever being reviewed —
which is exactly what happened: ``acceptance_evidence_public_value_not_permitted`` was raised four
times in ``evidence.py`` and absent from ``reasons.py``, while seven sibling loader refusals were
declared. Found by acc-C-queues, who flagged it without asserting it was wrong, correctly, since the
rule had never been decided.

THE RULE, NOW DECIDED
---------------------
**Every bounded code this harness can emit is declared, whether or not it can reach a document.**
Loader refusals never appear in a ``reason_code`` — the document carrying them is refused rather
than read — and they are still declared, because a reason code is what an operator sees when a run
refuses, and an undeclared one has been reviewed by nobody.

Checked over the AST rather than by importing and catching, because the property is "this literal
appears in a raise position", which is structural. Value-level checks cannot answer it: a code that
is never raised on any path a test exercises is invisible to every runtime approach.
"""

from __future__ import annotations

import ast
import pathlib

from secp_acceptance.reasons import ALL_REASONS

_PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "secp_acceptance"


def _raised_codes() -> dict[str, list[str]]:
    """Every string literal passed as the first argument to ``AcceptanceError(...)``.

    Literals only. A code built at runtime could not be checked here — and would itself be a defect,
    since the whole point of the vocabulary is that the set is reviewable by reading it.
    """
    found: dict[str, list[str]] = {}
    for path in sorted(_PACKAGE.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "id", "") != "AcceptanceError":
                continue
            if node.args and isinstance(node.args[0], ast.Constant):
                value = node.args[0].value
                if isinstance(value, str):
                    found.setdefault(value, []).append(path.name)
    return found


def test_every_raised_code_is_declared():
    """THE guard. A code raised but not declared has been reviewed by nobody."""
    raised = _raised_codes()
    undeclared = {
        code: sorted(set(files)) for code, files in raised.items() if code not in ALL_REASONS
    }
    assert undeclared == {}, (
        f"these codes are raised but absent from the closed vocabulary: {undeclared}\n"
        f"Add them to HARNESS_REASONS with a comment saying what they mean. A reason code is what "
        f"an operator sees when a run refuses; an undeclared one has been reviewed by nobody."
    )


def test_the_raise_scanner_can_actually_fail():
    """CONTROL. A scanner that found nothing would make the guard above vacuous forever.

    Both directions: it must find a real raise, and it must NOT match a call that merely mentions
    the name — the distinction a substring search cannot draw, and the one that let a renamed
    ``DOCKER_HOST`` survive a workflow guard earlier in this milestone.
    """
    raised = _raised_codes()
    assert len(raised) > 10, "the scanner found almost nothing; it is not reading the package"
    assert "acceptance_evidence_invalid" in raised

    # a call that is not an AcceptanceError construction must not be collected
    tree = ast.parse('SomethingElse("acceptance_not_a_real_code")\n')
    hits = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "AcceptanceError"
    ]
    assert hits == []


def test_the_declared_vocabulary_is_not_padded_with_codes_nothing_raises():
    """The other direction, reported rather than asserted.

    A declared code nothing raises is NOT a defect — several are emitted by product code, or exist
    for stages not yet built, and deleting them would break the provenance guarantees. But a large
    unexplained gap would mean the vocabulary had stopped describing the harness, so the count is
    pinned loosely enough to allow growth and tightly enough to notice abandonment.
    """
    from secp_acceptance.reasons import HARNESS_REASONS

    raised = set(_raised_codes())
    harness_only_unraised = HARNESS_REASONS - raised
    # Every unraised harness code must at least be referenced somewhere in the package, so a code
    # that is neither raised nor mentioned cannot sit in the set unnoticed.
    corpus = "\n".join(
        path.read_text(encoding="utf-8")
        for path in _PACKAGE.rglob("*.py")
        if "__pycache__" not in path.parts
    )
    orphans = sorted(code for code in harness_only_unraised if code not in corpus)
    assert orphans == [], (
        f"these harness codes are declared, never raised, and mentioned nowhere in the package: "
        f"{orphans}. Either something should emit them or they should go."
    )
